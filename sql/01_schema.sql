-- 01_schema.sql
-- Sensitive PII schema for the postgres-pii MCP server.
-- Two PII tables joined on a PII field: patients.cpf <-> appointments.patient_cpf

\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ------------------------------------------------------------------ tables

CREATE TABLE patients (
  patient_id bigserial PRIMARY KEY,
  full_name  text NOT NULL,           -- PII (direct)
  cpf        text NOT NULL UNIQUE,    -- PII (direct) AND the join key
  email      text NOT NULL,           -- PII (direct)
  phone      text,                    -- PII (direct)
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE appointments (
  appointment_id  bigserial PRIMARY KEY,
  patient_cpf     text NOT NULL REFERENCES patients (cpf),  -- PII join key
  appointment_at  timestamptz NOT NULL,
  specialty       text NOT NULL,      -- public
  diagnosis_code  text,               -- sensitive (clinical)
  notes           text                -- PII embedded in free text
);

CREATE INDEX idx_appointments_patient_cpf ON appointments (patient_cpf);

-- --------------------------------------------------- classification catalog
-- Source of truth for what the MCP exposes and how each column is rendered.
-- Columns absent from this table are NOT exposed by the server at all.

CREATE TABLE column_classification (
  table_name     text NOT NULL,
  column_name    text NOT NULL,
  classification text NOT NULL
                 CHECK (classification IN ('public','pii_direct','pii_embedded','sensitive')),
  pii_kind       text,               -- token namespace: cpf | email | phone | name
  PRIMARY KEY (table_name, column_name)
);

INSERT INTO column_classification (table_name, column_name, classification, pii_kind) VALUES
  ('patients',      'patient_id',    'public',       NULL),
  ('patients',      'full_name',     'pii_direct',   'name'),
  ('patients',      'cpf',           'pii_direct',   'cpf'),
  ('patients',      'email',         'pii_direct',   'email'),
  ('patients',      'phone',         'pii_direct',   'phone'),
  ('patients',      'created_at',    'public',       NULL),
  ('appointments',  'appointment_id','public',       NULL),
  ('appointments',  'patient_cpf',   'pii_direct',   'cpf'),
  ('appointments',  'appointment_at','public',       NULL),
  ('appointments',  'specialty',     'public',       NULL),
  ('appointments',  'diagnosis_code','sensitive',    NULL),
  ('appointments',  'notes',         'pii_embedded', NULL);

-- ---------------------------------------------------- declared join topology
-- The server will ONLY join tables along these declared edges (the join key
-- itself is PII). No arbitrary joins are possible.

CREATE TABLE join_relationships (
  left_table   text NOT NULL,
  left_column  text NOT NULL,
  right_table  text NOT NULL,
  right_column text NOT NULL,
  PRIMARY KEY (left_table, left_column, right_table, right_column)
);

INSERT INTO join_relationships (left_table, left_column, right_table, right_column)
VALUES ('appointments', 'patient_cpf', 'patients', 'cpf');

-- --------------------------------------------------------------- token vault
-- Token -> encrypted original value. Ciphertext only at rest; the PII_KEY is
-- never stored, it is passed as a function argument by the MCP server.

CREATE TABLE pii_vault (
  token      text PRIMARY KEY,
  cipher     bytea NOT NULL,        -- pgp_sym_encrypt(plain, PII_KEY)
  value_kind text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Deterministic pseudonymization: same value + kind + key => same token, so
-- tokens correlate across tables without ever exposing the raw value.
CREATE OR REPLACE FUNCTION pii_tokenize (p_value text, p_kind text, p_key text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER VOLATILE AS $fn$
DECLARE
  v_token  text;
  v_cipher bytea;
BEGIN
  IF p_value IS NULL THEN
    RETURN NULL;
  END IF;
  v_token := 'tok_'
             || substring(encode(digest(p_value || '|' || p_kind || '|' || p_key, 'sha256'), 'hex')
                          FROM 1 FOR 24);
  v_cipher := pgp_sym_encrypt(p_value, p_key, 'cipher-algo=aes256');
  INSERT INTO pii_vault (token, cipher, value_kind)
  VALUES (v_token, v_cipher, p_kind)
  ON CONFLICT (token) DO NOTHING;
  RETURN v_token;
END $fn$;

CREATE OR REPLACE FUNCTION pii_unmask (p_token text, p_key text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER STABLE AS $fn$
DECLARE
  v_plain text;
BEGIN
  SELECT pgp_sym_decrypt(v.cipher, p_key) INTO v_plain
    FROM pii_vault v
   WHERE v.token = p_token;
  IF v_plain IS NULL THEN
    RAISE EXCEPTION 'unmask failed: unknown token';
  END IF;
  RETURN v_plain;
END $fn$;

-- Strips PII that is embedded in free text (emails, CPFs, phone numbers).
CREATE OR REPLACE FUNCTION pii_redact (p_value text)
RETURNS text LANGUAGE sql IMMUTABLE AS $fn$
  SELECT regexp_replace(
           regexp_replace(
             regexp_replace(COALESCE(p_value, ''),
               '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<email>', 'g'),
             '\d{3}\.?\d{3}\.?\d{3}-?\d{2}', '<cpf>', 'g'),
           '\d{2}[- ]?\d{4,5}[- ]?\d{4}', '<phone>', 'g');
$fn$;

-- ------------------------------------------------------------- reader role
-- The MCP connects as mcp_reader: read-only, no DDL/DML, no ownership of the
-- data. Masking is enforced by the server's query builder (single code path);
-- this role limits the blast radius if that path were ever bypassed.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_reader') THEN
    CREATE ROLE mcp_reader NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO mcp_reader;
GRANT SELECT ON patients, appointments, column_classification, join_relationships, pii_vault
  TO mcp_reader;
GRANT EXECUTE ON FUNCTION pii_tokenize (text, text, text),
                 pii_unmask (text, text),
                 pii_redact (text)
  TO mcp_reader;
