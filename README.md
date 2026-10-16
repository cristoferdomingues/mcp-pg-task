# mcp-pg-task

A Postgres MCP server (`mcp-postgres-pii`) that lets an agent **join across PII tables**
while guaranteeing **raw PII never enters the agent's context**. Built as the server half
of a two-part system: this repo is the MCP server; the consuming subagent ships in
`artifacts/` (`pii-data-analyst` agent + `pii-query-protocol` skill + `pii-data-guardrails`
rule) — snapshots of the canonical copies in the BlackAgents workspace.

## The problem it solves

Give an agent access to sensitive customer data so it can answer real questions
("list the cardiology appointments for this CPF") without ever seeing a raw CPF,
email, name, or clinical note. The tables are joined **on a PII field**
(`patients.cpf  <->  appointments.patient_cpf`), which is the hard case: the join key
itself is sensitive, so a naive `SELECT ... JOIN` leaks PII on every row.

## Design goals (and how each is met)

| Goal | Mechanism |
|---|---|
| Minimum tool count | **3 tools** — `db.describe`, `db.query`, `db.unmask`. One declarative tool collapses explore+join+filter+project into a single call. |
| Minimize tool calls | Classification + join topology ship inside `db.describe`, so the agent never probes the schema. `db.query` does the join server-side in one call. |
| Separate blast radius | Tools are tagged `allow` / `ask` / `deny` so the harness gates them independently (see below). |
| Raw PII never in context | Deterministic **tokenization** for direct PII, server-side **redaction** for embedded PII, **withholding** for sensitive columns. Enforced in one code path (the query builder), not scattered. |

## Tool surface & blast radius

| Tool | Blast radius | Gate | Behavior |
|---|---|---|---|
| `db.describe` | none (metadata) | **allow** | tables, columns, types, classification, `renderedAs`, row estimates, declared joins. Safe to allow-list. |
| `db.query` | low→high (arg-dependent) | **ask** | Declarative SELECT over declared joins. PII columns returned masked. Tags `hints.requiresApproval`. |
| `db.unmask` | inherently high | **deny** | Reveals raw value from a token. Disabled unless `PII_UNMASK_ENABLED=true`. |

### Why "always dangerous" vs "possibly dangerous"

- **Always dangerous → `deny` regardless of arguments:** raw SQL, bulk export, `db.unmask`.
  There is no argument that makes these safe, so `db.unmask` is simply not reachable unless
  the operator flips the switch. There is no raw-SQL tool at all — injection is impossible
  *by construction*, not by sanitization.
- **Possibly dangerous → `ask`, depends on arguments:** `db.query` requesting PII columns.
  Danger depends on *which* columns and *how many* rows, so it is ask-gated and the server
  tells the human exactly what is being approved via `hints.piiColumns`.

## Masking model (enforced server-side)

A `column_classification` catalog is the single source of truth. Columns absent from it
are **not exposed at all**.

| Classification | Example | Rendered as | Mechanism |
|---|---|---|---|
| `public` | `specialty`, `appointment_at` | raw | returned as-is |
| `pii_direct` | `cpf`, `email`, `full_name`, `phone` | **token** (`tok_…`) | `pii_tokenize` — deterministic sha256 + encrypted vault |
| `pii_embedded` | `notes` (free text) | **redacted** (`<email>`, `<cpf>`, `<phone>`) | `pii_redact` |
| `sensitive` | `diagnosis_code` | **restricted** (`[restricted]`) | withheld |

**Tokens are deterministic**: same value ⇒ same token. This is what makes joins and
filters work with zero PII exposure — the token *is* the correlation key:

```sql
-- what db.query actually runs when you filter a joined table by a token
SELECT appointments.appointment_at, pii_redact(appointments.notes)
  FROM appointments
 WHERE pii_tokenize(appointments.patient_cpf, $2, $1) = $3
 LIMIT $4;
```

The agent gets a token back from the join, then reuses that token as a `where` value to
follow up — no raw CPF ever crosses the wire in either direction. Raw values live only in
`pii_vault` as `pgp_sym_encrypt` ciphertext, decryptable only via `db.unmask` (deny-gated).

## Declarative `db.query` — no raw SQL

The payload is a validated AST (Zod), not a string:

- `tables: string[]` — must be in the catalog
- `columns: { table, column }[]` — must be classified
- `join` — **derived by the server** from the `join_relationships` topology. The agent never writes join syntax; only declared edges (whose keys are themselves PII) are usable.
- `where: { table, column, op, value }[]` — `op` from a fixed allow-list
- `orderBy`, `limit` — `limit` is mandatory and capped server-side by `MAX_ROWS`

## How to Use from Chat

When interacting with an AI agent connected to this MCP server, you can query data in natural language or execute structured tool calls. The agent maps user requests to the 3 available tools:

### 1. `db.describe` (Metadata & Schema — Always Safe)
Inspect the exposed catalog, column classifications, and allowed joins without reading any row data.
- **Natural language prompts:**
  - *"Describe the available tables and columns in the database."*
  - *"Show the schema for `patients` and how PII fields are handled."*
  - *"Which join relationships are permitted between tables?"*
- **Example tool payload:**
  ```json
  { "table": "patients" }
  ```

### 2. `db.query` (Declarative Queries — Ask-Gated)
Query and join across tables with server-side masking (`tok_...` tokens, redacted free text, restricted clinical fields). Raw SQL text is never accepted.
- **Natural language prompts:**
  - *"How many appointments are scheduled per medical specialty?"*
  - *"List appointments for 'Cardiology' ordered by date."*
  - *"Find all appointments associated with patient token `tok_1a2b3c...`."*
  - *"Show patient appointment history joining patients and appointments (limit 10)."*
- **Example tool payload:**
  ```json
  {
    "tables": ["patients", "appointments"],
    "columns": [
      { "table": "patients", "column": "cpf" },
      { "table": "appointments", "column": "specialty" },
      { "table": "appointments", "column": "appointment_at" }
    ],
    "where": [
      { "table": "appointments", "column": "specialty", "op": "eq", "value": "Cardiology" }
    ],
    "limit": 10
  }
  ```

### 3. `db.unmask` (Token Resolution — Deny-Gated)
Resolves pseudonym tokens back to raw PII from the encrypted vault. Disabled by default (`PII_UNMASK_ENABLED=false`) and requires explicit approval with a stated business reason.
- **Natural language prompts:**
  - *"Reveal the original value for token `tok_a1b2c3d4e5f60718` for emergency contact verification."*
- **Example tool payload:**
  ```json
  { "tokens": ["tok_a1b2c3d4e5f60718"] }
  ```

### Boundaries & Restrictions
- **No raw SQL or DML/DDL:** Commands like `SELECT * FROM ...`, `INSERT`, `UPDATE`, `DELETE`, or `DROP` are rejected by design (the database user `mcp_reader` is strictly read-only, and no raw SQL string input exists).
- **No arbitrary joins:** Only relationships declared in `join_relationships` can be joined.
- **No uncataloged columns:** Columns missing from the classification catalog are invisible and inaccessible.

## Layout

```
mcp-pg-task/
├── sql/
│   ├── 01_schema.sql      # tables, classification catalog, join topology, vault, functions, role
│   └── 02_seed.sql        # synthetic patients + appointments
├── src/
│   ├── config.ts          # env parsing (DATABASE_URL, PII_KEY, PII_UNMASK_ENABLED, MAX_ROWS)
│   ├── db.ts              # pg pool
│   ├── catalog.ts         # loads classification + join topology (cached)
│   ├── query.ts           # declarative AST -> parameterized SQL + masking
│   ├── tools.ts           # the 3 tools, tagged with blast radius
│   └── index.ts           # MCP server, stdio transport
├── scripts/smoke.mjs      # end-to-end smoke over stdio (5 scenarios)
├── artifacts/             # consuming subagent (agent + skill + rule) — see below
└── .env.example
```

### The consuming subagent (`artifacts/`)

| Artifact | Name | Role |
|---|---|---|
| `artifacts/agents/pii-data-analyst.md` | **pii-data-analyst** | the subagent — may only call this MCP server |
| `artifacts/skills/pii-query-protocol/SKILL.md` | **pii-query-protocol** | tool contract, masking semantics, gate philosophy |
| `artifacts/rules/pii-data-guardrails.md` | **pii-data-guardrails** | non-negotiables: no raw PII, no gate circumvention |

Canonical copies live in the BlackAgents workspace (`.black-agents/artifacts/`); these are
snapshots for the exercise. The agent's frontmatter declares `mcpServers: ["postgres-pii"]`
so the harness scopes it to this server only.

## Run it

```bash
cp .env.example .env         # fill in DATABASE_URL, PII_KEY
npm install
npm run build

# create the schema + seed (needs a superuser/owner connection)
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/01_schema.sql -f sql/02_seed.sql

npm start                    # MCP server on stdio
```

### Transport

**stdio** for this exercise — simplest to run and audit. Swapping to Streamable HTTP
changes only the transport wiring in `index.ts`; the tool contract, masking, and gate
labels are transport-agnostic.

### Smoke test

```bash
SMOKE_DATABASE_URL="postgres://mcp_reader:…@localhost:5432/clinic" node scripts/smoke.mjs
```

Covers: (1) `db.describe`, (2) masked join across both PII tables, (3) follow-up filter by
token with no raw PII, (4) SQL-injection attempt rejected by validation, (5) `db.unmask`
deny posture.

## Security posture (defense in depth)

1. **Query builder** is the single masking code path — every column passes through it.
2. **Zod validation** rejects anything outside the declarative schema (injection impossible by construction).
3. **Declared join topology** — arbitrary joins are unreachable.
4. **`mcp_reader` role** — `SELECT` only, no DDL/DML; limits blast radius if the builder were ever bypassed.
5. **Encrypted vault** — raw values at rest are `pgp_sym_encrypt` ciphertext; `PII_KEY` is never stored, only passed as a function argument.
6. **Deny-gated `unmask`** — the only path to raw data is off by default.

## Note on function volatility

`pii_tokenize` is `VOLATILE` (it writes to `pii_vault`); `pii_unmask` and `pii_redact`
are `STABLE`/`IMMUTABLE`. Marking `pii_tokenize` `STABLE` would make Postgres reject the
`INSERT` ("INSERT is not allowed in a non-volatile function").
