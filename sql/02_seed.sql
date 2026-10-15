-- 02_seed.sql
-- Synthetic demo data. All identities are fictional.

\set ON_ERROR_STOP on

INSERT INTO patients (full_name, cpf, email, phone, created_at) VALUES
  ('Ana Beatriz Souza',    '529.982.247-25', 'ana.souza@example.com',    '(11) 98888-1234', '2024-01-10 08:00:00-03'),
  ('Carlos Eduardo Lima',  '111.444.777-35', 'carlos.lima@example.com',  '(21) 97777-5678', '2024-02-15 09:30:00-03'),
  ('Mariana Ferreira',     '390.533.447-05', 'mari.ferreira@example.com', NULL,             '2024-03-05 10:15:00-03'),
  ('Joao Pedro Alves',     '123.456.789-09', 'joao.alves@example.com',   '(31) 96666-9012', '2024-04-20 14:00:00-03'),
  ('Leticia Ramos',        '987.654.321-00', 'leti.ramos@example.com',   '(41) 95555-3456', '2024-05-30 11:45:00-03');

INSERT INTO appointments (patient_cpf, appointment_at, specialty, diagnosis_code, notes) VALUES
  ('529.982.247-25', '2024-09-02 09:00:00-03', 'Cardiologia', 'I10',
   'Paciente relatou dor no peito; retornar com exames.'),
  ('529.982.247-25', '2024-11-14 14:30:00-03', 'Cardiologia', NULL,
   'Retorno. Confirmar agenda por ana.souza@example.com.'),
  ('111.444.777-35', '2024-09-05 10:15:00-03', 'Ortopedia',   'M54.5',
   'Dor lombar cronica. Contato: (21) 97777-5678.'),
  ('111.444.777-35', '2024-12-01 16:00:00-03', 'Ortopedia',   NULL,
   'Sessao de fisioterapia concluida.'),
  ('390.533.447-05', '2024-09-12 08:30:00-03', 'Dermatologia','L70.0',
   'Paciente Mariana autoriza envio de exames para mari.ferreira@example.com.'),
  ('123.456.789-09', '2024-10-03 11:00:00-03', 'Neurologia',  'G43.9',
   'Migraine com aura; paciente Joao (31) 96666-9012.'),
  ('123.456.789-09', '2024-12-18 15:30:00-03', 'Neurologia',  NULL,
   'Aguardando laudo.'),
  ('987.654.321-00', '2024-11-07 09:45:00-03', 'Endocrino',   'E11.9',
   'Paciente Leticia (41) 95555-3456; ajustar dose da metformina.');

ANALYZE patients;
ANALYZE appointments;
