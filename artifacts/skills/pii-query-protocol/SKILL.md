---
name: pii-query-protocol
description: >-
  Reference for the postgres-pii MCP server: the three-tool surface,
  blast-radius tiers, the declarative db.query shape, and how
  masking/tokenization work. Trigger when querying PII-bearing Postgres data or
  reasoning about allow/ask/deny gates on this server.
---

## When to Apply
Use whenever you are about to call `db.describe`, `db.query`, or `db.unmask` on the `postgres-pii` MCP server, or when deciding whether a query touches PII.

## Tool surface and blast radius
The server deliberately exposes the **minimum** number of tools (three), split by security blast radius so the harness can gate them independently:

| Tool | Blast radius | Gate | Purpose |
|---|---|---|---|
| `db.describe` | none (metadata only) | **allow** | tables, columns, types, classification, row estimates, declared joins |
| `db.query` | low→high (arg-dependent) | **ask** | declarative SELECT over declared joins; PII rendered masked |
| `db.unmask` | inherently high | **deny** (opt-in) | reveals raw value from a token |

## Why only three tools
One declarative tool (`db.query`) collapses explore + join + filter + project into a single call, minimizing tool calls. Classification metadata ships inside `db.describe`, so the agent never has to "guess" the schema with probing queries.

## Declarative db.query contract
No raw SQL — the payload is a validated AST, so injection is impossible by construction:
- `tables: string[]` — must all be in the catalog
- `columns: { table, column }[]` — must exist and be classified
- `join` is **derived** by the server from the declared `join_relationships` topology (edges whose keys are themselves PII). The agent does not specify join syntax.
- `where: { table, column, op, value }[]` — `op` from a fixed set (`eq`, `gt`, `lt`, `in`, …). Filtering on a token works because tokens are deterministic.
- `orderBy`, `limit` — `limit` is mandatory and capped server-side (MAX_ROWS) regardless of what the agent asks.

## Masking rules enforced server-side
- `public` → returned raw.
- `pii_direct` (cpf, email, name, phone) → returned as a **deterministic token** (`tok_…`). Same value ⇒ same token, so tokens join across tables with no raw PII anywhere.
- `pii_embedded` (free-text `notes`) → run through a redactor that replaces embedded emails/CPFs/phones with `<email>`/`<cpf>`/`<phone>`.
- `sensitive` (e.g. clinical `diagnosis_code`) → withheld as `restricted`.
- Columns absent from the classification catalog are **not exposed at all**.

## Gate philosophy (deny vs ask)
- **Always dangerous** (deny regardless of args): raw SQL, bulk/export (`SELECT *`), `db.unmask`. These tools are simply not registered or hard-deny — there is no argument that makes them safe.
- **Possibly dangerous** (danger depends on args): `db.query` requesting PII columns. These are **ask**-gated. The server tags the result (e.g. `requiresApproval: "pii_columns: [email, cpf]"`) so the human sees exactly what is being approved.

## How to Use
1. Call `db.describe` first, always.
2. Map the question to columns; note each column's `classification`/`renderedAs`.
3. Compose one `db.query` with the needed filter; reuse a returned token as a `where` value to "join" follow-ups without new PII exposure.
4. If PII columns are unavoidable, justify before the gated call and accept a denial by degrading to masked output.

Related rule: `pii-data-guardrails`.
