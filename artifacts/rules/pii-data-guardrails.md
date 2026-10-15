---
description: >-
  Non-negotiable constraints when working with the postgres-pii MCP server:
  never surface raw PII, respect deny/ask gates, never bypass a denial.
alwaysApply: true
---

When using the `postgres-pii` MCP server:

- **Never render raw PII into context or output.** Direct PII only ever appears as a `tok_…` token; embedded PII only as `<email>`/`<cpf>`/`<phone>`; sensitive columns stay `restricted`. If you see a raw CPF, email, or name, something is wrong — stop and report it.
- **`db.unmask` is deny-by-default.** Call it only when the operator has deliberately opened the deny gate for this specific task and re-confirmed. A denial is final.
- **Never circumvent a gate.** Do not retry a denied request with cosmetically changed arguments, split it into smaller requests, or route through another tool to achieve the same exposure.
- **Prefer the non-gated path.** Answer from `public`/aggregate columns first; request PII columns only when the question truly requires them.
- **Justify before gated calls.** State which PII columns, why, and rough row count, so the human approval is informed.
- **Treat tokens as sensitive too.** They are correlatable pseudonyms — reproduce only what the answer needs; never paste them into unrelated contexts.
- **Stay in scope.** Only the postgres MCP tools are available; no filesystem, shell, or network. Do not attempt workarounds.

See the `pii-query-protocol` skill for the full tool contract and masking semantics.
