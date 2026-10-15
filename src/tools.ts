import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { config } from "./config.js";
import { pool } from "./db.js";
import { loadCatalog, renderedAs } from "./catalog.js";
import { buildQuery, queryInput, QueryError } from "./query.js";

const IDENT = /^[a-z_][a-z0-9_]*$/;
const TOKEN = /^tok_[0-9a-f]{16,64}$/;

const describeInput = z.object({ table: z.string().regex(IDENT).optional() });
const unmaskInput = z.object({
  tokens: z.array(z.string().regex(TOKEN)).min(1).max(config.unmaskMaxTokens)
});

type ToolResult = {
  [key: string]: unknown; // the SDK result type carries an index signature
  content: { type: "text"; text: string }[];
  isError?: boolean;
};

function ok (payload: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}

function fail (error: string, message: string, extra: Record<string, unknown> = {}): ToolResult {
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify({ error, message, ...extra }, null, 2) }]
  };
}

function message (e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Three tools, deliberately split by security blast radius:
 *
 *   db.describe  ALWAYS SAFE          -> allow-gate in the harness
 *   db.query     SAFE OR DANGEROUS    -> ask-gate; danger depends on arguments
 *   db.unmask    ALWAYS DANGEROUS     -> deny-gate; also off by default server-side
 *
 * Raw PII cannot leave the server through db.query regardless of arguments:
 * masking is enforced in the SQL builder, not in a post-processing step.
 */
export function registerTools (server: McpServer): void {
  server.registerTool(
    "db.describe",
    {
      title: "Describe database schema (safe)",
      description:
        "ALWAYS SAFE / allow-gate candidate. Returns the exposed tables, columns, PII " +
        "classification, how each column will be rendered (raw|token|redacted|restricted), " +
        "the declared join keys and row estimates. Contains no row data. Call this first.",
      inputSchema: describeInput.shape
    },
    async (rawArgs: unknown) => {
      const args = describeInput.parse(rawArgs ?? {});
      try {
        const catalog = await loadCatalog();
        const tables = [...catalog.tables.values()].filter((t) => !args.table || t.table === args.table);
        if (args.table && tables.length === 0) {
          return fail("UNKNOWN_TABLE", `table '${args.table}' is not exposed; call db.describe without arguments`);
        }
        return ok({
          tables: tables.map((t) => ({
            table: t.table,
            rowEstimate: t.rowEstimate,
            columns: t.columns.map((c) => ({
              column: c.column,
              dataType: c.dataType,
              classification: c.classification,
              renderedAs: renderedAs(c.classification)
            }))
          })),
          joins: catalog.joins,
          policies: {
            joins: "only the declared join_relationships edges can be joined; no SQL text is ever accepted",
            ordering: "orderBy is allowed on public columns only",
            aggregate: "sum/avg/min/max on public columns only; count() anywhere",
            limits: { defaultRows: config.defaultRows, maxRows: config.maxRows },
            unmask: config.unmaskEnabled
              ? "db.unmask is enabled server-side (still deny-gated by policy)"
              : "db.unmask is DISABLED server-side"
          }
        });
      } catch (e) {
        return fail("DESCRIBE_FAILED", message(e));
      }
    }
  );

  server.registerTool(
    "db.query",
    {
      title: "Declarative read-only query (ask-gate candidate)",
      description:
        "ASK-GATE candidate: blast radius depends on the arguments. Declarative read-only " +
        "query — pass tables, columns and filters; the join is derived from the declared PII " +
        "join topology, so one call can span joined tables. Raw PII is NEVER returned: " +
        "pii_direct columns come back as tok_... pseudonyms, free-text PII is redacted and " +
        "sensitive clinical fields become '[restricted]'. Prefer filtering by an existing " +
        "token over supplying raw PII values, and prefer aggregated/public columns.",
      inputSchema: queryInput.shape
    },
    async (rawArgs: unknown) => {
      try {
        const input = queryInput.parse(rawArgs);
        const catalog = await loadCatalog();
        const built = buildQuery(input, catalog);
        const result = await pool.query(built.sql, built.params);
        let rows = result.rows;
        let truncated = false;
        if (rows.length > built.requestedLimit) {
          rows = rows.slice(0, built.requestedLimit);
          truncated = true;
        }
        return ok({
          columns: built.columns,
          rows,
          rowCount: rows.length,
          truncated,
          hints: built.hints,
          executedSql: built.sql // parameterized text; values (incl. the PII key) are never inlined
        });
      } catch (e) {
        if (e instanceof QueryError) return fail(e.code, e.message);
        return fail("QUERY_FAILED", message(e));
      }
    }
  );

  server.registerTool(
    "db.unmask",
    {
      title: "Resolve tokens to raw PII (DANGEROUS)",
      description:
        "ALWAYS DANGEROUS / deny-gate by default. Maps tok_... pseudonyms back to raw PII " +
        "values. Only call after an explicit user approval that states a business reason, " +
        "and never keep the values in reports or persisted context. Disabled unless the " +
        "operator sets PII_UNMASK_ENABLED=true.",
      inputSchema: unmaskInput.shape
    },
    async (rawArgs: unknown) => {
      const args = unmaskInput.parse(rawArgs);
      if (!config.unmaskEnabled) {
        return fail(
          "UNMASK_DISABLED",
          "db.unmask is disabled server-side (PII_UNMASK_ENABLED=false). Do not retry; degrade to masked data."
        );
      }
      try {
        const result = await pool.query(
          `SELECT token, pii_unmask(token, $1) AS value, value_kind
             FROM pii_vault
            WHERE token = ANY($2::text[])`,
          [config.piiKey, args.tokens]
        );
        // Audit trail on stderr (stdout is reserved for the MCP protocol).
        console.error(`[postgres-pii] AUDIT db.unmask resolved ${result.rowCount} token(s)`);
        const found = new Set(result.rows.map((r) => r.token as string));
        return ok({
          values: result.rows,
          unknownTokens: args.tokens.filter((t) => !found.has(t)),
          warning: "Raw PII. Do not copy into reports, logs or persisted context."
        });
      } catch (e) {
        return fail("UNMASK_FAILED", message(e));
      }
    }
  );
}
