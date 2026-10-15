import { z } from "zod";
import { config } from "./config.js";
import type { Catalog, Classification, ColumnInfo, RenderedAs } from "./catalog.js";
import { joinPath } from "./catalog.js";

const IDENT = /^[a-z_][a-z0-9_]*$/;
const TOKEN = /^tok_[0-9a-f]{16,64}$/;
const ident = z.string().regex(IDENT);

/**
 * Declarative query contract. There is intentionally NO way to pass SQL text:
 * the agent describes *what* it wants (tables, columns, filters) and the
 * server builds a parameterized statement it fully controls.
 */
export const queryInput = z.object({
  /** Up to 3 tables; the join is derived from the declared PII join topology. */
  tables: z.array(ident).min(1).max(3),
  columns: z
    .array(z.object({ table: ident, column: ident, as: ident.optional() }))
    .min(1)
    .max(20),
  where: z
    .array(
      z.object({
        table: ident,
        column: ident,
        op: z.enum(["eq", "neq", "gt", "gte", "lt", "lte", "like", "in", "is_null", "not_null"]),
        value: z.union([z.string(), z.number(), z.array(z.union([z.string(), z.number()]))]).optional()
      })
    )
    .max(8)
    .optional(),
  groupBy: z.array(z.object({ table: ident, column: ident })).max(4).optional(),
  aggregates: z
    .array(
      z.object({
        fn: z.enum(["count", "sum", "avg", "min", "max"]),
        table: ident,
        column: ident.optional(),
        as: ident
      })
    )
    .max(6)
    .optional(),
  orderBy: z
    .array(
      z.object({
        table: ident,
        column: ident,
        direction: z.enum(["asc", "desc"]).default("asc")
      })
    )
    .max(2)
    .optional(),
  limit: z.number().int().min(1).max(config.maxRows).optional()
});

export type QueryInput = z.infer<typeof queryInput>;

export class QueryError extends Error {
  constructor (
    public readonly code: string,
    message: string
  ) {
    super(message);
  }
}

export interface RenderedColumn {
  name: string;
  source: string;
  classification: Classification | "aggregate";
  renderedAs: RenderedAs;
}

export interface ApprovalHints {
  requiresApproval: boolean;
  piiColumns: string[];
  rawPiiFilters: string[];
  sensitiveFilters: string[];
}

export interface BuiltQuery {
  sql: string;
  params: unknown[];
  columns: RenderedColumn[];
  hints: ApprovalHints;
  requestedLimit: number;
}

interface Ctx {
  params: unknown[];
  piiColumns: string[];
  rawPiiFilters: string[];
  sensitiveFilters: string[];
}

function push (ctx: Ctx, value: unknown): string {
  ctx.params.push(value);
  return `$${ctx.params.length}`;
}

function columnOf (catalog: Catalog, table: string, column: string): ColumnInfo {
  const t = catalog.tables.get(table);
  if (!t) {
    throw new QueryError("UNKNOWN_TABLE", `table '${table}' is not exposed; call db.describe`);
  }
  const c = t.columns.find((x) => x.column === column);
  if (!c) {
    throw new QueryError(
      "UNKNOWN_COLUMN",
      `column '${table}.${column}' does not exist or is not exposed; call db.describe`
    );
  }
  return c;
}

function assertTableInQuery (tables: string[], table: string): void {
  if (!tables.includes(table)) {
    throw new QueryError(
      "TABLE_NOT_IN_QUERY",
      `table '${table}' is not part of this query; add it to 'tables'`
    );
  }
}

function dedupeName (used: Set<string>, name: string): string {
  let unique = name;
  let i = 2;
  while (used.has(unique)) unique = `${name}_${i++}`;
  used.add(unique);
  return unique;
}

/**
 * Renders one column according to its classification. This is the single place
 * where raw PII is (not) exposed:
 *   public       -> raw column reference
 *   pii_direct   -> pii_tokenize(...)   (deterministic tok_... pseudonym)
 *   pii_embedded -> pii_redact(...)     (emails / CPFs / phones stripped)
 *   sensitive    -> constant '[restricted]'
 */
function renderSelect (col: ColumnInfo, ctx: Ctx): { expr: string; renderedAs: RenderedAs } {
  const qual = `${col.table}.${col.column}`;
  switch (col.classification) {
    case "public":
      return { expr: qual, renderedAs: "raw" };
    case "pii_direct": {
      const kind = push(ctx, col.piiKind ?? "generic");
      ctx.piiColumns.push(`${qual} (token)`);
      return { expr: `pii_tokenize(${qual}, ${kind}, $1)`, renderedAs: "token" };
    }
    case "pii_embedded":
      ctx.piiColumns.push(`${qual} (redacted)`);
      return { expr: `pii_redact(${qual})`, renderedAs: "redacted" };
    case "sensitive":
      ctx.piiColumns.push(`${qual} (restricted)`);
      return { expr: `'[restricted]'::text`, renderedAs: "restricted" };
  }
}

const SCALAR_OPS: Record<string, string> = {
  eq: "=",
  neq: "<>",
  gt: ">",
  gte: ">=",
  lt: "<",
  lte: "<=",
  like: "LIKE"
};

function renderWhere (
  item: NonNullable<QueryInput["where"]>[number],
  catalog: Catalog,
  ctx: Ctx,
  tables: string[]
): string {
  assertTableInQuery(tables, item.table);
  const col = columnOf(catalog, item.table, item.column);
  const qual = `${item.table}.${item.column}`;

  if (item.op === "is_null") return `${qual} IS NULL`;
  if (item.op === "not_null") return `${qual} IS NOT NULL`;

  if (item.value === undefined) {
    throw new QueryError("MISSING_FILTER_VALUE", `filter '${qual} ${item.op}' requires a value`);
  }

  if (item.op === "in") {
    if (!Array.isArray(item.value) || item.value.length === 0 || item.value.length > 50) {
      throw new QueryError("BAD_FILTER_VALUE", `'in' on '${qual}' requires an array with 1..50 values`);
    }
    if (col.classification === "pii_direct") {
      const allTokens = item.value.every((v) => typeof v === "string" && TOKEN.test(v));
      if (allTokens) {
        // Filter by tokens the agent already holds: raw PII never appears.
        const kind = push(ctx, col.piiKind ?? "generic");
        const arr = push(ctx, item.value);
        return `pii_tokenize(${qual}, ${kind}, $1) = ANY(${arr}::text[])`;
      }
      ctx.rawPiiFilters.push(`${qual} in (raw values supplied)`);
    } else if (col.classification !== "public") {
      ctx.sensitiveFilters.push(`${qual} in (...)`);
    }
    const arr = push(ctx, (item.value as Array<string | number>).map(String));
    return `${qual} = ANY(${arr}::text[])`;
  }

  if (typeof item.value === "object") {
    throw new QueryError("BAD_FILTER_VALUE", `filter '${qual} ${item.op}' requires a scalar value`);
  }

  // Token filter path: tokenize the column in-database and compare with the
  // token. The raw value is never selected, returned or logged.
  if (col.classification === "pii_direct" && typeof item.value === "string" && TOKEN.test(item.value)) {
    if (item.op === "like") {
      throw new QueryError("TOKEN_OP_UNSUPPORTED", "use eq/neq with a token; LIKE on PII columns is not allowed");
    }
    const kind = push(ctx, col.piiKind ?? "generic");
    const v = push(ctx, item.value);
    return `pii_tokenize(${qual}, ${kind}, $1) ${SCALAR_OPS[item.op]} ${v}`;
  }

  // Raw-value filter path: allowed, but always surfaced in the approval hints.
  if (col.classification === "pii_direct") ctx.rawPiiFilters.push(`${qual} ${item.op} (raw value supplied)`);
  if (col.classification === "pii_embedded") ctx.rawPiiFilters.push(`${qual} ${item.op} (embedded PII matched raw)`);
  if (col.classification === "sensitive") ctx.sensitiveFilters.push(`${qual} ${item.op}`);

  const v = push(ctx, item.value);
  return `${qual} ${SCALAR_OPS[item.op]} ${v}`;
}

export function buildQuery (raw: QueryInput, catalog: Catalog): BuiltQuery {
  const tables = [...new Set(raw.tables)];
  for (const t of tables) {
    if (!catalog.tables.has(t)) {
      throw new QueryError("UNKNOWN_TABLE", `table '${t}' is not exposed; call db.describe`);
    }
  }

  const chain = tables.length > 1 ? joinPath(catalog, tables) : [];
  if (!chain) {
    throw new QueryError(
      "NO_JOIN_PATH",
      `tables [${tables.join(", ")}] are not connected by a declared join path`
    );
  }

  // $1 is always the PII key (used by pii_tokenize); every other value is
  // appended as a bound parameter. Nothing is ever string-interpolated.
  const ctx: Ctx = { params: [config.piiKey], piiColumns: [], rawPiiFilters: [], sensitiveFilters: [] };

  const usedNames = new Set<string>();
  const columns: RenderedColumn[] = [];
  const selectParts: string[] = [];

  for (const c of raw.columns) {
    assertTableInQuery(tables, c.table);
    const col = columnOf(catalog, c.table, c.column);
    const { expr, renderedAs } = renderSelect(col, ctx);
    const name = dedupeName(usedNames, c.as ?? (tables.length > 1 ? `${c.table}.${c.column}` : c.column));
    selectParts.push(`${expr} AS "${name}"`);
    columns.push({
      name,
      source: `${c.table}.${c.column}`,
      classification: col.classification,
      renderedAs
    });
  }

  const aggregates = raw.aggregates ?? [];
  for (const a of aggregates) {
    assertTableInQuery(tables, a.table);
    let expr: string;
    let source: string;
    if (a.fn === "count" && !a.column) {
      expr = "COUNT(*)";
      source = "count(*)";
    } else {
      if (!a.column) {
        throw new QueryError("AGGREGATE_COLUMN_REQUIRED", `aggregate ${a.fn}() requires a column`);
      }
      const col = columnOf(catalog, a.table, a.column);
      if (a.fn !== "count" && col.classification !== "public") {
        throw new QueryError(
          "AGGREGATE_ON_PROTECTED",
          `${a.fn}() is only allowed on public columns ('${a.table}.${a.column}' is ${col.classification}); use count() instead`
        );
      }
      expr = `${a.fn.toUpperCase()}(${a.table}.${a.column})`;
      source = `${a.fn}(${a.table}.${a.column})`;
    }
    const name = dedupeName(usedNames, a.as);
    selectParts.push(`${expr} AS "${name}"`);
    columns.push({ name, source, classification: "aggregate", renderedAs: "raw" });
  }

  const groupBy = raw.groupBy ?? [];
  const groupExprs: string[] = [];
  if (groupBy.length > 0 || aggregates.length > 0) {
    const groupKeys = new Set(groupBy.map((g) => `${g.table}.${g.column}`));
    for (const g of groupBy) {
      assertTableInQuery(tables, g.table);
      const col = columnOf(catalog, g.table, g.column);
      if (col.classification === "sensitive") {
        throw new QueryError(
          "GROUP_BY_PROTECTED",
          `grouping by restricted column '${g.table}.${g.column}' is not allowed`
        );
      }
      groupExprs.push(renderSelect(col, ctx).expr);
    }
    if (aggregates.length > 0) {
      for (const c of raw.columns) {
        if (!groupKeys.has(`${c.table}.${c.column}`)) {
          throw new QueryError(
            "AGGREGATION_MISMATCH",
            `column '${c.table}.${c.column}' must be listed in groupBy when aggregates are used`
          );
        }
      }
    }
  }

  const whereParts = (raw.where ?? []).map((w) => renderWhere(w, catalog, ctx, tables));

  const orderParts: string[] = [];
  for (const o of raw.orderBy ?? []) {
    assertTableInQuery(tables, o.table);
    const col = columnOf(catalog, o.table, o.column);
    if (col.classification !== "public") {
      throw new QueryError(
        "ORDER_BY_PROTECTED",
        `orderBy is only allowed on public columns ('${o.table}.${o.column}' is ${col.classification})`
      );
    }
    orderParts.push(`${o.table}.${o.column} ${o.direction === "desc" ? "DESC" : "ASC"}`);
  }

  const requestedLimit = raw.limit ?? config.defaultRows;
  const limitParam = push(ctx, requestedLimit + 1); // +1 row to detect truncation

  let sql = `SELECT ${selectParts.join(", ")} FROM ${tables[0]}`;
  for (const s of chain) {
    sql += ` JOIN ${s.to} ON ${s.from}.${s.fromColumn} = ${s.to}.${s.toColumn}`;
  }
  if (whereParts.length > 0) sql += ` WHERE ${whereParts.join(" AND ")}`;
  if (groupExprs.length > 0) sql += ` GROUP BY ${groupExprs.join(", ")}`;
  if (orderParts.length > 0) sql += ` ORDER BY ${orderParts.join(", ")}`;
  sql += ` LIMIT ${limitParam}`;

  const hints: ApprovalHints = {
    requiresApproval: false,
    piiColumns: [...new Set(ctx.piiColumns)],
    rawPiiFilters: [...new Set(ctx.rawPiiFilters)],
    sensitiveFilters: [...new Set(ctx.sensitiveFilters)]
  };
  hints.requiresApproval =
    hints.piiColumns.length > 0 || hints.rawPiiFilters.length > 0 || hints.sensitiveFilters.length > 0;

  return { sql, params: ctx.params, columns, hints, requestedLimit };
}
