import { pool } from "./db.js";

export type Classification = "public" | "pii_direct" | "pii_embedded" | "sensitive";
export type RenderedAs = "raw" | "token" | "redacted" | "restricted";

export interface ColumnInfo {
  table: string;
  column: string;
  dataType: string;
  classification: Classification;
  piiKind: string | null;
}

export interface TableInfo {
  table: string;
  rowEstimate: number;
  columns: ColumnInfo[];
}

export interface JoinEdge {
  leftTable: string;
  leftColumn: string;
  rightTable: string;
  rightColumn: string;
}

export interface Catalog {
  tables: Map<string, TableInfo>;
  joins: JoinEdge[];
  loadedAt: number;
}

const TTL_MS = 30_000;
let cached: Catalog | null = null;

export function renderedAs (classification: Classification): RenderedAs {
  switch (classification) {
    case "public": return "raw";
    case "pii_direct": return "token";
    case "pii_embedded": return "redacted";
    case "sensitive": return "restricted";
  }
}

/**
 * Loads the exposed surface: only tables/columns listed in
 * column_classification are visible to the agent. Everything else does not
 * exist as far as the MCP is concerned.
 */
export async function loadCatalog (force = false): Promise<Catalog> {
  if (cached && !force && Date.now() - cached.loadedAt < TTL_MS) {
    return cached;
  }

  const cols = await pool.query<{
    table_name: string;
    column_name: string;
    data_type: string;
    classification: Classification;
    pii_kind: string | null;
  }>(`
    SELECT c.table_name, c.column_name, c.data_type,
           cc.classification, cc.pii_kind
      FROM information_schema.columns c
      JOIN column_classification cc
        ON cc.table_name = c.table_name
       AND cc.column_name = c.column_name
     WHERE c.table_schema = 'public'
     ORDER BY c.table_name, c.ordinal_position
  `);

  const joins = await pool.query<JoinEdge>(`
    SELECT left_table AS "leftTable", left_column AS "leftColumn",
           right_table AS "rightTable", right_column AS "rightColumn"
      FROM join_relationships
  `);

  const estimates = await pool.query<{ relname: string; estimate: string }>(`
    SELECT c.relname, GREATEST(c.reltuples, 0)::bigint::text AS estimate
      FROM pg_class c
     WHERE c.relkind = 'r'
       AND c.relnamespace = 'public'::regnamespace
  `);
  const estimateByTable = new Map(estimates.rows.map((r) => [r.relname, Number(r.estimate)]));

  const tables = new Map<string, TableInfo>();
  for (const row of cols.rows) {
    let table = tables.get(row.table_name);
    if (!table) {
      table = { table: row.table_name, rowEstimate: estimateByTable.get(row.table_name) ?? 0, columns: [] };
      tables.set(row.table_name, table);
    }
    table.columns.push({
      table: row.table_name,
      column: row.column_name,
      dataType: row.data_type,
      classification: row.classification,
      piiKind: row.pii_kind
    });
  }

  cached = { tables, joins: joins.rows, loadedAt: Date.now() };
  return cached;
}

export interface JoinStep {
  from: string;
  to: string;
  fromColumn: string;
  toColumn: string;
}

/**
 * Finds a path connecting all requested tables using ONLY the declared join
 * edges (whose keys are themselves PII). Returns null when no path exists —
 * the server then refuses the query instead of inventing a join.
 */
export function joinPath (catalog: Catalog, tables: string[]): JoinStep[] | null {
  const target = new Set(tables);
  const reached = new Set<string>([tables[0]]);
  const steps: JoinStep[] = [];

  while (reached.size < target.size) {
    let progress = false;
    for (const e of catalog.joins) {
      const directions = [
        { from: e.leftTable, to: e.rightTable },
        { from: e.rightTable, to: e.leftTable }
      ];
      for (const d of directions) {
        if (!target.has(d.from) || !target.has(d.to)) continue;
        if (reached.has(d.from) && !reached.has(d.to)) {
          reached.add(d.to);
          steps.push({
            from: d.from,
            to: d.to,
            fromColumn: d.from === e.leftTable ? e.leftColumn : e.rightColumn,
            toColumn: d.to === e.leftTable ? e.leftColumn : e.rightColumn
          });
          progress = true;
          break;
        }
      }
      if (progress) break;
    }
    if (!progress) break;
  }

  return reached.size === target.size ? steps : null;
}
