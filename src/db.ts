import pg from "pg";
import { config } from "./config.js";

/**
 * Single shared pool. The server only ever runs parameterized statements built
 * by src/query.ts — there is no code path that accepts raw SQL from a caller.
 */
export const pool = new pg.Pool({
  connectionString: config.databaseUrl,
  max: 5,
  idleTimeoutMillis: 30_000
});
