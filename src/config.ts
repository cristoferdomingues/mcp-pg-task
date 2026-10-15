function must (name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`[postgres-pii] missing required environment variable: ${name}`);
    process.exit(1);
  }
  return value;
}

export const config = {
  /** Connection string for the restricted mcp_reader role. */
  databaseUrl: must("DATABASE_URL"),
  /** Salt for tokenization + key for vault encryption. Never persisted. */
  piiKey: must("PII_KEY"),
  /** Server-side unlock switch for db.unmask (the harness deny-gate is the first line). */
  unmaskEnabled: process.env.PII_UNMASK_ENABLED === "true",
  /** Hard cap on rows per query, regardless of what the agent asks for. */
  maxRows: Number(process.env.MAX_ROWS ?? "200"),
  defaultRows: Number(process.env.DEFAULT_ROWS ?? "50"),
  /** Hard cap on how many tokens db.unmask resolves per call. */
  unmaskMaxTokens: 20
};
