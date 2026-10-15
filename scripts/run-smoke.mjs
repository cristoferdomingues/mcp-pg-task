// Local runner: injects secrets from ~/.black-agents/secrets.json and runs smoke.mjs.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { spawnSync } from "node:child_process";

const secrets = JSON.parse(
  readFileSync(`${homedir()}/.black-agents/secrets.json`, "utf8")
).secrets;

const env = {
  ...process.env,
  DATABASE_URL: secrets["postgres-pii.database-url"],
  SMOKE_DATABASE_URL: secrets["postgres-pii.database-url"],
  PII_KEY: secrets["postgres-pii.pii-key"],
  PII_UNMASK_ENABLED: "false",
};

const r = spawnSync("node", ["scripts/smoke.mjs"], { env, stdio: "inherit" });
process.exit(r.status ?? 1);