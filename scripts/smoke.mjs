// scripts/smoke.mjs — end-to-end smoke test over the MCP stdio transport.
// Run with SMOKE_DATABASE_URL pointing at a database with sql/ applied.
import { spawn } from "node:child_process";

const server = spawn("node", ["dist/index.js"], {
  env: {
    ...process.env,
    DATABASE_URL: process.env.SMOKE_DATABASE_URL,
    PII_KEY: "smoke-test-key-1234567890",
    PII_UNMASK_ENABLED: "false"
  },
  stdio: ["pipe", "pipe", "inherit"]
});

let buffer = "";
const pending = new Map();

server.stdout.on("data", (chunk) => {
  buffer += chunk.toString();
  let idx;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});

let nextId = 1;
function request (method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout waiting for ${method}`)), 15000);
    pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
    server.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

function notify (method, params) {
  server.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

function payload (res) {
  const text = res.result?.content?.[0]?.text;
  if (!text) return { raw: res };
  try { return JSON.parse(text); } catch { return text; }
}

function show (name, res) {
  console.log(`\n=== ${name} ===`);
  console.log(JSON.stringify(payload(res), null, 2).slice(0, 1800));
}

await request("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "smoke", version: "0" }
});
notify("notifications/initialized", {});

// 1. db.describe — always-safe metadata
const describe = await request("tools/call", { name: "db.describe", arguments: {} });
show("db.describe", describe);

// 2. db.query — join across both PII tables; everything masked
const join = await request("tools/call", {
  name: "db.query",
  arguments: {
    tables: ["patients", "appointments"],
    columns: [
      { table: "patients", column: "cpf" },
      { table: "patients", column: "full_name" },
      { table: "patients", column: "email" },
      { table: "appointments", column: "appointment_at" },
      { table: "appointments", column: "specialty" },
      { table: "appointments", column: "diagnosis_code" },
      { table: "appointments", column: "notes" }
    ],
    where: [{ table: "appointments", column: "specialty", op: "eq", value: "Cardiologia" }],
    orderBy: [{ table: "appointments", column: "appointment_at", direction: "asc" }],
    limit: 10
  }
});
show("db.query (join, PII masked)", join);

// 3. db.query filtered by the token obtained above — no raw PII anywhere
const first = payload(join);
const token = first?.rows?.[0]?.["patients.cpf"];
if (!token) throw new Error("expected a token in the joined result");
const byToken = await request("tools/call", {
  name: "db.query",
  arguments: {
    tables: ["appointments"],
    columns: [
      { table: "appointments", column: "appointment_at" },
      { table: "appointments", column: "notes" }
    ],
    where: [{ table: "appointments", column: "patient_cpf", op: "eq", value: token }],
    limit: 10
  }
});
show(`db.query (filter by token ${token})`, byToken);

// 4. SQL injection through identifiers — rejected by schema validation
const injection = await request("tools/call", {
  name: "db.query",
  arguments: {
    tables: ["patients\"; DROP TABLE patients; --"],
    columns: [{ table: "patients", column: "cpf" }],
    limit: 5
  }
});
show("db.query (SQL injection attempt)", injection);

// 5. db.unmask — disabled server-side (deny posture)
const unmask = await request("tools/call", {
  name: "db.unmask",
  arguments: { tokens: ["tok_deadbeefdeadbeefdeadbeef"] }
});
show("db.unmask (deny posture)", unmask);

server.kill();
console.log("\n[smoke] done");
