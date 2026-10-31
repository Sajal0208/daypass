// Drives the MCP server over stdio like a real client and asserts the safety behaviour.
// Expects: a live lease on a target whose role hides customers.email and customers.secret.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const home = process.env.DAYPASS_HOME;
assert.ok(home, 'DAYPASS_HOME must be set');

const client = new Client({ name: 'daypass-smoke', version: '0' });
const transport = new StdioClientTransport({ command: 'node', args: ['dist/cli/main.js', 'mcp'], env: process.env });
await client.connect(transport);

const call = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  const text = r.content[0].text;
  console.log(`${r.isError ? '✖' : '✔'} ${name} ${JSON.stringify(args)} → ${text.split('\n')[0].slice(0, 100)}`);
  return { ok: !r.isError, text };
};

// DEMO=1 (scripts/record-demo.sh): show three calls for the README recording, no assertions.
if (process.env.DEMO === '1') {
  await call('query', { sql: 'select id, name from customers' });
  await call('query', { sql: 'select * from customers' });
  await call('query', { sql: "update customers set name = 'x'" });
  await client.close();
  process.exit(0);
}

const tools = (await client.listTools()).tools.map((t) => t.name).sort();
assert.deepEqual(tools, ['daypass_status', 'describe_table', 'explain', 'list_tables', 'query']);

let r = await call('query', { sql: 'select id, name from customers' });
assert.ok(r.ok && r.text.includes('"Ada"'), 'visible columns readable');

r = await call('query', { sql: 'select * from customers' });
assert.ok(!r.ok && /permission denied/.test(r.text), 'SELECT * denied on a table with hidden columns');

r = await call('query', { sql: 'select secret from customers' });
assert.ok(!r.ok && /permission denied/.test(r.text), 'hidden column denied by the database');

r = await call('query', { sql: "update customers set name = 'x'" });
assert.ok(!r.ok && /Only SELECT/.test(r.text), 'write rejected by the parser');

r = await call('query', { sql: 'select 1; drop table customers' });
assert.ok(!r.ok && /one statement/.test(r.text), 'multi-statement rejected');

r = await call('query', { sql: 'select pg_sleep(5)' });
assert.ok(!r.ok && /pg_sleep/.test(r.text), 'pg_sleep rejected');

// A refused explain must be audited exactly like a refused query (allowed: false + blockedReason).
const lastAudit = () => {
  const lines = readFileSync(join(home, 'audit.jsonl'), 'utf8').trim().split('\n');
  return JSON.parse(lines[lines.length - 1]);
};
r = await call('explain', { sql: "update customers set name = 'x'" });
assert.ok(!r.ok && /Only SELECT/.test(r.text), 'explain of a write rejected by the parser');
let a = lastAudit();
assert.equal(a.tool, 'explain', 'refused explain is audited');
assert.equal(a.allowed, false, 'refused explain audited as allowed: false');
assert.ok(a.blockedReason, 'refused explain audit line carries blockedReason');

r = await call('explain', { sql: "explain update customers set name = 'x'" });
assert.ok(!r.ok && /only wrap a SELECT/.test(r.text), 'explicit EXPLAIN of a write rejected by the parser');
a = lastAudit();
assert.ok(a.tool === 'explain' && a.allowed === false && a.blockedReason, 'refused explicit EXPLAIN is audited');

r = await call('query', { sql: 'select generate_series(1, 2000) as n' });
assert.ok(r.ok && /TRUNCATED/.test(r.text), 'result capped');

r = await call('explain', { sql: 'select id from customers' });
assert.ok(r.ok && /QUERY PLAN/.test(r.text), 'explain works');

r = await call('list_tables');
assert.ok(r.ok && /customers/.test(r.text), 'list_tables sees the table');
// The fixture's customer_secrets view is withheld by the setup: list_tables must not offer it.
assert.ok(!/customer_secrets/.test(r.text), 'list_tables hides relations the role cannot read');

// --- Review 2026-10-30 (WS2): fence holes ---
const auditTail = (n) => readFileSync(join(home, 'audit.jsonl'), 'utf8').trim().split('\n').slice(-n).map((l) => JSON.parse(l));
const alive = async (what) => {
  const s = await call('daypass_status');
  assert.ok(s.ok && /min left/.test(s.text), `server still answers after ${what}`);
};

// F2: every allowed call writes a `start` line before the query and an `end` line after, paired by callId.
r = await call('query', { sql: 'select id, name from customers' });
assert.ok(r.ok, 'visible query works');
let [st, en] = auditTail(2);
assert.ok(st.phase === 'start' && st.allowed === true && st.rows === undefined && st.callId, 'start line: allowed, no rows, callId');
assert.ok(en.phase === 'end' && en.callId === st.callId && en.rows === 1 && typeof en.ms === 'number' && !en.error, 'end line: same callId, rows, ms');
r = await call('query', { sql: 'select 1/0 as boom' });
assert.ok(!r.ok && /division by zero/.test(r.text), 'database error reported');
[st, en] = auditTail(2);
assert.ok(st.phase === 'start' && en.phase === 'end' && en.callId === st.callId && /division by zero/.test(en.error), 'failed call: start + end with error');

// F3: functions that run SQL or hold locks are refused by the parser.
for (const sql of [
  "select query_to_xml('select 1', true, false, '')",
  'select pg_try_advisory_lock_shared(42)',
  'select pg_advisory_lock(1)',
  "select set_config('statement_timeout', '0', false)",
  "select pg_ls_dir('.')",
]) {
  r = await call('query', { sql });
  assert.ok(!r.ok && /Blocked/.test(r.text), `refused: ${sql}`);
  a = lastAudit();
  assert.ok(a.allowed === false && a.blockedReason && a.phase === undefined, `refusal audited as one unphased line: ${sql}`);
}
// F3: EXPLAIN without ANALYZE in any spelling is allowed; ANALYZE (or ANALYZE true) is not.
for (const sql of ['explain (analyze false) select id from customers', 'explain (analyze off) select id from customers']) {
  r = await call('explain', { sql });
  assert.ok(r.ok && /QUERY PLAN/.test(r.text), `allowed: ${sql}`);
}
r = await call('explain', { sql: 'explain (analyze) select id from customers' });
assert.ok(!r.ok && /Blocked/.test(r.text), 'EXPLAIN (ANALYZE) refused');

// F4: trailing comments and semicolons no longer break the wrap.
for (const sql of ['select id, name from customers -- trailing comment', 'select 1 as n; -- c', 'select 1 as n;;', 'select 1 as n\n-- last line comment']) {
  r = await call('query', { sql });
  assert.ok(r.ok && /1 row\(s\)/.test(r.text), `query with trailing comment/semicolon: ${JSON.stringify(sql)}`);
  r = await call('explain', { sql });
  assert.ok(r.ok && /QUERY PLAN/.test(r.text), `explain with trailing comment/semicolon: ${JSON.stringify(sql)}`);
}

// Review pass 2: the escape chain (SQL-from-string function -> flip standard_conforming_strings
// on the pooled backend -> smuggle statements past the guard) fails safely at every step.
let t1 = Date.now();
r = await call('query', { sql: "select * from ts_stat('select to_tsvector(pg_sleep(3)::text)')" });
assert.ok(!r.ok && /ts_stat/.test(r.text) && Date.now() - t1 < 1500, 'ts_stat running SQL from a string refused');
r = await call('query', { sql: "select * from ts_stat($$select to_tsvector(set_config('standard_conforming_strings','off',false))$$)" });
assert.ok(!r.ok && /ts_stat/.test(r.text), 'ts_stat set_config escape refused');
t1 = Date.now();
r = await call('query', {
  sql: "explain select '\\' as a, '; commit; set statement_timeout = 0; select pg_sleep(14); select pg_advisory_lock(42); --' as b",
});
assert.ok(r.ok && /QUERY PLAN/.test(r.text) && Date.now() - t1 < 3000, 'backslash-quote smuggling input is one harmless EXPLAIN');
r = await call('query', {
  sql: "select current_setting('statement_timeout') as st, current_setting('standard_conforming_strings') as scs, (select count(*)::int from pg_locks where locktype = 'advisory') as locks",
});
assert.ok(r.ok && r.text.includes('{"st":"10s","scs":"on","locks":0}'), 'session settings intact after the escape chain');
for (const tool of ['query', 'explain']) {
  r = await call(tool, { sql: 'with d as (delete from customers returning id) select id from d' });
  assert.ok(!r.ok && /Data-modifying/.test(r.text), `data-modifying CTE refused (${tool})`);
}
// Column order and exact numerics survive (to_json, not to_jsonb).
r = await call('query', { sql: "select 12345678901234567.89::numeric m, 'z' as z, 1 as a" });
assert.ok(r.ok && r.text.includes('[{"m":"12345678901234567.89","z":"z","a":1}]'), 'column order and numeric precision kept');

// Review pass 3: SQL over 256 KiB is refused before parsing (audited, only a prefix kept); the
// server keeps answering. setseed (state that survives DISCARD ALL) is refused.
t1 = Date.now();
r = await call('query', { sql: 'select ' + Array(150000).fill('1').join(',') });
assert.ok(!r.ok && /too long/.test(r.text) && Date.now() - t1 < 1000, 'oversized SQL refused quickly');
a = lastAudit();
assert.ok(a.allowed === false && /too long/.test(a.blockedReason) && a.sql.length < 5000, 'oversized SQL audited as a refusal with a prefix only');
await alive('an oversized statement');
r = await call('query', { sql: 'select setseed(0.5)' });
assert.ok(!r.ok && /setseed/.test(r.text), 'setseed refused');

// int8 beyond 2^53 survives the JSON round trip as a string.
r = await call('query', { sql: 'select 9007199254740993::bigint as big' });
assert.ok(r.ok && r.text.includes('"9007199254740993"'), 'large bigint kept exact');

// F6: describe_table never names a hidden column, even through an index definition.
r = await call('describe_table', { table: 'customers' });
assert.ok(r.ok && /customers_pkey/.test(r.text), 'describe_table lists the index on a visible column');
assert.ok(!/\b(secret|email)\b/.test(r.text), 'describe_table output names no hidden column');

// F1: a 600 MB cell is cut in the database; the server neither crashes nor balloons, and audits it.
r = await call('query', { sql: "select repeat('x', 600000000) as big" });
assert.ok(r.ok ? /daypass_truncated_row/.test(r.text) : /failed/.test(r.text), 'huge cell: truncated row or clean error');
[st, en] = auditTail(2);
assert.ok(st.phase === 'start' && en.phase === 'end' && en.callId === st.callId && /repeat/.test(st.sql), 'huge cell: start + end audit lines');
await alive('a 600 MB cell');
r = await call('query', { sql: 'select array_agg(g) as a from generate_series(1, 20000000) g' });
assert.ok(r.ok ? /daypass_truncated_row/.test(r.text) : /failed/.test(r.text), 'huge array: truncated row or clean error');
await alive('a 20M-element array');
// Many rows that together exceed the byte budget: cut in SQL, the note says so.
r = await call('query', { sql: "select g, repeat('y', 10000) as pad from generate_series(1, 400) g" });
assert.ok(r.ok && /byte budget/.test(r.text), 'byte budget cuts rows and says so');

// F2: statement_timeout is bounded by the lease: with ~3 s left a long query is cancelled well before 10 s.
const leasePath = join(home, 'lease.json');
const lease = JSON.parse(readFileSync(leasePath, 'utf8'));
const realExpiry = lease.expiresAt;
writeFileSync(leasePath, JSON.stringify({ ...lease, expiresAt: new Date(Date.now() + 3000).toISOString() }));
const t0 = Date.now();
r = await call('query', { sql: 'select count(*) from generate_series(1, 100000) a, generate_series(1, 100000) b' });
const took = Date.now() - t0;
assert.ok(!r.ok && /statement timeout/.test(r.text) && took < 8000, `query cancelled at the lease end (${took} ms)`);
writeFileSync(leasePath, JSON.stringify({ ...lease, expiresAt: realExpiry }));

// Expire the lease on disk; the next call must be refused.
writeFileSync(leasePath, JSON.stringify({ ...lease, expiresAt: new Date(Date.now() - 1000).toISOString() }));
r = await call('query', { sql: 'select 1' });
assert.ok(!r.ok && /expired/.test(r.text), 'expired lease refused');

// F2: SIGTERM while a query is in flight still writes that call's `end` line.
writeFileSync(leasePath, JSON.stringify({ ...lease, expiresAt: realExpiry }));
const pending = client
  .callTool({ name: 'query', arguments: { sql: 'select count(*) from generate_series(1, 100000) a, generate_series(1, 100000) b' } })
  .catch(() => null);
await new Promise((res) => setTimeout(res, 1000));
const before = auditTail(1)[0];
assert.ok(before.phase === 'start', 'long query has written its start line');
process.kill(transport.pid, 'SIGTERM');
await Promise.race([pending, new Promise((res) => setTimeout(res, 5000))]);
await new Promise((res) => setTimeout(res, 500));
const after = auditTail(1)[0];
assert.ok(after.phase === 'end' && after.callId === before.callId && /SIGTERM/.test(after.error), 'in-flight call audited on SIGTERM');

await client.close().catch(() => {});
console.log('smoke: all assertions passed');
