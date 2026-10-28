// Drives the MCP server over stdio like a real client and asserts the safety behaviour.
// Expects: a live lease on a target whose role hides customers.email and customers.secret.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const home = process.env.PEEPHOLE_HOME;
assert.ok(home, 'PEEPHOLE_HOME must be set');

const client = new Client({ name: 'peephole-smoke', version: '0' });
await client.connect(new StdioClientTransport({ command: 'node', args: ['dist/cli/main.js', 'mcp'], env: process.env }));

const call = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  const text = r.content[0].text;
  console.log(`${r.isError ? '✖' : '✔'} ${name} ${JSON.stringify(args)} → ${text.split('\n')[0].slice(0, 100)}`);
  return { ok: !r.isError, text };
};

const tools = (await client.listTools()).tools.map((t) => t.name).sort();
assert.deepEqual(tools, ['describe_table', 'explain', 'list_tables', 'peephole_status', 'query']);

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

r = await call('query', { sql: 'select generate_series(1, 2000) as n' });
assert.ok(r.ok && /TRUNCATED/.test(r.text), 'result capped');

r = await call('explain', { sql: 'select id from customers' });
assert.ok(r.ok && /QUERY PLAN/.test(r.text), 'explain works');

r = await call('list_tables');
assert.ok(r.ok && /customers/.test(r.text), 'list_tables sees the table');

// Expire the lease on disk; the next call must be refused.
const leasePath = join(home, 'lease.json');
const lease = JSON.parse(readFileSync(leasePath, 'utf8'));
lease.expiresAt = new Date(Date.now() - 1000).toISOString();
writeFileSync(leasePath, JSON.stringify(lease));
r = await call('query', { sql: 'select 1' });
assert.ok(!r.ok && /expired/.test(r.text), 'expired lease refused');

await client.close();
console.log('smoke: all assertions passed');
