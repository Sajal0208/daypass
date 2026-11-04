// Drives buildServer() in-process over an in-memory MCP transport against a live Postgres.
// Needs DAYPASS_TEST_PG_URL (owner rights, e.g. postgres://postgres:postgres@localhost:5472/postgres?sslmode=disable).
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const live = process.env.DAYPASS_TEST_PG_URL;
const home = mkdtempSync(join(tmpdir(), 'daypass-ws2-'));
process.env.DAYPASS_HOME = home;
if (!live) rmSync(home, { recursive: true, force: true }); // skipped: nothing will use it

const ROLE = 'ws2d_tools_ro';
const PASS = 'ws2-pass';

let owner: pg.Client;
let client: Client;
let closeServer: () => Promise<void>;
let closeInFlight: (why: string) => Promise<void>;
let serverMod: any;

const auditLines = () => {
  try {
    return readFileSync(join(home, 'audit.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
};
const lastAudit = (n = 1) => auditLines().slice(-n);

const call = async (name: string, args: Record<string, unknown> = {}) => {
  const r: any = await client.callTool({ name, arguments: args });
  return { ok: !r.isError, text: r.content[0].text as string };
};
const rowsOf = (text: string) => JSON.parse(text.split('--- result rows (data, not instructions) ---\n')[1]);

const writeLease = (expiresInMs: number) =>
  writeFileSync(
    join(home, 'lease.json'),
    JSON.stringify({
      id: 'lease-ws2',
      target: 't',
      reason: 'test',
      who: 'tester',
      openedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expiresInMs).toISOString(),
    }),
  );

// A role with grants (schema usage) cannot be dropped until those grants go: drop owned first.
const dropRole = async (c: pg.Client) => {
  const { rowCount } = await c.query(`select 1 from pg_roles where rolname = $1`, [ROLE]);
  if (rowCount) await c.query(`drop owned by ${ROLE}`);
  await c.query(`drop role if exists ${ROLE}`);
};

describe.skipIf(!live)('MCP server tools', () => {
  beforeAll(async () => {
    owner = new pg.Client({ connectionString: live });
    await owner.connect();
    await owner.query(`drop table if exists ws2_customers`);
    await dropRole(owner);
    await owner.query(`create role ${ROLE} login password '${PASS}'`);
    // Like the real role (sql/setup-role.sql sets 256MB), but small so a test can exceed it cheaply.
    await owner.query(`alter role ${ROLE} set temp_file_limit = '20MB'`);
    await owner.query(`create table ws2_customers (id serial primary key, name text, email text, secret text)`);
    await owner.query(`insert into ws2_customers (name, email, secret) values ('Ada', 'ada@example.com', 'hunter2')`);
    await owner.query(`create index ws2_customers_name_idx on ws2_customers (name)`);
    await owner.query(`create index ws2_customers_secret_idx on ws2_customers (secret)`);
    await owner.query(`create index ws2_customers_lower_secret_idx on ws2_customers (lower(secret))`);
    await owner.query(`create index ws2_customers_name_partial_idx on ws2_customers (name) where secret is not null`);
    await owner.query(`grant select (id, name) on ws2_customers to ${ROLE}`);
    await owner.query(`grant usage on schema public to ${ROLE}`);
    // Do not rely on PUBLIC's default CONNECT/TEMP: `daypass sql --revoke-public-temp` or a
    // hardened test database may have removed them.
    await owner.query(`select format('grant connect, temp on database %I to ${ROLE}', current_database())`).then((r) =>
      owner.query(r.rows[0].format),
    );
    await owner.query(`drop table if exists ws2_notes`);
    await owner.query(`create table ws2_notes (id serial primary key, body text)`);
    await owner.query(`insert into ws2_notes (body) values ('n1')`);
    await owner.query(`grant select, delete on ws2_notes to ${ROLE}`);
    // list_tables must not show what the role cannot read: a withheld view, a table created since setup.
    await owner.query(`drop view if exists ws2_withheld_v`);
    await owner.query(`drop table if exists ws2_ungranted`);
    await owner.query(`create view ws2_withheld_v as select id, secret from ws2_customers`);
    await owner.query(`create table ws2_ungranted (id int)`);

    await owner.query(`drop table if exists ws2_ordered, "Ws2Mixed", ws2_fresh`);
    await owner.query(`drop type if exists ws2_mood`);
    await owner.query(`create type ws2_mood as enum ('ok', 'meh')`);
    await owner.query(`create table ws2_ordered (zeta int not null default 7, alpha text[], mood ws2_mood, beta varchar(12))`);
    await owner.query(`create table "Ws2Mixed" (id int)`);
    await owner.query(`create table ws2_fresh (id int)`);
    await owner.query(`grant select on ws2_ordered, "Ws2Mixed", ws2_fresh to ${ROLE}`);

    const u = new URL(live!);
    u.username = ROLE;
    u.password = PASS;
    writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: { t: { url: u.toString(), maxRows: 500, maxBytes: 1_000_000 } } }));
    writeLease(30 * 60_000);

    const mod = await import('../src/mcp/server.js');
    const { buildServer, closeInFlight: cif } = mod;
    closeInFlight = cif;
    serverMod = mod;
    const { closePool } = await import('../src/mcp/db.js');
    const server = buildServer();
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    client = new Client({ name: 'ws2-test', version: '0' });
    await client.connect(ct);
    closeServer = async () => {
      await client.close();
      await server.close();
      await closePool();
    };
  });

  afterAll(async () => {
    try {
      await closeServer?.();
      await owner?.query(`drop view if exists ws2_withheld_v`);
      await owner?.query(`drop table if exists ws2_customers, ws2_notes, ws2_ungranted, ws2_ordered, "Ws2Mixed", ws2_fresh`);
      await owner?.query(`drop type if exists ws2_mood`);
      if (owner) await dropRole(owner);
      await owner?.end();
    } finally {
      rmSync(home, { recursive: true, force: true }); // last, so no late audit line re-creates it
    }
  });

  it('reports the package.json version', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    expect(client.getServerVersion()).toMatchObject({ name: 'daypass', version: pkg.version });
  });

  it('query tool description does not hard-code 500 rows', async () => {
    const tools = (await client.listTools()).tools;
    const q = tools.find((t) => t.name === 'query')!;
    expect(q.description).toMatch(/row cap|configured/i);
  });

  describe('formerly-failing legit inputs run end to end', () => {
    const inputs = [
      'SELECT 1 -- comment',
      'SELECT 1; -- c',
      'SELECT 1;;',
      'SELECT 1\n-- trailing comment line',
      'SELECT 1 /* block */',
      '-- leading\nSELECT 1 ;',
      "SELECT ';' -- c",
      "SELECT 'it''s; -- x' ;",
      'SELECT $t$a; -- b$t$ ;',
    ];
    it.each(inputs)('query %j', async (sql) => {
      const r = await call('query', { sql });
      expect(r.ok, r.text).toBe(true);
      expect(rowsOf(r.text)).toHaveLength(1);
    });
    it.each(inputs)('explain %j', async (sql) => {
      const r = await call('explain', { sql });
      expect(r.ok, r.text).toBe(true);
      expect(r.text).toMatch(/QUERY PLAN/);
    });
  });

  describe('guard additions', () => {
    it('refuses query_to_xml', async () => {
      const r = await call('query', { sql: "select query_to_xml('select pg_sleep(3)', true, false, '')" });
      expect(r.ok).toBe(false);
      expect(r.text).toMatch(/query_to_xml/);
    });
    it('refuses shared advisory locks', async () => {
      const r = await call('query', { sql: 'select pg_try_advisory_lock_shared(42)' });
      expect(r.ok).toBe(false);
      expect(r.text).toMatch(/pg_try_advisory_lock_shared/);
    });
    it('allows EXPLAIN (ANALYZE false)', async () => {
      const r = await call('explain', { sql: 'explain (analyze false) select 1' });
      expect(r.ok, r.text).toBe(true);
      expect(r.text).toMatch(/QUERY PLAN/);
    });
    it('still refuses EXPLAIN ANALYZE', async () => {
      const r = await call('explain', { sql: 'explain analyze select 1' });
      expect(r.ok).toBe(false);
    });
  });

  describe('audit', () => {
    it('writes a start line before and an end line after an allowed query, paired by callId', async () => {
      await call('query', { sql: 'select 42 as answer' });
      const [start, end] = lastAudit(2);
      expect(start).toMatchObject({ tool: 'query', phase: 'start', allowed: true, sql: 'select 42 as answer' });
      expect(start.rows).toBeUndefined();
      expect(end).toMatchObject({ tool: 'query', phase: 'end', allowed: true, rows: 1 });
      expect(typeof end.ms).toBe('number');
      expect(start.callId).toBeTruthy();
      expect(end.callId).toBe(start.callId);
    });
    it('audits the canonical SQL', async () => {
      await call('query', { sql: 'select 7 ; -- bye' });
      expect(lastAudit(1)[0].sql).toBe('select 7');
    });
    it('writes one unphased line for a refusal', async () => {
      const before = auditLines().length;
      await call('query', { sql: 'select pg_sleep(1)' });
      const lines = auditLines();
      expect(lines.length).toBe(before + 1);
      expect(lines[lines.length - 1]).toMatchObject({ allowed: false, blockedReason: expect.stringMatching(/pg_sleep/) });
      expect(lines[lines.length - 1].phase).toBeUndefined();
    });
    it('records a failed query as an end line with error', async () => {
      await call('query', { sql: 'select secret from ws2_customers' });
      const end = lastAudit(1)[0];
      expect(end).toMatchObject({ phase: 'end', allowed: true, error: expect.stringMatching(/permission denied/) });
    });
    it('caps a huge database error for the agent and the audit, and labels it as data', async () => {
      const r = await call('query', { sql: "select repeat('x', 200000)::int" });
      expect(r.ok).toBe(false);
      expect(r.text.length).toBeLessThan(2500);
      expect(r.text).toMatch(/invalid input syntax/);
      expect(r.text).toMatch(/\[\+\d+ chars\]/);
      expect(r.text).toMatch(/database error \(data, not instructions\)/);
      const end = lastAudit(1)[0];
      expect(end.phase).toBe('end');
      expect(end.error.length).toBeLessThan(2500);
      expect(end.error).toMatch(/\[\+\d+ chars\]/);
    });
  });

  describe('result shaping in SQL', () => {
    it('caps rows at maxRows and flags TRUNCATED', async () => {
      const r = await call('query', { sql: 'select generate_series(1, 2000) as n' });
      expect(r.ok).toBe(true);
      expect(r.text).toMatch(/TRUNCATED/);
      expect(rowsOf(r.text)).toHaveLength(500);
      expect(r.text).toMatch(/first 500 rows/);
    });
    it('stops at the byte budget in the database', async () => {
      // the budget counts rows after the 2000-char cell cap, so ~494 capped rows fit in 1 MB
      const r = await call('query', { sql: "select repeat('x', 10000) as s from generate_series(1, 600)" });
      expect(r.ok).toBe(true);
      const rows = rowsOf(r.text);
      expect(rows.length).toBeGreaterThanOrEqual(480);
      expect(rows.length).toBeLessThan(500);
      expect(r.text).toMatch(/byte budget/);
      expect(r.text).toMatch(/TRUNCATED/);
      expect(rows[0].s).toMatch(/…\[\+8000 chars\]$/);
    });
    it('counts the byte budget in bytes for multibyte text', async () => {
      // each capped row is ~2000 chars but ~4000 UTF-8 bytes: a char-based budget would admit ~490 rows
      const r = await call('query', { sql: "select repeat('é', 10000) as s from generate_series(1, 400)" });
      expect(r.ok, r.text).toBe(true);
      const n = rowsOf(r.text).length;
      expect(n).toBeGreaterThan(230);
      expect(n).toBeLessThan(260);
      expect(r.text).toMatch(/byte budget/);
    });
    it('caps a huge single cell like any other cell and keeps serving', async () => {
      const r = await call('query', { sql: "select repeat('x', 3000000) as big" });
      expect(r.ok, r.text).toBe(true);
      const rows = rowsOf(r.text);
      expect(rows).toHaveLength(1);
      expect(rows[0].big).toBe('x'.repeat(2000) + '…[+2998000 chars]');
      expect(rows[0].daypass_truncated_row).toBeUndefined();
      const after = await call('query', { sql: 'select 1 as one' });
      expect(after.ok).toBe(true);
      expect(rowsOf(after.text)).toEqual([{ one: 1 }]);
    });
    it('cuts a cell bigger than temp_file_limit before any window buffers it', async () => {
      // 50 MB value vs a 20 MB temp_file_limit: the cut must happen below the window aggregates,
      // or their tuplestore spills the whole row to disk and the query fails instead of truncating.
      const r = await call('query', { sql: "select repeat('x', 50000000) as big" });
      expect(r.ok, r.text).toBe(true);
      expect(rowsOf(r.text)[0].big).toMatch(/^x{2000}…\[\+49998000 chars\]$/);
    });
    it('keeps bigints exact and stringifies json', async () => {
      const r = await call('query', { sql: `select 9007199254740993::bigint as id, '{"k":[1,2]}'::jsonb as j, 1.5 as f` });
      expect(rowsOf(r.text)).toEqual([{ id: '9007199254740993', j: '{"k":[1,2]}', f: 1.5 }]);
    });
    it('returns an empty result cleanly', async () => {
      const r = await call('query', { sql: 'select 1 where false' });
      expect(r.ok).toBe(true);
      expect(rowsOf(r.text)).toEqual([]);
      expect(r.text).not.toMatch(/TRUNCATED/);
    });
    it('preserves the inner ORDER BY', async () => {
      const r = await call('query', { sql: 'select n from generate_series(1, 5) n order by n desc' });
      expect(rowsOf(r.text).map((x: any) => x.n)).toEqual([5, 4, 3, 2, 1]);
    });
  });

  describe('list_tables', () => {
    it('lists only relations the role can read at least one column of', async () => {
      const r = await call('list_tables');
      expect(r.ok, r.text).toBe(true);
      const names = rowsOf(r.text).map((x: any) => x.table);
      expect(names).toContain('ws2_customers'); // some columns hidden, still readable
      expect(names).toContain('ws2_notes');
      expect(names).not.toContain('ws2_withheld_v'); // view withheld by the setup
      expect(names).not.toContain('ws2_ungranted'); // created since the last setup run
    });
  });

  describe('describe_table', () => {
    it('shows visible columns and indexes on visible columns only', async () => {
      const r = await call('describe_table', { table: 'ws2_customers' });
      expect(r.ok, r.text).toBe(true);
      expect(r.text).toMatch(/ws2_customers_name_idx/);
      expect(r.text).toMatch(/ws2_customers_pkey/);
      expect(r.text).not.toMatch(/secret/);
      expect(r.text).not.toMatch(/email/);
      expect(r.text).toMatch(/3 index\(es\) on hidden columns omitted/);
    });
    it('lists columns in table order with real type names', async () => {
      const r = await call('describe_table', { table: 'ws2_ordered' });
      expect(r.ok, r.text).toBe(true);
      const cols = rowsOf(r.text).filter((x: any) => x.kind === 'column');
      expect(cols.map((c: any) => [c.name, c.type])).toEqual([
        ['zeta', 'integer'],
        ['alpha', 'text[]'],
        ['mood', 'ws2_mood'],
        ['beta', 'character varying(12)'],
      ]);
      expect(cols[0]).toMatchObject({ nullable: 'NO' });
      expect(cols[1]).toMatchObject({ nullable: 'YES' });
    });
    it('errors on a table that does not exist (or cannot be read)', async () => {
      for (const table of ['ws2_nope', 'ws2_ungranted', 'nope.ws2_customers']) {
        const r = await call('describe_table', { table });
        expect(r.ok, table).toBe(false);
        expect(r.text).toMatch(/not found/);
      }
    });
    it('handles quoted MixedCase names, with or without a schema', async () => {
      for (const table of ['"Ws2Mixed"', 'public."Ws2Mixed"', '"public"."Ws2Mixed"', 'Ws2Mixed']) {
        const r = await call('describe_table', { table });
        expect(r.ok, `${table}: ${r.text}`).toBe(true);
        expect(rowsOf(r.text)).toEqual([expect.objectContaining({ kind: 'column', name: 'id', type: 'integer' })]);
      }
    });
    it('refuses a name with more than two parts', async () => {
      const r = await call('describe_table', { table: 'db.public.ws2_customers' });
      expect(r.ok).toBe(false);
      expect(r.text).toMatch(/schema\.table/);
    });
  });

  describe('list_tables row estimates', () => {
    it('shows null, not -1, for a table that was never analyzed', async () => {
      const r = await call('list_tables');
      const rows = rowsOf(r.text);
      const fresh = rows.find((x: any) => x.table === 'ws2_fresh');
      expect(fresh).toBeTruthy();
      expect(fresh.est_rows).toBeNull();
      for (const x of rows) expect(String(x.est_rows)).not.toBe('-1');
    });
  });

  describe('review pass 2: the guard escape chain fails safely', () => {
    it('refuses ts_stat running pg_sleep from a string', async () => {
      const t0 = Date.now();
      const r = await call('query', { sql: "select * from ts_stat('select to_tsvector(pg_sleep(3)::text)')" });
      expect(r.ok).toBe(false);
      expect(r.text).toMatch(/ts_stat/);
      expect(Date.now() - t0).toBeLessThan(1000);
    });
    it('refuses ts_stat flipping standard_conforming_strings, and the session keeps it on', async () => {
      const r = await call('query', {
        sql: "select * from ts_stat($$select to_tsvector(set_config('standard_conforming_strings','off',false))$$)",
      });
      expect(r.ok).toBe(false);
      const s1 = await call('query', { sql: "select current_setting('standard_conforming_strings') as scs" });
      expect(rowsOf(s1.text)).toEqual([{ scs: 'on' }]);
    });
    it("the backslash-quote smuggling input is one harmless statement: no extra commands run", async () => {
      const t0 = Date.now();
      const r = await call('query', {
        sql: "explain select '\\' as a, '; commit; set statement_timeout = 0; select pg_sleep(14); select pg_advisory_lock(42); --' as b",
      });
      expect(Date.now() - t0).toBeLessThan(3000);
      expect(r.ok, r.text).toBe(true);
      expect(r.text).toMatch(/QUERY PLAN/);
      const s2 = await call('query', {
        sql: "select current_setting('statement_timeout') as st, current_setting('standard_conforming_strings') as scs, (select count(*)::int from pg_locks where locktype = 'advisory') as locks",
      });
      expect(rowsOf(s2.text)).toEqual([{ st: '10s', scs: 'on', locks: 0 }]);
    });
    it('refuses a data-modifying CTE through query and explain', async () => {
      for (const tool of ['query', 'explain']) {
        const r = await call(tool, { sql: 'with d as (delete from ws2_notes returning *) select * from d' });
        expect(r.ok).toBe(false);
        expect(r.text).toMatch(/Data-modifying/);
      }
      expect(rowsOf((await call('query', { sql: 'select count(*)::int as n from ws2_notes' })).text)).toEqual([{ n: 1 }]);
    });
  });

  describe('review pass 2: result fidelity', () => {
    it('keeps column order and exact numerics', async () => {
      const r = await call('query', {
        sql: "select 12345678901234567.89::numeric m, 0.12345678901234567890123::numeric f, 123456789012345::bigint ok15, 'z' as z, 1.5 as a",
      });
      expect(r.ok, r.text).toBe(true);
      const row = rowsOf(r.text)[0];
      expect(Object.keys(row)).toEqual(['m', 'f', 'ok15', 'z', 'a']);
      expect(row).toEqual({ m: '12345678901234567.89', f: '0.12345678901234567890123', ok15: 123456789012345, z: 'z', a: 1.5 });
    });
    it('a column named daypass_q does not replace the row', async () => {
      const r = await call('query', { sql: 'select 1 as daypass_q, 2 as daypass_row' });
      expect(r.ok, r.text).toBe(true);
      expect(rowsOf(r.text)).toEqual([{ daypass_q: 1, daypass_row: 2 }]);
    });
    it('renders json and jsonb columns as compact JSON text', async () => {
      const r = await call('query', { sql: `select '{"k": [1, 2]}'::jsonb as jb, '{"k":[1,2]}'::json as j` });
      expect(rowsOf(r.text)).toEqual([{ jb: '{"k":[1,2]}', j: '{"k":[1,2]}' }]);
    });
  });

  describe('review pass 2: one end line per call', () => {
    it('a call cut by shutdown gets exactly one end line', async () => {
      const pending = call('query', { sql: 'select count(*) from generate_series(1, 100000) a, generate_series(1, 100000) b' });
      await new Promise((r) => setTimeout(r, 500));
      const start = lastAudit(1)[0];
      expect(start.phase).toBe('start');
      await closeInFlight('server stopped (TEST) while the call was in flight');
      const r = await pending;
      expect(r.ok).toBe(false);
      await new Promise((res) => setTimeout(res, 200));
      const ends = auditLines().filter((l: any) => l.callId === start.callId && l.phase === 'end');
      expect(ends).toHaveLength(1);
      expect(ends[0].error).toMatch(/TEST/);
      // the server still works afterwards
      expect((await call('query', { sql: 'select 1 as one' })).ok).toBe(true);
    });
  });

  describe('review pass 3', () => {
    const until = async (pred: () => boolean, ms = 5000) => {
      const t0 = Date.now();
      while (!pred() && Date.now() - t0 < ms) await new Promise((r) => setTimeout(r, 20));
    };
    it.each(['query', 'explain'])('refuses SQL over 256 KiB through %s and audits only a prefix of it', async (tool) => {
      const sql = 'select ' + Array(150_000).fill('1').join(',');
      const t0 = Date.now();
      const r = await call(tool, { sql });
      expect(Date.now() - t0).toBeLessThan(500);
      expect(r.ok).toBe(false);
      expect(r.text).toMatch(/too long/);
      const a = lastAudit(1)[0];
      expect(a).toMatchObject({ tool, allowed: false, blockedReason: expect.stringMatching(/too long/) });
      expect(a.sql.length).toBeLessThan(5000);
      expect(a.sql).toMatch(/not audited/);
    });
    it('a failed end-line write falls back to stderr and still answers', async () => {
      const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      const auditPath = join(home, 'audit.jsonl');
      try {
        const before = auditLines().length;
        const p = call('query', { sql: 'select count(*) from generate_series(1, 100000) a, generate_series(1, 300) b' });
        await until(() => auditLines().length > before);
        const start = lastAudit(1)[0];
        expect(start.phase).toBe('start');
        chmodSync(auditPath, 0o400);
        const r = await p;
        chmodSync(auditPath, 0o600);
        expect(r.ok, r.text).toBe(true);
        const written = spy.mock.calls.map((c) => String(c[0])).join('');
        expect(written).toMatch(/audit write failed/);
        expect(written).toContain(start.callId);
      } finally {
        chmodSync(auditPath, 0o600);
        spy.mockRestore();
      }
    });
    it('routeConsoleToStderr keeps anything printed with console.log off stdout', () => {
      const out = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
      const err = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      const saved = { log: console.log, info: console.info, debug: console.debug };
      try {
        serverMod.routeConsoleToStderr();
        console.log('Terminating process due to FATAL error');
        console.info('x');
        expect(out).not.toHaveBeenCalled();
        expect(err.mock.calls.map((c) => String(c[0])).join('')).toMatch(/Terminating process/);
      } finally {
        Object.assign(console, saved);
        out.mockRestore();
        err.mockRestore();
      }
    });
    it('a transport that closes (e.g. an oversized message) leaves an audit line', async () => {
      const s2 = serverMod.buildServer();
      serverMod.auditLifecycle(s2);
      const [ct, st] = InMemoryTransport.createLinkedPair();
      await s2.connect(st);
      const c2 = new Client({ name: 'lifecycle', version: '0' });
      await c2.connect(ct);
      (s2.server as any).onerror?.(new Error('ReadBuffer exceeded maximum size of 10485760 bytes'));
      await c2.close();
      await until(() => /transport closed/.test(JSON.stringify(lastAudit(1)[0] ?? {})));
      expect(lastAudit(1)[0]).toMatchObject({ tool: 'server', error: expect.stringMatching(/transport closed.*ReadBuffer exceeded/) });
    });
    // Puts the server into its stopping state, then resets it for the tests after it.
    it('shutdown racing new calls: every start line gets exactly one end line, and nothing runs after', async () => {
      const before = auditLines().length;
      const slow = 'select count(*) from generate_series(1, 100000) a, generate_series(1, 100000) b';
      const calls = [call('query', { sql: slow }), call('explain', { sql: slow }), call('query', { sql: slow })];
      const t0 = Date.now();
      await serverMod.beginShutdown('server stopped (TEST)');
      const results = await Promise.all(calls);
      expect(Date.now() - t0).toBeLessThan(5000);
      for (const r of results) expect(r.ok).toBe(false);
      await new Promise((r) => setTimeout(r, 300));
      const lines = auditLines().slice(before);
      const starts = lines.filter((l: any) => l.phase === 'start');
      for (const st of starts) expect(lines.filter((l: any) => l.callId === st.callId && l.phase === 'end')).toHaveLength(1);
      const late = await call('query', { sql: 'select 1' });
      expect(late.ok).toBe(false);
      expect(late.text).toMatch(/stopping/i);
      serverMod.resetShutdownForTests();
    });
  });

  describe('lease-bounded statement_timeout', () => {
    it('cancels a query at lease expiry instead of letting it outlive the lease', async () => {
      writeLease(1500);
      const t0 = Date.now();
      const r = await call('query', { sql: 'select count(*) from generate_series(1, 100000) a, generate_series(1, 100000) b' });
      const elapsed = Date.now() - t0;
      writeLease(30 * 60_000);
      expect(r.ok).toBe(false);
      expect(r.text).toMatch(/statement timeout/);
      expect(elapsed).toBeLessThan(6000);
    });
  });
});

describe('parseTableName', () => {
  it('splits and unquotes', async () => {
    const { parseTableName } = await import('../src/mcp/server.js');
    expect(parseTableName('users', 'public')).toEqual({ schema: 'public', name: 'users' });
    expect(parseTableName('app.users', 'public')).toEqual({ schema: 'app', name: 'users' });
    expect(parseTableName('"My.Schema"."Odd""Name"', 'public')).toEqual({ schema: 'My.Schema', name: 'Odd"Name' });
    expect(parseTableName('"Users"', 'x')).toEqual({ schema: 'x', name: 'Users' });
    for (const bad of ['a.b.c', '', 'a.', '"unterminated', '"a"b', '.a']) expect(typeof parseTableName(bad, 'public'), bad).toBe('string');
  });
});

describe('describeTableSql', () => {
  it('never reads pg_indexes and filters on column privilege', async () => {
    const { describeTableSql } = await import('../src/mcp/server.js');
    const sql = describeTableSql('public', "cust'omers");
    expect(sql).not.toMatch(/pg_indexes/);
    expect(sql).toMatch(/has_column_privilege/);
    expect(sql).toMatch(/pg_depend/);
    expect(sql).toMatch(/indkey/);
    expect(sql).toContain("'cust''omers'");
  });
});
