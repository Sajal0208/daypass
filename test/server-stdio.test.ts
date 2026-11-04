// Runs the built `daypass mcp` over real stdio against a live Postgres (DAYPASS_TEST_PG_URL).
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import pg from 'pg';

const live = process.env.DAYPASS_TEST_PG_URL;
const CLI = join(resolve(__dirname, '..'), 'dist', 'cli', 'main.js');
const SLOW = 'select count(*) from generate_series(1, 100000) a, generate_series(1, 100000) b';

describe.skipIf(!live)('daypass mcp over stdio', () => {
  let home: string;
  beforeAll(() => {
    home = mkdtempSync(join(tmpdir(), 'daypass-stdio-'));
    writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: { t: { url: live } } }), { mode: 0o600 });
    writeFileSync(
      join(home, 'lease.json'),
      JSON.stringify({ id: 'stdio001', target: 't', reason: 'r', who: 'me', openedAt: '', expiresAt: new Date(Date.now() + 3600e3).toISOString() }),
      { mode: 0o600 },
    );
  });
  afterAll(() => rmSync(home, { recursive: true, force: true }));

  const audit = () => {
    try {
      return readFileSync(join(home, 'audit.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
    } catch {
      return [];
    }
  };
  const until = async (pred: () => boolean, ms = 10_000) => {
    const t0 = Date.now();
    while (!pred() && Date.now() - t0 < ms) await new Promise((r) => setTimeout(r, 25));
  };
  function start(): { child: ChildProcess; send: (m: object) => void; exited: Promise<number | null>; out: () => string } {
    const child = spawn('node', [CLI, 'mcp'], { env: { ...process.env, DAYPASS_HOME: home }, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    child.stdout!.on('data', (d) => (out += d));
    child.stderr!.on('data', () => {});
    const exited = new Promise<number | null>((r) => child.on('exit', (code) => r(code)));
    const send = (m: object) => child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', ...m }) + '\n');
    send({ id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } } });
    send({ method: 'notifications/initialized' });
    return { child, send, exited, out: () => out };
  }

  it('exits promptly when stdin closes after a query (no idle pool keeps it alive)', async () => {
    const s = start();
    s.send({ id: 2, method: 'tools/call', params: { name: 'query', arguments: { sql: 'select 1 as one' } } });
    await until(() => s.out().includes('"id":2'));
    expect(s.out()).toMatch(/1 row\(s\)/);
    const t0 = Date.now();
    s.child.stdin!.end();
    const code = await s.exited;
    expect(Date.now() - t0).toBeLessThan(4000);
    expect(code).toBe(0);
    expect(audit().at(-1)).toMatchObject({ tool: 'server', error: expect.stringMatching(/transport closed/) });
  }, 20_000);

  it('cancels an in-flight query, audits its end, and exits promptly when stdin closes', async () => {
    const before = audit().length;
    const s = start();
    s.send({ id: 2, method: 'tools/call', params: { name: 'query', arguments: { sql: SLOW } } });
    await until(() => audit().slice(before).some((l) => l.phase === 'start'));
    await new Promise((r) => setTimeout(r, 300));
    const startLine = audit().slice(before).find((l) => l.phase === 'start');
    const t0 = Date.now();
    s.child.stdin!.end();
    await s.exited;
    expect(Date.now() - t0).toBeLessThan(4000);
    const ends = audit().filter((l) => l.callId === startLine.callId && l.phase === 'end');
    expect(ends).toHaveLength(1);
    expect(ends[0].error).toMatch(/transport closed/);
    // the backend was cancelled, not left running to statement_timeout
    const c = new pg.Client({ connectionString: live });
    await c.connect();
    try {
      let n = 1;
      for (let i = 0; i < 20 && n; i++) {
        n = (await c.query(`select count(*)::int as n from pg_stat_activity where application_name = 'daypass' and state = 'active' and query like '%generate_series(1, 100000) a%'`)).rows[0].n;
        if (n) await new Promise((r) => setTimeout(r, 100));
      }
      expect(n).toBe(0);
    } finally {
      await c.end();
    }
  }, 20_000);
});
