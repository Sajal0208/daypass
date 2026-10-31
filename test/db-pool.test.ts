import { describe, it, expect, afterEach } from 'vitest';
import pg from 'pg';
import { getPool, closePool, runBounded, MAX_WIRE_BYTES, cancelAndDestroy, shutdownPool, resetShutdownForTests } from '../src/mcp/db.js';
import { resolveTarget } from '../src/mcp/state.js';

// A password target: pg.Pool does not connect until the first query, so no network is needed.
const t = resolveTarget('t', { url: 'postgres://u:p@db.invalid:5432/d?sslmode=disable' });

afterEach(() => closePool());

describe('getPool refresh is serialised', () => {
  it('two concurrent first calls share one pool', async () => {
    const [a, b] = await Promise.all([getPool('t', t, 0), getPool('t', t, 0)]);
    expect(a).toBe(b);
  });
  it('two concurrent calls at token refresh end the old pool once and create exactly one new pool', async () => {
    const old = await getPool('t', t, 0);
    const later = 11 * 60_000;
    const [a, b] = await Promise.all([getPool('t', t, later), getPool('t', t, later)]);
    expect(a).toBe(b);
    expect(a).not.toBe(old);
    expect((old as any).ended).toBe(true);
    expect((a as any).ended).toBeFalsy();
  });
  it('a fresh pool is reused within the token ttl', async () => {
    const a = await getPool('t', t, 0);
    const b = await getPool('t', t, 5 * 60_000);
    expect(a).toBe(b);
  });
});

describe('MAX_WIRE_BYTES', () => {
  it('is 32 MiB', () => expect(MAX_WIRE_BYTES).toBe(32 * 1024 * 1024));
});

// Live checks need a throwaway Postgres: DAYPASS_TEST_PG_URL=postgres://postgres:postgres@localhost:5472/postgres?sslmode=disable
const live = process.env.DAYPASS_TEST_PG_URL;
describe.skipIf(!live)('runBounded against a live database', () => {
  const lt = live ? resolveTarget('live', { url: live }) : t;

  it('runs a query inside a read-only transaction with the given statement_timeout', async () => {
    const pool = await getPool('live', lt);
    const r = await runBounded(pool, "select current_setting('statement_timeout') as st, current_setting('transaction_read_only') as ro", {
      timeoutMs: 1234,
    });
    expect(r.rows[0]).toEqual({ st: '1234ms', ro: 'on' });
  });
  it('the SET LOCAL does not leak into the next use of the connection', async () => {
    const pool = await getPool('live', lt);
    await runBounded(pool, 'select 1', { timeoutMs: 777 });
    const r = await runBounded(pool, "select current_setting('statement_timeout') as st", { timeoutMs: 999 });
    expect(r.rows[0].st).toBe('999ms');
    const plain = await pool.query("select current_setting('statement_timeout') as st");
    expect(plain.rows[0].st).toBe('10s');
  });
  it('cancels a query that outlives the timeout', async () => {
    const pool = await getPool('live', lt);
    const t0 = Date.now();
    await expect(runBounded(pool, 'select count(*) from generate_series(1, 200000000)', { timeoutMs: 300 })).rejects.toThrow(
      /statement timeout/,
    );
    expect(Date.now() - t0).toBeLessThan(5000);
    // the connection is still usable
    const r = await runBounded(pool, 'select 2 as two', { timeoutMs: 1000 });
    expect(r.rows[0].two).toBe(2);
  });
  it('rejects writes even if the role could write', async () => {
    const pool = await getPool('live', lt);
    await expect(runBounded(pool, 'create temp table daypass_x (a int)', { timeoutMs: 1000 })).rejects.toThrow(/read-only/);
  });
  it('releases advisory locks taken during the call', async () => {
    const pool = await getPool('live', lt);
    await runBounded(pool, 'select pg_advisory_lock(424242)', { timeoutMs: 1000 });
    const r = await pool.query("select count(*)::int as n from pg_locks where locktype = 'advisory' and objid = 424242");
    expect(r.rows[0].n).toBe(0);
  });
  // Review 2026-10-30 (second pass): the escape chain flipped standard_conforming_strings on the
  // pooled backend so the guard and the server parsed the same text differently, then smuggled
  // extra statements through the simple protocol.
  it('rejects more than one statement (extended protocol), even if the guard were fooled', async () => {
    const pool = await getPool('live', lt);
    await expect(runBounded(pool, 'select 1; select 2', { timeoutMs: 1000 })).rejects.toThrow(/multiple commands/);
    await expect(runBounded(pool, 'select 1; commit; select pg_sleep(0)', { timeoutMs: 1000 })).rejects.toThrow(/multiple commands/);
  });
  it('forces standard_conforming_strings on inside the call', async () => {
    const pool = await getPool('live', lt);
    const r = await runBounded(pool, "select current_setting('standard_conforming_strings') as scs", { timeoutMs: 1000 });
    expect(r.rows[0].scs).toBe('on');
  });
  it('resets session state a call changed before the connection goes back to the pool', async () => {
    const pool = await getPool('live', lt);
    const pids = new Set<number>();
    // Both pool connections get poisoned, so the follow-up call lands on a poisoned backend.
    for (let i = 0; i < 2; i++) {
      await Promise.all(
        [0, 1].map(() =>
          runBounded(
            pool,
            "select pg_backend_pid() as pid, set_config('standard_conforming_strings','off',false), set_config('daypass.poison','x',false), pg_sleep(0.05)",
            { timeoutMs: 2000 },
          ).then((r) => pids.add(r.rows[0].pid)),
        ),
      );
    }
    const plain = await pool.query(
      "select pg_backend_pid() as pid, current_setting('standard_conforming_strings') as scs, current_setting('daypass.poison', true) as poison",
    );
    expect(pids.has(plain.rows[0].pid)).toBe(true);
    expect(plain.rows[0].scs).toBe('on');
    expect(plain.rows[0].poison ?? '').toBe('');
  });
  it('the pool itself starts sessions with standard_conforming_strings on', async () => {
    const pool = await getPool('live', lt);
    const opts = (pool as any).options?.options as string;
    expect(opts).toMatch(/-c standard_conforming_strings=on/);
  });
  it('computes the timeout from the deadline after the connection is checked out', async () => {
    const pool = await getPool('live', lt);
    const r = await runBounded(pool, "select current_setting('statement_timeout') as st", { timeoutMs: 10_000, deadlineMs: Date.now() + 4000 });
    const ms = parseInt(r.rows[0].st, 10) * (r.rows[0].st.endsWith('ms') ? 1 : 1000);
    expect(ms).toBeLessThanOrEqual(4000);
    expect(ms).toBeGreaterThan(3000);
  });
  it('refuses to start when the deadline has already passed', async () => {
    const pool = await getPool('live', lt);
    await expect(runBounded(pool, 'select 1', { timeoutMs: 10_000, deadlineMs: Date.now() - 1 })).rejects.toThrow(/lease.*expired/i);
  });
  // Review pass 3: destroying the socket alone left the backend running until statement_timeout.
  const activeBackend = async (pid: number) => {
    const c = new pg.Client({ connectionString: live });
    await c.connect();
    try {
      const r = await c.query(`select count(*)::int as n from pg_stat_activity where pid = $1 and state = 'active'`, [pid]);
      return r.rows[0].n as number;
    } finally {
      await c.end();
    }
  };
  it('cancelAndDestroy stops the backend, not just the socket', async () => {
    const pool = await getPool('live', lt);
    let client: any;
    const p = runBounded(pool, 'select count(*) from generate_series(1, 100000) a, generate_series(1, 100000) b', {
      timeoutMs: 10_000,
      onClient: (c) => (client = c),
    });
    await new Promise((r) => setTimeout(r, 400));
    const pid = client.processID as number;
    expect(await activeBackend(pid)).toBe(1);
    const settled = p.then(
      () => null,
      (e) => e,
    ); // observe the rejection now, not after cancelAndDestroy
    await cancelAndDestroy(client, new Error('stop (test)'));
    expect(await settled).toBeInstanceOf(Error);
    let n = 1;
    for (let i = 0; i < 20 && n; i++) {
      await new Promise((r) => setTimeout(r, 100));
      n = await activeBackend(pid);
    }
    expect(n).toBe(0);
  });
  it('sets client_connection_check_interval inside the call where the server supports it, and runs fine where not', async () => {
    // Supported only on PG 14+ and platforms with POLLRDHUP (Linux; not macOS).
    const probe = new pg.Client({ connectionString: live });
    await probe.connect();
    const supported = await probe.query('set client_connection_check_interval = 1000').then(
      () => true,
      () => false,
    );
    await probe.end();
    const pool = await getPool('live', lt);
    for (let i = 0; i < 2; i++) {
      const r = await runBounded(pool, "select current_setting('client_connection_check_interval', true) as cci, 1 as one", {
        timeoutMs: 1000,
      });
      expect(r.rows[0]).toMatchObject({ cci: supported ? '1s' : expect.anything(), one: 1 });
      if (!supported) expect(['0', null]).toContain(r.rows[0].cci);
    }
  });
  it('refuses new pools after shutdownPool()', async () => {
    await shutdownPool();
    await expect(getPool('live', lt)).rejects.toThrow(/shutting down/);
    resetShutdownForTests();
  });
  it('destroys the connection and rejects when the result exceeds the wire cap', async () => {
    const pool = await getPool('live', lt);
    await expect(runBounded(pool, "select repeat('x', 3000000)", { timeoutMs: 10_000, maxWireBytes: 1_000_000 })).rejects.toThrow(
      /wire/,
    );
    const r = await runBounded(pool, 'select 3 as three', { timeoutMs: 1000 });
    expect(r.rows[0].three).toBe(3);
  });
});
