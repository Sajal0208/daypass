// A database that stops answering mid-call (network drop, stalled server) must not hang the call:
// runBounded gives up a little after the statement timeout, frees the connection, and the next
// call gets a fresh one. Needs a live Postgres behind a local TCP proxy that can go silent.
import { describe, it, expect, afterEach } from 'vitest';
import net from 'node:net';
import { getPool, closePool, runBounded } from '../src/mcp/db.js';
import { resolveTarget } from '../src/mcp/state.js';

const live = process.env.DAYPASS_TEST_PG_URL;

/** Forwards to the live server; while `silent`, drops everything in both directions. */
async function silentProxy(target: URL) {
  const state = { silent: false, sockets: [] as net.Socket[] };
  const server = net.createServer((c) => {
    const up = net.connect(Number(target.port || 5432), target.hostname);
    state.sockets.push(c, up);
    c.on('data', (d) => !state.silent && up.write(d));
    up.on('data', (d) => !state.silent && c.write(d));
    c.on('error', () => up.destroy());
    up.on('error', () => c.destroy());
    c.on('close', () => up.destroy());
    up.on('close', () => c.destroy());
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as net.AddressInfo).port;
  return {
    state,
    port,
    close: () => {
      state.sockets.forEach((s) => s.destroy());
      return new Promise<void>((r) => server.close(() => r()));
    },
  };
}

afterEach(() => closePool());

describe.skipIf(!live)('runBounded when the database stops answering', () => {
  it('rejects a little after the statement timeout instead of waiting forever, and the next call works', async () => {
    const proxy = await silentProxy(new URL(live!));
    const u = new URL(live!);
    try {
      u.hostname = '127.0.0.1';
      u.port = String(proxy.port);
      const pool = await getPool('stall', resolveTarget('stall', { url: u.toString() }));
      const t0 = Date.now();
      const r = runBounded(pool, 'select 1', { timeoutMs: 300, graceMs: 500, onClient: () => (proxy.state.silent = true) });
      await expect(r).rejects.toThrow(/no answer from the database/i);
      expect(Date.now() - t0).toBeLessThan(5000);
      proxy.state.silent = false;
      const again = await runBounded(pool, 'select 2 as two', { timeoutMs: 1000 });
      expect(again.rows[0].two).toBe(2);
    } finally {
      await proxy.close();
    }
  }, 20_000);
});
