import pg from 'pg';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Signer } from '@aws-sdk/rds-signer';
import { fromIni } from '@aws-sdk/credential-providers';
import type { ResolvedTarget, TargetConfig } from './state.js';

const TOKEN_TTL_MS = 10 * 60_000; // RDS tokens last 15 min; refresh well before that.
/** Query time cap. Keep low while Daypass points at the live instance; raise once it has a read replica. */
export const STATEMENT_TIMEOUT_MS = 10_000;
/**
 * Hard cap on bytes read from the socket during one call. The SQL-side budget keeps `query`
 * far below this; it is the backstop for every other path and for a wrapper that misbehaves.
 * Past it the connection is destroyed, so the condition becomes a rejected query instead of
 * a pg-protocol exception inside a socket handler (which would take the process down).
 */
export const MAX_WIRE_BYTES = 32 * 1024 * 1024;

/** AWS RDS global CA bundle, shipped with the package (https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem). */
const RDS_CA_PATH = new URL('../../certs/global-bundle.pem', import.meta.url);

export type SslOptions = { rejectUnauthorized: true; ca?: string } | undefined;

/**
 * TLS is always verified. RDS targets (IAM `region` set, or any `*.rds.amazonaws.com` host)
 * pin the bundled RDS CA: the token and the data travel over the public internet, and the
 * system store does not carry Amazon's RDS roots. Other TLS targets use the system CAs, or
 * `sslCa` if set. Only `ssl: false` (local dev) turns TLS off.
 */
export function sslOptions(t: TargetConfig, rdsCaPem: string | undefined): SslOptions {
  if (t.ssl === false) {
    // An IAM token, or anything bound for RDS, crosses the internet: never in clear text.
    if (t.region || (t.host && isRdsHost(t.host))) {
      throw new Error('TLS cannot be turned off for an RDS or IAM (region) target: remove ssl: false / sslmode=disable.');
    }
    return undefined;
  }
  if (t.sslCa) return { rejectUnauthorized: true, ca: readFileSync(t.sslCa, 'utf8') };
  if ((t.region || (t.host && isRdsHost(t.host))) && rdsCaPem) return { rejectUnauthorized: true, ca: rdsCaPem };
  return { rejectUnauthorized: true };
}

/** The bundled RDS CA bundle, or undefined if it is not shipped with this install. */
export function rdsCa(): string | undefined {
  try {
    return readFileSync(RDS_CA_PATH, 'utf8');
  } catch {
    return undefined;
  }
}

/**
 * `.rds.` under the DNS suffix of every AWS partition (commercial and GovCloud, China, the
 * European Sovereign Cloud, the ISO partitions), with or without a trailing root dot.
 */
const RDS_HOST = /\.rds\.(?:amazonaws\.com(?:\.cn)?|amazonaws\.eu|c2s\.ic\.gov|sc2s\.sgov\.gov|cloud\.adc-e\.uk|csp\.hci\.ic\.gov)\.?$/i;

/**
 * True for an AWS RDS endpoint: TLS cannot be turned off for it, and a plain URL target pins the
 * bundled RDS CA like an IAM target does (the bundle holds the commercial-partition roots; other
 * partitions need `sslCa`).
 */
export function isRdsHost(host: string): boolean {
  return RDS_HOST.test(host);
}

let cached: { key: string; pool: pg.Pool } | null = null;
/** Pools replaced after a config change, ended once nobody is waiting on them. */
const retired = new Set<pg.Pool>();

/**
 * A token getter that fetches at most once per `ttlMs` (concurrent callers share one fetch) and
 * never caches a failure. Exported for tests.
 */
export function cachedToken(fetch: () => Promise<string>, ttlMs: number, clock: () => number = Date.now): () => Promise<string> {
  let token: { value: string; at: number } | null = null;
  let pending: Promise<string> | null = null;
  return () => {
    if (token && clock() - token.at <= ttlMs) return Promise.resolve(token.value);
    pending ??= fetch()
      .then((value) => {
        token = { value, at: clock() };
        return value;
      })
      .finally(() => (pending = null));
    return pending;
  };
}

/**
 * The pool's password. For IAM targets it is a function pg calls for each new connection, so a
 * fresh token is used whenever one is needed and the pool never has to be rebuilt to refresh it.
 */
function password(t: ResolvedTarget): string | (() => Promise<string>) {
  if (!t.region) {
    if (!t.password) throw new Error('Target has neither region (IAM auth) nor password');
    return t.password;
  }
  const signer = new Signer({
    hostname: t.host,
    port: t.port,
    username: t.user,
    region: t.region,
    ...(t.awsProfile ? { credentials: fromIni({ profile: t.awsProfile }) } : {}),
  });
  return cachedToken(() => signer.getAuthToken(), TOKEN_TTL_MS);
}

/** Everything that decides where and how the pool connects; a change means a new pool. */
function poolKey(name: string, t: ResolvedTarget): string {
  const secret = t.password ? createHash('sha256').update(t.password).digest('hex') : '';
  return JSON.stringify([name, t.host, t.port, t.database, t.user, t.ssl ?? null, t.sslCa ?? null, t.region ?? null, t.awsProfile ?? null, secret]);
}

/**
 * End a replaced pool without pulling it from under a caller that already holds it: after a
 * grace period, and only once nobody is queued for one of its connections. Checked-out
 * connections finish their call first (pg-pool's end() waits for them).
 */
function retire(pool: pg.Pool): void {
  retired.add(pool);
  const tryEnd = () => {
    if (!retired.has(pool)) return;
    if (pool.waitingCount > 0) {
      setTimeout(tryEnd, 200).unref();
      return;
    }
    retired.delete(pool);
    void pool.end().catch(() => {});
  };
  setTimeout(tryEnd, 1000).unref();
}

/**
 * One connection per process, per target: the role's CONNECTION LIMIT is shared by every
 * Daypass process (one per AI session), so concurrent calls queue here instead. An idle
 * connection is closed after a few seconds. Even if the DB role were misconfigured, every
 * connection also forces read-only + timeouts at the session level.
 */
export async function getPool(name: string, t: ResolvedTarget): Promise<pg.Pool> {
  if (shuttingDown) throw new Error('Daypass is shutting down; no new database connections.');
  const key = poolKey(name, t);
  if (cached && cached.key === key) return cached.pool;
  const pool = new pg.Pool({
    host: t.host,
    port: t.port,
    database: t.database,
    user: t.user,
    password: password(t),
    ssl: sslOptions(t, rdsCa()),
    max: 1,
    idleTimeoutMillis: 5_000,
    // Includes time queued behind another call on the single connection (up to the 10 s statement cap).
    connectionTimeoutMillis: 15_000,
    application_name: 'daypass',
    options:
      `-c default_transaction_read_only=on -c statement_timeout=${STATEMENT_TIMEOUT_MS} -c idle_in_transaction_session_timeout=30000 -c lock_timeout=1000` +
      // The guard parses with standard_conforming_strings on; the server must agree, or '\'
      // means different things to each and one "statement" becomes several.
      ` -c standard_conforming_strings=on`,
  });
  pool.on('error', () => {});
  if (cached) retire(cached.pool);
  cached = { key, pool };
  return pool;
}

let shuttingDown = false;
/** Close the pool for good: later getPool calls fail instead of quietly building a new one. */
export async function shutdownPool(): Promise<void> {
  shuttingDown = true;
  await closePool();
}
export function resetShutdownForTests(): void {
  shuttingDown = false;
}

/**
 * Ask the server to cancel whatever `client`'s backend is running, over a separate connection
 * (the protocol CancelRequest with the backend's processID and secretKey; needs no privileges).
 * Best effort and bounded: resolves within ~2 s whatever happens.
 */
export function sendCancel(client: pg.PoolClient | pg.Client): Promise<void> {
  const c: any = client;
  const params = c.connectionParameters ?? {};
  if (!c.processID || !c.secretKey) return Promise.resolve();
  return new Promise((resolve) => {
    const con: any = new (pg as any).Connection({ ssl: params.ssl });
    let finished = false;
    const done = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try {
        con.stream?.destroy?.();
      } catch {
        /* gone */
      }
      resolve();
    };
    const timer = setTimeout(done, 2000);
    con.on('error', done);
    con.on('end', done);
    const fire = () => {
      try {
        con.cancel(c.processID, c.secretKey); // the server closes the cancel connection itself
      } catch {
        done();
      }
    };
    if (params.ssl) {
      con.once('connect', () => con.requestSsl());
      con.once('sslconnect', fire);
    } else {
      con.once('connect', fire);
    }
    con.connect(params.port, params.host);
  });
}

/**
 * Stop a call for real: cut the socket (no more data reaches Node) and cancel the backend
 * (otherwise it keeps running, holding locks and CPU, until statement_timeout).
 */
export async function cancelAndDestroy(client: pg.PoolClient | pg.Client, why: Error): Promise<void> {
  try {
    (client as any).connection?.stream?.destroy?.(why);
  } catch {
    /* already gone */
  }
  await sendCancel(client);
}

export async function closePool(): Promise<void> {
  const pools = [...retired, ...(cached ? [cached.pool] : [])];
  retired.clear();
  cached = null;
  await Promise.all(pools.map((p) => p.end().catch(() => {})));
}

/** The role's CONNECTION LIMIT is full (SQLSTATE 53300 names the role). */
function connectionLimitError(e: any): Error | null {
  if (e?.code !== '53300' && !/too many connections for role/i.test(e?.message ?? '')) return null;
  return new Error(
    `${e.message}: the Daypass role's connection limit is reached. Every daypass process (one per AI session) ` +
      'holds at most one connection and drops it after a few idle seconds; close other sessions or retry shortly.',
  );
}

export interface BoundedOptions {
  /** Upper bound for `SET LOCAL statement_timeout`, in ms (normally STATEMENT_TIMEOUT_MS). */
  timeoutMs: number;
  /**
   * Absolute time (epoch ms) the statement must not outlive, e.g. the lease expiry. The timeout
   * becomes min(timeoutMs, deadlineMs - now) measured AFTER the connection is checked out, so
   * time spent waiting for a connection cannot stretch the call past the lease.
   */
  deadlineMs?: number;
  /**
   * How long past the statement timeout to wait for the server before giving up on it (a dropped
   * network or a stalled server never answers, and statement_timeout is enforced by the server).
   * Default STALL_GRACE_MS.
   */
  graceMs?: number;
  /** Bytes read from the socket before the connection is destroyed. Default MAX_WIRE_BYTES. */
  maxWireBytes?: number;
  /** Test hook: called with the checked-out client before the query runs. */
  onClient?: (client: pg.PoolClient) => void;
}

/**
 * Run one statement on a checked-out connection inside
 * `BEGIN READ ONLY; SET LOCAL statement_timeout = …; <sql>; COMMIT`, counting bytes on the
 * socket and destroying the connection past `maxWireBytes`. The statement runs with the
 * extended protocol (one command only) and `standard_conforming_strings = on`. Afterwards
 * advisory locks are released and `DISCARD ALL` resets the session, so nothing a call did can
 * reach the next caller; a connection that cannot be reset is dropped.
 */
export const STALL_GRACE_MS = 5_000;

export async function runBounded(pool: pg.Pool, sql: string, o: BoundedOptions): Promise<pg.QueryResult> {
  const max = o.maxWireBytes ?? MAX_WIRE_BYTES;
  let client: pg.PoolClient;
  try {
    client = await pool.connect();
  } catch (e) {
    throw connectionLimitError(e) ?? e;
  }
  const left = o.deadlineMs === undefined ? Infinity : o.deadlineMs - Date.now();
  if (left <= 0) {
    client.release();
    throw new Error('The lease expired before the query could start.');
  }
  const timeout = Math.max(1, Math.floor(Math.min(o.timeoutMs, left)));
  o.onClient?.(client);
  // pg-pool detaches its own error listener while a client is checked out; a destroyed socket
  // would otherwise surface as an unhandled 'error' event instead of a rejected query.
  const swallow = () => {};
  client.on('error', swallow);
  const stream: NodeJS.EventEmitter & { destroy?: (e?: Error) => void } | undefined = (client as any).connection?.stream;
  let bytes = 0;
  let tripped: Error | null = null;
  const onData = (chunk: Buffer) => {
    bytes += chunk.length;
    if (bytes > max && !tripped) {
      tripped = new Error(`Result exceeded ${max} bytes on the wire; connection closed. Select fewer or smaller columns.`);
      void cancelAndDestroy(client, tripped);
    }
  };
  stream?.on('data', onData);
  // The server enforces statement_timeout, but only a server that answers can. If nothing comes
  // back (network gone, server stalled), cut the connection rather than wait for TCP to notice.
  const graceMs = o.graceMs ?? STALL_GRACE_MS;
  const watchdog = setTimeout(() => {
    if (tripped) return;
    tripped = new Error(`No answer from the database ${Math.round((timeout + graceMs) / 1000)} s into the call; connection closed.`);
    void cancelAndDestroy(client, tripped);
  }, timeout + graceMs);
  watchdog.unref();
  let failure: unknown = null;
  let resetFailed: Error | undefined;
  try {
    await client.query('BEGIN READ ONLY');
    await client.query('SET LOCAL standard_conforming_strings = on');
    await client.query(`SET LOCAL statement_timeout = ${timeout}`);
    await checkClientConnection(pool, client);
    // Extended protocol: the server refuses more than one command in it, so even SQL that fooled
    // the guard cannot add a COMMIT or a second statement. (`values: []` alone stays simple protocol.)
    const res: any = await client.query({ text: sql, queryMode: 'extended' } as pg.QueryConfig);
    if (Array.isArray(res)) throw new Error(`Expected one result, got ${res.length}; nothing was returned.`);
    await client.query('COMMIT');
    return res;
  } catch (e) {
    failure = tripped ?? e;
    if (!tripped) await client.query('ROLLBACK').catch(() => {});
    throw failure;
  } finally {
    stream?.off('data', onData);
    if (!tripped) {
      // Whatever the statement did to the session (set_config(..., false), advisory locks,
      // LISTEN, prepared statements, temp objects) must not reach the next caller. DISCARD ALL
      // resets to the connection's startup options. If it cannot run, drop the connection.
      try {
        await client.query('SELECT pg_advisory_unlock_all()');
        await client.query('DISCARD ALL');
      } catch (e: any) {
        resetFailed = new Error(`session reset failed: ${e?.message ?? e}`);
      }
    }
    clearTimeout(watchdog);
    const dead = tripped ?? (isConnectionDead(failure) ? (failure as Error) : resetFailed);
    if (!dead) client.off('error', swallow); // a dead client is discarded by the pool; keep swallowing its last gasps
    client.release(dead);
  }
}

/** Pools whose server refused client_connection_check_interval (PG <= 13, or a platform without POLLRDHUP such as macOS). */
const noConnectionCheck = new WeakSet<pg.Pool>();

/**
 * PG 14+ on Linux: the backend notices a vanished client within 1 s and stops instead of running
 * on to statement_timeout. Transaction-local and inside a savepoint, because the server may not
 * support it: as a startup option, an unknown or unsupported value would fail every connection.
 */
async function checkClientConnection(pool: pg.Pool, client: pg.PoolClient): Promise<void> {
  if (noConnectionCheck.has(pool)) return;
  await client.query('SAVEPOINT daypass_cci');
  try {
    const r = await client.query(
      "SELECT set_config('client_connection_check_interval', '1000', true) AS v WHERE current_setting('server_version_num')::int >= 140000",
    );
    if (r.rowCount === 0) noConnectionCheck.add(pool);
    await client.query('RELEASE SAVEPOINT daypass_cci');
  } catch {
    noConnectionCheck.add(pool);
    await client.query('ROLLBACK TO SAVEPOINT daypass_cci');
  }
}

/** pg marks a client whose socket died; releasing it with the error makes the pool drop it. */
function isConnectionDead(e: unknown): boolean {
  const msg = (e as any)?.message ?? '';
  return /terminated|ECONNRESET|EPIPE|closed/i.test(msg);
}
