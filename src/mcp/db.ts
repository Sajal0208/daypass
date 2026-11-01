import pg from 'pg';
import { readFileSync } from 'node:fs';
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
  if (t.ssl === false) return undefined;
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

/** True for an AWS RDS endpoint, so a plain URL target can pin the bundled RDS CA like an IAM target does. */
export function isRdsHost(host: string): boolean {
  return /\.rds\.amazonaws\.com$/i.test(host);
}

let cached: { key: string; pool: pg.Pool; tokenAt: number } | null = null;
/** In-flight (re)creation, so two callers at the refresh boundary share one pool instead of each building one. */
let creating: Promise<pg.Pool> | null = null;

async function password(t: ResolvedTarget): Promise<string> {
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
  return signer.getAuthToken();
}

/**
 * One small pool per target. Even if the DB role were misconfigured, every
 * connection also forces read-only + timeouts at the session level.
 * `now` is injectable for tests of the refresh path.
 */
export async function getPool(name: string, t: ResolvedTarget, now = Date.now()): Promise<pg.Pool> {
  if (shuttingDown) throw new Error('Daypass is shutting down; no new database connections.');
  const key = `${name}:${t.host}:${t.user}`;
  if (cached && cached.key === key && now - cached.tokenAt <= TOKEN_TTL_MS) return cached.pool;
  if (!creating) {
    creating = (async () => {
      try {
        if (cached) {
          await cached.pool.end().catch(() => {});
          cached = null;
        }
        const pool = new pg.Pool({
          host: t.host,
          port: t.port,
          database: t.database,
          user: t.user,
          password: await password(t),
          ssl: sslOptions(t, rdsCa()),
          max: 2,
          idleTimeoutMillis: 30_000,
          connectionTimeoutMillis: 10_000,
          application_name: 'daypass',
          options:
            `-c default_transaction_read_only=on -c statement_timeout=${STATEMENT_TIMEOUT_MS} -c idle_in_transaction_session_timeout=30000 -c lock_timeout=1000` +
            // The guard parses with standard_conforming_strings on; the server must agree, or '\'
            // means different things to each and one "statement" becomes several.
            ` -c standard_conforming_strings=on`,
        });
        pool.on('error', () => {});
        cached = { key, pool, tokenAt: now };
        return pool;
      } finally {
        creating = null;
      }
    })();
  }
  return creating;
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
  if (creating) await creating.catch(() => {});
  if (cached) {
    await cached.pool.end().catch(() => {});
    cached = null;
  }
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
export async function runBounded(pool: pg.Pool, sql: string, o: BoundedOptions): Promise<pg.QueryResult> {
  const max = o.maxWireBytes ?? MAX_WIRE_BYTES;
  const client = await pool.connect();
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
