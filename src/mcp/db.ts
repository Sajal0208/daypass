import pg from 'pg';
import { readFileSync } from 'node:fs';
import { Signer } from '@aws-sdk/rds-signer';
import { fromIni } from '@aws-sdk/credential-providers';
import type { ResolvedTarget, TargetConfig } from './state.js';

const TOKEN_TTL_MS = 10 * 60_000; // RDS tokens last 15 min; refresh well before that.
/** Query time cap. Keep low while Peephole points at the live instance; raise once it has a read replica. */
export const STATEMENT_TIMEOUT_MS = 10_000;

/** AWS RDS global CA bundle, shipped with the package (https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem). */
const RDS_CA_PATH = new URL('../../certs/global-bundle.pem', import.meta.url);

export type SslOptions = { rejectUnauthorized: true; ca?: string } | undefined;

/**
 * TLS is always verified. IAM/RDS targets pin the bundled RDS CA (the token and the
 * data travel over the public internet); other TLS targets use the system CAs, or
 * `sslCa` if set. Only `ssl: false` (local dev) turns TLS off.
 */
export function sslOptions(t: TargetConfig, rdsCaPem: string | undefined): SslOptions {
  if (t.ssl === false) return undefined;
  if (t.sslCa) return { rejectUnauthorized: true, ca: readFileSync(t.sslCa, 'utf8') };
  if (t.region && rdsCaPem) return { rejectUnauthorized: true, ca: rdsCaPem };
  return { rejectUnauthorized: true };
}

function rdsCa(): string | undefined {
  try {
    return readFileSync(RDS_CA_PATH, 'utf8');
  } catch {
    return undefined;
  }
}

let cached: { key: string; pool: pg.Pool; tokenAt: number } | null = null;

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
 */
export async function getPool(name: string, t: ResolvedTarget): Promise<pg.Pool> {
  const key = `${name}:${t.host}:${t.user}`;
  const stale = cached && (cached.key !== key || Date.now() - cached.tokenAt > TOKEN_TTL_MS);
  if (cached && stale) {
    await cached.pool.end().catch(() => {});
    cached = null;
  }
  if (!cached) {
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
      application_name: 'peephole',
      options:
        `-c default_transaction_read_only=on -c statement_timeout=${STATEMENT_TIMEOUT_MS} -c idle_in_transaction_session_timeout=30000 -c lock_timeout=1000`,
    });
    pool.on('error', () => {});
    cached = { key, pool, tokenAt: Date.now() };
  }
  return cached.pool;
}

export async function closePool(): Promise<void> {
  if (cached) {
    await cached.pool.end().catch(() => {});
    cached = null;
  }
}
