import { promises as fs } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { Lease, AuditEvent } from '../core/index.js';
import { formatAudit } from '../core/index.js';

/** Everything Daypass keeps on disk lives under ~/.daypass (override with DAYPASS_HOME). */
export const DAYPASS_HOME = process.env.DAYPASS_HOME ?? join(homedir(), '.daypass');
export const CONFIG_PATH = join(DAYPASS_HOME, 'config.json');
export const LEASE_PATH = join(DAYPASS_HOME, 'lease.json');
export const AUDIT_PATH = join(DAYPASS_HOME, 'audit.jsonl');

export interface TargetConfig {
  /** Shortcut for any Postgres: postgres://user:pass@host:5432/db. Fields below override it. */
  url?: string;
  host?: string;
  port?: number;
  database?: string;
  user?: string;
  /** AWS region of the RDS instance; enables IAM auth. Omit for password auth (local dev). */
  region?: string;
  /** Security group to punch the caller's IP into on `open`. Optional. */
  securityGroupId?: string;
  awsProfile?: string;
  /** Password auth for local/dev targets only. Never used when `region` is set. */
  password?: string;
  ssl?: boolean;
  /** Path to a CA bundle (PEM) for non-RDS TLS targets. RDS targets use the bundled AWS CA. */
  sslCa?: string;
  /** Schemas Claude may see. Default ['public']. */
  schemas?: string[];
  maxRows?: number;
  maxCell?: number;
  maxBytes?: number;
}

export interface Config {
  targets: Record<string, TargetConfig>;
}

export interface ResolvedTarget extends TargetConfig {
  host: string;
  port: number;
  database: string;
  user: string;
}

/** Merge `url` and explicit fields; fail loudly if the essentials are missing. */
export function resolveTarget(name: string, t: TargetConfig): ResolvedTarget {
  let fromUrl: Partial<ResolvedTarget> = {};
  if (t.url) {
    const u = new URL(t.url.replace(/^postgresql:/, 'postgres:'));
    fromUrl = {
      host: u.hostname,
      port: u.port ? Number(u.port) : undefined,
      database: u.pathname.replace(/^\//, ''),
      user: decodeURIComponent(u.username),
      password: u.password ? decodeURIComponent(u.password) : undefined,
      ssl: u.searchParams.get('sslmode') === 'disable' ? false : undefined,
    };
  }
  const r = { ...fromUrl, ...stripUndefined(t) } as ResolvedTarget;
  r.port = r.port ?? 5432;
  for (const k of ['host', 'database', 'user'] as const) {
    if (!r[k]) throw new Error(`Target "${name}" is missing "${k}" (set it or give a url)`);
  }
  if (!r.region && !r.password) throw new Error(`Target "${name}" needs either "region" (RDS IAM auth) or a password`);
  return r;
}

function stripUndefined<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

export async function readConfig(): Promise<Config> {
  try {
    return JSON.parse(await fs.readFile(CONFIG_PATH, 'utf8'));
  } catch (e: any) {
    if (e.code === 'ENOENT') throw new Error(`No config at ${CONFIG_PATH}. Run: daypass init`);
    throw e;
  }
}

export async function readLease(): Promise<Lease | null> {
  try {
    return JSON.parse(await fs.readFile(LEASE_PATH, 'utf8'));
  } catch (e: any) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

export async function writeLease(l: Lease): Promise<void> {
  await fs.mkdir(DAYPASS_HOME, { recursive: true, mode: 0o700 });
  await fs.writeFile(LEASE_PATH, JSON.stringify(l, null, 2), { mode: 0o600 });
}

export async function clearLease(): Promise<void> {
  await fs.rm(LEASE_PATH, { force: true });
}

export async function appendAudit(e: AuditEvent): Promise<void> {
  await fs.mkdir(DAYPASS_HOME, { recursive: true, mode: 0o700 });
  await fs.appendFile(AUDIT_PATH, formatAudit(e), { mode: 0o600 });
}

export async function readAudit(last: number): Promise<AuditEvent[]> {
  try {
    const text = await fs.readFile(AUDIT_PATH, 'utf8');
    return text
      .split('\n')
      .filter(Boolean)
      .slice(-last)
      .map((l) => JSON.parse(l));
  } catch (e: any) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
}
