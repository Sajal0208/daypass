import { promises as fs, constants as fsc, type Stats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { Lease, AuditEvent } from '../core/index.js';
import { formatAudit } from '../core/index.js';

/** Everything Daypass keeps on disk lives under ~/.daypass (override with DAYPASS_HOME). */
export const DAYPASS_HOME = process.env.DAYPASS_HOME ?? join(homedir(), '.daypass');
export const CONFIG_PATH = join(DAYPASS_HOME, 'config.json');
export const LEASE_PATH = join(DAYPASS_HOME, 'lease.json');
export const AUDIT_PATH = join(DAYPASS_HOME, 'audit.jsonl');
/** The plugin's default hidden-columns list. Not read through this module; doctor checks it. */
export const HIDDEN_LIST_PATH = join(DAYPASS_HOME, 'hidden-columns.txt');

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

/**
 * The connection fields of a postgres:// or postgresql:// URL: an IPv6 literal host loses its
 * brackets, and the user, password and database are percent-decoded.
 */
export function parsePostgresUrl(url: string): {
  host: string;
  port?: number;
  database?: string;
  user?: string;
  password?: string;
  /** sslmode=disable in the URL. */
  sslDisabled: boolean;
} {
  const u = new URL(url.replace(/^postgresql:/, 'postgres:'));
  return {
    host: u.hostname.replace(/^\[(.*)\]$/, '$1'),
    port: u.port ? Number(u.port) : undefined,
    database: u.pathname.length > 1 ? decodeURIComponent(u.pathname.slice(1)) : undefined,
    user: u.username ? decodeURIComponent(u.username) : undefined,
    password: u.password ? decodeURIComponent(u.password) : undefined,
    sslDisabled: u.searchParams.get('sslmode') === 'disable',
  };
}

/** Merge `url` and explicit fields; fail loudly if the essentials are missing. */
export function resolveTarget(name: string, t: TargetConfig): ResolvedTarget {
  let fromUrl: Partial<ResolvedTarget> = {};
  if (t.url) {
    const u = parsePostgresUrl(t.url);
    fromUrl = {
      host: u.host,
      port: u.port,
      database: u.database,
      user: u.user,
      password: u.password,
      ssl: u.sslDisabled ? false : undefined,
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

/**
 * Every read and write of ~/.daypass goes through here. DAYPASS_HOME itself (its last path
 * component only: a symlink or another user's directory higher up the path is not checked) and the
 * files in it must not be symlinks and must belong to the current user; a file must be a regular
 * file with one link (a hard link elsewhere would be a second name for it); a looser mode than 0700
 * (directory) or 0600 (files) is tightened, with a one-line warning. Files are opened with
 * O_NOFOLLOW and O_NONBLOCK (a FIFO put in place of one cannot block the open) and checked on the
 * open descriptor, so a swap between check and use is not possible. On Windows (no uids, POSIX
 * modes or FIFOs) only the symlink, file-type and link-count checks apply.
 */
const POSIX = typeof process.getuid === 'function' && process.platform !== 'win32';
const O_NOFOLLOW = fsc.O_NOFOLLOW ?? 0;
const O_NONBLOCK = fsc.O_NONBLOCK ?? 0;

const octal = (m: number) => (m & 0o777).toString(8).padStart(4, '0');
function warnMode(path: string, was: number, now: number): void {
  process.stderr.write(`daypass: ${path} was mode ${octal(was)}; set it to ${octal(now)}\n`);
}

/**
 * Why DAYPASS_HOME (`dir`) or a file in it must not be used, from its lstat (or fstat): a symlink,
 * the wrong file type, or another owner. Null when it may be used; the mode is checked apart.
 */
function refusal(path: string, st: Stats, dir: boolean): string | null {
  if (st.isSymbolicLink()) return dir ? `${path} is a symlink; refusing to use it. Make it a real directory with mode 0700.` : symlinkError(path).message;
  if (dir && !st.isDirectory()) return `${path} is not a directory.`;
  if (!dir && !st.isFile()) return `${path} is not a regular file; refusing to use it.`;
  if (!dir && st.nlink > 1) {
    return `${path} has ${st.nlink} hard links; refusing to use it (another name for it could be read or written). Remove the other links (find ~ -samefile ${path}).`;
  }
  if (POSIX && st.uid !== process.getuid!()) return `${path} is owned by uid ${st.uid}, not by you (uid ${process.getuid!()}); refusing to use it.`;
  return null;
}

/**
 * Check (and with `create`, make) DAYPASS_HOME. Returns false when it does not exist and `create` is
 * off. Only DAYPASS_HOME itself is checked, not the directories above it.
 */
async function checkHome(create: boolean): Promise<boolean> {
  let st;
  try {
    st = await fs.lstat(DAYPASS_HOME);
  } catch (e: any) {
    if (e.code !== 'ENOENT') throw e;
    if (!create) return false;
    await fs.mkdir(DAYPASS_HOME, { recursive: true, mode: 0o700 });
    st = await fs.lstat(DAYPASS_HOME);
  }
  const no = refusal(DAYPASS_HOME, st, true);
  if (no) throw new Error(no);
  if (POSIX) {
    if (st.mode & 0o077) {
      await fs.chmod(DAYPASS_HOME, 0o700);
      warnMode(DAYPASS_HOME, st.mode, 0o700);
    }
  }
  return true;
}

function symlinkError(path: string): Error {
  return new Error(`${path} is a symlink; refusing to use it. Replace it with a regular file.`);
}

/** Refuse a symlink at `path` (no-op when it does not exist). */
async function refuseSymlink(path: string): Promise<void> {
  try {
    if ((await fs.lstat(path)).isSymbolicLink()) throw symlinkError(path);
  } catch (e: any) {
    if (e.code !== 'ENOENT') throw e;
  }
}

/** Ownership and mode checks on an open descriptor. */
async function checkOpenFile(fh: FileHandle, path: string): Promise<void> {
  const st = await fh.stat();
  const no = refusal(path, st, false);
  if (no) throw new Error(no);
  if (POSIX) {
    if (st.mode & 0o077) {
      await fh.chmod(0o600);
      warnMode(path, st.mode, 0o600);
    }
  }
}

/**
 * Open a file under DAYPASS_HOME after checking the directory, never following a symlink, and
 * check the descriptor. Returns null when the file (or, without O_CREAT, the directory) is missing.
 */
async function openSafe(path: string, flags: number): Promise<FileHandle | null> {
  const create = (flags & fsc.O_CREAT) !== 0;
  if (!(await checkHome(create))) return null;
  if (!O_NOFOLLOW) await refuseSymlink(path);
  let fh: FileHandle;
  try {
    fh = await fs.open(path, flags | O_NOFOLLOW | O_NONBLOCK, 0o600);
  } catch (e: any) {
    if (e.code === 'ENOENT') return null;
    if (e.code === 'ELOOP' || e.code === 'EMLINK') throw symlinkError(path);
    // EISDIR: a directory; ENXIO: a FIFO with no reader opened for writing (O_NONBLOCK).
    if (e.code === 'EISDIR' || e.code === 'ENXIO') throw new Error(`${path} is not a regular file; refusing to use it.`);
    throw e;
  }
  try {
    await checkOpenFile(fh, path);
  } catch (e) {
    await fh.close().catch(() => {});
    throw e;
  }
  return fh;
}

/** DAYPASS_HOME or one file in it, as every read and write would judge it (see inspectStateFiles). */
export interface StateFileStatus {
  path: string;
  /** Why daypass refuses to use it (symlink, wrong type, another owner); absent when usable. */
  refused?: string;
  /** Permission bits (POSIX only). */
  mode?: number;
  /** The mode daypass sets: 0700 for the directory, 0600 for a file. */
  want: number;
}

/**
 * DAYPASS_HOME and those of config.json, lease.json, audit.jsonl and hidden-columns.txt that exist,
 * judged by the same rules as every read and write here, without opening or changing anything
 * (for doctor). Empty when DAYPASS_HOME does not exist. Files are not inspected under a refused
 * directory. On Windows only the symlink and file-type checks apply and `mode` is absent.
 */
export async function inspectStateFiles(): Promise<StateFileStatus[]> {
  const out: StateFileStatus[] = [];
  for (const [path, dir] of [[DAYPASS_HOME, true], [CONFIG_PATH, false], [LEASE_PATH, false], [AUDIT_PATH, false], [HIDDEN_LIST_PATH, false]] as const) {
    let st: Stats;
    try {
      st = await fs.lstat(path);
    } catch (e: any) {
      if (e.code === 'ENOENT') {
        if (dir) return out;
        continue;
      }
      throw e;
    }
    const refused = refusal(path, st, dir);
    out.push({ path, ...(refused ? { refused } : {}), ...(POSIX ? { mode: st.mode & 0o777 } : {}), want: dir ? 0o700 : 0o600 });
    if (dir && refused) return out;
  }
  return out;
}

async function readSafe(path: string): Promise<string | null> {
  const fh = await openSafe(path, fsc.O_RDONLY);
  if (!fh) return null;
  try {
    return await fh.readFile('utf8');
  } finally {
    await fh.close();
  }
}

export async function readConfig(): Promise<Config> {
  const text = await readSafe(CONFIG_PATH);
  if (text === null) throw new Error(`No config at ${CONFIG_PATH}. Run: daypass init`);
  try {
    return JSON.parse(text);
  } catch (e: any) {
    throw new Error(`The config ${CONFIG_PATH} is not valid JSON (${e.message}).`);
  }
}

/**
 * Write a starter config only if none exists (O_EXCL: never through a symlink or over a file).
 * Returns false when a config is already there.
 */
export async function writeConfigIfMissing(text: string): Promise<boolean> {
  await checkHome(true);
  let fh: FileHandle;
  try {
    fh = await fs.open(CONFIG_PATH, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | O_NOFOLLOW, 0o600);
  } catch (e: any) {
    if (e.code === 'EEXIST') return false;
    throw e;
  }
  try {
    await fh.writeFile(text);
  } finally {
    await fh.close();
  }
  return true;
}

/** Thrown by readLeases when lease.json exists but holds no valid leases. */
export class LeaseCorruptError extends Error {
  readonly code = 'ELEASECORRUPT';
}
const corrupt = () => new LeaseCorruptError(`The lease file ${LEASE_PATH} is corrupt. Run: daypass close`);

function parseLease(l: any): Lease {
  if (!l || typeof l !== 'object' || typeof l.id !== 'string' || typeof l.target !== 'string' || typeof l.expiresAt !== 'string') throw corrupt();
  return l as Lease;
}

/**
 * Every lease on disk, at most one per target. A file with one lease is the 0.2.0 shape (a bare
 * lease); two or more are `{ version: 2, leases }`. Missing file: [].
 */
export async function readLeases(): Promise<Lease[]> {
  const text = await readSafe(LEASE_PATH);
  if (text === null) return [];
  let v: any;
  try {
    v = JSON.parse(text);
  } catch {
    throw corrupt();
  }
  const leases: Lease[] = v?.version === 2 && Array.isArray(v.leases) ? v.leases.map(parseLease) : [parseLease(v)];
  // An empty file is removed, never written as an empty list: one that says so was not written by daypass.
  if (leases.length === 0) throw corrupt();
  if (new Set(leases.map((l) => l.target)).size !== leases.length) throw corrupt();
  return leases;
}

/** Serialises every change of lease.json (writeLease, clearLease) across processes. */
const LEASE_LOCK = join(DAYPASS_HOME, '.lease.lock');
/** Held for the instant it takes to remove a stale lease lock, so only one waiter removes it. */
const BREAK_LOCK = join(DAYPASS_HOME, '.lease.lock.break');
/** A lock older than this was left by a process that died holding it; the critical section takes milliseconds. */
const LOCK_STALE_MS = 5_000;
const LOCK_WAIT_MS = 10_000;

const isStale = (st: Stats | null) => !!st && Date.now() - st.mtimeMs > LOCK_STALE_MS;

/**
 * Remove the lease lock if it is stale, and say whether it did. Only the waiter holding
 * BREAK_LOCK may remove it, and only after looking at the lock again: otherwise a waiter that
 * saw the old lock could remove the fresh one another waiter has just taken, and two writers
 * would then run at once and lose a target's lease. A BREAK_LOCK left by a dead process is
 * itself removed once stale.
 */
async function breakStaleLock(): Promise<boolean> {
  if (!isStale(await fs.lstat(LEASE_LOCK).catch(() => null))) return false;
  try {
    await (await fs.open(BREAK_LOCK, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | O_NOFOLLOW, 0o600)).close();
  } catch (e: any) {
    if (e.code !== 'EEXIST') throw e;
    if (isStale(await fs.lstat(BREAK_LOCK).catch(() => null))) await fs.rm(BREAK_LOCK, { force: true });
    return false;
  }
  try {
    if (!isStale(await fs.lstat(LEASE_LOCK).catch(() => null))) return false;
    await fs.rm(LEASE_LOCK, { force: true });
    return true;
  } finally {
    await fs.rm(BREAK_LOCK, { force: true }).catch(() => {});
  }
}

/**
 * Run `fn` holding the lease lock: an O_EXCL lockfile in DAYPASS_HOME that holds a random token.
 * A lock older than LOCK_STALE_MS was left by a dead process and is removed by one waiter only
 * (breakStaleLock). On the way out the lock is removed only if it still holds this call's
 * token, so a holder that ran past LOCK_STALE_MS (a laptop that slept) cannot remove the lock
 * of the waiter that took over from it. Gives up after LOCK_WAIT_MS.
 */
async function withLeaseLock<T>(fn: () => Promise<T>): Promise<T> {
  const token = randomBytes(8).toString('hex');
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fh = await fs.open(LEASE_LOCK, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | O_NOFOLLOW, 0o600);
      try {
        await fh.writeFile(token);
      } finally {
        await fh.close();
      }
      break;
    } catch (e: any) {
      if (e.code !== 'EEXIST') throw e;
    }
    if (await breakStaleLock()) continue;
    if (Date.now() > deadline) {
      throw new Error(`${LEASE_LOCK} is held by another daypass process; if none is running, remove it.`);
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  try {
    return await fn();
  } finally {
    const now = await fs.readFile(LEASE_LOCK, 'utf8').catch(() => null);
    if (now === token) await fs.rm(LEASE_LOCK, { force: true }).catch(() => {});
  }
}

/**
 * Replace lease.json with `leases` atomically (temp file in the same directory, fsync, rename),
 * or remove it when empty. One lease keeps the 0.2.0 shape so an older daypass can still read it.
 * Call only while holding the lease lock.
 */
async function writeLeaseFile(leases: Lease[]): Promise<void> {
  if (leases.length === 0) {
    await fs.rm(LEASE_PATH, { force: true });
    return;
  }
  await refuseSymlink(LEASE_PATH);
  const body = leases.length === 1 ? leases[0] : { version: 2, leases };
  const tmp = join(DAYPASS_HOME, `.lease.${randomBytes(6).toString('hex')}.tmp`);
  try {
    const fh = await fs.open(tmp, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | O_NOFOLLOW, 0o600);
    try {
      await fh.writeFile(JSON.stringify(body, null, 2));
      await fh.sync();
    } finally {
      await fh.close();
    }
    await fs.rename(tmp, LEASE_PATH);
    await syncDir();
  } finally {
    await fs.rm(tmp, { force: true }).catch(() => {});
  }
}

/** Make a rename in DAYPASS_HOME durable. Best effort: some platforms cannot fsync a directory. */
async function syncDir(): Promise<void> {
  const dh = await fs.open(DAYPASS_HOME, fsc.O_RDONLY).catch(() => null);
  if (!dh) return;
  try {
    await dh.sync();
  } catch {
    /* not supported here */
  } finally {
    await dh.close();
  }
}

/**
 * Put `l` in lease.json, replacing the lease for the same target and keeping the others. The
 * read, the check and the write all run under the lease lock. With `ifId`, it writes only if
 * the lease on disk for `l.target` still has that id (null: only if that target has none), so
 * cleanup of an old lease cannot overwrite one opened meanwhile; a corrupt file then returns
 * false. Without `ifId`, a corrupt file throws LeaseCorruptError: overwriting it would drop the
 * other targets' leases and the security-group rules they record. Returns whether it wrote.
 */
export async function writeLease(l: Lease, opts: { ifId?: string | null } = {}): Promise<boolean> {
  await checkHome(true);
  await refuseSymlink(LEASE_PATH);
  return withLeaseLock(async () => {
    let leases: Lease[];
    try {
      leases = await readLeases();
    } catch (e) {
      if (opts.ifId !== undefined && e instanceof LeaseCorruptError) return false;
      throw e;
    }
    const i = leases.findIndex((x) => x.target === l.target);
    if (opts.ifId !== undefined && (i < 0 ? null : leases[i].id) !== opts.ifId) return false;
    if (i < 0) leases.push(l);
    else leases[i] = l;
    await writeLeaseFile(leases);
    return true;
  });
}

/**
 * Remove the lease for `target`, or every lease (the whole file, even a corrupt one) without one.
 * With `ifId`, the target's lease is removed only if it still has that id, so a lease opened
 * since the caller looked is kept. Returns whether it removed anything.
 */
export async function clearLease(target?: string, opts: { ifId?: string } = {}): Promise<boolean> {
  if (!(await checkHome(false))) return false;
  return withLeaseLock(async () => {
    if (target === undefined) {
      await fs.rm(LEASE_PATH, { force: true });
      return true;
    }
    const leases = await readLeases();
    const mine = leases.find((x) => x.target === target);
    if (!mine || (opts.ifId !== undefined && mine.id !== opts.ifId)) return false;
    await writeLeaseFile(leases.filter((x) => x !== mine));
    return true;
  });
}

/**
 * One line per event, written with a single write() on an O_APPEND descriptor (formatAudit caps
 * a line far below 64 KiB), so concurrent servers cannot interleave inside a line. If the file
 * does not end with a newline (a torn earlier write), the line starts on a fresh one.
 */
export async function appendAudit(e: AuditEvent): Promise<void> {
  const fh = (await openSafe(AUDIT_PATH, fsc.O_RDWR | fsc.O_APPEND | fsc.O_CREAT))!;
  try {
    let buf = Buffer.from(formatAudit(e), 'utf8');
    const { size } = await fh.stat();
    if (size > 0) {
      const last = Buffer.alloc(1);
      await fh.read(last, 0, 1, size - 1);
      if (last[0] !== 0x0a) buf = Buffer.concat([Buffer.from('\n'), buf]);
    }
    let off = 0;
    while (off < buf.length) off += (await fh.write(buf, off)).bytesWritten;
  } finally {
    await fh.close();
  }
}

/** The last `last` readable audit events (all if `last` is 0), and how many lines in the file could not be parsed. */
export async function readAuditDetailed(last: number): Promise<{ events: AuditEvent[]; corrupt: number }> {
  const text = await readSafe(AUDIT_PATH);
  if (text === null) return { events: [], corrupt: 0 };
  const events: AuditEvent[] = [];
  let corrupt = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      const v = JSON.parse(line);
      if (v && typeof v === 'object' && !Array.isArray(v)) events.push(v);
      else corrupt++;
    } catch {
      corrupt++;
    }
  }
  return { events: last > 0 ? events.slice(-last) : events, corrupt };
}

export async function readAudit(last: number): Promise<AuditEvent[]> {
  return (await readAuditDetailed(last)).events;
}
