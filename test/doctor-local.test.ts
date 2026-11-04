import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync, chmodSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = mkdtempSync(join(tmpdir(), 'daypass-doctor-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));
const posix = process.platform !== 'win32';
const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;

// A target whose checks fail fast and locally: port 1 refuses, no lease is open.
const local = { targets: { t: { url: 'postgres://u:p@127.0.0.1:1/db?sslmode=disable' } } };

let n = 0;
/** Run doctor against a fresh DAYPASS_HOME (or the given path) and a fresh module graph. */
async function run(setup?: (home: string) => void, opts: { home?: string; target?: string } = {}) {
  const home = opts.home ?? join(root, `h${n++}`);
  if (!opts.home) {
    mkdirSync(home, { mode: 0o700 });
    setup?.(home);
  }
  process.env.DAYPASS_HOME = home;
  vi.resetModules();
  const { doctor } = await import('../src/cli/doctor.js');
  const checks = await doctor(opts.target);
  return { home, checks, get: (name: string) => checks.find((c) => c.name === name) };
}
const cfg = (h: string, c: object = local) => writeFileSync(join(h, 'config.json'), JSON.stringify(c), { mode: 0o600 });

let stderr: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  stderr?.mockRestore();
  stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

describe('doctor: files', () => {
  it('passes for a 0700 home and 0600 files', async () => {
    const { get } = await run((h) => cfg(h));
    expect(get('files')).toMatchObject({ ok: true });
    expect(get('files')!.detail).not.toMatch(/warning/);
  });
  it.skipIf(!posix)('fails for a symlinked config.json and lease.json, without throwing', async () => {
    const outside = join(root, 'victim-config');
    writeFileSync(outside, JSON.stringify(local));
    const lease = join(root, 'victim-lease');
    writeFileSync(lease, '{}');
    const { get } = await run((h) => {
      symlinkSync(outside, join(h, 'config.json'));
      symlinkSync(lease, join(h, 'lease.json'));
    });
    expect(get('files')).toMatchObject({ ok: false });
    expect(get('files')!.detail).toMatch(/config\.json is a symlink/);
    expect(get('files')!.detail).toMatch(/lease\.json is a symlink/);
    expect(get('config')).toMatchObject({ ok: false });
  });
  it.skipIf(!posix)('a symlinked lease.json fails the lease line instead of throwing', async () => {
    const lease = join(root, 'victim-lease2');
    writeFileSync(lease, '{}');
    const { get } = await run((h) => {
      cfg(h);
      symlinkSync(lease, join(h, 'lease.json'));
    });
    expect(get('lease')).toMatchObject({ ok: false });
    expect(get('lease')!.detail).toMatch(/symlink/);
  });
  it.skipIf(!posix || asRoot)('fails for a home owned by another uid', async () => {
    const { get } = await run(undefined, { home: '/usr' });
    expect(get('files')).toMatchObject({ ok: false });
    expect(get('files')!.detail).toMatch(/owned by uid 0/);
  });
  it.skipIf(!posix)('warns for files readable by others, before daypass tightens them', async () => {
    const { get, home } = await run((h) => {
      cfg(h);
      chmodSync(join(h, 'config.json'), 0o644);
      chmodSync(h, 0o750);
    });
    expect(get('files')).toMatchObject({ ok: true });
    expect(get('files')!.detail).toMatch(/^warning: /);
    expect(get('files')!.detail).toMatch(/config\.json 0644 \(want 0600\)/);
    expect(get('files')!.detail).toMatch(/0750 \(want 0700\)/);
    // the config read that follows tightens them, as every daypass read does
    expect(statSync(join(home, 'config.json')).mode & 0o777).toBe(0o600);
  });
  it.skipIf(!posix)('fails for a file other users can write (the hidden list is never tightened by daypass)', async () => {
    const { get } = await run((h) => {
      cfg(h);
      writeFileSync(join(h, 'hidden-columns.txt'), 'users.email\n');
      chmodSync(join(h, 'hidden-columns.txt'), 0o666);
      chmodSync(join(h, 'config.json'), 0o644);
    });
    expect(get('files')!.detail).toMatch(/readable by other users: .*config\.json 0644 \(want 0600\)/);
    expect(get('files')).toMatchObject({ ok: false });
    expect(get('files')!.detail).toMatch(/writable by other users: .*hidden-columns\.txt 0666 \(want 0600\)/);
    expect(get('files')!.detail).toMatch(/chmod 600/);
  });
  it('says so when DAYPASS_HOME does not exist yet', async () => {
    const { get } = await run(undefined, { home: join(root, 'nope') });
    expect(get('files')).toMatchObject({ ok: true });
    expect(get('files')!.detail).toMatch(/does not exist yet/);
  });
});

describe('doctor: audit log', () => {
  const good = JSON.stringify({ at: 'x', who: 'me', leaseId: null, target: 't', reason: null, tool: 'query', sql: 'select 1', allowed: true });
  it('warns with the count of unreadable lines', async () => {
    const { get } = await run((h) => {
      cfg(h);
      writeFileSync(join(h, 'audit.jsonl'), `${good}\n{"torn\n42\n${good}\n`, { mode: 0o600 });
    });
    expect(get('audit log')).toMatchObject({ ok: true });
    expect(get('audit log')!.detail).toMatch(/^warning: 2 unreadable line\(s\)/);
  });
  it('is quiet about a clean log', async () => {
    const { get } = await run((h) => {
      cfg(h);
      writeFileSync(join(h, 'audit.jsonl'), `${good}\n`, { mode: 0o600 });
    });
    expect(get('audit log')).toMatchObject({ ok: true, detail: expect.stringMatching(/1 event\(s\), all readable/) });
  });
});

describe('doctor: tls', () => {
  it('a region target with ssl: false is a failed tls line with the fix', async () => {
    const saved = { ...process.env };
    // The aws credentials line must fail locally: nothing may reach AWS.
    Object.assign(process.env, {
      AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE', AWS_SECRET_ACCESS_KEY: 'test', AWS_CONFIG_FILE: '/nonexistent',
      AWS_SHARED_CREDENTIALS_FILE: '/nonexistent', AWS_EC2_METADATA_DISABLED: 'true', AWS_ENDPOINT_URL_STS: 'http://127.0.0.1:1',
    });
    try {
      const { get } = await run((h) => cfg(h, { targets: { t: { host: '127.0.0.1', port: 1, database: 'db', user: 'u', region: 'us-east-1', ssl: false } } }));
      expect(get('tls')).toEqual({ name: 'tls', ok: false, detail: expect.stringMatching(/TLS cannot be turned off .*remove ssl: false/) });
      expect(get('tls')!.detail).not.toMatch(/\n\s+at /);
    } finally {
      process.env = saved;
    }
  });
  it('an unreadable sslCa is a failed tls line', async () => {
    const { get } = await run((h) => cfg(h, { targets: { t: { url: 'postgres://u:p@127.0.0.1:1/db', sslCa: join(root, 'missing.pem') } } }));
    expect(get('tls')).toMatchObject({ ok: false, detail: expect.stringMatching(/sslCa .*missing\.pem/) });
  });
  it('reports TLS off for a local target', async () => {
    const { get } = await run((h) => cfg(h));
    expect(get('tls')).toMatchObject({ ok: true, detail: expect.stringMatching(/off/) });
  });
  it('reports verification for a TLS target', async () => {
    const { get } = await run((h) => cfg(h, { targets: { t: { url: 'postgres://u:p@127.0.0.1:1/db' } } }));
    expect(get('tls')).toMatchObject({ ok: true, detail: expect.stringMatching(/verified/) });
  });
});

describe('doctor: escaping', () => {
  it('escapes control characters in every detail (names come from the config and the database)', async () => {
    const { get } = await run((h) => cfg(h, { targets: { 'x\x1b[2Jy': local.targets.t } }));
    expect(get('config')!.detail).toContain('x\\x1b[2Jy');
    expect(get('config')!.detail).not.toContain('\x1b');
  });
});

describe('doctor: several leases', () => {
  const two = { targets: { a: { url: 'postgres://u:p@127.0.0.1:1/a?sslmode=disable' }, b: { url: 'postgres://u:p@127.0.0.1:1/b?sslmode=disable' } } };
  const until = new Date(Date.now() + 3600e3).toISOString();
  const l = (id: string, target: string) => ({ id, target, reason: 'r', who: 'me', openedAt: '', expiresAt: until });
  const setup = (h: string) => {
    cfg(h, two);
    writeFileSync(join(h, 'lease.json'), JSON.stringify({ version: 2, leases: [l('aaaa1111', 'a'), l('bbbb2222', 'b')] }), { mode: 0o600 });
  };
  it('doctor b checks the lease on b', async () => {
    const { get } = await run(setup, { target: 'b' });
    expect(get('lease')).toMatchObject({ ok: true });
    expect(get('lease')!.detail).toContain('bbbb2222');
  });
  it('doctor with no target checks the first config target and its lease', async () => {
    const { get } = await run(setup);
    expect(get('target')!.detail).toMatch(/^a: /);
    expect(get('lease')).toMatchObject({ ok: true });
    expect(get('lease')!.detail).toContain('aaaa1111');
  });
});

describe('doctor: several leases, no target (review fix, PR #29)', () => {
  it('checks the first config target that has a live lease, not one with none', async () => {
    const three = { targets: {
      a: { url: 'postgres://u:p@127.0.0.1:1/a?sslmode=disable' },
      b: { url: 'postgres://u:p@127.0.0.1:1/b?sslmode=disable' },
      c: { url: 'postgres://u:p@127.0.0.1:1/c?sslmode=disable' },
    } };
    const until = new Date(Date.now() + 3600e3).toISOString();
    const l = (id: string, target: string) => ({ id, target, reason: 'r', who: 'me', openedAt: '', expiresAt: until });
    const { get } = await run((h) => {
      cfg(h, three);
      writeFileSync(join(h, 'lease.json'), JSON.stringify({ version: 2, leases: [l('cccc3333', 'c'), l('bbbb2222', 'b')] }), { mode: 0o600 });
    });
    expect(get('target')!.detail).toMatch(/^b: /);
    expect(get('lease')).toMatchObject({ ok: true });
    expect(get('lease')!.detail).toContain('bbbb2222');
  });
});
