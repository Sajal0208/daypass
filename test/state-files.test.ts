import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, symlinkSync, statSync, chmodSync, lstatSync, existsSync, linkSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const CLI = join(resolve(__dirname, '..'), 'dist', 'cli', 'main.js');
const root = mkdtempSync(join(tmpdir(), 'daypass-files-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));
const posix = process.platform !== 'win32';

let n = 0;
/** A fresh DAYPASS_HOME and a fresh copy of state.ts bound to it. */
async function fresh(setup?: (home: string) => void) {
  const home = join(root, `h${n++}`);
  mkdirSync(home, { mode: 0o700 });
  setup?.(home);
  process.env.DAYPASS_HOME = home;
  vi.resetModules();
  const state = await import('../src/mcp/state.js');
  return { home, state };
}
const lease = { id: 'aaaa1111', target: 't', reason: 'r', who: 'me', openedAt: '', expiresAt: '2999-01-01T00:00:00Z' };
const ev = { at: 'x', who: 'me', leaseId: null, target: 't', reason: null, tool: 'query', sql: 'select 1', allowed: true };

let stderr: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  stderr?.mockRestore();
  stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

describe.skipIf(!posix)('~/.daypass files: symlinks are refused', () => {
  it('lease.json symlink: read and write both refuse, the link target is untouched', async () => {
    const outside = join(root, 'victim-lease');
    writeFileSync(outside, JSON.stringify(lease));
    const { home, state } = await fresh((h) => symlinkSync(outside, join(h, 'lease.json')));
    await expect(state.readLeases()).rejects.toThrow(/symlink/);
    await expect(state.writeLease({ ...lease, id: 'bbbb2222' })).rejects.toThrow(/symlink/);
    expect(JSON.parse(readFileSync(outside, 'utf8')).id).toBe('aaaa1111');
    expect(lstatSync(join(home, 'lease.json')).isSymbolicLink()).toBe(true);
  });
  it('audit.jsonl symlink: append refuses and writes nothing through it', async () => {
    const outside = join(root, 'victim-audit');
    writeFileSync(outside, 'keep\n');
    const { state } = await fresh((h) => symlinkSync(outside, join(h, 'audit.jsonl')));
    await expect(state.appendAudit(ev)).rejects.toThrow(/symlink/);
    await expect(state.readAudit(5)).rejects.toThrow(/symlink/);
    expect(readFileSync(outside, 'utf8')).toBe('keep\n');
  });
  it('config.json symlink: read refuses', async () => {
    const outside = join(root, 'victim-config');
    writeFileSync(outside, '{"targets":{}}');
    const { state } = await fresh((h) => symlinkSync(outside, join(h, 'config.json')));
    await expect(state.readConfig()).rejects.toThrow(/symlink/);
  });
  it('a symlinked DAYPASS_HOME is refused', async () => {
    const real = join(root, 'real-home');
    mkdirSync(real, { mode: 0o700 });
    const link = join(root, 'link-home');
    symlinkSync(real, link);
    process.env.DAYPASS_HOME = link;
    vi.resetModules();
    const state = await import('../src/mcp/state.js');
    await expect(state.readLeases()).rejects.toThrow(/symlink/);
    await expect(state.appendAudit(ev)).rejects.toThrow(/symlink/);
    expect(existsSync(join(real, 'audit.jsonl'))).toBe(false);
  });
  it('a lease.json that is not a regular file is refused', async () => {
    const { state } = await fresh((h) => mkdirSync(join(h, 'lease.json')));
    await expect(state.readLeases()).rejects.toThrow(/not a regular file/);
  });
});

describe.skipIf(!posix)('~/.daypass files: loose modes are tightened on every use', () => {
  it('config 0644 and dir 0755 become 0600 and 0700, with a warning', async () => {
    const { home, state } = await fresh((h) => {
      writeFileSync(join(h, 'config.json'), '{"targets":{}}', { mode: 0o644 });
      chmodSync(join(h, 'config.json'), 0o644);
      chmodSync(h, 0o755);
    });
    await state.readConfig();
    expect(statSync(join(home, 'config.json')).mode & 0o777).toBe(0o600);
    expect(statSync(home).mode & 0o777).toBe(0o700);
    const warned = stderr.mock.calls.map((c) => String(c[0])).join('');
    expect(warned).toMatch(/config\.json.*0644.*0600/);
  });
  it('an existing audit.jsonl at 0666 is tightened on append', async () => {
    const { home, state } = await fresh((h) => {
      writeFileSync(join(h, 'audit.jsonl'), '');
      chmodSync(join(h, 'audit.jsonl'), 0o666);
    });
    await state.appendAudit(ev);
    expect(statSync(join(home, 'audit.jsonl')).mode & 0o777).toBe(0o600);
  });
  it('writeLease leaves a 0600 file even when one existed at 0644', async () => {
    const { home, state } = await fresh((h) => {
      writeFileSync(join(h, 'lease.json'), JSON.stringify(lease));
      chmodSync(join(h, 'lease.json'), 0o644);
    });
    await state.writeLease({ ...lease, id: 'cccc3333' });
    expect(statSync(join(home, 'lease.json')).mode & 0o777).toBe(0o600);
    expect((await state.readLeases())[0].id).toBe('cccc3333');
  });
  it('daypass init tightens an existing 0755 home', async () => {
    const home = join(root, 'init-home');
    mkdirSync(home, { mode: 0o755 });
    chmodSync(home, 0o755);
    await promisify(execFile)('node', [CLI, 'init'], { env: { ...process.env, DAYPASS_HOME: home } });
    expect(statSync(home).mode & 0o777).toBe(0o700);
    expect(statSync(join(home, 'config.json')).mode & 0o777).toBe(0o600);
  });
});

describe.skipIf(!posix)('~/.daypass files: hard links, FIFOs and the lease lock (re-review 2026-11-02)', () => {
  it('a state file with a second hard link is refused (read, write, append) and reported', async () => {
    const outside = join(root, 'hardlink-out');
    const { home, state } = await fresh((h) => {
      writeFileSync(join(h, 'config.json'), '{"targets":{}}', { mode: 0o600 });
      writeFileSync(join(h, 'audit.jsonl'), '', { mode: 0o600 });
    });
    linkSync(join(home, 'config.json'), outside);
    linkSync(join(home, 'audit.jsonl'), outside + '-audit');
    await expect(state.readConfig()).rejects.toThrow(/2 hard links/);
    await expect(state.appendAudit(ev)).rejects.toThrow(/2 hard links/);
    expect(readFileSync(outside + '-audit', 'utf8')).toBe('');
    const report = await state.inspectStateFiles();
    expect(report.find((f) => f.path.endsWith('config.json'))!.refused).toMatch(/2 hard links/);
  });
  it('a FIFO in place of a state file is refused at once, never waited on', async () => {
    const { home, state } = await fresh();
    await promisify(execFile)('mkfifo', [join(home, 'config.json')]);
    await promisify(execFile)('mkfifo', [join(home, 'audit.jsonl')]);
    const t0 = Date.now();
    await expect(state.readConfig()).rejects.toThrow(/not a regular file/);
    await expect(state.appendAudit(ev)).rejects.toThrow(/not a regular file/);
    expect(Date.now() - t0).toBeLessThan(2000);
  }, 10_000);
  it('concurrent conditional lease writes: exactly one wins', async () => {
    const { state } = await fresh();
    await state.writeLease(lease);
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) => state.writeLease({ ...lease, id: `new${i}` }, { ifId: lease.id })),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    const now = (await state.readLeases())[0] ?? null;
    expect(now!.id).toBe(`new${results.indexOf(true)}`);
  });
  it('a stale lock left by a crashed process is broken; a fresh one is waited for', async () => {
    const { home, state } = await fresh();
    const lock = join(home, '.lease.lock');
    writeFileSync(lock, 'crashed');
    const old = new Date(Date.now() - 60_000);
    utimesSync(lock, old, old);
    await expect(state.writeLease(lease)).resolves.toBe(true);
    expect(existsSync(lock)).toBe(false);
    writeFileSync(lock, 'busy');
    let done = false;
    const p = state.writeLease({ ...lease, id: 'later' }).then((r) => ((done = true), r));
    await new Promise((r) => setTimeout(r, 150));
    expect(done).toBe(false);
    rmSync(lock);
    await expect(p).resolves.toBe(true);
    expect((await state.readLeases())[0].id).toBe('later');
  });
});

describe('lease.json: one lease per target', () => {
  const file = (h: string) => JSON.parse(readFileSync(join(h, 'lease.json'), 'utf8'));
  it('reads a 0.2.0 single-lease file as one lease', async () => {
    const { state } = await fresh((h) => writeFileSync(join(h, 'lease.json'), JSON.stringify(lease), { mode: 0o600 }));
    expect((await state.readLeases()).map((l: any) => l.id)).toEqual(['aaaa1111']);
  });
  it('one lease is written in the 0.2.0 shape', async () => {
    const { home, state } = await fresh();
    await state.writeLease(lease);
    expect(file(home)).toMatchObject({ id: 'aaaa1111', target: 't' });
    expect(file(home).version).toBeUndefined();
  });
  it('a second target switches to v2 and keeps the first', async () => {
    const { home, state } = await fresh();
    await state.writeLease(lease);
    await state.writeLease({ ...lease, id: 'bbbb2222', target: 'u' });
    expect(file(home).version).toBe(2);
    expect((await state.readLeases()).map((l: any) => l.target).sort()).toEqual(['t', 'u']);
  });
  it('writeLease replaces the lease for the same target', async () => {
    const { state } = await fresh();
    await state.writeLease(lease);
    await state.writeLease({ ...lease, id: 'cccc3333' });
    expect((await state.readLeases()).map((l: any) => l.id)).toEqual(['cccc3333']);
  });
  it('ifId compares against the lease for that target only', async () => {
    const { state } = await fresh();
    await state.writeLease(lease);
    await state.writeLease({ ...lease, id: 'u1', target: 'u' });
    expect(await state.writeLease({ ...lease, id: 'x' }, { ifId: 'u1' })).toBe(false);
    expect(await state.writeLease({ ...lease, id: 'x' }, { ifId: 'aaaa1111' })).toBe(true);
    expect(await state.writeLease({ ...lease, id: 'v', target: 'v' }, { ifId: null })).toBe(true);
    expect(await state.writeLease({ ...lease, id: 'v2', target: 'v' }, { ifId: null })).toBe(false);
  });
  it('clearLease(target) removes one and goes back to the 0.2.0 shape; clearLease() removes all', async () => {
    const { home, state } = await fresh();
    await state.writeLease(lease);
    await state.writeLease({ ...lease, id: 'u1', target: 'u' });
    await state.clearLease('t');
    expect(file(home)).toMatchObject({ id: 'u1', target: 'u' });
    await state.writeLease(lease);
    await state.clearLease();
    expect(existsSync(join(home, 'lease.json'))).toBe(false);
  });
  it('clearLease(last target) removes the file', async () => {
    const { home, state } = await fresh();
    await state.writeLease(lease);
    await state.clearLease('t');
    expect(existsSync(join(home, 'lease.json'))).toBe(false);
  });
  it('a v2 file with a bad entry or a duplicate target is corrupt', async () => {
    for (const leases of [[{ id: 1 }], [lease, { ...lease, id: 'dup' }]]) {
      const { state } = await fresh((h) => writeFileSync(join(h, 'lease.json'), JSON.stringify({ version: 2, leases }), { mode: 0o600 }));
      await expect(state.readLeases()).rejects.toThrow(/corrupt/);
    }
  });
  it('two opens of the same target at once: exactly one wins', async () => {
    const { state } = await fresh();
    const rs = await Promise.all([1, 2, 3].map((i) => state.writeLease({ ...lease, id: `r${i}` }, { ifId: null })));
    expect(rs.filter(Boolean)).toHaveLength(1);
  });
  it('corrupt file: an unconditional write and clearLease(target) refuse; ifId returns false; clearLease() removes it', async () => {
    const { home, state } = await fresh((h) => writeFileSync(join(h, 'lease.json'), '{nope', { mode: 0o600 }));
    await expect(state.writeLease(lease)).rejects.toThrow(/corrupt/);
    await expect(state.clearLease('t')).rejects.toThrow(/corrupt/);
    expect(await state.writeLease(lease, { ifId: null })).toBe(false);
    expect(readFileSync(join(home, 'lease.json'), 'utf8')).toBe('{nope');
    await state.clearLease();
    expect(existsSync(join(home, 'lease.json'))).toBe(false);
  });
});

describe('lease.json: review fixes (PR #29)', () => {
  it('a v2 file with no leases is corrupt, not empty', async () => {
    const { state } = await fresh((h) => writeFileSync(join(h, 'lease.json'), JSON.stringify({ version: 2, leases: [] }), { mode: 0o600 }));
    await expect(state.readLeases()).rejects.toThrow(/corrupt/);
  });
  it('clearLease(target, { ifId }) removes the lease only while it still has that id', async () => {
    const { state } = await fresh();
    await state.writeLease(lease);
    expect(await state.clearLease('t', { ifId: 'other' })).toBe(false);
    expect((await state.readLeases()).map((l: any) => l.id)).toEqual(['aaaa1111']);
    expect(await state.clearLease('t', { ifId: 'aaaa1111' })).toBe(true);
    expect(await state.readLeases()).toEqual([]);
  });
  it('several processes breaking the same stale lock never lose a target', async () => {
    const STATE = join(resolve(__dirname, '..'), 'dist', 'mcp', 'state.js');
    const script = `const s = await import(${JSON.stringify(STATE)}); await s.writeLease({ id: 'id-' + process.argv[1], target: process.argv[1], reason: 'r', who: 'w', openedAt: '', expiresAt: '2999-01-01T00:00:00Z' });`;
    for (let round = 0; round < 8; round++) {
      const { home, state } = await fresh();
      const lock = join(home, '.lease.lock');
      writeFileSync(lock, 'crashed');
      const old = new Date(Date.now() - 60_000);
      utimesSync(lock, old, old);
      const names = ['t1', 't2', 't3', 't4', 't5', 't6'];
      await Promise.all(names.map((n) => promisify(execFile)('node', ['--input-type=module', '-e', script, n], { env: { ...process.env, DAYPASS_HOME: home } })));
      expect((await state.readLeases()).map((l: any) => l.target).sort(), `round ${round}`).toEqual(names);
    }
  }, 60_000);
});
