import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { resolveTarget, parsePostgresUrl } from '../src/mcp/state.js';

const ROOT = resolve(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli', 'main.js');
const live = process.env.DAYPASS_TEST_PG_URL;

/** Run the CLI with optional stdin text and extra env. */
function run(args: string[], o: { stdin?: string; env?: Record<string, string> } = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((res) => {
    const c = spawn('node', [CLI, ...args], { cwd: ROOT, env: { ...process.env, ...o.env } });
    let stdout = '';
    let stderr = '';
    c.stdout.on('data', (d) => (stdout += d));
    c.stderr.on('data', (d) => (stderr += d));
    c.on('close', (code) => res({ code, stdout, stderr }));
    c.stdin.end(o.stdin ?? '');
  });
}

describe('postgres URL parsing', () => {
  it('strips the brackets of an IPv6 literal host', () => {
    expect(resolveTarget('x', { url: 'postgres://u:p@[::1]:5433/db' })).toMatchObject({ host: '::1', port: 5433, database: 'db' });
    expect(parsePostgresUrl('postgresql://u@[::1]/db').host).toBe('::1');
  });
  it('percent-decodes the database name', () => {
    expect(resolveTarget('x', { url: 'postgres://u:p@h/my%20db' }).database).toBe('my db');
    expect(parsePostgresUrl('postgres://u@h/caf%C3%A9').database).toBe('café');
  });
});

describe('daypass hidden: where the owner URL comes from', () => {
  // Port 1 refuses connections: the error proves which URL was used, without a database.
  const dead = 'postgres://owner:s3cret@127.0.0.1:1/db?sslmode=disable';
  it('--url with a password still works but warns about argv', async () => {
    const r = await run(['hidden', 'suggest', '--url', dead]);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/warning: .*password.*--url/i);
    expect(r.stderr).toMatch(/ECONNREFUSED|127\.0\.0\.1:1/);
  });
  it('--url - reads the URL from stdin, with no warning', async () => {
    const r = await run(['hidden', 'suggest', '--url', '-'], { stdin: dead + '\n' });
    expect(r.code).toBe(1);
    expect(r.stderr).not.toMatch(/warning/i);
    expect(r.stderr).toMatch(/ECONNREFUSED|127\.0\.0\.1:1/);
  });
  it('--url - with nothing on stdin is a clear error', async () => {
    const r = await run(['hidden', 'suggest', '--url', '-'], { stdin: '' });
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/no URL on stdin/i);
  });
  it('--url-env reads DAYPASS_OWNER_URL by default, or the named variable', async () => {
    const a = await run(['hidden', 'suggest', '--url-env'], { env: { DAYPASS_OWNER_URL: dead } });
    expect(a.code).toBe(1);
    expect(a.stderr).not.toMatch(/warning/i);
    expect(a.stderr).toMatch(/ECONNREFUSED|127\.0\.0\.1:1/);
    const b = await run(['hidden', 'suggest', '--url-env', 'MY_OWNER'], { env: { MY_OWNER: dead } });
    expect(b.stderr).toMatch(/ECONNREFUSED|127\.0\.0\.1:1/);
    const c = await run(['hidden', 'suggest', '--url-env', 'UNSET_VAR_X']);
    expect(c.code).toBe(1);
    expect(c.stderr).toMatch(/UNSET_VAR_X is not set/);
  });
  it('refuses sslmode=disable for an RDS host before connecting', async () => {
    const r = await run(['hidden', 'suggest', '--url', '-'], { stdin: 'postgres://o@x.abc123.us-east-1.rds.amazonaws.com/db?sslmode=disable' });
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/TLS/);
  });
  it.skipIf(!live)('--url - against a live database', async () => {
    const r = await run(['hidden', 'suggest', '--url', '-'], { stdin: live! });
    expect(r.code, r.stderr).toBe(0);
    expect(r.stderr).toMatch(/columns flagged/);
  });
});

describe('daypass log -n', () => {
  let home: string;
  beforeAll(() => {
    home = mkdtempSync(join(tmpdir(), 'daypass-logn-'));
    writeFileSync(join(home, 'audit.jsonl'), '', { mode: 0o600 });
  });
  afterAll(() => rmSync(home, { recursive: true, force: true }));
  it.each(['0', 'abc', '-3', '1.5', ''])('rejects %j', async (n) => {
    const r = await promisify(execFile)('node', [CLI, 'log', '-n', n], { env: { ...process.env, DAYPASS_HOME: home } }).then(
      () => ({ code: 0, stderr: '' }),
      (e) => ({ code: e.code, stderr: e.stderr as string }),
    );
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/positive integer/);
  });
});
