import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(new URL('../scripts/scrub-check.sh', import.meta.url));
// Assembled from pieces so that this file never contains a string the scanner would flag.
const FAKE_SG = ['sg', '0abcdef1234567890'].join('-');

let dir: string;

function git(...args: string[]): string {
  const r = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...args], {
    cwd: dir,
    encoding: 'utf8',
  });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout.trim();
}
function write(rel: string, content: string) {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}
function commit(message: string): string {
  git('add', '-A');
  git('commit', '-q', '-m', message);
  return git('rev-parse', 'HEAD');
}
function scrub(env: Record<string, string> = {}) {
  const r = spawnSync('bash', ['scripts/scrub-check.sh'], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, SCRUB_HISTORY: '', SCRUB_HISTORY_RANGE: '', SCRUB_EXTRA_PATTERNS: '', ...env },
  });
  return { status: r.status, out: r.stdout + r.stderr };
}

describe.skipIf(process.platform === 'win32')('scripts/scrub-check.sh', () => {
  beforeEach(() => {
    // Each fixture is a fresh repo holding a copy of the script (it scans the repo it lives in),
    // so every case also proves the script does not match its own source.
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scrub-'));
    git('init', '-q');
    git('checkout', '-q', '-b', 'main');
    fs.mkdirSync(path.join(dir, 'scripts'));
    fs.copyFileSync(SCRIPT, path.join(dir, 'scripts/scrub-check.sh'));
    write('README.md', '# fixture\n');
    commit('init');
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('clean repo passes', () => {
    const r = scrub();
    expect(r.status).toBe(0);
    expect(r.out).toContain('scrub: clean');
  });

  it('flags a tracked file and names it', () => {
    write('config.json', `{ "securityGroupId": "${FAKE_SG}" }\n`);
    commit('add config');
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('config.json');
  });

  it('flags an untracked file', () => {
    write('notes.txt', `group ${FAKE_SG}\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('notes.txt');
  });

  it('never reads gitignored files', () => {
    write('.gitignore', '.env\n');
    commit('ignore env');
    write('.env', `SG=${FAKE_SG}\n`);
    const r = scrub();
    expect(r.status).toBe(0);
    expect(r.out).not.toContain(FAKE_SG);
  });

  it('refuses to run with an invalid extra pattern', () => {
    const file = path.join(dir, 'patterns.txt');
    fs.writeFileSync(file, '(\n');
    const r = scrub({ SCRUB_EXTRA_PATTERNS: file });
    expect(r.status).toBe(2);
    expect(r.out).toMatch(/invalid pattern/);
  });

  it('SCRUB_HISTORY=1 finds an id that was added and later removed', () => {
    write('leak.txt', `${FAKE_SG}\n`);
    const added = commit('add id');
    fs.rmSync(path.join(dir, 'leak.txt'));
    const removed = commit('remove id');
    expect(scrub().status).toBe(0);
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain(added);
    expect(r.out).not.toContain(removed);
  });

  it('SCRUB_HISTORY_RANGE ignores ids that only exist in the base history', () => {
    write('leak.txt', `${FAKE_SG}\n`);
    commit('add id');
    fs.rmSync(path.join(dir, 'leak.txt'));
    commit('remove id');
    git('checkout', '-q', '-b', 'feature');
    write('feature.txt', 'nothing to see\n');
    commit('feature work');
    const r = scrub({ SCRUB_HISTORY_RANGE: 'main..feature' });
    expect(r.status).toBe(0);
    expect(r.out).toContain('scrub: history (main..feature)');
  });

  it('SCRUB_HISTORY=1 finds an id that only appears in a commit message', () => {
    write('clean.txt', 'nothing here\n');
    const sha = commit(`opened ${FAKE_SG} for the lease`);
    expect(scrub().status).toBe(0);
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain(sha);
  });

  it('SCRUB_HISTORY=1 reports a binary file under its commit', () => {
    fs.writeFileSync(path.join(dir, 'leak.png'), Buffer.concat([Buffer.from('\x89PNG\r\n\x1a\n\x00\x00', 'binary'), Buffer.from(FAKE_SG)]));
    const added = commit('add image');
    fs.rmSync(path.join(dir, 'leak.png'));
    commit('remove image');
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain(`commit ${added}`);
    expect(r.out).not.toMatch(/Binary file .* matches/);
  });

  it('accepts an ARN with the documented placeholder account', () => {
    write('policy.json', '{ "Resource": "arn:aws:iam::123456789012:role/peephole" }\n');
    commit('add policy');
    expect(scrub().status).toBe(0);
  });
});
