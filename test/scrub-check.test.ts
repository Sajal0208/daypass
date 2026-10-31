import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(new URL('../scripts/scrub-check.sh', import.meta.url));
// Assembled from pieces so that this file never contains a string the scanner would flag.
const FAKE_SG = ['sg', '0abcdef1234567890'].join('-');
const FAKE_AKIA = ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('');
const FAKE_ASIA = ['AS', 'IA', 'QRSTUVWXYZ234567'].join('');
const FAKE_ARN_CN = ['arn:aws-cn:iam:', ':210987654321:role/x'].join('');
const FAKE_ARN = ['arn:aws:iam:', ':210987654321:role/y'].join('');
const FAKE_PG_URL = ['postgres:/', '/app:s3cret@db.prod.internal:5432/app'].join('');
const FAKE_PG_IP_URL = ['postgresql:/', '/app:s3cret@10.20.30.40/app'].join('');
const FAKE_RDS_CN = ['mydb.cluster-ro-abcdefghijkl.cn-north-1.rds', 'amazonaws.com.cn'].join('.');
const FAKE_RDS_SHORT = ['mydb.xyz.eu-west-1.rds', 'amazonaws.com'].join('.');
// AWS's own documentation examples, which tests and docs use freely.
const DOC_AKIA = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const DOC_SG = ['sg', '0123456789abcdef0'].join('-');
const ZERO_SG = ['sg', '0'.repeat(17)].join('-');
const ZERO_SGR = ['sgr', '0'.repeat(17)].join('-');
// Base64-looking run that contains "akia" + 16 base32-ish chars but is not a key id.
const B64_AKIA = ['MIIEBjCCAu6gAwIBAgIJAMc0Zza', 'akia', 'qwertyuiopasdfgh', 'EFWK'].join('');
// Connection URLs the first version of the pattern missed.
const PG_AT_IN_PASSWORD = ['postgres:/', '/u:p@ss@prod.corp.net/db'].join('');
const PG_DRIVER_SUFFIX = ['postgresql+psycopg:/', '/u:p@prod.corp.net/db'].join('');
const PG_EMPTY_USER = ['postgres:/', '/:p@prod.corp.net/db'].join('');
const PG_IPV6 = ['postgres:/', '/u:p@[2001:db8::5]:5432/db'].join('');
// Second review: URL and DSN shapes that still reached a real host.
const PG_BYPASSES = [
  ['postgresql:/', '/u:p@localhost,prod.corp.net:5432/db'],
  ['postgresql:/', '/u:p@localhost:5432,prod.corp.net:5432/db'],
  ['postgresql:/', '/u:p@localhost/db?host', '=prod.corp.net'],
  ['postgres:/', '/app@prod.corp.net/db'],
  ['postgres:/', '/u:pa/ss@prod.corp.net/db'],
  ['postgres:/', '/u:p@prod.test_corp.net/db'],
  ['jdbc:postgresql:/', '/prod.corp.net:5432/db?user=u&password=p'],
  ['host', '=prod.corp.net port=5432 password=s3cret'],
].map((parts) => parts.join(''));
// AWS account ids outside an ARN.
const ACCOUNT_BYPASSES = [
  ['2109876543', '21.dkr.ecr.eu-central-1.amazonaws.com/app:latest'],
  ['"AccountId": "2109876543', '21"'],
  ['account_id = 2109876543', '21'],
  ['arn:aws-iso-b:iam:', ':210987654321:role/x'],
].map((parts) => parts.join(''));
const ACCOUNT_PLACEHOLDERS = [
  ['1234567890', '12.dkr.ecr.eu-central-1.amazonaws.com/daypass:latest'],
  ['"AccountId": "1234567890', '12"'],
  ['arn:aws-iso:iam:', ':123456789012:role/daypass'],
].map((parts) => parts.join(''));

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
    write('policy.json', '{ "Resource": "arn:aws:iam::123456789012:role/daypass" }\n');
    commit('add policy');
    expect(scrub().status).toBe(0);
  });

  it('SCRUB_HISTORY=1 scans every ref, not just HEAD and tags, and names the ref', () => {
    git('checkout', '-q', '-b', 'pre-squash-backup');
    write('leak.txt', `${FAKE_SG}\n`);
    const added = commit('backup with id');
    git('checkout', '-q', 'main');
    expect(scrub().status).toBe(0);
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain(`commit ${added}`);
    expect(r.out).toContain('pre-squash-backup');
  });

  it('SCRUB_HISTORY_RANGE still scans only the given range', () => {
    git('checkout', '-q', '-b', 'pre-squash-backup');
    write('leak.txt', `${FAKE_SG}\n`);
    commit('backup with id');
    git('checkout', '-q', 'main');
    git('checkout', '-q', '-b', 'feature');
    write('feature.txt', 'nothing to see\n');
    commit('feature work');
    const r = scrub({ SCRUB_HISTORY_RANGE: 'main..feature' });
    expect(r.status).toBe(0);
    expect(r.out).toContain('scrub: history (main..feature)');
  });

  it.each([FAKE_AKIA, FAKE_ASIA])('flags the AWS access key id %s', (key) => {
    write('creds.txt', `aws_access_key_id = ${key}\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('creds.txt');
  });

  it('flags an ARN in another partition that carries a real account id', () => {
    write('policy.json', `{ "Resource": "${FAKE_ARN_CN}" }\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('policy.json');
  });

  it('accepts the placeholder account in any partition', () => {
    write('policy.json', '{ "Resource": "arn:aws-us-gov:iam::123456789012:role/daypass" }\n');
    expect(scrub().status).toBe(0);
  });

  it('flags a real value that sits on the same line as a placeholder', () => {
    write('policy.json', `arn:aws:iam::123456789012:role/daypass ${FAKE_ARN}\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('policy.json');
  });

  it.each([FAKE_PG_URL, FAKE_PG_IP_URL])('flags a connection URL with a password to a real host: %s', (url) => {
    write('targets.json', `{ "url": "${url}" }\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('targets.json');
  });

  it('accepts the documented placeholder connection URLs', () => {
    write(
      'docs.md',
      [
        'postgres://postgres:postgres@localhost:5432/postgres',
        'postgres://daypass_ro:pw@staging-db.example.com:5432/app',
        'postgresql://u:pw@h/db',
        'postgres://user:pass@host:5432/db',
        'postgres://daypass_ro:pw@127.0.0.1:5432/app?sslmode=disable',
        'postgres://u:p@db.invalid:5432/d?sslmode=disable',
        'postgres://u:p@db.example.org/d',
      ].join('\n') + '\n',
    );
    const r = scrub();
    expect(r.status).toBe(0);
  });

  it.each([FAKE_RDS_CN, FAKE_RDS_SHORT])('flags the RDS host %s', (host) => {
    write('notes.txt', `host: ${host}\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('notes.txt');
  });

  it('accepts the abc123 RDS placeholder (any case) and the public truststore host', () => {
    write(
      'docs.md',
      [
        'my-db.abc123.eu-central-1.rds.amazonaws.com',
        'MY-DB.ABC123.US-EAST-1.RDS.AMAZONAWS.COM',
        'https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem',
      ].join('\n') + '\n',
    );
    expect(scrub().status).toBe(0);
  });

  it('flags a binary file in the working tree and names it', () => {
    fs.writeFileSync(path.join(dir, 'leak.png'), Buffer.concat([Buffer.from('\x89PNG\r\n\x1a\n\x00\x00', 'binary'), Buffer.from(FAKE_SG)]));
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('leak.png');
  });

  it('SCRUB_HISTORY=1 scans the latest stash entry, including unstaged changes', () => {
    write('README.md', `# fixture\n${FAKE_SG}\n`);
    git('stash', '-q');
    expect(scrub().status).toBe(0);
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain('refs/stash');
  });

  it('accepts the AWS documentation example ids', () => {
    write('fixtures.ts', [DOC_AKIA, DOC_SG, ZERO_SG, ZERO_SGR].map((v) => `const x = '${v}';`).join('\n') + '\n');
    expect(scrub().status).toBe(0);
  });

  it('still flags a real id that is longer than an allowlisted example', () => {
    write('fixtures.ts', `const x = '${ZERO_SG}1';\n`);
    expect(scrub().status).toBe(1);
  });

  it('does not flag "akia" inside a base64 run, but flags a delimited key id', () => {
    write('bundle.pem', `${B64_AKIA}\n`);
    expect(scrub().status).toBe(0);
    write('creds.env', `AWS_ACCESS_KEY_ID=${FAKE_AKIA}\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('creds.env');
    expect(r.out).not.toContain('bundle.pem');
  });

  it('SCRUB_HISTORY=1 finds a key id at the very start of an added line', () => {
    write('creds.txt', `${FAKE_AKIA}\n`);
    const added = commit('add key');
    fs.rmSync(path.join(dir, 'creds.txt'));
    commit('remove key');
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain(`commit ${added}`);
  });

  it('scans package-lock.json in the tree and in history (no blind spot)', () => {
    write('package-lock.json', `{ "integrity": "sha512-${B64_AKIA}", "x": "${FAKE_SG}" }\n`);
    expect(scrub().out).toContain('package-lock.json');
    const added = commit('lockfile');
    fs.rmSync(path.join(dir, 'package-lock.json'));
    commit('drop lockfile');
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain(`commit ${added}`);
  });

  it('does not flag the sha512 integrity strings of a lockfile', () => {
    write('package-lock.json', `{ "integrity": "sha512-${B64_AKIA}" }\n`);
    expect(scrub().status).toBe(0);
  });

  it.each([PG_AT_IN_PASSWORD, PG_DRIVER_SUFFIX, PG_EMPTY_USER, PG_IPV6])(
    'flags the connection URL %s',
    (url) => {
      write('targets.json', `{ "url": "${url}" }\n`);
      const r = scrub();
      expect(r.status).toBe(1);
      expect(r.out).toContain('targets.json');
    },
  );

  it('accepts placeholder URLs with a driver suffix or the IPv6 loopback', () => {
    write(
      'docs.md',
      ['postgresql+psycopg://u:pw@localhost/db', 'postgres://u:pw@[::1]:5432/db'].join('\n') + '\n',
    );
    expect(scrub().status).toBe(0);
  });

  it.each(PG_BYPASSES)('flags the connection string %s', (dsn) => {
    write('targets.txt', `${dsn}\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('targets.txt');
  });

  it('accepts placeholder hosts in keyword DSNs and multi-host URLs', () => {
    write(
      'docs.md',
      ['host=localhost port=5432 password=pw', 'postgres://u:pw@localhost:5432,db.example.com:5433/app'].join('\n') + '\n',
    );
    expect(scrub().status).toBe(0);
  });

  it.each(ACCOUNT_BYPASSES)('flags the AWS account id in %s', (line) => {
    write('infra.txt', `${line}\n`);
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('infra.txt');
  });

  it.each(ACCOUNT_PLACEHOLDERS)('accepts the placeholder account in %s', (line) => {
    write('docs.md', `${line}\n`);
    expect(scrub().status).toBe(0);
  });

  it('SCRUB_HISTORY=1 flags a message body line that looks like a commit header', () => {
    write('clean.txt', 'nothing\n');
    commit(`subject\n\ncommit abc123 opened ${FAKE_SG}`);
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain(FAKE_SG);
  });

  it('scans the index: an id that is staged but gone from the working copy', () => {
    write('a.txt', `${FAKE_SG}\n`);
    git('add', 'a.txt');
    write('a.txt', 'clean\n');
    const r = scrub();
    expect(r.status).toBe(1);
    expect(r.out).toContain('a.txt');
  });

  it('SCRUB_HISTORY=1 scans annotated tag messages', () => {
    git('tag', '-a', 'v1', '-m', `prod ${FAKE_SG}`);
    const r = scrub({ SCRUB_HISTORY: '1' });
    expect(r.status).toBe(1);
    expect(r.out).toContain('refs/tags/v1');
  });

  it('fails with exit 2 when perl is missing', () => {
    // A PATH holding only what the script needs before its perl check.
    const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'scrub-bin-'));
    try {
      for (const tool of ['dirname', 'mktemp', 'rm']) {
        const which = spawnSync('/bin/sh', ['-c', `command -v ${tool}`], { encoding: 'utf8' }).stdout.trim();
        fs.symlinkSync(which, path.join(bin, tool));
      }
      const r = spawnSync('/bin/bash', ['scripts/scrub-check.sh'], { cwd: dir, encoding: 'utf8', env: { PATH: bin } });
      expect(r.status).toBe(2);
      expect(r.stdout + r.stderr).toMatch(/perl is required/);
    } finally {
      fs.rmSync(bin, { recursive: true, force: true });
    }
  });
});
