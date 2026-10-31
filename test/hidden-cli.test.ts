import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { ensureBuilt } from './setup-build.js';

/** Runs the built CLI; ensureBuilt() recompiles when dist is missing or older than src/ or sql/. */
const ROOT = resolve(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli', 'main.js');
const run = async (...args: string[]) => {
  try {
    const r = await promisify(execFile)('node', [CLI, ...args], { cwd: ROOT });
    return { code: 0, ...r };
  } catch (e: any) {
    return { code: e.code as number, stdout: e.stdout as string, stderr: e.stderr as string };
  }
};

const SCHEMA = `
model User {
  id          String  @id
  phoneNumber String?
  APIKey      String
  createdAt   DateTime
  @@map("AppUser")
}
`;

describe('daypass hidden (CLI)', () => {
  let dir: string;
  beforeAll(() => {
    ensureBuilt();
    dir = mkdtempSync(join(tmpdir(), 'daypass-hidden-'));
    writeFileSync(join(dir, 'schema.prisma'), SCHEMA);
  }, 60_000);
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('suggest --prisma on a camelCase schema feeds sql --hide-file', async () => {
    const suggest = await run('hidden', 'suggest', '--prisma', join(dir, 'schema.prisma'));
    expect(suggest.code).toBe(0);
    expect(suggest.stdout.split('\n').filter((l) => l && !l.startsWith('#'))).toEqual(['AppUser.APIKey', 'AppUser.phoneNumber']);
    expect(suggest.stderr).toContain('daypass hidden suggest: 2 of 4 columns flagged');
    writeFileSync(join(dir, 'hidden.txt'), suggest.stdout);

    const sql = await run('sql', '--hide-file', join(dir, 'hidden.txt'));
    expect(sql.code).toBe(0);
    expect(sql.stdout).toContain("'public|AppUser|phoneNumber'");
    expect(sql.stdout).toContain("'public|AppUser|APIKey'");
  });

  it('check --prisma with a stale list exits 1 and names the drift', async () => {
    writeFileSync(join(dir, 'stale.txt'), 'AppUser.phoneNumber\nAppUser.gone\n!AppUser.alsoGone\n');
    const r = await run('hidden', 'check', '--file', join(dir, 'stale.txt'), '--prisma', join(dir, 'schema.prisma'));
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('AppUser.gone');
    expect(r.stdout).toContain('AppUser.alsoGone');
    expect(r.stdout).toContain('AppUser.APIKey');
  });

  it('check --prisma honours ! allow lines', async () => {
    writeFileSync(join(dir, 'ok.txt'), 'AppUser.phoneNumber\n!AppUser.APIKey\n');
    const r = await run('hidden', 'check', '--file', join(dir, 'ok.txt'), '--prisma', join(dir, 'schema.prisma'));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('hidden list matches the schema (1 hidden, 4 columns scanned)');
  });

  it('check --prisma reports a column that is both hidden and !allowed and exits 1', async () => {
    writeFileSync(join(dir, 'conflict.txt'), 'AppUser.phoneNumber\n!AppUser.phoneNumber\n!AppUser.APIKey\n');
    const r = await run('hidden', 'check', '--file', join(dir, 'conflict.txt'), '--prisma', join(dir, 'schema.prisma'));
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/both hidden and !allowed/);
    expect(r.stdout).toContain('AppUser.phoneNumber');
  });

  it('check --prisma dedupes before counting', async () => {
    writeFileSync(join(dir, 'dup.txt'), 'AppUser.phoneNumber\npublic.AppUser.phoneNumber\n"AppUser"."phoneNumber"\n!AppUser.APIKey\n');
    const r = await run('hidden', 'check', '--file', join(dir, 'dup.txt'), '--prisma', join(dir, 'schema.prisma'));
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('(1 hidden, 4 columns scanned)');
  });

  it('check rejects a bare ! line', async () => {
    writeFileSync(join(dir, 'bare.txt'), 'AppUser.phoneNumber\n!\n');
    const r = await run('hidden', 'check', '--file', join(dir, 'bare.txt'), '--prisma', join(dir, 'schema.prisma'));
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/bare "!"/);
  });
});

describe('daypass sql (CLI)', () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'daypass-sql-'));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('accepts quoted and schema-qualified entries and passes schema|table|column triples', async () => {
    writeFileSync(join(dir, 'h.txt'), '"order-items".ship_address\nanalytics.events.user_email\n!customers.newcol\n');
    const r = await run('sql', '--hide-file', join(dir, 'h.txt'), '--schemas', 'public,analytics');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("'public|order-items|ship_address'");
    expect(r.stdout).toContain("'analytics|events|user_email'");
    expect(r.stdout).toContain("'public|customers|newcol'");
    expect(r.stdout).toContain("ARRAY['public','analytics']");
    expect(r.stdout).toMatch(/allow_definer\s+boolean\s*:=\s*false/);
    expect(r.stdout).toMatch(/revoke_temp\s+boolean\s*:=\s*false/);
    expect(r.stdout).not.toMatch(/__[A-Z_]+__/);
  });

  it('refuses an entry whose schema is not in --schemas', async () => {
    const r = await run('sql', '--hide', 'analytics.events.user_email');
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('--schemas');
    expect(r.stderr).toContain('analytics');
  });

  it('refuses a column that is both hidden and !allowed', async () => {
    writeFileSync(join(dir, 'c.txt'), 'customers.email\n!customers.email\n');
    const r = await run('sql', '--hide-file', join(dir, 'c.txt'));
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/both hidden and !allowed/);
    expect(r.stderr).toContain('customers.email');
  });

  it('refuses a bare ! line and a malformed entry', async () => {
    writeFileSync(join(dir, 'b.txt'), '!\n');
    expect((await run('sql', '--hide-file', join(dir, 'b.txt'))).stderr).toMatch(/bare "!"/);
    const r = await run('sql', '--hide', 'users');
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/bad hidden entry/);
  });

  it('dedupes equivalent spellings', async () => {
    const r = await run('sql', '--hide', 'users.email', 'public.users.email', '"users"."email"');
    expect(r.code).toBe(0);
    expect(r.stdout.match(/'public\|users\|email'/g)).toHaveLength(1);
  });

  it('--allow-definer-functions, --revoke-public-temp and --schemas flow into the template', async () => {
    const r = await run('sql', '--allow-definer-functions', '--revoke-public-temp', '--schemas', 'public, analytics');
    expect(r.code).toBe(0);
    expect(r.stdout).toMatch(/allow_definer\s+boolean\s*:=\s*true/);
    expect(r.stdout).toMatch(/revoke_temp\s+boolean\s*:=\s*true/);
    expect(r.stdout).toContain("ARRAY['public','analytics']");
  });

  it('rejects a schema name that is not a plain identifier', async () => {
    const r = await run('sql', '--schemas', 'public,bad-schema');
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/schema/);
  });
});

describe('review 2026-10-30 round 2 (CLI)', () => {
  let dir: string;
  beforeAll(() => {
    ensureBuilt();
    dir = mkdtempSync(join(tmpdir(), 'daypass-r2-'));
    writeFileSync(join(dir, 'schema.prisma'), SCHEMA);
  }, 60_000);
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('M10: check names the unscanned schema of a missing entry and the --schemas fix', async () => {
    writeFileSync(join(dir, 'other.txt'), 'AppUser.phoneNumber\n!AppUser.APIKey\nanalytics.events.user_email\n');
    const r = await run('hidden', 'check', '--file', join(dir, 'other.txt'), '--prisma', join(dir, 'schema.prisma'));
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('analytics.events.user_email  (schema analytics was not scanned: add --schemas public,analytics)');
  });
  it('I2: sql --revoke-public-create flows into the template', async () => {
    expect((await run('sql')).stdout).toMatch(/revoke_create\s+boolean\s*:=\s*false/);
    expect((await run('sql', '--revoke-public-create')).stdout).toMatch(/revoke_create\s+boolean\s*:=\s*true/);
  });
  it('I1: an identifier with $$ reaches the SQL hex-encoded, never as $$ inside a DO body', async () => {
    const r = await run('sql', '--hide', 't."a$$b"');
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(`convert_from(decode('${Buffer.from('public|t|a$$b').toString('hex')}', 'hex'), 'UTF8')`);
    expect(r.stdout).not.toContain('a$$b');
  });
});

