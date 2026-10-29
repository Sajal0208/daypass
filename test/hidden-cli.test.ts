import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile, execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

/** Runs the built CLI. `npm test` alone does not build, so compile once if dist is absent. */
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

describe('peephole hidden (CLI)', () => {
  let dir: string;
  beforeAll(() => {
    if (!existsSync(CLI)) execFileSync('npx', ['tsc', '-p', 'tsconfig.json'], { cwd: ROOT, stdio: 'inherit' });
    dir = mkdtempSync(join(tmpdir(), 'peephole-hidden-'));
    writeFileSync(join(dir, 'schema.prisma'), SCHEMA);
  }, 60_000);
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('suggest --prisma on a camelCase schema feeds sql --hide-file', async () => {
    const suggest = await run('hidden', 'suggest', '--prisma', join(dir, 'schema.prisma'));
    expect(suggest.code).toBe(0);
    expect(suggest.stdout.split('\n').filter((l) => l && !l.startsWith('#'))).toEqual(['AppUser.APIKey', 'AppUser.phoneNumber']);
    expect(suggest.stderr).toContain('peephole hidden suggest: 2 of 4 columns flagged');
    writeFileSync(join(dir, 'hidden.txt'), suggest.stdout);

    const sql = await run('sql', '--hide-file', join(dir, 'hidden.txt'));
    expect(sql.code).toBe(0);
    expect(sql.stdout).toContain("'AppUser.phoneNumber'");
    expect(sql.stdout).toContain("'AppUser.APIKey'");
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
});
