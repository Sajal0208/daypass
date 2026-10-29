import { afterAll, describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide, looksSensitive as hookLooksSensitive } from '../plugin/hooks/pii-guard.mjs';
import { looksSensitive as coreLooksSensitive } from '../src/core/hidden.js';

const PATH = '/home/me/.peephole/hidden-columns.txt';
const env = (extra: Record<string, string> = {}) => ({ PEEPHOLE_HIDDEN_FILE: PATH, ...extra });

describe('decide', () => {
  it('allows a query with no sensitive-looking identifier', () => {
    expect(decide('select id, name from users', 'users.email\n', env())).toEqual({ allow: true });
  });

  it('denies a sensitive identifier when there is no list file, naming the path', () => {
    const r = decide('select phone from users', null, env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('no hidden-columns list');
    expect(r.reason).toContain(PATH);
    expect(r.reason).toContain('peephole hidden suggest --live');
    expect(r.reason).toContain('https://github.com/Sajal0208/peephole/blob/main/docs/hidden-columns.md');
    expect(r.reason).toContain('Tell the user:');
  });

  it('denies with a distinct reason when the list exists but cannot be read', () => {
    const r = decide('select phone from users', { error: 'EISDIR' }, env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('cannot read hidden-columns list');
    expect(r.reason).toContain(PATH);
    expect(r.reason).toContain('EISDIR');
    expect(r.reason).not.toContain('no hidden-columns list');
  });

  it('ignores an unreadable list when no identifier looks sensitive', () => {
    expect(decide('select id, name from users', { error: 'EISDIR' }, env())).toEqual({ allow: true });
  });

  it('denies a sensitive identifier the list does not cover, naming it and the path', () => {
    const r = decide('select phone from users', 'users.email\n', env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('"phone"');
    expect(r.reason).toContain(PATH);
    expect(r.reason).toContain('"<table>.phone"');
    expect(r.reason).toContain('"!<table>.phone"');
    expect(r.reason).toContain('PEEPHOLE_PII_HOOK=off');
    expect(r.reason).toContain('Tell the user:');
    expect(r.reason).toContain('have the database owner re-run peephole sql --hide-file ' + PATH);
  });

  it('allows a sensitive identifier that the list hides', () => {
    expect(decide('select phone from users', 'users.phone\n', env())).toEqual({ allow: true });
  });

  it('allows a sensitive identifier on an allow (!) line', () => {
    expect(decide('select phone from users', '!users.phone  # reviewed\n', env())).toEqual({ allow: true });
  });

  it('matches list entries case-insensitively and strips comments', () => {
    expect(decide('select PHONE from users', '# header\nusers.Phone # c\n', env())).toEqual({ allow: true });
  });

  it('infers the table for a qualified identifier through a FROM alias', () => {
    const r = decide('select p.email_address from profiles p', 'users.email\n', env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('"profiles.email_address"');
    expect(r.reason).toContain('"!profiles.email_address"');
  });

  it('infers the table for a qualified identifier through a JOIN "as" alias', () => {
    const r = decide('select u.id from users u join profiles as pr on pr.user_id = u.id where pr.phone is null', '', env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('"profiles.phone"');
  });

  it('allows a safe-tail name such as email_verified', () => {
    expect(decide('select id from users where email_verified = true', '', env())).toEqual({ allow: true });
  });

  it('ignores sensitive words inside string literals and comments', () => {
    const sql = `select id from users where name = 'phone' -- phone\n and status = 'it''s email' /* secret */`;
    expect(decide(sql, '', env())).toEqual({ allow: true });
  });

  it('is disabled by PEEPHOLE_PII_HOOK=off, even without a list', () => {
    expect(decide('select phone, password_hash from users', null, env({ PEEPHOLE_PII_HOOK: 'off' }))).toEqual({ allow: true });
  });

  it('never flags SQL keywords such as count', () => {
    expect(decide('select count(*) from users', '', env())).toEqual({ allow: true });
  });

  it('inspects double-quoted identifiers', () => {
    const r = decide('select "phoneNumber" from "users"', '', env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('"phoneNumber"');
  });

  it('falls back to ~/.peephole/hidden-columns.txt when PEEPHOLE_HIDDEN_FILE is unset', () => {
    const r = decide('select phone from users', null, {});
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toMatch(/\.peephole\/hidden-columns\.txt/);
  });
});

describe('looksSensitive parity with src/core/hidden.ts', () => {
  const names = [
    'phone', 'phone_number', 'mobile', 'email', 'email_address', 'api_key', 'key_hash', 'secret', 'client_secret',
    'token', 'refresh_token', 'password', 'password_hash', 'transcript', 'address', 'street_address', 'ssn', 'iban',
    'card_number', 'encrypted_payload', 'prompt_snapshot', 'date_of_birth', 'id', 'created_at', 'status',
    'email_verified', 'phone_country', 'tokens_used', 'keyboard_layout', 'name', 'amount', 'phoneNumber', 'apiKey',
    'emailVerified', 'APIKey', 'HTTPToken', 'national_id', 'user_id', 'invoice_number', 'lines',
    // the account_id fix on main: foreign keys stay visible, the identifiers themselves stay hidden
    'account_id', 'bank_account_id', 'account_number', 'bank_account_number', 'tax_id',
  ];
  it('has 45 fixtures', () => expect(names).toHaveLength(45));
  it.each(names)('agrees on %s', (n) => expect(hookLooksSensitive(n)).toBe(coreLooksSensitive(n)));
});

describe('end to end (stdin -> exit code)', () => {
  const tmpDirs: string[] = [];
  const tmp = () => {
    const d = mkdtempSync(join(tmpdir(), 'peephole-hook-'));
    tmpDirs.push(d);
    return d;
  };
  afterAll(() => {
    for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
  });
  const runRaw = (stdin: string, extraEnv: Record<string, string>) =>
    spawnSync('node', ['plugin/hooks/pii-guard.mjs'], {
      input: stdin,
      // PEEPHOLE_PII_HOOK is cleared so a developer's own shell setting cannot turn the guard off here.
      env: { ...process.env, PEEPHOLE_PII_HOOK: '', ...extraEnv },
      encoding: 'utf8',
    });
  const run = (sql: string | undefined, extraEnv: Record<string, string>) =>
    runRaw(JSON.stringify({ tool_name: 'mcp__plugin_peephole_peephole__query', tool_input: sql === undefined ? {} : { sql } }), extraEnv);

  it('exits 2 with the reason on stderr when there is no list', () => {
    const r = run('select phone from users', { PEEPHOLE_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('no hidden-columns list');
    expect(r.stdout).toBe('');
  });

  it('exits 0 when the list covers the column', () => {
    const file = join(tmp(), 'hidden-columns.txt');
    writeFileSync(file, 'users.phone\n');
    const r = run('select phone from users', { PEEPHOLE_HIDDEN_FILE: file });
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });

  it('exits 2 with "cannot read" when the list path is a directory', () => {
    const r = run('select phone from users', { PEEPHOLE_HIDDEN_FILE: tmp() });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('cannot read hidden-columns list');
    expect(r.stderr).toContain('EISDIR');
    expect(r.stderr).not.toContain('no hidden-columns list');
  });

  it('exits 1 (non-blocking) with a notice when tool_input has no sql', () => {
    const r = run(undefined, { PEEPHOLE_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(1);
    expect(r.stderr).toBe('Peephole PII guard: no "sql" in tool input, not checked\n');
    expect(r.stdout).toBe('');
  });

  it('exits 0 silently on stdin that is not JSON', () => {
    const r = runRaw('not json', { PEEPHOLE_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });

  it('exits 0 silently when there is no tool_input object', () => {
    const r = runRaw(JSON.stringify({ tool_name: 'mcp__plugin_peephole_peephole__query' }), { PEEPHOLE_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });
});
