// The setup and `hidden check` against a live Postgres: plain views over row-level-security tables,
// views over a sequence owned by a hidden column, a matview behind a domain CHECK, and escaped names.
// Needs DAYPASS_TEST_PG_URL (owner rights) and psql on PATH.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import pg from 'pg';

const ROOT = resolve(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli', 'main.js');
const live = process.env.DAYPASS_TEST_PG_URL;
const hasPsql = spawnSync('psql', ['--version']).status === 0;
const S = `r2views_${process.pid}`;
const ROLE = `r2views_ro_${process.pid}`;

function run(cmd: string, args: string[], stdin = ''): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((res) => {
    const c = spawn(cmd, args, { cwd: ROOT, env: process.env });
    let stdout = '';
    let stderr = '';
    c.stdout.on('data', (d) => (stdout += d));
    c.stderr.on('data', (d) => (stderr += d));
    c.on('close', (code) => res({ code, stdout, stderr }));
    c.stdin.end(stdin);
  });
}

describe.skipIf(!live || !hasPsql)('setup: views that read as their owner (live)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'daypass-r2views-'));
  const db = new pg.Client({ connectionString: live });
  let setup: { code: number | null; stdout: string; stderr: string };
  let pgVersion = 0;
  const can = async (rel: string) =>
    (await db.query(`select has_table_privilege($1, $2, 'SELECT') as ok`, [ROLE, `${S}.${rel}`])).rows[0].ok as boolean;

  beforeAll(async () => {
    await db.connect();
    pgVersion = Number((await db.query('show server_version_num')).rows[0].server_version_num);
    await db.query(`drop schema if exists ${S} cascade; create schema ${S};
      create table ${S}.tenant_notes (id int, tenant text, body text);
      alter table ${S}.tenant_notes enable row level security;
      create policy own on ${S}.tenant_notes using (tenant = current_user);
      create view ${S}.notes_v as select id, body from ${S}.tenant_notes;
      create view ${S}.notes_nested as select id from ${S}.notes_v;
      create table ${S}.accounts (id serial primary key, api_key_id bigserial, name text);
      create view ${S}.key_counter as select last_value from ${S}.accounts_api_key_id_seq;
      create view ${S}.id_counter as select last_value from ${S}.accounts_id_seq;
      create function ${S}.chk(text) returns boolean language sql immutable as $$ select length($1) < 50 $$;
      create domain ${S}.short_text as text check (${S}.chk(value));
      create materialized view ${S}.mv_dom as select name::${S}.short_text as n from ${S}.accounts;
      create materialized view ${S}.mv_plain as select id, name from ${S}.accounts;
      create table ${S}."t${'\x1b'}[2Jx" (id int, secret_token text);`);
    if (pgVersion >= 150000) {
      await db.query(`create view ${S}.notes_inv with (security_invoker = on) as select id, body from ${S}.tenant_notes;
        create view ${S}.notes_over_inv as select id from ${S}.notes_inv;
        create view ${S}.notes_inv_over_plain with (security_invoker) as select id from ${S}.notes_v;`);
    }
    writeFileSync(join(dir, 'hidden.txt'), `${S}.accounts.api_key_id\n`);
    const sql = await run('node', [CLI, 'sql', '--role', ROLE, '--schemas', S, '--allow-definer-functions', '--hide-file', join(dir, 'hidden.txt')]);
    expect(sql.code, sql.stderr).toBe(0);
    setup = await run('psql', ['-X', '-q', '-v', 'ON_ERROR_STOP=1', live!], sql.stdout);
  }, 60_000);
  afterAll(async () => {
    await db.query(`drop schema if exists ${S} cascade`);
    const { rowCount } = await db.query(`select 1 from pg_roles where rolname = $1`, [ROLE]);
    if (rowCount) await db.query(`drop owned by ${ROLE}; drop role ${ROLE}`);
    await db.end();
    rmSync(dir, { recursive: true, force: true });
  });

  it('runs', () => {
    expect(setup.code, setup.stderr).toBe(0);
  });
  it('withholds a plain view over a row-level-security table, and views over it', async () => {
    expect(setup.stderr).toContain(`view ${S}.notes_v reads ${S}.tenant_notes, which has row-level security (a view reads its tables with its owner's rights`);
    expect(await can('notes_v')).toBe(false);
    expect(await can('notes_nested')).toBe(false);
  });
  it('grants a security_invoker view over it, but not an owner-rights view on top (PG 15+)', async () => {
    if (pgVersion < 150000) return;
    expect(await can('notes_inv')).toBe(true);
    expect(await can('notes_over_inv')).toBe(false);
    expect(await can('notes_inv_over_plain')).toBe(false);
  });
  it('withholds a view over a sequence owned by a hidden column, not one over another sequence', async () => {
    expect(setup.stderr).toContain(`view ${S}.key_counter reads ${S}.accounts_api_key_id_seq, which the role is not granted`);
    expect(await can('key_counter')).toBe(false);
    expect(await can('id_counter')).toBe(true);
  });
  it('withholds a matview whose domain CHECK calls a function outside pg_catalog', async () => {
    expect(setup.stderr).toContain(`view ${S}.mv_dom calls function ${S}.chk(text)`);
    expect(await can('mv_dom')).toBe(false);
    expect(await can('mv_plain')).toBe(true);
  });
  it('hidden check reports the same views and escapes control characters in names', async () => {
    const r = await run('node', [CLI, 'hidden', 'check', '--file', join(dir, 'hidden.txt'), '--url', '-', '--schemas', S], live!);
    expect(r.stdout, r.stderr).toMatch(new RegExp(`view ${S}\\.notes_v reads ${S}\\.tenant_notes, which has row-level security \\(a view reads`));
    expect(r.stdout).toContain(`view ${S}.key_counter reads ${S}.accounts_api_key_id_seq, a sequence owned by a hidden column`);
    expect(r.stdout).toContain(`view ${S}.mv_dom calls function ${S}.chk(text)`);
    expect(r.stdout).not.toMatch(new RegExp(`view ${S}\\.(id_counter|mv_plain) `));
    // The table name holds ESC [2J (clear screen): printed escaped, never raw.
    expect(r.stdout).toContain('t\\x1b[2Jx');
    expect(r.stdout).not.toContain('\x1b');
  }, 60_000);
});
