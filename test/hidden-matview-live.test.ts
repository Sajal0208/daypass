import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import pg from 'pg';

const ROOT = resolve(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli', 'main.js');
const live = process.env.DAYPASS_TEST_PG_URL;
const S = `mvleak_${process.pid}`;

function run(args: string[], stdin: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((res) => {
    const c = spawn('node', [CLI, ...args], { cwd: ROOT, env: process.env });
    let stdout = '';
    let stderr = '';
    c.stdout.on('data', (d) => (stdout += d));
    c.stderr.on('data', (d) => (stderr += d));
    c.on('close', (code) => res({ code, stdout, stderr }));
    c.stdin.end(stdin);
  });
}

describe.skipIf(!live)('hidden check: materialized views stored as the owner (live)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'daypass-mv-'));
  const db = new pg.Client({ connectionString: live });
  beforeAll(async () => {
    await db.connect();
    await db.query(`drop schema if exists ${S} cascade; create schema ${S};
      create table ${S}.t (id int, note text);
      create materialized view ${S}.mv_stats as select attname, n_distinct from pg_catalog.pg_stats;
      create view ${S}.v_over as select * from ${S}.mv_stats;
      create view ${S}.v_xml as select query_to_xml('select 1', true, false, '') as x;
      create materialized view ${S}.mv_xml as select * from ${S}.v_xml;
      create materialized view ${S}.mv_ok as select id from ${S}.t;`);
    writeFileSync(join(dir, 'hidden.txt'), '');
  });
  afterAll(async () => {
    await db.query(`drop schema if exists ${S} cascade`);
    await db.end();
    rmSync(dir, { recursive: true, force: true });
  });
  it('reports a matview over pg_stats, views over it, and a matview over a view that calls query_to_xml', async () => {
    const r = await run(['hidden', 'check', '--file', join(dir, 'hidden.txt'), '--url', '-', '--schemas', S], live!);
    expect(r.stdout, r.stderr).toMatch(new RegExp(`view ${S}\\.mv_stats reads pg_catalog\\.pg_stats \\(a materialized view stores`));
    expect(r.stdout).toMatch(new RegExp(`view ${S}\\.v_over reads pg_catalog\\.pg_stats .* through view ${S}\\.mv_stats`));
    expect(r.stdout).toMatch(new RegExp(`view ${S}\\.mv_xml calls function pg_catalog\\.query_to_xml\\(text,boolean,boolean,text\\) through view ${S}\\.v_xml`));
    expect(r.stdout).not.toMatch(new RegExp(`view ${S}\\.mv_ok `));
  }, 60_000);
});
