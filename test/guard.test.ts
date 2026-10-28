import { describe, it, expect } from 'vitest';
import { checkSql } from '../src/core/guard.js';

const ok = async (sql: string) => expect(await checkSql(sql)).toMatchObject({ ok: true });
const bad = async (sql: string, reason: RegExp) => {
  const r = await checkSql(sql);
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.reason).toMatch(reason);
};

describe('checkSql allows', () => {
  it('plain select', () => ok('select 1'));
  it('select with trailing semicolon and whitespace', () => ok('  SELECT id FROM users ; '));
  it('CTE select', () => ok('with a as (select 1 x) select * from a'));
  it('subqueries and joins', () =>
    ok('select u.id from users u join sessions s on s.user_id = u.id where s.id in (select id from sessions limit 5)'));
  it('explain select', async () => expect(await checkSql('explain select 1')).toMatchObject({ ok: true, kind: 'explain' }));
  it('explain (format json) select', () => ok('explain (format json) select * from users'));
  it('values', () => ok('values (1), (2)'));
  it('reports kind select', async () => expect(await checkSql('select 1')).toMatchObject({ ok: true, kind: 'select' }));
});

describe('checkSql rejects', () => {
  it('empty', () => bad('', /empty/i));
  it('whitespace only', () => bad('   ', /empty/i));
  it('two statements', () => bad('select 1; select 2', /one statement/i));
  it('select then drop', () => bad('select 1; drop table users', /one statement/i));
  it('insert', () => bad('insert into users(id) values (1)', /select/i));
  it('update', () => bad('update users set x = 1', /select/i));
  it('delete', () => bad('delete from users', /select/i));
  it('truncate', () => bad('truncate users', /select/i));
  it('drop', () => bad('drop table users', /select/i));
  it('alter', () => bad('alter table users add c int', /select/i));
  it('create', () => bad('create table t (a int)', /select/i));
  it('grant', () => bad('grant all on users to public', /select/i));
  it('copy', () => bad("copy users to '/tmp/x'", /select/i));
  it('set', () => bad('set default_transaction_read_only = off', /select/i));
  it('do block', () => bad('do $$ begin end $$', /select/i));
  it('begin', () => bad('begin', /select/i));
  it('select for update', () => bad('select * from users for update', /lock/i));
  it('select for share', () => bad('select * from users for share', /lock/i));
  it('select for update in CTE', () => bad('with a as (select * from users for update) select * from a', /lock/i));
  it('explain analyze', () => bad('explain analyze select 1', /analyze/i));
  it('explain (analyze true)', () => bad('explain (analyze true) select 1', /analyze/i));
  it('explain of insert', () => bad('explain insert into users(id) values (1)', /select/i));
  it('pg_sleep', () => bad('select pg_sleep(10)', /pg_sleep/i));
  it('pg_sleep with schema', () => bad('select pg_catalog.pg_sleep(10)', /pg_sleep/i));
  it('pg_sleep in subquery', () => bad('select * from users where id = (select pg_sleep(1))', /pg_sleep/i));
  it('dblink', () => bad("select * from dblink('host=x', 'select 1') as t(a int)", /dblink/i));
  it('pg_read_file', () => bad("select pg_read_file('/etc/passwd')", /pg_read_file/i));
  it('pg_read_binary_file', () => bad("select pg_read_binary_file('/etc/passwd')", /pg_read_binary_file/i));
  it('lo_import', () => bad("select lo_import('/etc/passwd')", /lo_import/i));
  it('lo_export', () => bad("select lo_export(1, '/tmp/x')", /lo_export/i));
  it('pg_terminate_backend', () => bad('select pg_terminate_backend(1)', /pg_terminate_backend/i));
  it('pg_cancel_backend', () => bad('select pg_cancel_backend(1)', /pg_cancel_backend/i));
  it('set_config', () => bad("select set_config('x', 'y', false)", /set_config/i));
  it('pg_advisory_lock', () => bad('select pg_advisory_lock(1)', /pg_advisory_lock/i));
  it('nextval', () => bad("select nextval('s')", /nextval/i));
  it('parse error', () => bad('select from where', /syntax|parse/i));
  it('select into', () => bad('select 1 into t', /into/i));
});
