import { describe, it, expect } from 'vitest';
import { checkSql } from '../src/core/guard.js';

const bad = async (sql: string, reason: RegExp) => {
  const r = await checkSql(sql);
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.reason).toMatch(reason);
};
const ok = async (sql: string) => expect(await checkSql(sql)).toMatchObject({ ok: true });

// Postgres reads `(arg).func` and `tbl.func` as `func(arg)` / `func(tbl)`.
describe('attribute-notation function calls', () => {
  it('refuses (3).pg_sleep', () => bad('select (3).pg_sleep', /pg_sleep/));
  it('refuses quoted, upper-cased attribute names', () => bad('select (3)."PG_SLEEP"', /pg_sleep/i));
  it('refuses ts_stat over a query string', () =>
    bad("select ('select pg_sleep(2)::text::tsvector').ts_stat", /ts_stat/));
  it('refuses (pid).pg_terminate_backend', () =>
    bad('select (pid).pg_terminate_backend from pg_stat_activity', /pg_terminate_backend/));
  it('refuses (0.5).setseed', () => bad('select (0.5).setseed', /setseed/));
  it('refuses a banned name anywhere in a chained indirection', async () => {
    await bad('select ((3)).pg_sleep.x', /pg_sleep/);
    await bad('select (x).pg_catalog.pg_sleep from (select 1 x) s', /pg_sleep/);
    await bad('select (3).pg_sleep[1]', /pg_sleep/);
  });
  it('refuses tbl.func and alias.func column refs', async () => {
    await bad('select t.pg_sleep from t', /pg_sleep/);
    await bad('select a.PG_ADVISORY_LOCK from t a', /pg_advisory_lock/i);
    await bad('select 1 from t where t.set_config is null', /set_config/);
    await bad('select s.t.pg_sleep from s.t', /pg_sleep/);
    await bad('select x from t order by t.setseed', /setseed/);
  });
  it('refuses attribute calls inside EXPLAIN and subqueries', async () => {
    await bad('explain select (3).pg_sleep', /pg_sleep/);
    await bad('select * from (select (1).pg_sleep) s', /pg_sleep/);
  });
  it('still allows ordinary qualified columns and field selection', async () => {
    await ok('select t.id, t.name, s.t.created_at from s.t join u on u.id = t.uid');
    await ok('select (c).x, (row(1, 2)).*, (t.*) from t');
    await ok('select pg_sleep from t'); // a bare name is a column, never a call
  });
});

describe('internal errors', () => {
  it('returns ok:false instead of throwing on raw control characters', async () => {
    const r = await checkSql("select '\x01'");
    expect(r.ok).toBe(false);
  });
  it('returns ok:false for other control characters', async () => {
    for (const c of ['\x02', '\x1f', '\x08']) {
      const r = await checkSql(`select '${c}' as x`);
      expect(r.ok).toBe(false);
    }
  });
});
