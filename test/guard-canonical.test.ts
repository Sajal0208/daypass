import { describe, it, expect } from 'vitest';
import { checkSql } from '../src/core/guard.js';

const canon = async (sql: string) => {
  const r = await checkSql(sql);
  expect(r.ok).toBe(true);
  return r.ok ? r.sql : '';
};

describe('checkSql returns canonical SQL (no trailing comments or semicolons)', () => {
  it.each([
    ['SELECT 1 -- comment', 'SELECT 1'],
    ['SELECT 1; -- c', 'SELECT 1'],
    ['SELECT 1;;', 'SELECT 1'],
    ['SELECT 1\n-- trailing comment line', 'SELECT 1'],
    ['SELECT 1 /* block */', 'SELECT 1'],
    ['SELECT 1 /* a /* nested */ b */ ;', 'SELECT 1'],
    ['  -- leading comment\nSELECT 1 ; ', 'SELECT 1'],
    ["SELECT ';' -- c", "SELECT ';'"],
    ["SELECT 'it''s; -- not a comment' ;", "SELECT 'it''s; -- not a comment'"],
    ["SELECT E'a\\'b; -- x'", "SELECT E'a\\'b; -- x'"],
    ['SELECT $t$a; -- b$t$ ;', 'SELECT $t$a; -- b$t$'],
    ['SELECT "c;--" FROM t', 'SELECT "c;--" FROM t'],
    ['SELECT 1 -- a\n, 2 -- b\n;', 'SELECT 1 -- a\n, 2'],
    ["SELECT 'é' -- ü", "SELECT 'é'"],
  ])('%j → %j', async (input, expected) => {
    expect(await canon(input)).toBe(expected);
  });
  it('canonicalises EXPLAIN too', async () => {
    const r = await checkSql('explain select 1 ; -- x');
    expect(r).toMatchObject({ ok: true, kind: 'explain', sql: 'explain select 1' });
  });
});
