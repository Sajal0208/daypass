import { describe, it, expect } from 'vitest';
import { wrapWithBudget, shapeBudgetRows, parseJsonPreservingBigInts, shapeRows } from '../src/core/shape.js';

describe('wrapWithBudget', () => {
  const sql = wrapWithBudget('select 1 -- c', 500, 1_000_000);
  it('caps rows in SQL with one sentinel row', () => {
    expect(sql).toMatch(/LIMIT 501\b/);
  });
  it('cuts each row to maxBytes + 1 chars in SQL, in the LIMIT subquery below the window aggregates', () => {
    expect(sql).toMatch(/\(SELECT left\(to_json\(daypass_q\.\*\)::text, 1000001\) AS daypass_row FROM \(\n[\s\S]*\n\) daypass_q LIMIT 501\) daypass_l/);
    expect(sql.indexOf('left(')).toBeGreaterThan(sql.indexOf('count(*) OVER ()'));
  });
  it('stops emitting rows once the running total of BYTES reaches maxBytes', () => {
    expect(sql).toMatch(/sum\(octet_length\(daypass_row\)\)/);
    expect(sql).toMatch(/daypass_total - octet_length\(daypass_row\) < 1000000/);
    expect(sql).not.toMatch(/[^_]length\(daypass_row\)/);
  });
  it('isolates the inner query on its own line so a trailing -- comment cannot swallow the wrapper', () => {
    expect(sql).toContain('(\nselect 1 -- c\n) daypass_q');
  });
  it('orders by the row number so the client sees rows in query order', () => {
    expect(sql).toMatch(/ORDER BY daypass_n\s*$/);
  });
});

describe('parseJsonPreservingBigInts', () => {
  it('keeps integers beyond 2^53 as strings', () => {
    expect(parseJsonPreservingBigInts('{"id":9007199254740993,"n":1}')).toEqual({ id: '9007199254740993', n: 1 });
  });
  it('leaves digits inside strings alone', () => {
    expect(parseJsonPreservingBigInts('{"s":"12345678901234567890","e":"a\\"12345678901234567890"}')).toEqual({
      s: '12345678901234567890',
      e: 'a"12345678901234567890',
    });
  });
  it('leaves short floats and exponents alone, keeps a 21-digit decimal exact', () => {
    expect(parseJsonPreservingBigInts('{"f":12345678901234567890.5,"x":1e20,"y":2.5e-3}')).toEqual({ f: '12345678901234567890.5', x: 1e20, y: 2.5e-3 });
  });
  it('keeps decimals with more than 15 significant digits as exact strings', () => {
    expect(parseJsonPreservingBigInts('{"m":12345678901234567.89,"f":0.12345678901234567890123}')).toEqual({
      m: '12345678901234567.89',
      f: '0.12345678901234567890123',
    });
  });
  it('keeps numbers with up to 15 significant digits as numbers', () => {
    expect(parseJsonPreservingBigInts('[123456789012345,0.000000123456789012345,1.5,-0.0,100]')).toEqual([
      123456789012345, 0.000000123456789012345, 1.5, -0, 100,
    ]);
  });
  it('keeps float8 values that round-trip exactly as numbers (16-17 digits)', () => {
    expect(parseJsonPreservingBigInts('[0.30000000000000004,1.2345678901234567,-2.718281828459045,1e-300,1.7976931348623157e+308]')).toEqual([
      0.30000000000000004, 1.2345678901234567, -2.718281828459045, 1e-300, 1.7976931348623157e308,
    ]);
  });
  it('treats trailing zeros as exact (numeric scale), and 2^53 as exact', () => {
    expect(parseJsonPreservingBigInts('[1.50,100.000,9007199254740992,0.0]')).toEqual([1.5, 100, 9007199254740992, 0]);
  });
  it('still keeps non-round-trippable values as strings', () => {
    expect(parseJsonPreservingBigInts('[9007199254740993,12345678901234567.89,0.1234567890123456789]')).toEqual([
      '9007199254740993',
      '12345678901234567.89',
      '0.1234567890123456789',
    ]);
  });
  it('keeps a huge numeric (to_json prints all its digits) as a string', () => {
    const big = '1' + '0'.repeat(400);
    expect(parseJsonPreservingBigInts(`[${big}]`)).toEqual([big]);
  });
  it('handles negative big integers', () => {
    expect(parseJsonPreservingBigInts('[-12345678901234567890]')).toEqual(['-12345678901234567890']);
  });
});

describe('wrapWithBudget column order and numerics', () => {
  it('uses to_json (keeps column order and numeric text), not to_jsonb', () => {
    const sql = wrapWithBudget('select 1', 500, 1_000_000);
    expect(sql).toMatch(/to_json\(daypass_q\.\*\)::text/);
    expect(sql).not.toMatch(/to_jsonb/);
  });
});

describe('shapeBudgetRows', () => {
  const opts = { maxRows: 2, maxCell: 5, maxBytes: 100 };
  const db = (rows: string[], count: number) => rows.map((r) => ({ daypass_row: r, daypass_count: String(count) }));

  it('returns an empty result for no rows', () => {
    expect(shapeBudgetRows([], opts)).toEqual({ rows: [], truncated: false, note: undefined });
  });
  it('parses complete rows and applies the cell cap', () => {
    const r = shapeBudgetRows(db(['{"a":"abcdefghij","b":1}'], 1), opts);
    expect(r.rows).toEqual([{ a: 'abcde…[+5 chars]', b: 1 }]);
    expect(r.truncated).toBe(false);
  });
  it('stringifies nested json before capping', () => {
    const r = shapeBudgetRows(db(['{"j":{"k":[1,2,3]}}'], 1), { ...opts, maxCell: 100 });
    expect(r.rows[0].j).toBe('{"k":[1,2,3]}');
  });
  it('drops the sentinel row and flags the row cap', () => {
    const r = shapeBudgetRows(db(['{"a":1}', '{"a":2}', '{"a":3}'], 3), opts);
    expect(r.rows).toEqual([{ a: 1 }, { a: 2 }]);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/first 2 rows/);
  });
  it('reports a byte-budget cut when fewer rows came back than the count', () => {
    const r = shapeBudgetRows(db(['{"a":1}'], 2), opts);
    expect(r.rows).toEqual([{ a: 1 }]);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/byte budget/);
    expect(r.note).toMatch(/1 of 2 rows/);
  });
  it('reports both when the byte budget cut and more rows exist beyond the cap', () => {
    const r = shapeBudgetRows(db(['{"a":1}'], 3), opts);
    expect(r.rows).toHaveLength(1);
    expect(r.note).toMatch(/byte budget/);
    expect(r.note).toMatch(/more than 2 rows/);
  });
  it('represents a row cut mid-JSON as daypass_truncated_row', () => {
    const cut = '{"a":"' + 'x'.repeat(95); // 101 chars = maxBytes + 1, invalid JSON
    const r = shapeBudgetRows(db([cut], 1), opts);
    expect(r.rows).toHaveLength(1);
    const row = r.rows[0] as any;
    expect(Object.keys(row)).toEqual(['daypass_truncated_row']);
    expect(row.daypass_truncated_row.startsWith('{"a":"xxx')).toBe(true);
    expect(row.daypass_truncated_row.endsWith('…')).toBe(true);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/row 1 .*longer than 100 bytes/i);
  });
  it('throws a descriptive error when the result is not the wrapper shape', () => {
    expect(() => shapeBudgetRows([[{ a: 1 }], [{ b: 2 }]] as any, opts)).toThrow(/Unexpected result shape/);
    expect(() => shapeBudgetRows([{ a: 1 }] as any, opts)).toThrow(/Unexpected result shape.*daypass_row/);
    expect(() => shapeBudgetRows(undefined as any, opts)).toThrow(/Unexpected result shape/);
  });
  it('counts a row by bytes: a multibyte row over the budget is shown truncated', () => {
    const row = '{"a":"' + 'é'.repeat(60) + '"}'; // 68 chars, 128 bytes; maxBytes 100
    const r = shapeBudgetRows(db([row], 1), opts);
    expect(Object.keys(r.rows[0])).toEqual(['daypass_truncated_row']);
    expect(r.note).toMatch(/longer than 100 bytes/);
  });
  it('keeps column order', () => {
    const r = shapeBudgetRows(db(['{"z":1,"a":2,"m":3}'], 1), opts);
    expect(Object.keys(r.rows[0])).toEqual(['z', 'a', 'm']);
  });
  it('keeps the truncated row preview to 2000 chars', () => {
    const cut = '{"a":"' + 'x'.repeat(5000);
    const r = shapeBudgetRows(db([cut], 1), { maxRows: 5, maxCell: 10, maxBytes: 4000 });
    expect((r.rows[0] as any).daypass_truncated_row.length).toBe(2001);
  });
});

describe('shapeRows counts bytes, not UTF-16 code units', () => {
  it('stops at the byte budget for multi-byte text', () => {
    // Each row is 28 bytes ({"a":"…"} framing + 20 bytes of é) but 18 UTF-16 units; 40 admits one row by bytes, two by chars.
    const r = shapeRows([{ a: 'éééééééééé' }, { a: 'éééééééééé' }], { maxRows: 10, maxCell: 100, maxBytes: 40 });
    expect(r.rows).toHaveLength(1);
    expect(r.truncated).toBe(true);
  });
});
