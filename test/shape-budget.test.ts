import { describe, it, expect } from 'vitest';
import { wrapWithBudget, shapeBudgetRows, parseJsonPreservingBigInts, shapeRows } from '../src/core/shape.js';

describe('wrapWithBudget', () => {
  const sql = wrapWithBudget('select 1 -- c', 500, 1_000_000);
  it('caps rows in SQL with one sentinel row', () => {
    expect(sql).toMatch(/LIMIT 501\b/);
  });
  it('cuts each row to maxBytes + 1 chars in SQL, in the LIMIT subquery below the window aggregates', () => {
    expect(sql).toMatch(
      /\(SELECT left\(coalesce\([\s\S]*, 1000001\) AS daypass_row\n\s*FROM \(SELECT [\s\S]* AS daypass_j\n\s*FROM \(SELECT to_json\(daypass_q\.\*\) AS daypass_r FROM \(\n[\s\S]*\n\) daypass_q LIMIT 501\) daypass_v OFFSET 0\) daypass_w OFFSET 0\) daypass_l/,
    );
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
    expect(sql).toMatch(/to_json\(daypass_q\.\*\)/);
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
  it('drops a row cut mid-JSON with a note instead of showing a slice of it', () => {
    const cut = '{"a":"' + 'x'.repeat(95); // 101 chars = maxBytes + 1, invalid JSON
    const r = shapeBudgetRows(db([cut], 1), opts);
    expect(r.rows).toEqual([]);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/row 1 is larger than the 100 byte budget/i);
  });
  it('throws a descriptive error when the result is not the wrapper shape', () => {
    expect(() => shapeBudgetRows([[{ a: 1 }], [{ b: 2 }]] as any, opts)).toThrow(/Unexpected result shape/);
    expect(() => shapeBudgetRows([{ a: 1 }] as any, opts)).toThrow(/Unexpected result shape.*daypass_row/);
    expect(() => shapeBudgetRows(undefined as any, opts)).toThrow(/Unexpected result shape/);
  });
  it('counts a row by bytes: a multibyte row over the budget is not shown', () => {
    const row = '{"a":"' + 'é'.repeat(60) + '"}'; // 68 chars, 128 bytes; maxBytes 100
    const r = shapeBudgetRows(db([row], 1), { ...opts, maxCell: 100 });
    expect(r.rows).toEqual([]);
    expect(r.note).toMatch(/larger than the 100 byte budget/);
  });
  it('keeps column order', () => {
    const r = shapeBudgetRows(db(['{"z":1,"a":2,"m":3}'], 1), opts);
    expect(Object.keys(r.rows[0])).toEqual(['z', 'a', 'm']);
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

describe('2026-11 shaping fixes', () => {
  const db = (rows: string[], count: number) => rows.map((r) => ({ daypass_row: r, daypass_count: String(count) }));
  const big = { maxRows: 5, maxCell: 2000, maxBytes: 1_000_000 };

  it('keeps every column when names repeat, renaming the later ones and saying so', () => {
    const r = shapeBudgetRows(db(['{"count":3,"count":2,"sum":10.5,"sum":7}'], 1), big);
    expect(Object.keys(r.rows[0])).toEqual(['count', 'count_2', 'sum', 'sum_2']);
    expect(r.rows[0]).toEqual({ count: 3, count_2: 2, sum: 10.5, sum_2: 7 });
    expect(r.truncated).toBe(false);
    expect(r.note).toMatch(/renamed/i);
    expect(r.note).toContain('count_2');
    expect(r.note).toContain('sum_2');
  });
  it('picks a rename that does not clash with an existing column name', () => {
    const r = shapeBudgetRows(db(['{"a":1,"a":2,"a_2":3,"a":4}'], 1), big);
    expect(Object.keys(r.rows[0])).toEqual(['a', 'a_3', 'a_2', 'a_4']);
    expect(r.rows[0]).toEqual({ a: 1, a_3: 2, a_2: 3, a_4: 4 });
  });
  it('renames repeated ?column? names', () => {
    const r = shapeBudgetRows(db(['{"?column?":1,"?column?":2}'], 1), big);
    expect(r.rows[0]).toEqual({ '?column?': 1, '?column?_2': 2 });
  });
  it('keeps a column named __proto__ as a plain column', () => {
    const r = shapeBudgetRows(db(['{"__proto__":1,"b":2}'], 1), big);
    expect(JSON.stringify(r.rows)).toBe('[{"__proto__":1,"b":2}]');
  });
  it('turns a cell the database cut (!N"...") into text with the marker', () => {
    const r = shapeBudgetRows(db(['{"id":1,"big":!1098000"xxxx","important":42}'], 1), { ...big, maxCell: 4 });
    expect(r.rows[0]).toEqual({ id: 1, big: 'xxxx…[+1098000 chars]', important: 42 });
  });
  it('keeps big numbers inside json exact (no quotes) and compacts whitespace', () => {
    const r = shapeBudgetRows(db(['{"j":{"a": 12345678901234567890, "s": "x y"},"n":12345678901234567890}'], 1), big);
    expect(r.rows[0]).toEqual({ j: '{"a":12345678901234567890,"s":"x y"}', n: '12345678901234567890' });
  });
  it('drops a row the database cut mid-JSON with a note, never a raw JSON slice', () => {
    const cut = '{"a":"' + 'x'.repeat(95);
    const r = shapeBudgetRows(db(['{"a":1}', cut], 2), { maxRows: 5, maxCell: 2000, maxBytes: 100 });
    expect(r.rows).toEqual([{ a: 1 }]);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/Row 2 .*larger than the 100 byte budget/);
  });
  it('keeps the total returned within maxBytes after cell caps', () => {
    const row = '{"s":"' + 'y'.repeat(30) + '"}'; // 38 bytes each
    const r = shapeBudgetRows(db([row, row, row], 3), { maxRows: 5, maxCell: 2000, maxBytes: 100 });
    expect(Buffer.byteLength(JSON.stringify(r.rows))).toBeLessThanOrEqual(102);
    expect(r.rows).toHaveLength(2);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/2 of 3 rows.*100 byte budget/);
  });
  it('a row with zero columns is an empty object', () => {
    expect(shapeBudgetRows(db(['{}'], 1), big).rows).toEqual([{}]);
  });
});

describe('2026-11 round 2 shaping fixes', () => {
  const db = (rows: string[], count: number) => rows.map((r) => ({ daypass_row: r, daypass_count: String(count) }));
  const big = { maxRows: 5, maxCell: 2000, maxBytes: 1_000_000 };

  it('keeps the whitespace of a cut text cell that starts with { or [', () => {
    const r = shapeBudgetRows(db(['{"t":!5"{ \\"a\\" :  1","l":!3"[INFO]  x  y"}'], 1), big);
    expect(r.rows[0]).toEqual({ t: '{ "a" :  1…[+5 chars]', l: '[INFO]  x  y…[+3 chars]' });
  });
  it('compacts the kept prefix of a cut json object or array (!Nj)', () => {
    const r = shapeBudgetRows(db(['{"j":!7j"{\\"k\\" : \\"a b\\", ","a":!2j"[1, 2"}'], 1), big);
    expect(r.rows[0]).toEqual({ j: '{"k":"a b",…[+7 chars]', a: '[1,2…[+2 chars]' });
  });
  it('caps the renamed-columns note at 20 names', () => {
    const row = '{' + Array.from({ length: 1664 }, () => '"x":1').join(',') + '}';
    const r = shapeBudgetRows(db([row], 1), big);
    expect(Object.keys(r.rows[0])).toHaveLength(1664);
    expect(r.note).toContain('column 21 "x" is "x_21"');
    expect(r.note).not.toContain('column 22 "x"');
    expect(r.note).toContain('and 1643 more');
    expect(r.note!.length).toBeLessThan(1000);
  });
  it('renames integer-like column names so the columns keep their order', () => {
    const r = shapeBudgetRows(db(['{"b":1,"1":2,"0":3,"a":4,"01":5,"_1":6}'], 1), big);
    expect(Object.keys(r.rows[0])).toEqual(['b', '_1_2', '_0', 'a', '01', '_1']);
    expect(r.rows[0]).toEqual({ b: 1, _1_2: 2, _0: 3, a: 4, '01': 5, _1: 6 });
    expect(r.note).toContain('column 2 "1" is "_1_2"');
    expect(r.note).toContain('column 3 "0" is "_0"');
  });
});

describe('wrapWithBudget caps each cell in SQL', () => {
  const sql = wrapWithBudget('select 1', 500, 1_000_000, 2000);
  it('walks the row cells in column order and cuts long cells to maxCell chars', () => {
    expect(sql).toMatch(/to_json\(daypass_q\.\*\) AS daypass_r/);
    expect(sql).toMatch(/json_object_keys\(daypass_w\.daypass_j\) WITH ORDINALITY/);
    expect(sql).toMatch(/json_each\(daypass_w\.daypass_j\) WITH ORDINALITY/);
    expect(sql).toMatch(/ORDER BY daypass_e\.daypass_i/);
    expect(sql).toMatch(/left\(daypass_c\.daypass_t, 2000\)/);
  });
  it('uses only ASCII in the wrapper (any server encoding)', () => {
    expect(/^[\x00-\x7f]*$/.test(sql)).toBe(true);
  });
  it('defaults maxCell to 2000', () => {
    expect(wrapWithBudget('select 1', 500, 1_000_000)).toBe(sql);
  });
});

describe('code-point cuts', () => {
  it('never splits a surrogate pair and counts the rest in code points', () => {
    const r = shapeRows([{ a: '😀😀😀' }], { maxRows: 5, maxCell: 2, maxBytes: 1000 });
    expect(r.rows[0].a).toBe('😀😀…[+1 chars]');
  });
  it('does not cut a string of maxCell astral characters', () => {
    const r = shapeRows([{ a: '😀😀' }], { maxRows: 5, maxCell: 2, maxBytes: 1000 });
    expect(r.rows[0].a).toBe('😀😀');
  });
});

describe('EXPLAIN plans', () => {
  it('a long EXPLAIN (FORMAT JSON) plan is not cut by the cell cap, so it stays valid JSON', () => {
    const plan = [{ Plan: { 'Node Type': 'Seq Scan', Filter: 'x'.repeat(5000) } }];
    const r = shapeRows([{ 'QUERY PLAN': plan }], { maxRows: 5, maxCell: 2000, maxBytes: 1_000_000 });
    expect(JSON.parse(r.rows[0]['QUERY PLAN'] as string)).toEqual(plan);
  });
  it('a plan over the byte budget is refused with a note, not cut', () => {
    const plan = [{ Plan: { Filter: 'x'.repeat(5000) } }];
    const r = shapeRows([{ 'QUERY PLAN': plan }], { maxRows: 5, maxCell: 2000, maxBytes: 1000 });
    expect(r.rows).toEqual([]);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/byte budget/);
  });
});
