import { describe, it, expect } from 'vitest';
import { wrapWithLimit, shapeRows } from '../src/core/shape.js';

describe('wrapWithLimit', () => {
  it('wraps a select and asks for one extra row', () => {
    expect(wrapWithLimit('select 1', 500)).toBe('SELECT * FROM (select 1) daypass_q LIMIT 501');
  });
  it('strips a trailing semicolon', () => {
    expect(wrapWithLimit('select 1 ;', 10)).toBe('SELECT * FROM (select 1) daypass_q LIMIT 11');
  });
});

describe('shapeRows', () => {
  const opts = { maxRows: 2, maxCell: 5, maxBytes: 10_000 };
  it('passes small results through', () => {
    const r = shapeRows([{ a: 1 }], opts);
    expect(r.rows).toEqual([{ a: 1 }]);
    expect(r.truncated).toBe(false);
  });
  it('drops the sentinel row and flags truncation', () => {
    const r = shapeRows([{ a: 1 }, { a: 2 }, { a: 3 }], opts);
    expect(r.rows).toHaveLength(2);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/2 rows/);
  });
  it('cuts long cells', () => {
    const r = shapeRows([{ a: 'abcdefghij' }], opts);
    expect(r.rows[0].a).toBe('abcde…[+5 chars]');
  });
  it('stops at the byte budget', () => {
    const r = shapeRows([{ a: 'xxxx' }, { a: 'yyyy' }, { a: 'zzzz' }], { maxRows: 10, maxCell: 100, maxBytes: 20 });
    expect(r.rows.length).toBeLessThan(3);
    expect(r.truncated).toBe(true);
    expect(r.note).toMatch(/byte/);
  });
  it('serialises bigint, Date and Buffer safely', () => {
    const r = shapeRows([{ n: 10n, d: new Date('2026-01-01T00:00:00Z'), b: Buffer.from('hi') }], { maxRows: 5, maxCell: 100, maxBytes: 1000 });
    expect(r.rows[0]).toEqual({ n: '10', d: '2026-01-01T00:00:00.000Z', b: '<2 bytes>' });
  });
});
