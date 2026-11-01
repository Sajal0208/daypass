import { describe, it, expect } from 'vitest';
import { tokenize } from '../plugin/hooks/pii-guard.mjs';

const kinds = (sql: string) => tokenize(sql).map((t) => `${t.type}:${t.value}`);

describe('tokenize', () => {
  it('splits identifiers, punctuation, numbers and operators', () => {
    expect(kinds('select u.id, 2*3 from users u')).toEqual([
      'ident:select', 'ident:u', 'punct:.', 'ident:id', 'punct:,', 'number:2', 'op:*', 'number:3', 'ident:from', 'ident:users', 'ident:u',
    ]);
  });
  it('keeps :: as one operator', () => {
    expect(kinds('u::text')).toEqual(['ident:u', 'op:::', 'ident:text']);
  });
  it("reads '...' with '' escapes and no backslash escape", () => {
    expect(kinds("'it''s' , 'a\\' , x")).toEqual(['string:', 'punct:,', 'string:', 'punct:,', 'ident:x']);
  });
  it("reads E'...' with backslash escapes", () => {
    expect(kinds("E'\\'' , x -- '")).toEqual(['string:', 'punct:,', 'ident:x']);
    expect(kinds("e'a\\\\' , x")).toEqual(['string:', 'punct:,', 'ident:x']);
  });
  it('reads $$ and $tag$ strings, and $n parameters', () => {
    expect(kinds("$$'$$ , x where y = $tag$ ' $$ $tag$ and z = $1")).toEqual([
      'string:', 'punct:,', 'ident:x', 'ident:where', 'ident:y', 'op:=', 'string:', 'ident:and', 'ident:z', 'op:=', 'param:$1',
    ]);
  });
  it('reads "..." identifiers with "" escapes and marks them quoted', () => {
    const t = tokenize('"x\'y", "a""b"');
    expect(t[0]).toMatchObject({ type: 'ident', value: "x'y", quoted: true });
    expect(t[2]).toMatchObject({ type: 'ident', value: 'a"b', quoted: true });
  });
  it('decodes U&"..." identifiers, with \\XXXX, \\+XXXXXX and UESCAPE', () => {
    expect(tokenize('U&"ph\\006Fne"')[0]).toMatchObject({ type: 'ident', value: 'phone', quoted: true });
    expect(tokenize('U&"ph\\+00006Fne"')[0]).toMatchObject({ type: 'ident', value: 'phone' });
    expect(tokenize("U&\"ph!006Fne\" UESCAPE '!'")).toHaveLength(1);
    expect(tokenize("U&\"ph!006Fne\" UESCAPE '!'")[0].value).toBe('phone');
    expect(tokenize('U&"a\\\\b"')[0].value).toBe('a\\b');
  });
  it('drops -- and nested /* */ comments', () => {
    expect(kinds('a -- b\n c /* d /* e */ f */ g')).toEqual(['ident:a', 'ident:c', 'ident:g']);
  });
  it('folds unquoted identifiers to lower case in fold, keeps quoted as written', () => {
    const t = tokenize('Users "Users"');
    expect(t[0].fold).toBe('users');
    expect(t[1].fold).toBe('Users');
  });
  it('reads numbers in their common forms', () => {
    expect(kinds('1 1.5 .5 1e5 1.5e-3 0x1F 1_000')).toEqual(['number:1', 'number:1.5', 'number:.5', 'number:1e5', 'number:1.5e-3', 'number:0x1F', 'number:1_000']);
  });
  it('survives unterminated strings and comments', () => {
    expect(kinds("a 'b")).toEqual(['ident:a', 'string:']);
    expect(kinds('a /* b')).toEqual(['ident:a']);
    expect(kinds('a $$ b')).toEqual(['ident:a', 'string:']);
  });
});

describe('tokenize: 2026-10-30 review fixes', () => {
  it('finds UESCAPE after whitespace and comments', () => {
    for (const sql of [`U&"!0070hone" /* c */ UESCAPE '!'`, `U&"!0070hone" -- c\n UESCAPE '!'`, `U&"!0070hone"/*a /* n */ */uescape'!'`]) {
      const t = tokenize(sql);
      expect(t, sql).toHaveLength(1);
      expect(t[0].value, sql).toBe('phone');
    }
  });
  it('leaves a U& identifier without UESCAPE alone', () => {
    expect(kinds(`U&"a" /* c */ x`)).toEqual(['ident:a', 'ident:x']);
  });
  it("flags a '...' string whose end moves when standard_conforming_strings is off", () => {
    expect(tokenize("'a\\'' x'")[0].ambiguous).toBe(true);
    expect(tokenize("'C:\\' x")[0].ambiguous).toBe(true);
    // both readings run to the end of the input: nothing after it can hide
    expect(tokenize("'C:\\'")[0].ambiguous).toBeFalsy();
    expect(tokenize("'a\\\\b'")[0].ambiguous).toBeFalsy();
    expect(tokenize("'it''s'")[0].ambiguous).toBeFalsy();
    expect(tokenize("E'a\\''")[0].ambiguous).toBeFalsy();
  });
});

describe('tokenize: second review fixes', () => {
  it('folds unquoted names by lower-casing A-Z only, like Postgres', () => {
    const t = tokenize('Ku PHONE');
    expect(t[0].fold).toBe('Ku');
    expect(t[1].fold).toBe('phone');
  });
  it('truncates identifiers to 63 bytes at a character boundary', () => {
    expect(tokenize('a'.repeat(70))[0].value).toBe('a'.repeat(63));
    expect(tokenize(`"${'é'.repeat(40)}"`)[0].value).toBe('é'.repeat(31));
    expect(tokenize('short')[0].value).toBe('short');
  });
});
