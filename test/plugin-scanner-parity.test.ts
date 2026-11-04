// The hook's tokenizer must cut SQL where Postgres's scanner does: a comment, string or
// identifier that ends one character early or late hides SQL from the guard (or shows it text
// that Postgres reads as code). This compares token boundaries with libpg-query's scanSync,
// which is Postgres's own scan.l, on hand-picked edge cases and on generated inputs.
import { beforeAll, describe, it, expect } from 'vitest';
import { loadModule, scanSync } from 'libpg-query';
import { tokenize } from '../plugin/hooks/pii-guard.mjs';

type Span = [cls: string, start: number, end: number];

/** Byte offset of every UTF-16 index (scanSync reports UTF-8 byte offsets). */
function byteOffsets(sql: string): number[] {
  const out = new Array<number>(sql.length + 1);
  let b = 0;
  for (let i = 0; i < sql.length; i++) {
    out[i] = b;
    const c = sql.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < sql.length) {
      out[i + 1] = b;
      b += 4;
      i++;
    } else b += c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
  }
  out[sql.length] = b;
  return out;
}

/** Non-operator tokens as [class, start, end]; operator/punctuation characters as a set of byte positions (Postgres groups `<>`, `::`, `..` into one token, the hook does not). */
function hookShape(sql: string) {
  const off = byteOffsets(sql);
  const spans: Span[] = [];
  const ops = new Set<number>();
  for (const t of tokenize(sql)) {
    const cls = { ident: 'word', string: 'str', number: 'num', param: 'param' }[t.type as string];
    if (cls) spans.push([cls, off[t.start], off[t.end]]);
    else for (let b = off[t.start]; b < off[t.end]; b++) ops.add(b);
  }
  return { spans, ops };
}

const isComment = (n: string) => n === 'SQL_COMMENT' || n === 'C_COMMENT';

function pgShape(sql: string) {
  const buf = Buffer.from(sql, 'utf8');
  const all = scanSync(sql).tokens;
  const toks = all.filter((t) => !isComment(t.tokenName));
  const cls = (t: (typeof toks)[number]) => {
    if (t.tokenName === 'ICONST' || t.tokenName === 'FCONST') return 'num';
    if (t.tokenName === 'PARAM') return 'param';
    if (t.tokenName === 'IDENT' || t.keywordKind !== 0 || /^[Uu]&"/.test(t.text)) return 'word';
    if (/^(?:'|[EeBbXx]'|[Uu]&')/.test(t.text) || /^\$[^$]*\$[\s\S]*\$$/.test(t.text)) return 'str';
    return 'op';
  };
  const spans: Span[] = [];
  const ops = new Set<number>();
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    let c = cls(t);
    let end = t.end;
    let uescape = false;
    // N'...' is scanned as the keyword N and a string; the hook reads one string
    if (c === 'word' && /^[Nn]$/.test(t.text) && toks[k + 1] && toks[k + 1].start === t.end && cls(toks[k + 1]) === 'str') {
      c = 'str';
      end = toks[++k].end;
    }
    // U&"..." UESCAPE '<c>' is one name (gram.y's base_yylex joins them); the hook reads one token
    if (/^[Uu]&"/.test(t.text) && toks[k + 1]?.text.toLowerCase() === 'uescape' && toks[k + 2] && cls(toks[k + 2]) === 'str') {
      end = toks[k + 2].end;
      k += 2;
      uescape = true;
    }
    if ((c === 'str' || uescape) && buf[end - 1] === 0x27) {
      // Quote continuation across `--` comments: Postgres joins `'a' --c\n'b'` into one constant
      // (checked on PG 16 and 17), but libpg-query emits the comments as tokens and so splits it.
      for (;;) {
        let j = all.indexOf(toks[k]) + 1;
        while (all[j]?.tokenName === 'SQL_COMMENT') j++;
        const nxt = all[j];
        if (j === all.indexOf(toks[k]) + 1 || !nxt || nxt.text[0] !== "'") break;
        const gap = buf.subarray(end, nxt.start).toString('utf8');
        if (!/^(?:[ \t\f\v]|--[^\n\r]*)*[\n\r](?:[ \t\n\r\f\v]|--[^\n\r]*[\n\r])*$/.test(gap)) break;
        end = nxt.end;
        k = toks.indexOf(nxt);
      }
    }
    if (c === 'op') for (let b = t.start; b < t.end; b++) ops.add(b);
    else spans.push([c, t.start, end]);
  }
  return { spans, ops };
}

/** Postgres's verdict, or null when it rejects the input (an error leaks nothing). */
function pgOrNull(sql: string) {
  try {
    return pgShape(sql);
  } catch {
    return null;
  }
}

const EDGE = [
  'select id, --x\r email from users',
  'select 1 --x\r, * from users',
  'a --x\r\nb',
  'a --x\n\rb',
  'a\vb\fc\rd\te\nf',
  'a /* x /* y */ z */ b',
  'a /*/ b */ c',
  'a /**/ b /***/ c',
  'a */* b */ c',
  'a +/* b */ c',
  'a +-- b\n c',
  'a <-- b\n c',
  "select 'it''s', 'a\\', x",
  "select E'\\'', x",
  "select e'a\\\\' , x",
  "select E'\\x41\\101\\u0041' x",
  "select 'a'\n'b' x",
  "select 'a'\r'b' x",
  "select 'a'  \n  'b' x",
  "select 'a'\n\n\t'b' x",
  "select 'a'\n--c\n'b' x",
  "select 'a' --c\n'b' x",
  "select 'a' 'b'",
  "select E'a'\n'b' x",
  "select B'01'\n'10' x",
  "select X'0F''1' x",
  "select N'a' x",
  "select n'a'\n'b' x",
  "select U&'a\\0061' x",
  "select U&'a!0061' uescape '!' x",
  'select U&"em\\0061il" x',
  "select U&\"em!0061il\" UESCAPE '!' x",
  "select U&\"em!0061il\" /* c */ UESCAPE /* d */ '!' x",
  'select U&"em!0061il" UESCAPE $$!$$ x',
  "select U&\"em!0061il\" UESCAPE E'!' x",
  'select "a""b", "x\'y" from t',
  'select $$a$$, $tag$ $x$ $$ $tag$, $a$$b$a$ x',
  'select $1, $12 x',
  'select a$b, a$$b$$ from t',
  'select $a x',
  'select 1, 1.5, .5, 1., 1e5, 1.5e-3, 1E+3 x',
  'select 0x1F, 0o17, 0b101, 1_000, 1_000.000_1 x',
  'select 1..2',
  'select 1::int, a::text',
  'select a<>b, a>=b, a!=b, a=>b, a:=b, a||b',
  'select ä, Ølé, "naïve", 日本 from t',
  'select a b from t',
  'select a.b.c, a.*, (a).b from t',
  'select count(*) from t;',
  "select 'x'::text as y",
  'select e from t',
  'select U&x',
  'select UESCAPE',
  'select 1 -- trailing',
  'select 1 /* trailing */',
];

/** Fragments for generated inputs: every scanner state, joined in random order. */
const FRAGMENTS = [
  ' ', '\n', '\r', '\t', '\f', '\v', '--c\n', '--c\r', '--c\r\n', '/* c */', '/* a /* b */ c */', '/**/',
  "'s'", "''", "'a''b'", "E's\\''", "e'\\\\'", "B'01'", "X'0f'", "N's'", "U&'s'", '$$d$$', '$q$ $ $$ $q$', '$1',
  '"q"', '"a""b"', 'U&"\\0061"', "U&\"!0061\" UESCAPE '!'", 'ident', 'é', 'select', 'from', 'u', 'email', '1', '1.5',
  '.5', '1e3', '0x1F', '1_000', '::', '*', ',', '(', ')', '.', ';', '+', '-', '<', '>', '=', '|', '[', ']',
];

describe('tokenizer token boundaries match Postgres (libpg-query scanSync)', () => {
  beforeAll(async () => {
    await loadModule();
  });

  it.each(EDGE)('agrees on %j', (sql) => {
    const pg = pgOrNull(sql);
    expect(pg, `scanSync rejected ${JSON.stringify(sql)}`).not.toBeNull();
    const hook = hookShape(sql);
    expect(hook.spans).toEqual(pg!.spans);
    expect([...hook.ops].sort((a, b) => a - b)).toEqual([...pg!.ops].sort((a, b) => a - b));
  });

  it('agrees on 10000 generated inputs', () => {
    let seed = 20261101;
    const rand = (n: number) => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    let compared = 0;
    for (let i = 0; i < 10000; i++) {
      const parts: string[] = [];
      const len = 2 + rand(10);
      for (let j = 0; j < len; j++) parts.push(FRAGMENTS[rand(FRAGMENTS.length)]);
      const sql = parts.join(rand(3) === 0 ? '' : ' ');
      const pg = pgOrNull(sql);
      if (pg === null) continue;
      compared++;
      const hook = hookShape(sql);
      expect(hook.spans, JSON.stringify(sql)).toEqual(pg.spans);
      expect([...hook.ops].sort((a, b) => a - b), JSON.stringify(sql)).toEqual([...pg.ops].sort((a, b) => a - b));
    }
    expect(compared).toBeGreaterThan(5000);
  });
});
