export interface ShapeOptions {
  maxRows: number;
  maxCell: number;
  maxBytes: number;
}

export interface Shaped {
  rows: Record<string, unknown>[];
  truncated: boolean;
  note?: string;
}

/** No longer used: rows are no longer shown as a slice of raw JSON. Kept so the ./core export stays stable. */
export const TRUNCATED_ROW_PREVIEW_CHARS = 2000;

/**
 * Ask for one row more than the cap so we can tell "exactly N" from "more than N".
 * Expects canonical SQL (see `checkSql`): no trailing comment or semicolon.
 */
export function wrapWithLimit(sql: string, maxRows: number): string {
  const inner = sql.trim().replace(/;\s*$/, '').trim();
  return `SELECT * FROM (${inner}) daypass_q LIMIT ${maxRows + 1}`;
}

/**
 * `daypass_v.daypass_r` (one row's json) with each \u escape Postgres cannot decode made literal
 * text by doubling its backslash: \u0000, a surrogate escape that is not part of a high+low pair,
 * and, when the database is not UTF8, any escape above U+007F. Only a row whose text contains
 * `\u` and matches the quick pattern is tokenised: a surrogate pair, a \u escape, any other escape
 * or a run without backslashes, left to right, so an escaped backslash before `u0000` is never
 * taken for an escape. E'' strings: independent of standard_conforming_strings. ASCII only.
 */
const SAFE_ESCAPES = String.raw`CASE WHEN strpos(daypass_v.daypass_r::text, E'\\u') > 0
            AND (daypass_v.daypass_r::text ~ E'\\\\u(0000|[dD][89a-fA-F])'
                 OR (getdatabaseencoding() <> 'UTF8' AND daypass_v.daypass_r::text ~ E'\\\\u(?!00[0-7])'))
          THEN (SELECT string_agg(CASE WHEN daypass_x.daypass_m[1] ~ E'^\\\\u(0000|[dD][89a-fA-F][0-9a-fA-F]{2})$'
                                         OR (getdatabaseencoding() <> 'UTF8' AND daypass_x.daypass_m[1] ~ E'^\\\\u(?!00[0-7])')
                                       THEN replace(daypass_x.daypass_m[1], E'\\', E'\\\\') ELSE daypass_x.daypass_m[1] END, '' ORDER BY daypass_x.daypass_o)
                  FROM regexp_matches(daypass_v.daypass_r::text,
                         E'\\\\u[dD][89abAB][0-9a-fA-F]{2}\\\\u[dD][c-fC-F][0-9a-fA-F]{2}|\\\\u[0-9a-fA-F]{4}|\\\\.|[^\\\\]+', 'g')
                       WITH ORDINALITY AS daypass_x(daypass_m, daypass_o))::json
          ELSE daypass_v.daypass_r END`;

/**
 * Push the row cap, the per-cell cap AND the byte budget into SQL so the database, not Node, does the cutting.
 *
 * Shape of what comes back: one text column `daypass_row` and `daypass_count` (rows the inner
 * query produced, capped at maxRows+1). `daypass_row` is the row as a JSON-like object text built
 * from the cells of `to_json(daypass_q.*)`: every column in order, duplicate names kept (a JSON
 * object would keep only the last), json values verbatim (exact numbers). A cell whose text is
 * longer than maxCell characters is cut in SQL and written as `!N"first maxCell chars"` (N = chars
 * cut; `!Nj"..."` when the cell is a json object or array), which is not JSON and so cannot be
 * faked by data; `shapeBudgetRows` decodes it. The row is
 * then cut to maxBytes+1 chars as a safety net (only a row of hundreds of capped cells reaches it).
 * Both cuts sit in a level the planner cannot pull up (OFFSET 0) above the LIMIT one.
 *
 * Postgres stops emitting rows once the running total of previous rows reaches maxBytes
 * (octet_length: UTF-8 bytes, counted on the capped rows), so the wire carries at most maxBytes
 * bytes + one row of at most maxBytes+1 characters, and never more than maxRows+1 rows;
 * `shapeBudgetRows` then returns only rows that fit in maxBytes. The cuts happen in the LIMIT
 * subquery, below the window aggregates: their tuplestore then only ever buffers cut rows, so a
 * huge value is truncated rather than spilled to disk (where temp_file_limit would fail the
 * query). The extra LIMIT level also keeps `count(*) OVER ()` from scanning past maxRows+1.
 * Every json function used to split the row decodes the row's \u escapes, and Postgres refuses to
 * decode \u0000, a lone surrogate (both can sit in a json value) or, outside UTF8 databases, a
 * character above U+007F: one such value would fail the whole query. Such escapes get their
 * backslash doubled first (SAFE_ESCAPES), so they are shown as text (`\u0000`).
 * `to_json` (not to_jsonb) keeps column order and prints numerics with all their digits;
 * `daypass_q.*` is a whole-row reference even when the user's query has a column named
 * `daypass_q` (bare `daypass_q` would resolve to that column). The wrapper is ASCII only, so it
 * runs under any server encoding. The inner query sits on its own line: a trailing `--` comment
 * that survived canonicalisation cannot swallow the wrapper.
 */
export function wrapWithBudget(sql: string, maxRows: number, maxBytes: number, maxCell = 2000): string {
  const r = Math.floor(maxRows);
  const b = Math.floor(maxBytes);
  const c = Math.floor(maxCell);
  const j = 'daypass_w.daypass_j';
  // One object text from the cells listed by `from` (key daypass_e.daypass_k, position
  // daypass_e.daypass_i, value daypass_f.daypass_v). daypass_t is NULL for a cell whose JSON text
  // fits (a string's value is never longer than its JSON text), so short cells skip the unescape.
  // OFFSET 0 keeps each lateral from being inlined, so a value is fetched and unescaped once.
  const agg = (from: string) =>
    `(SELECT '{' || string_agg(to_json(daypass_e.daypass_k)::text || ':' ||\n` +
    `        CASE WHEN length(daypass_c.daypass_t) > ${c}\n` +
    `             THEN '!' || (length(daypass_c.daypass_t) - ${c})\n` +
    `                  || CASE WHEN json_typeof(daypass_f.daypass_v) IN ('object', 'array') THEN 'j' ELSE '' END\n` +
    `                  || to_json(left(daypass_c.daypass_t, ${c}))::text\n` +
    `             ELSE daypass_f.daypass_v::text END, ',' ORDER BY daypass_e.daypass_i) || '}'\n` +
    `      FROM ${from}\n` +
    `      CROSS JOIN LATERAL (SELECT CASE WHEN length(daypass_f.daypass_v::text) <= ${c} THEN NULL\n` +
    `        WHEN json_typeof(daypass_f.daypass_v) = 'string' THEN daypass_f.daypass_v #>> '{}'\n` +
    `        ELSE daypass_f.daypass_v::text END AS daypass_t OFFSET 0) daypass_c)`;
  // Distinct names: list only the keys and fetch each value with ->, so no work_mem tuplestore
  // ever holds a huge value (json_each would spill it to disk, into temp_file_limit). Repeated
  // names (-> would return the last one for each): json_each, which keeps every value by position.
  const capped =
    `coalesce(CASE WHEN (SELECT count(*) = count(DISTINCT daypass_k) FROM json_object_keys(${j}) daypass_k)\n` +
    `  THEN ${agg(`json_object_keys(${j}) WITH ORDINALITY AS daypass_e(daypass_k, daypass_i)\n` +
      `      CROSS JOIN LATERAL (SELECT ${j} -> daypass_e.daypass_k AS daypass_v OFFSET 0) daypass_f`)}\n` +
    `  ELSE ${agg(`json_each(${j}) WITH ORDINALITY AS daypass_e(daypass_k, daypass_f_v, daypass_i)\n` +
      `      CROSS JOIN LATERAL (SELECT daypass_e.daypass_f_v AS daypass_v) daypass_f`)} END, '{}')`;
  return (
    `SELECT daypass_row, daypass_count FROM (\n` +
    `  SELECT daypass_row, daypass_n, daypass_count,\n` +
    `         sum(octet_length(daypass_row)) OVER (ORDER BY daypass_n ROWS UNBOUNDED PRECEDING) AS daypass_total\n` +
    `  FROM (\n` +
    `    SELECT daypass_row, row_number() OVER () AS daypass_n, count(*) OVER () AS daypass_count\n` +
    `    FROM (SELECT left(${capped}, ${b + 1}) AS daypass_row\n` +
    `      FROM (SELECT ${SAFE_ESCAPES} AS daypass_j\n` +
    `        FROM (SELECT to_json(daypass_q.*) AS daypass_r FROM (\n${sql}\n) daypass_q LIMIT ${r + 1}) daypass_v OFFSET 0) daypass_w OFFSET 0) daypass_l\n` +
    `  ) daypass_s\n` +
    `) daypass_t WHERE daypass_total - octet_length(daypass_row) < ${b} ORDER BY daypass_n`
  );
}

/**
 * JSON.parse, but numbers a double cannot hold exactly (int8 beyond 2^53, long numerics,
 * decimals included) become exact strings instead of losing precision. Walks the text once, skipping string literals.
 */
export function parseJsonPreservingBigInts(text: string): unknown {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < n) {
        if (text[j] === '\\') j += 2;
        else if (text[j] === '"') break;
        else j++;
      }
      out += text.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === '-' || (ch >= '0' && ch <= '9')) {
      let j = i + 1;
      while (j < n && /[0-9.eE+-]/.test(text[j])) j++;
      const token = text.slice(i, j);
      out += isExactUnsafe(token) ? `"${token}"` : token;
      i = j;
      continue;
    }
    out += ch;
    i++;
  }
  return JSON.parse(out);
}

/** A decimal literal as sign, significant digits and power of ten, so equal values compare equal ("1.50" = "1.5", "1e+21" = "1000000000000000000000"). */
function canonDecimal(token: string): string {
  const neg = token.startsWith('-');
  const [mant, exp = '0'] = token.replace(/^[-+]/, '').toLowerCase().split('e');
  const [int, frac = ''] = mant.split('.');
  let digits = (int + frac).replace(/^0+/, '');
  if (digits === '') return '0';
  let e = Number(exp) - frac.length;
  const trimmed = digits.replace(/0+$/, '');
  e += digits.length - trimmed.length;
  digits = trimmed;
  return `${neg ? '-' : ''}${digits}e${e}`;
}

/**
 * True when JSON.parse would not give back this exact value: the double nearest to it prints
 * as a different decimal (int8 beyond 2^53, long numerics). float8 output round-trips by
 * construction, so it stays a number even with 16-17 digits.
 */
function isExactUnsafe(token: string): boolean {
  const n = Number(token);
  if (!Number.isFinite(n)) return true;
  return canonDecimal(String(n)) !== canonDecimal(token);
}

/** Cut a string to `max` code points (never inside a surrogate pair); the marker counts the rest in code points. */
function capText(s: string, max: number): string {
  if (s.length <= max) return s; // UTF-16 length bounds the code-point count
  let i = 0;
  for (let cp = 0; cp < max && i < s.length; cp++) i += s.codePointAt(i)! > 0xffff ? 2 : 1;
  if (i >= s.length) return s;
  let rest = 0;
  for (let j = i; j < s.length; rest++) j += s.codePointAt(j)! > 0xffff ? 2 : 1;
  return `${s.slice(0, i)}…[+${rest} chars]`;
}

function cell(v: unknown, maxCell: number): unknown {
  if (v === null || v === undefined) return null;
  if (typeof v === 'bigint') return v.toString();
  if (v instanceof Date) return v.toISOString();
  if (Buffer.isBuffer(v)) return `<${v.length} bytes>`;
  if (typeof v === 'object') v = JSON.stringify(v);
  if (typeof v === 'string') return capText(v, maxCell);
  return v;
}

/** JSON text without the whitespace outside strings (json/jsonb print `{"a": 1}`); works on a prefix too. */
function compactJson(text: string): string {
  let out = '';
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      out += ch;
      if (ch === '\\') out += text[++i] ?? '';
      else if (ch === '"') inStr = false;
    } else if (ch === '"') {
      out += ch;
      inStr = true;
    } else if (ch !== ' ' && ch !== '\n' && ch !== '\t' && ch !== '\r') out += ch;
  }
  return out;
}

/**
 * Split the object text `wrapWithBudget` builds into its cells, in order, keeping repeated keys.
 * A value is decoded here; json objects/arrays stay as their (compacted) text so nested numbers keep
 * every digit. Returns undefined for text that is not a complete row (cut by the row-size safety net).
 */
function splitRow(text: string, maxCell: number): [string, unknown][] | undefined {
  let i = 0;
  const n = text.length;
  const str = (): string => {
    const start = i;
    if (text[i] !== '"') throw new Error('expected a string');
    i++;
    while (i < n && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    if (i >= n) throw new Error('unterminated string');
    i++;
    return text.slice(start, i);
  };
  const raw = (): string => {
    const start = i;
    let depth = 0;
    while (i < n) {
      const ch = text[i];
      if (ch === '"') {
        str();
        continue;
      }
      if (ch === '{' || ch === '[') depth++;
      else if (ch === '}' || ch === ']') {
        if (depth === 0) break;
        depth--;
      } else if (ch === ',' && depth === 0) break;
      i++;
    }
    if (i >= n || depth !== 0) throw new Error('incomplete value');
    return text.slice(start, i).trim();
  };
  try {
    const cells: [string, unknown][] = [];
    if (text[i++] !== '{') return undefined;
    if (text[i] === '}') return i + 1 === n ? cells : undefined;
    for (;;) {
      const key = JSON.parse(str()) as string;
      if (text[i++] !== ':') return undefined;
      let value: unknown;
      if (text[i] === '!') {
        const m = /^!(\d+)(j?)/.exec(text.slice(i, i + 24));
        if (!m) return undefined;
        i += m[0].length;
        const kept = JSON.parse(str()) as string;
        // A cut json object/array (`j`) is JSON text: compact the kept prefix like a whole one.
        // Plain text that merely starts with { or [ keeps its whitespace.
        const shown = m[2] ? compactJson(kept) : kept;
        value = `${shown}…[+${m[1]} chars]`;
      } else {
        const t = raw();
        if (t.startsWith('{') || t.startsWith('[')) value = cell(compactJson(t), maxCell);
        else value = cell(t.startsWith('"') ? JSON.parse(t) : parseJsonPreservingBigInts(t), maxCell);
      }
      cells.push([key, value]);
      const sep = text[i++];
      if (sep === '}') return i === n ? cells : undefined;
      if (sep !== ',') return undefined;
    }
  } catch {
    return undefined;
  }
}

/** A name a JS object would list before all others (an array index: `0`, `1`, … `4294967294`). */
const isIndexName = (k: string) => /^(0|[1-9][0-9]{0,9})$/.test(k) && Number(k) < 4294967295;

/**
 * Give repeated column names a free `_2`, `_3`, … suffix; existing names are never taken. An
 * integer-like name (`select 2 as "1"`) becomes `_1` (or a free `_1_2`, …): a JS object would
 * otherwise list it first, out of column order.
 */
function uniqueNames(keys: string[]): { names: string[]; renamed: string[] } {
  const taken = new Set(keys);
  const used = new Set<string>();
  const renamed: string[] = [];
  const names = keys.map((k, idx) => {
    if (!used.has(k) && !isIndexName(k)) {
      used.add(k);
      return k;
    }
    const base = isIndexName(k) ? `_${k}` : k;
    let name = base;
    if (base === k || taken.has(base) || used.has(base)) {
      let s = 2;
      while (taken.has(`${base}_${s}`) || used.has(`${base}_${s}`)) s++;
      name = `${base}_${s}`;
    }
    taken.add(name);
    used.add(name);
    renamed.push(`column ${idx + 1} "${k}" is "${name}"`);
    return name;
  });
  return { names, renamed };
}

/** How many renamed columns the note lists by name. */
const RENAMED_SHOWN = 20;

/** Set a property even when the name is `__proto__`. */
function put(o: Record<string, unknown>, k: string, v: unknown): void {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}

/**
 * Decode the rows `wrapWithBudget` produces. Cells were already capped in SQL; this keeps every
 * column (renaming repeated names) and returns only rows whose JSON fits in maxBytes in total.
 */
export function shapeBudgetRows(raw: { daypass_row: string; daypass_count: string | number }[], o: ShapeOptions): Shaped {
  if (!Array.isArray(raw) || raw.some((r) => !r || typeof r !== 'object' || Array.isArray(r) || !('daypass_row' in r))) {
    const what = !Array.isArray(raw)
      ? typeof raw
      : `${raw.length} item(s), first has ${Array.isArray(raw[0]) ? 'an array' : `keys [${Object.keys(raw[0] ?? {}).join(', ')}]`}`;
    throw new Error(`Unexpected result shape from the database (${what}); expected daypass_row/daypass_count rows from the wrapper. Nothing was returned.`);
  }
  if (raw.length === 0) return { rows: [], truncated: false, note: undefined };
  const count = Math.min(Number(raw[0].daypass_count), o.maxRows + 1);
  const moreRowsExist = count > o.maxRows;
  const rows: Record<string, unknown>[] = [];
  const notes: string[] = [];
  let renamedNote: string | undefined;
  let bytes = 2; // the [ ] around the rows

  for (const r of raw.slice(0, o.maxRows)) {
    const cells = splitRow(r.daypass_row ?? '', o.maxCell);
    let out: Record<string, unknown> | undefined;
    if (cells) {
      const { names, renamed } = uniqueNames(cells.map(([k]) => k));
      if (renamed.length && !renamedNote) {
        // Capped: 1664 repeated names would otherwise make a note of ~60 KB outside the byte budget.
        const shown = renamed.slice(0, RENAMED_SHOWN).join(', ');
        const more = renamed.length > RENAMED_SHOWN ? ` and ${renamed.length - RENAMED_SHOWN} more` : '';
        renamedNote = `Repeated or integer-like column names were renamed: ${shown}${more}.`;
      }
      out = {};
      for (let k = 0; k < cells.length; k++) put(out, names[k], cells[k][1]);
    }
    const size = out ? Buffer.byteLength(JSON.stringify(out), 'utf8') + (rows.length ? 1 : 0) : Infinity;
    if (bytes + size > o.maxBytes) {
      if (!out || size + 2 > o.maxBytes) {
        notes.push(`Row ${rows.length + 1} is larger than the ${o.maxBytes} byte budget even with each cell cut to ${o.maxCell} chars, so it is not shown; select fewer columns.`);
      }
      break;
    }
    bytes += size;
    rows.push(out!);
  }

  if (rows.length < Math.min(count, o.maxRows)) {
    notes.push(
      `Stopped at ${rows.length} of ${moreRowsExist ? `more than ${o.maxRows}` : count} rows: result exceeded the ${o.maxBytes} byte budget.`,
    );
  } else if (moreRowsExist) {
    notes.push(`Only the first ${o.maxRows} rows are shown; add a WHERE or a smaller LIMIT.`);
  }
  const truncated = notes.length > 0;
  if (renamedNote) notes.unshift(renamedNote);
  return { rows, truncated, note: notes.length ? notes.join(' ') : undefined };
}

/** EXPLAIN's output column. A plan is only useful whole, so it is not cut per cell (the byte budget still applies). */
const PLAN_COLUMN = 'QUERY PLAN';

/** Cap rows, cell size and total bytes so one query cannot flood the model's context. */
export function shapeRows(raw: Record<string, unknown>[], o: ShapeOptions): Shaped {
  const rows: Record<string, unknown>[] = [];
  let bytes = 0;
  let truncated = false;
  let note: string | undefined;

  for (const r of raw) {
    if (rows.length >= o.maxRows) {
      truncated = true;
      note = `Only the first ${o.maxRows} rows are shown; add a WHERE or a smaller LIMIT.`;
      break;
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(r)) out[k] = cell(v, k === PLAN_COLUMN ? Infinity : o.maxCell);
    const size = Buffer.byteLength(JSON.stringify(out), 'utf8');
    if (bytes + size > o.maxBytes) {
      truncated = true;
      note = `Stopped at ${rows.length} rows: result exceeded the ${o.maxBytes} byte budget.`;
      break;
    }
    bytes += size;
    rows.push(out);
  }
  return { rows, truncated, note };
}
