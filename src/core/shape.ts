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

/** How much of a row that was cut mid-JSON the model gets to see. */
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
 * Push the row cap AND the byte budget into SQL so the database, not Node, does the cutting.
 *
 * Shape of what comes back: one text column `daypass_row` (the row as JSON, cut to
 * maxBytes+1 chars) and `daypass_count` (rows the inner query produced, capped at maxRows+1).
 * Postgres stops emitting rows once the running total of previous rows reaches maxBytes
 * (octet_length: UTF-8 bytes), so the wire carries at most maxBytes bytes + one row of at most
 * maxBytes+1 characters (left() cuts by characters, so at most 4*(maxBytes+1) bytes), and never
 * more than maxRows+1 rows. The cut (`left(...)`) happens in the LIMIT subquery, below the window
 * aggregates: their tuplestore then only ever buffers cut rows, so a huge value is truncated
 * rather than spilled to disk (where temp_file_limit would fail the query). The extra LIMIT
 * level also keeps `count(*) OVER ()` from scanning past maxRows+1. `to_json` (not to_jsonb)
 * keeps column order and prints numerics with all their digits; `daypass_q.*` is a whole-row
 * reference even when the user's query has a column named `daypass_q` (bare `daypass_q` would
 * resolve to that column). The inner query sits on its own line: a trailing `--` comment that
 * survived canonicalisation cannot swallow the wrapper.
 */
export function wrapWithBudget(sql: string, maxRows: number, maxBytes: number): string {
  const r = Math.floor(maxRows);
  const b = Math.floor(maxBytes);
  return (
    `SELECT daypass_row, daypass_count FROM (\n` +
    `  SELECT daypass_row, daypass_n, daypass_count,\n` +
    `         sum(octet_length(daypass_row)) OVER (ORDER BY daypass_n ROWS UNBOUNDED PRECEDING) AS daypass_total\n` +
    `  FROM (\n` +
    `    SELECT daypass_row, row_number() OVER () AS daypass_n, count(*) OVER () AS daypass_count\n` +
    `    FROM (SELECT left(to_json(daypass_q.*)::text, ${b + 1}) AS daypass_row FROM (\n${sql}\n) daypass_q LIMIT ${r + 1}) daypass_l\n` +
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

function cell(v: unknown, maxCell: number): unknown {
  if (v === null || v === undefined) return null;
  if (typeof v === 'bigint') return v.toString();
  if (v instanceof Date) return v.toISOString();
  if (Buffer.isBuffer(v)) return `<${v.length} bytes>`;
  if (typeof v === 'object') v = JSON.stringify(v);
  if (typeof v === 'string' && v.length > maxCell) return `${v.slice(0, maxCell)}…[+${v.length - maxCell} chars]`;
  return v;
}

/** Decode the rows `wrapWithBudget` produces and apply the per-cell cap. */
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
  const kept = raw.slice(0, o.maxRows);
  const rows: Record<string, unknown>[] = [];
  const notes: string[] = [];

  kept.forEach((r, idx) => {
    const text = r.daypass_row ?? '';
    let parsed: unknown;
    if (Buffer.byteLength(text, 'utf8') <= o.maxBytes) {
      try {
        parsed = parseJsonPreservingBigInts(text);
      } catch {
        parsed = undefined;
      }
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) out[k] = cell(v, o.maxCell);
      rows.push(out);
    } else {
      rows.push({ daypass_truncated_row: text.slice(0, TRUNCATED_ROW_PREVIEW_CHARS) + '…' });
      notes.push(`Row ${idx + 1} was longer than ${o.maxBytes} bytes and is shown truncated (first ${TRUNCATED_ROW_PREVIEW_CHARS} chars of its JSON).`);
    }
  });

  const byteCut = raw.length < count;
  if (byteCut) {
    notes.push(
      `Stopped at ${rows.length} of ${moreRowsExist ? `more than ${o.maxRows}` : count} rows: result exceeded the ${o.maxBytes} byte budget.`,
    );
  } else if (moreRowsExist) {
    notes.push(`Only the first ${o.maxRows} rows are shown; add a WHERE or a smaller LIMIT.`);
  }
  const truncated = notes.length > 0;
  return { rows, truncated, note: truncated ? notes.join(' ') : undefined };
}

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
    for (const [k, v] of Object.entries(r)) out[k] = cell(v, o.maxCell);
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
