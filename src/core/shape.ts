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

/** Ask for one row more than the cap so we can tell "exactly N" from "more than N". */
export function wrapWithLimit(sql: string, maxRows: number): string {
  const inner = sql.trim().replace(/;\s*$/, '').trim();
  return `SELECT * FROM (${inner}) daypass_q LIMIT ${maxRows + 1}`;
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
    const size = JSON.stringify(out).length;
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
