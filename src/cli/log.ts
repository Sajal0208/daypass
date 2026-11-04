import type { AuditEvent } from '../core/audit.js';

/**
 * Characters that must not reach the terminal raw: C0 and C1 controls and DEL (escape sequences,
 * newlines), format characters (Unicode category Cf: bidi marks and overrides, zero-width
 * characters, the word joiner, BOM, tag characters), line and paragraph separators, lone
 * surrogates, the blank Hangul fillers and the variation-selector supplement (which can carry
 * hidden text). Emoji variation selectors (U+FE00-FE0F) stay: they only pick a glyph.
 */
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\u115f\u1160\u3164\uffa0\u{e0100}-\u{e01ef}]/gu;

/**
 * Audit and lease fields hold text the agent chose (SQL, database errors, refusal reasons) or
 * that sits in a user-writable file, and database identifiers can hold anything. Printed raw, an
 * escape sequence could rewrite or hide rows on the terminal, and an invisible character could
 * make two different names look the same. Each such character becomes a visible `\xNN` (up to
 * U+00FF), `\uNNNN` or `\u{NNNNN}`. Use this for anything printed that the user did not type.
 */
export function printable(s: unknown): string {
  return String(s ?? '').replace(UNPRINTABLE, (c) => {
    const n = c.codePointAt(0)!;
    return n <= 0xff ? `\\x${n.toString(16).padStart(2, '0')}` : n <= 0xffff ? `\\u${n.toString(16).padStart(4, '0')}` : `\\u{${n.toString(16)}}`;
  });
}

/**
 * Rows for `daypass log`. The server writes two lines per allowed call (`phase: 'start'` before
 * the database sees it, `phase: 'end'` after, paired by `callId`), one unphased line per refusal,
 * and `tool: 'server'` lines for server-level events. Each call becomes one row at its start
 * time with the end line's result; a start without an end is shown as unfinished (still running,
 * or the server died mid-call); an end whose start fell outside the window stands on its own.
 * Unphased lines (refusals, and logs from older versions) render as they always did.
 * `last` keeps the newest rows after pairing.
 */
export function formatLog(events: AuditEvent[], last?: number): string[] {
  const ends = new Map<string, AuditEvent>();
  const starts = new Set<string>();
  for (const e of events) {
    if (e.phase === 'end' && e.callId) ends.set(e.callId, e);
    if (e.phase === 'start' && e.callId) starts.add(e.callId);
  }
  const rows: string[] = [];
  for (const e of events) {
    if (e.tool === 'server') {
      const why = e.error ? `  <- ${printable(e.error)}` : e.blockedReason ? `  <- ${printable(e.blockedReason)}` : '';
      rows.push(`${printable(e.at)} SRV  ${printable(e.who)} ${printable(e.target) || '-'} server${why}`);
    } else if (e.phase === 'start') {
      const end = e.callId ? ends.get(e.callId) : undefined;
      rows.push(end ? row({ ...end, at: e.at, sql: e.sql ?? end.sql }) : row(e, 'RUN ', '  <- unfinished: no end line yet (still running, or the server stopped mid-call)'));
    } else if (e.phase === 'end') {
      if (!e.callId || !starts.has(e.callId)) rows.push(row(e));
    } else {
      rows.push(row(e));
    }
  }
  return last === undefined ? rows : rows.slice(-last);
}

function row(e: AuditEvent, flagOverride?: string, suffix = ''): string {
  const flag = flagOverride ?? (e.allowed ? (e.error ? 'ERR ' : 'ok  ') : 'BLK ');
  const sql = printable((e.sql ?? '').replace(/\s+/g, ' ').slice(0, 120));
  const n = (x: unknown) => (typeof x === 'number' ? x : '-');
  return (
    `${printable(e.at)} ${flag} ${printable(e.who)} ${printable(e.target)} ${printable(e.tool)} ${n(e.rows)}r ${n(e.ms)}ms  ${sql}` +
    `${e.blockedReason ? `  <- ${printable(e.blockedReason)}` : ''}${e.error ? `  <- ${printable(e.error)}` : ''}${suffix}`
  );
}
