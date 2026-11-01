import type { AuditEvent } from '../core/audit.js';

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
      rows.push(`${e.at} SRV  ${e.who} ${e.target || '-'} server${e.error ? `  <- ${e.error}` : e.blockedReason ? `  <- ${e.blockedReason}` : ''}`);
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
  const sql = (e.sql ?? '').replace(/\s+/g, ' ').slice(0, 120);
  return (
    `${e.at} ${flag} ${e.who} ${e.target} ${e.tool} ${e.rows ?? '-'}r ${e.ms ?? '-'}ms  ${sql}` +
    `${e.blockedReason ? `  <- ${e.blockedReason}` : ''}${e.error ? `  <- ${e.error}` : ''}${suffix}`
  );
}
