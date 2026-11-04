import { createHash } from 'node:crypto';

/**
 * Allowed calls write two lines: `phase: 'start'` before anything reaches the database
 * (allowed: true, no rows/ms) and `phase: 'end'` after it (rows/ms, or error). A start line
 * with no matching end line means the process died mid-call. Refusals are one line with no
 * phase. `callId` pairs the two. Server-level events (uncaught exception, shutdown) use
 * `tool: 'server'`.
 */
export interface AuditEvent {
  at: string;
  who: string;
  leaseId: string | null;
  target: string;
  reason: string | null;
  tool: string;
  sql: string | null;
  allowed: boolean;
  blockedReason?: string;
  rows?: number;
  ms?: number;
  error?: string;
  phase?: 'start' | 'end';
  callId?: string;
  /** SHA-256 (hex, UTF-8) of the full statement, present when `sql` was cut to fit the line cap. */
  sqlSha256?: string;
}

/**
 * Per-field caps, in bytes of the JSON-encoded value. Their sum stays far below 64 KiB, so each
 * line goes out in one small write() on an O_APPEND descriptor and concurrent servers cannot
 * interleave inside a line.
 */
const FIELD_CAPS: Record<string, number> = {
  sql: 16 * 1024,
  error: 4096,
  blockedReason: 4096,
  reason: 2048,
  who: 1024,
  target: 512,
  tool: 128,
  leaseId: 128,
  callId: 128,
  at: 64,
  phase: 16,
  sqlSha256: 80,
};
/** Room kept free in a capped field for the `…[+N chars]` note. */
const NOTE_ROOM = 96;

const encodedBytes = (s: string) => Buffer.byteLength(JSON.stringify(s)) - 2;

export const sha256Hex = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

/** `s` cut so its JSON encoding fits in `max` bytes, never inside a surrogate pair, with a note of what was dropped. */
function capField(s: string, max: number, note: (dropped: number) => string): string {
  if (encodedBytes(s) <= max) return s;
  const room = Math.max(0, max - NOTE_ROOM);
  let lo = 0;
  let hi = Math.min(s.length, room);
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (encodedBytes(s.slice(0, mid)) <= room) lo = mid;
    else hi = mid - 1;
  }
  const c = s.charCodeAt(lo - 1);
  if (lo > 0 && c >= 0xd800 && c <= 0xdbff) lo--;
  return s.slice(0, lo) + note(s.length - lo);
}

/**
 * One JSON object per line, so the log can be tailed and grepped. Every string field is capped
 * (see FIELD_CAPS); a statement over its cap keeps a prefix plus `sqlSha256` of the whole text.
 */
export function formatAudit(e: AuditEvent): string {
  const out: Record<string, unknown> = { ...e };
  for (const [k, v] of Object.entries(out)) {
    if (typeof v !== 'string') continue;
    const max = FIELD_CAPS[k] ?? 1024;
    if (k === 'sql') {
      const capped = capField(v, max, (n) => `…[+${n} chars not stored; sqlSha256 is the hash of the full statement]`);
      if (capped !== v) {
        out.sql = capped;
        out.sqlSha256 = sha256Hex(v);
      }
    } else {
      out[k] = capField(v, max, (n) => `…[+${n} chars]`);
    }
  }
  return JSON.stringify(out) + '\n';
}
