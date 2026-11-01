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
}

/** One JSON object per line, so the log can be tailed and grepped. */
export function formatAudit(e: AuditEvent): string {
  return JSON.stringify(e) + '\n';
}
