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
}

/** One JSON object per line, so the log can be tailed and grepped. */
export function formatAudit(e: AuditEvent): string {
  return JSON.stringify(e) + '\n';
}
