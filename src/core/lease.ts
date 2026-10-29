export interface Lease {
  id: string;
  target: string;
  reason: string;
  who: string;
  openedAt: string;
  expiresAt: string;
  /** Public IP that was added to the security group, if any. */
  ip?: string;
  /** Security-group rule id created for this lease, if any. */
  sgRuleId?: string;
}

export function isLeaseLive(l: Lease | null | undefined, now = Date.now()): boolean {
  return !!l && Date.parse(l.expiresAt) > now;
}

/** "60m", "2h", "90s" → milliseconds. */
export function parseTtl(s: string): number {
  const m = /^(\d+)\s*(s|m|h)$/i.exec(s.trim());
  if (!m) throw new Error(`Bad ttl "${s}" (use e.g. 30m, 2h)`);
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  const ms = unit === 's' ? n * 1000 : unit === 'm' ? n * 60_000 : n * 3_600_000;
  if (ms > 8 * 3_600_000) throw new Error('ttl may not exceed 8h');
  if (ms < 60_000) throw new Error('ttl must be at least 60s');
  return ms;
}

/** An expired lease that still holds a security-group rule must have that rule revoked. */
export function shouldReleaseNetwork(l: Lease | null | undefined, now = Date.now()): boolean {
  return !!l && !isLeaseLive(l, now) && !!l.sgRuleId;
}
