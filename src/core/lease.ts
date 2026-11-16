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
  /**
   * Where that rule lives, recorded when it is created, so `close` and expiry cleanup revoke it
   * in the right place even if the target config changes in between.
   */
  sgRegion?: string;
  sgGroupId?: string;
  sgProfile?: string;
  /** Port the rule opens, recorded with sgGroupId, so `open` can spot a second target behind the same rule. */
  sgPort?: number;
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

export type Pick = { lease: Lease; error?: undefined } | { lease?: undefined; error: string };

const openHint = (t: string) => `Ask the user to run: daypass open ${t} --reason "..."`;
const expiredMsg = (l: Lease) => `Lease ${l.id} for "${l.target}" expired at ${l.expiresAt}. ${openHint(l.target)}`;

/** Which lease a tool call uses: the named target's, or the only live one. */
export function pickLease(leases: Lease[], target?: string, now = Date.now()): Pick {
  const live = leases.filter((l) => isLeaseLive(l, now));
  const names = (ls: Lease[]) => ls.map((x) => x.target).join(', ');
  if (target !== undefined) {
    const l = leases.find((x) => x.target === target);
    if (l && isLeaseLive(l, now)) return { lease: l };
    if (l) return { error: expiredMsg(l) };
    return { error: `No lease on "${target}". Open: ${names(live) || 'none'}. ${openHint(target)}` };
  }
  if (live.length === 1) return { lease: live[0] };
  if (live.length > 1) return { error: `${live.length} leases are open (${names(live)}). Pass target: one of them.` };
  if (leases.length === 1) return { error: expiredMsg(leases[0]) };
  if (leases.length > 1) return { error: `No live lease; expired: ${names(leases)}. ${openHint('<target>')}` };
  return { error: `No active Daypass lease. ${openHint('<target>')}` };
}
