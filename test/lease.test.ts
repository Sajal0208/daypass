import { describe, it, expect } from 'vitest';
import { isLeaseLive, parseTtl, shouldReleaseNetwork } from '../src/core/lease.js';
import { pickLease } from '../src/core/index.js';

const lease = (expiresAt: string) => ({ id: 'x', target: 'prod', reason: 'r', who: 'me', openedAt: '', expiresAt });

describe('isLeaseLive', () => {
  it('false for missing', () => expect(isLeaseLive(null)).toBe(false));
  it('false when expired', () => expect(isLeaseLive(lease('2000-01-01T00:00:00Z'))).toBe(false));
  it('true when in the future', () => expect(isLeaseLive(lease('2999-01-01T00:00:00Z'))).toBe(true));
});

describe('parseTtl', () => {
  it('minutes', () => expect(parseTtl('60m')).toBe(3_600_000));
  it('hours', () => expect(parseTtl('2h')).toBe(7_200_000));
  it('seconds', () => expect(parseTtl('90s')).toBe(90_000));
  it('rejects junk', () => expect(() => parseTtl('soon')).toThrow(/Bad ttl/));
  it('rejects over 8h', () => expect(() => parseTtl('9h')).toThrow(/8h/));
  it('rejects under 60s', () => expect(() => parseTtl('5s')).toThrow(/60s/));
});

describe('shouldReleaseNetwork', () => {
  const withRule = { ...lease('2000-01-01T00:00:00Z'), sgRuleId: 'sgr-1' };
  it('true when expired and a rule exists', () => expect(shouldReleaseNetwork(withRule)).toBe(true));
  it('false while live', () => expect(shouldReleaseNetwork({ ...withRule, expiresAt: '2999-01-01T00:00:00Z' })).toBe(false));
  it('false when expired but no rule', () => expect(shouldReleaseNetwork(lease('2000-01-01T00:00:00Z'))).toBe(false));
  it('false for missing', () => expect(shouldReleaseNetwork(null)).toBe(false));
});

const L = (target: string, mins: number, id = target) => ({ id, target, reason: 'r', who: 'w', openedAt: '', expiresAt: new Date(Date.now() + mins * 60_000).toISOString() });

describe('pickLease', () => {
  it('no leases: asks for daypass open', () => {
    expect(pickLease([]).error).toMatch(/No active Daypass lease/);
  });
  it('one live lease, no target: uses it', () => {
    expect(pickLease([L('ezo', 10)]).lease?.target).toBe('ezo');
  });
  it('one expired lease, no target: the expired message', () => {
    expect(pickLease([L('ezo', -1)]).error).toMatch(/expired at .*daypass open ezo/);
  });
  it('two live leases, no target: refuses and lists both', () => {
    const r = pickLease([L('ezo', 10), L('pineyard', 10)]);
    expect(r.error).toMatch(/2 leases are open \(ezo, pineyard\)/);
    expect(r.error).toMatch(/Pass target/);
  });
  it('two leases, one expired, no target: uses the live one', () => {
    expect(pickLease([L('ezo', -1), L('pineyard', 10)]).lease?.target).toBe('pineyard');
  });
  it('two expired leases, no target: names both', () => {
    expect(pickLease([L('ezo', -1), L('pineyard', -2)]).error).toMatch(/expired: ezo, pineyard/);
  });
  it('named target that is live: uses it', () => {
    expect(pickLease([L('ezo', 10), L('pineyard', 10)], 'pineyard').lease?.target).toBe('pineyard');
  });
  it('named target with no lease: says which are open', () => {
    expect(pickLease([L('ezo', 10)], 'pineyard').error).toMatch(/No lease on "pineyard".*Open: ezo/);
  });
  it('named target that expired: the expired message', () => {
    expect(pickLease([L('pineyard', -1)], 'pineyard').error).toMatch(/expired at/);
  });
});
