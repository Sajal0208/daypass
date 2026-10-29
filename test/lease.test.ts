import { describe, it, expect } from 'vitest';
import { isLeaseLive, parseTtl, shouldReleaseNetwork } from '../src/core/lease.js';

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
