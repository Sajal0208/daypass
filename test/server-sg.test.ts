import { describe, it, expect } from 'vitest';
import { parsePublicIp, ipPermission } from '../src/mcp/sg.js';

describe('parsePublicIp', () => {
  it('accepts IPv4', () => expect(parsePublicIp('203.0.113.9\n')).toBe('203.0.113.9'));
  it('accepts IPv6', () => expect(parsePublicIp('2001:db8::1\n')).toBe('2001:db8::1'));
  it('rejects junk with a clear message', () => expect(() => parsePublicIp('<html>')).toThrow(/public IP/));
});

describe('ipPermission', () => {
  const base = { port: 5432, description: 'daypass:x until y' };
  it('uses a /32 IpRange for IPv4', () => {
    expect(ipPermission({ ...base, ip: '203.0.113.9' })).toEqual({
      IpProtocol: 'tcp',
      FromPort: 5432,
      ToPort: 5432,
      IpRanges: [{ CidrIp: '203.0.113.9/32', Description: base.description }],
    });
  });
  it('uses a /128 Ipv6Range for IPv6', () => {
    expect(ipPermission({ ...base, ip: '2001:db8::1' })).toEqual({
      IpProtocol: 'tcp',
      FromPort: 5432,
      ToPort: 5432,
      Ipv6Ranges: [{ CidrIpv6: '2001:db8::1/128', Description: base.description }],
    });
  });
  it('refuses a non-IP', () => expect(() => ipPermission({ ...base, ip: 'nope' })).toThrow(/IP/));
});
