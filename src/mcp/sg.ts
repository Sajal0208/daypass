import {
  EC2Client,
  AuthorizeSecurityGroupIngressCommand,
  RevokeSecurityGroupIngressCommand,
  DescribeSecurityGroupRulesCommand,
} from '@aws-sdk/client-ec2';
import { fromIni } from '@aws-sdk/credential-providers';
import { isIPv4, isIPv6 } from 'node:net';

export const RULE_PREFIX = 'daypass:';

function client(region: string, profile?: string) {
  return new EC2Client({ region, ...(profile ? { credentials: fromIni({ profile }) } : {}) });
}

/** The body of a what-is-my-ip reply, validated as IPv4 or IPv6. */
export function parsePublicIp(body: string): string {
  const ip = body.trim();
  if (!isIPv4(ip) && !isIPv6(ip)) throw new Error(`Could not read public IP (got "${ip.slice(0, 60)}")`);
  return ip;
}

export async function myPublicIp(): Promise<string> {
  const r = await fetch('https://checkip.amazonaws.com', { signal: AbortSignal.timeout(5000) });
  return parsePublicIp(await r.text());
}

/** One ingress permission for a single address: /32 for IPv4, /128 for IPv6. */
export function ipPermission(o: { ip: string; port: number; description: string }) {
  const base = { IpProtocol: 'tcp', FromPort: o.port, ToPort: o.port };
  if (isIPv4(o.ip)) return { ...base, IpRanges: [{ CidrIp: `${o.ip}/32`, Description: o.description }] };
  if (isIPv6(o.ip)) return { ...base, Ipv6Ranges: [{ CidrIpv6: `${o.ip}/128`, Description: o.description }] };
  throw new Error(`"${o.ip}" is not an IP address`);
}

/** Adds a single-address ingress rule (/32 or /128) tagged with the lease id. Returns the rule id. */
export async function allowIp(o: {
  region: string;
  profile?: string;
  groupId: string;
  port: number;
  ip: string;
  leaseId: string;
  expiresAt: string;
}): Promise<string> {
  const ec2 = client(o.region, o.profile);
  const res = await ec2.send(
    new AuthorizeSecurityGroupIngressCommand({
      GroupId: o.groupId,
      IpPermissions: [ipPermission({ ip: o.ip, port: o.port, description: `${RULE_PREFIX}${o.leaseId} until ${o.expiresAt}` })],
    }),
  );
  const id = res.SecurityGroupRules?.[0]?.SecurityGroupRuleId;
  if (!id) throw new Error('AWS did not return a rule id');
  return id;
}

export async function revokeRule(o: { region: string; profile?: string; groupId: string; ruleId: string }): Promise<void> {
  const ec2 = client(o.region, o.profile);
  try {
    await ec2.send(new RevokeSecurityGroupIngressCommand({ GroupId: o.groupId, SecurityGroupRuleIds: [o.ruleId] }));
  } catch (e: any) {
    if (e?.name !== 'InvalidSecurityGroupRuleId.NotFound') throw e;
  }
}

/** Removes every daypass:* rule whose "until" timestamp is in the past. Returns the ids removed. */
export async function sweepExpired(o: { region: string; profile?: string; groupId: string; now?: number }): Promise<string[]> {
  const ec2 = client(o.region, o.profile);
  const now = o.now ?? Date.now();
  const res = await ec2.send(
    new DescribeSecurityGroupRulesCommand({ Filters: [{ Name: 'group-id', Values: [o.groupId] }] }),
  );
  const removed: string[] = [];
  for (const r of res.SecurityGroupRules ?? []) {
    const d = r.Description ?? '';
    if (!d.startsWith(RULE_PREFIX) || r.IsEgress || !r.SecurityGroupRuleId) continue;
    const until = /until (\S+)$/.exec(d)?.[1];
    if (!until || Date.parse(until) < now) {
      await revokeRule({ ...o, ruleId: r.SecurityGroupRuleId });
      removed.push(r.SecurityGroupRuleId);
    }
  }
  return removed;
}
