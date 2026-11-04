import {
  EC2Client,
  AuthorizeSecurityGroupIngressCommand,
  RevokeSecurityGroupIngressCommand,
  DescribeSecurityGroupRulesCommand,
} from '@aws-sdk/client-ec2';
import { fromIni } from '@aws-sdk/credential-providers';
import { isIPv4, isIPv6 } from 'node:net';
import type { Lease } from '../core/lease.js';

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

const RULE_NOT_FOUND = 'InvalidSecurityGroupRuleId.NotFound';

/**
 * Revoke one rule. A rule that is already gone counts as revoked unless `notFoundOk` is false
 * (then the NotFound error is thrown, e.g. when the group came from a config that may have changed).
 */
export async function revokeRule(o: { region: string; profile?: string; groupId: string; ruleId: string; notFoundOk?: boolean }): Promise<void> {
  const ec2 = client(o.region, o.profile);
  try {
    await ec2.send(new RevokeSecurityGroupIngressCommand({ GroupId: o.groupId, SecurityGroupRuleIds: [o.ruleId] }));
  } catch (e: any) {
    if (e?.name !== RULE_NOT_FOUND || o.notFoundOk === false) throw e;
  }
}

/** Shapes of what a lease names before any of it is sent to AWS (lease.json is a file on disk). */
const SHAPE = { region: /^[a-z0-9]+(?:-[a-z0-9]+)+$/, groupId: /^sg-[0-9a-z]+$/, ruleId: /^sgr-[0-9a-z]+$/, leaseId: /^[0-9a-f]{8}$/ };

/**
 * Whether rule `ruleId` in `groupId` is the ingress rule allowIp made for lease `leaseId`: its
 * description is exactly `daypass:<leaseId> until <ISO time>`. 'gone' when it does not exist.
 */
async function ruleOfLease(o: { region: string; profile?: string; groupId: string; ruleId: string; leaseId: string }): Promise<'ours' | 'gone' | 'other'> {
  let rules;
  try {
    rules = (
      await client(o.region, o.profile).send(
        new DescribeSecurityGroupRulesCommand({ SecurityGroupRuleIds: [o.ruleId], Filters: [{ Name: 'group-id', Values: [o.groupId] }] }),
      )
    ).SecurityGroupRules;
  } catch (e: any) {
    if (e?.name === RULE_NOT_FOUND) return 'gone';
    throw e;
  }
  const r = rules?.find((x) => x.SecurityGroupRuleId === o.ruleId && x.GroupId === o.groupId);
  if (!r) return 'gone';
  const d = r.Description ?? '';
  return !r.IsEgress && RULE_DESCRIPTION.test(d) && d.startsWith(`${RULE_PREFIX}${o.leaseId} until `) ? 'ours' : 'other';
}

/**
 * Revoke a lease's security-group rule where it was created: the region, group and profile the
 * lease recorded (there, a rule that is already gone counts as revoked). Leases from older
 * versions carry only the rule id; they fall back to the target config, and a rule not found
 * there is reported as a warning, because the config may point somewhere else by now.
 *
 * lease.json is only a file, so nothing in it is trusted to pick a rule: the ids must be
 * well-formed, and the rule is first looked up and revoked only if its description is the one
 * allowIp wrote for this lease id (`daypass:<id> until ...`). Checking the rule, not the config,
 * keeps `close` working after the config moved to another group or region.
 */
export async function revokeLeaseRule(
  lease: Lease,
  t: { region?: string; securityGroupId?: string; awsProfile?: string } | undefined,
): Promise<{ revoked: boolean; warning?: string }> {
  const ruleId = lease.sgRuleId;
  if (!ruleId) return { revoked: false };
  const recorded = !!(lease.sgRegion && lease.sgGroupId);
  if (!recorded && (!t?.region || !t.securityGroupId)) {
    return { revoked: false, warning: `security-group rule ${ruleId} was NOT revoked: neither the lease nor target "${lease.target}" names a region and securityGroupId. Run: daypass sweep ${lease.target}` };
  }
  const where = recorded
    ? { region: lease.sgRegion!, profile: lease.sgProfile, groupId: lease.sgGroupId! }
    : { region: t!.region!, profile: t!.awsProfile, groupId: t!.securityGroupId! };
  if (!SHAPE.ruleId.test(ruleId) || !SHAPE.groupId.test(where.groupId) || !SHAPE.region.test(where.region) || !SHAPE.leaseId.test(String(lease.id))) {
    return { revoked: false, warning: `security-group rule ${ruleId} was NOT revoked: the lease names a malformed rule, group, region or lease id. Check the group and run: daypass sweep ${lease.target}` };
  }
  const mine = await ruleOfLease({ ...where, ruleId, leaseId: lease.id });
  if (mine === 'other') {
    return {
      revoked: false,
      warning: `security-group rule ${ruleId} in ${where.groupId} (${where.region}) was NOT revoked: it is not the rule daypass created for lease ${lease.id} (its description differs).`,
    };
  }
  if (mine === 'gone') {
    return recorded
      ? { revoked: true }
      : {
          revoked: false,
          warning: `security-group rule ${ruleId} was not found in ${where.groupId} (${where.region}); the config may have changed since the lease was opened. Check the group it was created in.`,
        };
  }
  // Gone between the lookup and now still counts as revoked.
  await revokeRule({ ...where, ruleId });
  return { revoked: true };
}

/** Exactly what allowIp writes: `daypass:<8 hex lease id> until <ISO time>`. */
const RULE_DESCRIPTION = /^daypass:[0-9a-f]{8} until (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z)$/;

/** Removes every rule daypass created (exact description shape) whose "until" time is in the past. Returns the ids removed. */
export async function sweepExpired(o: { region: string; profile?: string; groupId: string; now?: number }): Promise<string[]> {
  const ec2 = client(o.region, o.profile);
  const now = o.now ?? Date.now();
  const res = await ec2.send(
    new DescribeSecurityGroupRulesCommand({ Filters: [{ Name: 'group-id', Values: [o.groupId] }] }),
  );
  const removed: string[] = [];
  for (const r of res.SecurityGroupRules ?? []) {
    const until = RULE_DESCRIPTION.exec(r.Description ?? '')?.[1];
    if (!until || r.IsEgress || !r.SecurityGroupRuleId) continue;
    if (Date.parse(until) < now) {
      await revokeRule({ ...o, ruleId: r.SecurityGroupRuleId });
      removed.push(r.SecurityGroupRuleId);
    }
  }
  return removed;
}
