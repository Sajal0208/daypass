import {
  EC2Client,
  AuthorizeSecurityGroupIngressCommand,
  RevokeSecurityGroupIngressCommand,
  DescribeSecurityGroupRulesCommand,
} from '@aws-sdk/client-ec2';
import { fromIni } from '@aws-sdk/credential-providers';

export const RULE_PREFIX = 'daypass:';

function client(region: string, profile?: string) {
  return new EC2Client({ region, ...(profile ? { credentials: fromIni({ profile }) } : {}) });
}

export async function myPublicIp(): Promise<string> {
  const r = await fetch('https://checkip.amazonaws.com', { signal: AbortSignal.timeout(5000) });
  const ip = (await r.text()).trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) throw new Error(`Could not read public IP (got "${ip}")`);
  return ip;
}

/** Adds a /32 ingress rule tagged with the lease id. Returns the rule id. */
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
      IpPermissions: [
        {
          IpProtocol: 'tcp',
          FromPort: o.port,
          ToPort: o.port,
          IpRanges: [{ CidrIp: `${o.ip}/32`, Description: `${RULE_PREFIX}${o.leaseId} until ${o.expiresAt}` }],
        },
      ],
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
