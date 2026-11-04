// A local stand-in for the EC2 query API: enough of Revoke/Describe/Authorize for the daypass
// security-group paths, plus STS GetCallerIdentity. Tests point the SDK at it with
// AWS_ENDPOINT_URL_EC2 and AWS_ENDPOINT_URL_STS; nothing reaches AWS.
import http from 'node:http';
import type { AddressInfo } from 'node:net';

export interface FakeRule { id: string; groupId: string; description: string; egress?: boolean }
export interface FakeEc2 {
  url: string;
  /** groupId -> rules */
  rules: FakeRule[];
  /** Every request: Action plus the decoded form parameters. */
  calls: Record<string, string>[];
  /** Delay before answering a Revoke, in ms. */
  revokeDelayMs: number;
  /** Delay before answering an Authorize, in ms. */
  authorizeDelayMs: number;
  close(): Promise<void>;
}

const NS = 'http://ec2.amazonaws.com/doc/2016-11-15/';
const err = (code: string) => `<?xml version="1.0"?><Response><Errors><Error><Code>${code}</Code><Message>${code}</Message></Error></Errors><RequestID>r</RequestID></Response>`;
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');

export async function startFakeEc2(): Promise<FakeEc2> {
  const fake: FakeEc2 = { url: '', rules: [], calls: [], revokeDelayMs: 0, authorizeDelayMs: 0, close: async () => {} };
  let n = 0;
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', async () => {
      const p = Object.fromEntries(new URLSearchParams(body));
      fake.calls.push(p);
      const send = (status: number, xml: string) => {
        res.writeHead(status, { 'content-type': 'text/xml' });
        res.end(xml);
      };
      if (p.Action === 'GetCallerIdentity') {
        // STS, so `daypass open` on a region target learns who without leaving the machine.
        return send(
          200,
          '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>' +
            '<Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>' +
            '</GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>',
        );
      }
      if (p.Action === 'RevokeSecurityGroupIngress') {
        if (fake.revokeDelayMs) await new Promise((r) => setTimeout(r, fake.revokeDelayMs));
        const id = p['SecurityGroupRuleId.1'];
        const i = fake.rules.findIndex((r) => r.id === id && r.groupId === p.GroupId);
        if (i < 0) return send(400, err('InvalidSecurityGroupRuleId.NotFound'));
        fake.rules.splice(i, 1);
        return send(200, `<RevokeSecurityGroupIngressResponse xmlns="${NS}"><requestId>r</requestId><return>true</return></RevokeSecurityGroupIngressResponse>`);
      }
      if (p.Action === 'DescribeSecurityGroupRules') {
        // Like EC2: a group-id filter and/or rule ids; asking for rule ids that do not exist is an error.
        const g = p['Filter.1.Name'] === 'group-id' ? p['Filter.1.Value.1'] : undefined;
        const ids = Object.keys(p).filter((k) => k.startsWith('SecurityGroupRuleId.')).map((k) => p[k]);
        const found = fake.rules.filter((r) => (g === undefined || r.groupId === g) && (!ids.length || ids.includes(r.id)));
        if (ids.length && !ids.every((id) => fake.rules.some((r) => r.id === id))) return send(400, err('InvalidSecurityGroupRuleId.NotFound'));
        const items = found
          .map((r) => `<item><securityGroupRuleId>${r.id}</securityGroupRuleId><groupId>${r.groupId}</groupId><isEgress>${!!r.egress}</isEgress><description>${esc(r.description)}</description></item>`)
          .join('');
        return send(200, `<DescribeSecurityGroupRulesResponse xmlns="${NS}"><requestId>r</requestId><securityGroupRuleSet>${items}</securityGroupRuleSet></DescribeSecurityGroupRulesResponse>`);
      }
      if (p.Action === 'AuthorizeSecurityGroupIngress') {
        if (fake.authorizeDelayMs) await new Promise((r) => setTimeout(r, fake.authorizeDelayMs));
        const id = `sgr-fake${n++}`;
        fake.rules.push({ id, groupId: p.GroupId, description: p['IpPermissions.1.IpRanges.1.Description'] ?? p['IpPermissions.1.Ipv6Ranges.1.Description'] ?? '' });
        return send(200, `<AuthorizeSecurityGroupIngressResponse xmlns="${NS}"><requestId>r</requestId><return>true</return><securityGroupRuleSet><item><securityGroupRuleId>${id}</securityGroupRuleId></item></securityGroupRuleSet></AuthorizeSecurityGroupIngressResponse>`);
      }
      send(400, err('InvalidAction'));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  fake.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  fake.close = () => new Promise((r) => server.close(() => r()));
  return fake;
}

/** Env that sends the AWS SDK to the fake with dummy credentials and no shared config files. */
export function fakeAwsEnv(fake: FakeEc2, dir: string): Record<string, string> {
  return {
    AWS_ENDPOINT_URL_EC2: fake.url,
    AWS_ENDPOINT_URL_STS: fake.url,
    AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
    AWS_SECRET_ACCESS_KEY: 'fake',
    AWS_EC2_METADATA_DISABLED: 'true',
    AWS_CONFIG_FILE: `${dir}/no-aws-config`,
    AWS_SHARED_CREDENTIALS_FILE: `${dir}/no-aws-credentials`,
    AWS_PROFILE: '',
  };
}
