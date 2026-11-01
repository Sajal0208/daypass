# AWS RDS

On AWS RDS, Daypass logs in without a password. The role is granted `rds_iam`, and each connection uses a 15-minute token signed with the AWS credentials already on your laptop. Lose AWS access, lose Daypass access. Optionally, `daypass open` also adds your current IP to the database's security group for the length of the lease and removes it afterwards. This page covers enabling IAM auth, the IAM policy a person needs, the IP rule, the sweep cron and the TLS pinning.

## Target config

```json
{
  "targets": {
    "prod": {
      "host": "my-db.abc123.eu-central-1.rds.amazonaws.com",
      "port": 5432,
      "database": "app",
      "user": "daypass_ro",
      "region": "eu-central-1",
      "awsProfile": "default",
      "securityGroupId": "sg-xxxxxxxxxxxxxxxxx",
      "schemas": ["public"],
      "maxRows": 500
    }
  }
}
```

`region` is what switches a target to IAM auth; a target with `region` never uses a password. `awsProfile` is optional and names a profile in `~/.aws/config`; without it the default AWS credential chain applies (environment variables, SSO session, instance role). `securityGroupId` is optional and enables the per-lease IP rule. `port` defaults to 5432.

## 1. Enable IAM authentication on the instance

Once per instance, by someone with RDS admin rights:

```bash
aws rds modify-db-instance \
  --db-instance-identifier my-db \
  --enable-iam-database-authentication \
  --apply-immediately
```

Then run the role setup from [Quickstart](quickstart.md) step 4 as the master user. On RDS the script finds the `rds_iam` role and grants it to `daypass_ro`; that grant is what allows token login. Do not set a password on the role. On PostgreSQL 16+, re-runs must come from the master user that created the role (it holds ADMIN OPTION on it) or a role granted `daypass_ro ... WITH ADMIN OPTION`; anyone else gets an error naming the `GRANT` to run. Set `rds.restrict_password_commands = 1` in the parameter group so the role cannot change its own password. The role is `NOINHERIT`, so on PostgreSQL 16+ the `rds_iam` grant is made with `INHERIT FALSE`; RDS checks membership, not inheritance, for IAM login, but this was not tested here on 16 (only PostgreSQL 14 was available): if IAM login fails after the setup, check `\drg daypass_ro`.

## 2. IAM permissions per person

Each person who opens leases needs `rds-db:connect` on the database user resource:

```
arn:aws:rds-db:<region>:<account-id>:dbuser:<db-resource-id>/daypass_ro
```

`<db-resource-id>` is the instance's resource id (`db-XXXXXXXXXXXXXXXXXXXXXXXXXX`), not its name. Find it with `aws rds describe-db-instances --db-instance-identifier my-db --query 'DBInstances[0].DbiResourceId'`.

If you use the IP rule, three more actions on the database's security group:

- `ec2:AuthorizeSecurityGroupIngress`: add the `/32` (or `/128`) rule on `open`
- `ec2:RevokeSecurityGroupIngress`: remove it on `close`, on the first tool call after expiry, and in `sweep`
- `ec2:DescribeSecurityGroupRules`: `sweep` lists rules to find expired ones

`sts:GetCallerIdentity`, which Daypass calls to record who opened the lease, needs no permission.

A full policy with placeholders. Replace `<account-id>` with your 12-digit account id and the resource ids with yours. `ec2:Describe*` actions do not take a resource, hence `*` on that statement.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DaypassConnect",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:eu-central-1:<account-id>:dbuser:db-XXXXXXXXXXXXXXXXXXXXXXXXXX/daypass_ro"
    },
    {
      "Sid": "DaypassIpRule",
      "Effect": "Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "arn:aws:ec2:eu-central-1:<account-id>:security-group/sg-xxxxxxxxxxxxxxxxx"
    },
    {
      "Sid": "DaypassSweep",
      "Effect": "Allow",
      "Action": "ec2:DescribeSecurityGroupRules",
      "Resource": "*"
    }
  ]
}
```

Attach it to a group or role that each developer assumes under their own identity. The audit `who` is the caller ARN, so if everyone shares one IAM user the log cannot tell them apart.

## 3. The per-lease IP rule

With `securityGroupId` set, `daypass open`:

1. writes the lease first, then asks `https://checkip.amazonaws.com` for your public IP address,
2. adds an inbound TCP rule for `<ip>/32` (an IPv4 address) or `<ip>/128` (an IPv6 address) on the target's port, described `daypass:<lease-id> until <expiresAt>`,
3. stores the rule id in the lease.

`daypass close` revokes that rule. If the lease expires without `close`, the next MCP tool call sees the expired lease and revokes the rule before refusing the call; if that revoke fails, it is silent and the sweep below removes the rule. Until then the rule stays in the group. If `open` crashes after AWS created the rule but before the rule id was written, the rule is still tagged with the lease id and its expiry, and `sweep` removes it once that time has passed.

**Remove any `0.0.0.0/0` rule from that security group first.** A per-IP rule adds nothing while the group is open to the world. Pass `--no-network` to `open` when you are already inside the VPC and do not want a rule.

The rule covers the one address `checkip.amazonaws.com` saw. If your public address changes during a lease (new Wi-Fi, VPN toggle), close and reopen.

## 4. Sweep cron

Expired rules can be left behind when a laptop goes to sleep or the AWS call fails. `daypass sweep prod` lists the group's rules and removes every `daypass:*` rule whose `until` timestamp is in the past. It also clears an expired local lease file. Run it every 15 minutes from a machine that has the same AWS permissions. Cron does not load your shell profile, so use the full path from `which daypass` and make sure the AWS profile is reachable:

```text
*/15 * * * * /usr/local/bin/daypass sweep prod >> "$HOME/.daypass/sweep.log" 2>&1
```

Output when nothing is left over is `Nothing to sweep.`

## 5. TLS and the pinned CA

RDS targets always verify TLS, and verify it against the AWS RDS global CA bundle that ships inside the package (`certs/global-bundle.pem`, from `truststore.pki.rds.amazonaws.com`). That covers every target with `region` and every target whose host ends in `.rds.amazonaws.com`, URL and password targets included. The token and the rows travel over the public internet, so the server has to present a certificate that chains to Amazon's RDS roots. A target that reaches RDS through a CNAME of your own and has no `region` uses the system CA store, which does not carry those roots: set `sslCa` to the bundle (or add `region`). `sslCa` always wins over the bundle. `"ssl": false` turns TLS off for any target, RDS included. Never set it on an RDS target.

Tokens are minted locally by `@aws-sdk/rds-signer` (a presigned request, no API call) and are valid for 15 minutes; Daypass discards its connection pool on the first call after 10 minutes and mints a fresh token, so a token never expires mid-pool.

## 6. Check it

```bash
daypass open prod --ttl 30m --reason "first prod lease"
daypass doctor prod
```

`doctor` prints one line per link in the chain. For an RDS target the `aws credentials` line shows the caller ARN that will appear in the audit log. If `tcp` says `timeout after 5 s (firewall / security group?)`, the IP rule is missing or your public IP is not the one `open` saw. Every line is explained in [Troubleshooting](troubleshooting.md).

## Known limit: load on the primary

Daypass points at whatever host you configure. On a busy primary, a scan of a large table competes with production traffic; the 10 s statement timeout and the 5-connection limit bound the damage but do not remove it. Pointing a target at a read replica is the real fix and is a config change on your side. The 10 s timeout is set for the primary case; raise it only once the target is a replica, and in both places: `sql/setup-role.sql` (the role setting) and `STATEMENT_TIMEOUT_MS` in `src/mcp/db.ts` (the session option, which overrides the role setting). `daypass doctor` accepts a role `statement_timeout` up to 5min.
