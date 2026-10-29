---
name: peephole-setup
description: Use when an admin wants to set up Peephole for the first time, add a database target, generate or review the hidden-columns list, or verify the read-only role.
---

# Peephole setup

Walk the admin from `npm install` to a verified read-only role, one step at a time. You do the
local, harmless parts (`peephole init`, `hidden suggest`, `doctor`); the admin does everything
that touches production or AWS. Secrets never enter the chat.

**Rules for the whole walkthrough**
- Ask ONE question per turn, two options max, say which you recommend.
- Never run `aws` yourself. Print the command, the admin runs it.
- Never ask for, echo, or store a production password or owner URL. The admin exports
  `OWNER_URL` in their own shell; you only reference `"$OWNER_URL"` in commands you print.
  If they paste one anyway: do not use it, do not repeat it, tell them to rotate it, carry on.
- Do not run `peephole open` for the admin except in step 7, after a yes to that step's own
  question. A general "go ahead" or "I'm in a hurry" earlier in the chat is not that yes.
- Non-secret values the admin gave (hostname, instance id, region, account id, group id) may be
  filled in. Where you do not know one, use the placeholders `my-db.abc123.eu-central-1.rds.amazonaws.com`,
  `123456789012`, `sg-xxxxxxxxxxxxxxxxx`, `db-XXXXXXXXXXXXXXXXXXXXXXXXXX`.

## 1. Which kind of database?

Ask: **(a)** any Postgres (URL with a password for the read-only role) or **(b)** AWS RDS (login
with an IAM token, no password at all)? Recommend (b) when the database is on RDS: access ends
with the person's AWS access and nothing is stored. Everything else is (a).

## 2. Install and write the target

Run `npm install -g peephole-db` and `peephole init` (writes `~/.peephole/config.json`, mode
0600, with example targets; it does nothing if the file exists). Then show the matching form
and ask the admin to replace the example targets with theirs. The `targets` key is the name
used by every later command.

URL form, (a). `CHANGE-ME` is the password set in step 4; TLS is verified unless the URL ends in
`?sslmode=disable` (local Postgres only):
```json
{ "targets": { "staging": { "url": "postgres://peephole_ro:CHANGE-ME@staging-db.example.com:5432/app" } } }
```
RDS form, (b). `region` is what switches a target to IAM auth. `awsProfile`, `securityGroupId`
(per-lease IP rule), `schemas` (default `["public"]`) and `maxRows` (default 500) are optional:
```json
{ "targets": { "prod": {
  "host": "my-db.abc123.eu-central-1.rds.amazonaws.com", "database": "app", "user": "peephole_ro",
  "region": "eu-central-1", "awsProfile": "default", "securityGroupId": "sg-xxxxxxxxxxxxxxxxx" } } }
```

## 3. Draft and review the hidden-columns list

Glob for `**/schema.prisma`. If one exists:
`peephole hidden suggest --prisma <path> > hidden-columns.txt`. Otherwise ask the admin to
`export OWNER_URL='postgres://<owner>:...@host:5432/app'` in their terminal, then run
`peephole hidden suggest --url "$OWNER_URL" > hidden-columns.txt`. (`--live <target>` also works
once the target can log in.) Show the file. Explain:

- The heuristic matches column *names* only (`phone`, `email`, `token`, `secret`, `key`,
  `transcript`, `password`, `address`, `ssn`, `encrypted_*`, `account_number`, `tax_id`,
  `national_id`, ...). It is a draft.
- Ask the admin to review every table, not just flagged lines: `notes`, `body`, `payload`,
  `metadata`, `raw` hide PII under neutral names. Hashed secrets stay hidden. Ids, timestamps,
  statuses, amounts stay visible; a whole-PII table keeps its primary key visible.
- A false positive is not deleted but turned into an allow line, `!servers.address  # host IP`,
  so `hidden check` records the decision and stops flagging it. `peephole sql` ignores `!` lines.
- Format: one `table.column` per line, `#` comments, camelCase accepted, `public` schema only.

Write the reviewed list to `~/.peephole/hidden-columns.txt` yourself (it holds column names,
nothing secret). The plugin's PII guard hook reads it from there (or from `PEEPHOLE_HIDDEN_FILE`). Suggest also committing a copy next to the
migrations in the repo that owns the schema.

## 4. Create the read-only role

The admin runs, as the database owner (RDS: the master user):
```bash
peephole sql --hide-file ~/.peephole/hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
```
Explain: the script is one transaction, so a failed run (typo, stale column) changes nothing,
and it is safe to re-run. It ends with a self-check; success prints
`NOTICE:  hidden columns verified: N columns across M tables`, failure stops with
`self-check failed: peephole_ro can still read <table.column>`. Outside RDS the
`NOTICE:  rds_iam role not found` line is expected. `--role NAME` renames the role.

(a) only: the role is created with no password. The admin sets one in their own psql session,
`ALTER ROLE peephole_ro PASSWORD '...'`, and puts that value into the target URL in
`~/.peephole/config.json`. The password is never typed into this chat. Re-runs of the setup SQL
keep the password. (b): no password, ever; the script grants `rds_iam`.

## 5. RDS only: IAM auth and permissions

Print these for the admin to run; do not run them. Enable IAM auth once per instance:
```bash
aws rds modify-db-instance --db-instance-identifier <id> --enable-iam-database-authentication --apply-immediately
aws rds describe-db-instances --db-instance-identifier <id> --query 'DBInstances[0].DbiResourceId'
```
Each person who opens leases needs this policy, attached to their own user or role (account id:
`aws sts get-caller-identity --query Account --output text`; second statement only with
`securityGroupId`; `ec2:DescribeSecurityGroupRules` takes no resource):
```json
{ "Version": "2012-10-17", "Statement": [
  { "Effect": "Allow", "Action": "rds-db:connect",
    "Resource": "arn:aws:rds-db:eu-central-1:123456789012:dbuser:db-XXXXXXXXXXXXXXXXXXXXXXXXXX/peephole_ro" },
  { "Effect": "Allow", "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"],
    "Resource": "arn:aws:ec2:eu-central-1:123456789012:security-group/sg-xxxxxxxxxxxxxxxxx" },
  { "Effect": "Allow", "Action": "ec2:DescribeSecurityGroupRules", "Resource": "*" } ] }
```
Warn: **remove any `0.0.0.0/0` inbound rule from that security group first**; a per-IP rule
means nothing while the group is open to the world. Shared IAM users make the audit `who`
useless; one identity per person.

## 6. Doctor

Run `peephole doctor <target>` and read it top to bottom; later checks only run when earlier ones
pass, and `db login` / `write blocked` need a live lease (expected ✖ `lease` at this point).
Map each ✖ to the heading of the same name in `docs/troubleshooting.md`:

| ✖ line | Usual fix |
|---|---|
| `config` | `peephole init`, or fix the JSON; check `PEEPHOLE_HOME` |
| `target` | name not under `targets`, or missing `host`/`database`/`user`, or neither `region` nor password |
| `dns` | typo, VPN down, or a hostname that only resolves inside the VPC |
| `aws credentials` | `aws sso login` / `aws configure` for that profile, or set `awsProfile` |
| `tcp` | empty = nothing listens; `timeout after 5 s` = no security-group rule for this IP: set `securityGroupId` (rule added per lease, so expect ✖ until step 7), or join the VPN/VPC |
| `db login` | password reset by a setup re-run (step 4); certificate error → `sslCa`; RDS auth error → step 5 |
| `read-only` / `write blocked` | stop, close the lease, re-run the setup SQL as owner |

## 7. Verification probe (ask first)

Ask: "Open a 5-minute lease on `<target>` to verify? I will run one denied query and one count."
Only on an explicit yes:
1. `peephole open <target> --ttl 5m --reason "setup check"` (add `--no-network` if they are
   inside the VPC). Then `peephole doctor <target>`: every line should be ✔.
2. `peephole hidden check --file ~/.peephole/hidden-columns.txt --live <target>`; exit 1 lists
   columns missing from the schema or sensitive-but-not-hidden: fix the file, re-run step 4.
3. Through the MCP tools: `query` with `select <hidden column> from <table> limit 1`, expecting
   `Query failed after ... ms: permission denied for table <table>`; then `query` with
   `select count(*) from <table>`, expecting a row. Anything else: the role is wrong, stop.
4. `peephole close`. Report the three results in one line each.

## 8. Hook up Claude Code

If this skill is running, the plugin is installed and the MCP server comes with it: nothing to
do. Otherwise, once per machine: `claude mcp add --scope user peephole -- peephole mcp`. Daily
use is `peephole open <target> --ttl 45m --reason "..."`, ask, `peephole log`, `peephole close`;
`docs/quickstart.md` walks through it. On RDS with the IP rule, suggest the
`*/15 * * * * peephole sweep <target>` cron from `docs/aws-rds.md`.
