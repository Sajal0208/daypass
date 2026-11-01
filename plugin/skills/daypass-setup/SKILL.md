---
name: daypass-setup
description: Use when an admin wants to set up Daypass for the first time, add a database target, generate or review the hidden-columns list, or verify the read-only role.
---

# Daypass setup

Walk the admin from `npm install` to a verified read-only role, one step at a time. You do the
local, harmless parts (`daypass init`, `hidden suggest`, `doctor`); the admin does everything
that touches production or AWS. Secrets never enter the chat.

**Rules for the whole walkthrough**
- Ask ONE question per turn, two options max, say which you recommend.
- Never run `aws` yourself. Print the command, the admin runs it.
- Never ask for, echo, or store a production password or owner URL. The admin exports
  `OWNER_URL` in their own shell; you only reference `"$OWNER_URL"` in commands you print.
  If they paste one anyway: do not use it, do not repeat it, tell them to rotate it, carry on.
- Never run `daypass open` or `daypass close` yourself, not even for the verification probe in
  step 7: a lease is the admin's decision and the audit log records it under their identity.
  Print the line, the admin runs it and tells you when it is open.
- Non-secret values the admin gave (hostname, instance id, region, account id, group id) may be
  filled in. Where you do not know one, use the placeholders `my-db.abc123.eu-central-1.rds.amazonaws.com`,
  `123456789012`, `sg-xxxxxxxxxxxxxxxxx`, `db-XXXXXXXXXXXXXXXXXXXXXXXXXX`.

## 1. Which kind of database?

Ask: **(a)** any Postgres (URL with a password for the read-only role) or **(b)** AWS RDS (login
with an IAM token, no password at all)? Recommend (b) when the database is on RDS: access ends
with the person's AWS access and nothing is stored. Everything else is (a).

## 2. Install and write the target

Run `npm install -g daypass` and `daypass init` (writes `~/.daypass/config.json`, mode
0600, with example targets; it does nothing if the file exists). Then show the matching form
and ask the admin to replace the example targets with theirs. The `targets` key is the name
used by every later command.

URL form, (a). `CHANGE-ME` is the password set in step 4; TLS is verified unless the URL ends in
`?sslmode=disable` (local Postgres only):
```json
{ "targets": { "staging": { "url": "postgres://daypass_ro:CHANGE-ME@staging-db.example.com:5432/app" } } }
```
RDS form, (b). `region` is what switches a target to IAM auth. `awsProfile`, `securityGroupId`
(per-lease IP rule), `schemas` (default `["public"]`) and `maxRows` (default 500) are optional:
```json
{ "targets": { "prod": {
  "host": "my-db.abc123.eu-central-1.rds.amazonaws.com", "database": "app", "user": "daypass_ro",
  "region": "eu-central-1", "awsProfile": "default", "securityGroupId": "sg-xxxxxxxxxxxxxxxxx" } } }
```

## 3. Draft and review the hidden-columns list

Glob for `**/schema.prisma`. If one exists:
`daypass hidden suggest --prisma <path> > hidden-columns.txt`. Otherwise ask the admin to
`export OWNER_URL='postgres://<owner>:...@host:5432/app'` in their terminal, then run
`daypass hidden suggest --url "$OWNER_URL" > hidden-columns.txt`. (`--live <target>` also works
once the target can log in.) Show the file. Explain:

- The heuristic matches column *names* only (`phone`, `email`, `token`, `secret`, `key`,
  `transcript`, `password`, `address`, `ssn`, `encrypted_*`, `account_number`, `tax_id`,
  `national_id`, ...). It is a draft.
- Ask the admin to review every table, not just flagged lines: free-text and blob columns
  (`raw`, `data`, `content`, `comment`) hide PII under names the heuristic does not know;
  `notes`, `body`, `payload`, `metadata` are flagged, and the admin decides each one. Hashed secrets stay hidden. Ids, timestamps,
  statuses, amounts stay visible; a whole-PII table keeps its primary key visible.
- A false positive is not deleted but turned into an allow line, `!servers.address  # host IP`,
  so `hidden check` records the decision and stops flagging it. `daypass sql` ignores `!` lines.
- Format: one `table.column` per line, `#` comments, camelCase accepted, `public` schema only.

Write the reviewed list to `~/.daypass/hidden-columns.txt` yourself (it holds column names,
nothing secret). The plugin's PII guard hook reads it from there (or from `DAYPASS_HIDDEN_FILE`). Suggest also committing a copy next to the
migrations in the repo that owns the schema.

## 4. Create the read-only role

The admin runs, as the database owner (RDS: the master user):
```bash
daypass sql --hide-file ~/.daypass/hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
```
Explain: the script is one transaction, so a failed run (typo, stale column) changes nothing,
and it is safe to re-run. It ends with a self-check; success prints
`NOTICE:  hidden columns verified: N columns across M tables`, failure stops with
`self-check failed: daypass_ro can still read <table.column>`. Outside RDS the
`NOTICE:  rds_iam role not found` line is expected. `--role NAME` renames the role.

(a) only: the role is created with no password. The admin sets one in their own psql session,
`ALTER ROLE daypass_ro PASSWORD '...'`, and puts that value into the target URL in
`~/.daypass/config.json`. The password is never typed into this chat. Re-runs of the setup SQL
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
    "Resource": "arn:aws:rds-db:eu-central-1:123456789012:dbuser:db-XXXXXXXXXXXXXXXXXXXXXXXXXX/daypass_ro" },
  { "Effect": "Allow", "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"],
    "Resource": "arn:aws:ec2:eu-central-1:123456789012:security-group/sg-xxxxxxxxxxxxxxxxx" },
  { "Effect": "Allow", "Action": "ec2:DescribeSecurityGroupRules", "Resource": "*" } ] }
```
Warn: **remove any `0.0.0.0/0` inbound rule from that security group first**; a per-IP rule
means nothing while the group is open to the world. Shared IAM users make the audit `who`
useless; one identity per person.

## 6. Doctor

Run `daypass doctor <target>` and read it top to bottom; later checks only run when earlier ones
pass, and every check from `db login` on needs a live lease (expected ✖ `lease` at this point,
so the database checks are rerun in step 7). Map each ✖ to the heading of the same name in
`docs/troubleshooting.md`:

| ✖ line | Usual fix |
|---|---|
| `config` | `daypass init`, or fix the JSON; check `DAYPASS_HOME` |
| `target` | name not under `targets`, or missing `host`/`database`/`user`, or neither `region` nor password |
| `dns` | typo, VPN down, or a hostname that only resolves inside the VPC |
| `aws credentials` | `aws sso login` / `aws configure` for that profile, or set `awsProfile` |
| `tcp` | empty = nothing listens; `timeout after 5 s` = no security-group rule for this IP: set `securityGroupId` (rule added per lease, so expect ✖ until step 7), or join the VPN/VPC |
| `db login` | password reset by a setup re-run (step 4); certificate error → `sslCa`; RDS auth error → step 5 |
| `read-only` / `role settings` | the session is not read-only or the role's settings (statement timeout, search path, ...) are not what the setup SQL sets: re-run the setup SQL as owner |
| `write blocked` | the role holds a write privilege on some table (the check reads the grants, it does not try a write): re-run the setup SQL as owner; if it still fails, something granted privileges outside Daypass |
| `hidden columns` | a column in the hidden list is still readable, or the list and the grants disagree: re-run the setup SQL with the current list, then `daypass hidden check` |
| `definer functions` | the role can call a `SECURITY DEFINER` function, which would run with its owner's rights and bypass the column grants: the owner revokes `EXECUTE` from the role (or from `PUBLIC`) on it |

Any other ✖ line: quote it and the fix `docs/troubleshooting.md` gives under that heading. Doctor
checks are added over time; describe a line you do not know from its detail text rather than
guessing, and never "fix" a database check by running SQL yourself.

## 7. Verification probe (the admin opens the lease)

Ask: "Ready to verify with a 5-minute lease on `<target>`? I will run one denied query and one
count, then you close it." On a yes, print this line for the admin to run in their terminal (add
`--no-network` when they are inside the VPC) and wait until they say it is open:
```bash
daypass open <target> --ttl 5m --reason "setup check"
```
Then, with the lease open:
1. `daypass doctor <target>`: every line should be ✔ now, including the database checks that
   needed the lease.
2. `daypass hidden check --file ~/.daypass/hidden-columns.txt --live <target>`; exit 1 lists
   columns missing from the schema or sensitive-but-not-hidden: fix the file, re-run step 4.
3. Through the MCP tools: `query` with `select <hidden column> from <table> limit 1`, expecting
   `Query failed after ... ms: permission denied for table <table>` (the plugin's PII guard lets
   this through because the column is in the hidden list; pick one that is); then `query` with
   `select count(*) from <table>`, expecting a row. Anything else: the role is wrong, stop.
4. Print `daypass close` for the admin to run. Report the three results in one line each.

## 8. Hook up Claude Code

If this skill is running, the plugin is installed and the MCP server comes with it: nothing to
do. Otherwise, once per machine: `claude mcp add --scope user daypass -- daypass mcp`. Daily
use is `daypass open <target> --ttl 45m --reason "..."`, ask, `daypass log`, `daypass close`;
`docs/quickstart.md` walks through it. On RDS with the IP rule, suggest the
`*/15 * * * * daypass sweep <target>` cron from `docs/aws-rds.md`.
