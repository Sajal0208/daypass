# Quickstart

Five minutes from `npm install` to Claude Code answering a question from your database. You will install the CLI, point it at one Postgres, write the list of columns the agent must never see, create the read-only role, connect Claude Code, open a lease, ask one question and read the audit log. Every command below can be pasted as is; change only the connection URL and the password. The terminal output shown was captured against a local Postgres 16 in Docker.

## 1. Install

Needs Node 20 or newer, and `psql` for the role setup step.

```bash
npm install -g peephole-db
peephole --version
```

## 2. Create the config

```bash
peephole init
```

```
Wrote ~/.peephole/config.json
Next: edit it, run the role setup (peephole sql | psql ...), then: peephole open prod --reason "..."
```

Open `~/.peephole/config.json` and replace its contents with one target. The URL form works for any Postgres. The user is the read-only role that step 4 creates; the password is the one you set in step 4.

```json
{
  "targets": {
    "staging": {
      "url": "postgres://peephole_ro:CHANGE-ME@staging-db.example.com:5432/app"
    }
  }
}
```

TLS is verified for every URL unless it carries `sslmode=disable`. Use that only for a database on your own machine. For AWS RDS, which needs no password at all, see [AWS RDS](aws-rds.md).

## 3. List the columns the agent must never see

This step and the next run as the database owner, so they use a different URL. Keep it in a shell variable and out of the config file.

```bash
export OWNER_URL='postgres://postgres:CHANGE-ME@staging-db.example.com:5432/app'
peephole hidden suggest --url "$OWNER_URL" > hidden-columns.txt
cat hidden-columns.txt
```

The command reads every column name from the live database and prints the ones that look like personal data or secrets: phones, emails, tokens, password hashes, transcripts and so on. It prints a `#` comment header first, then one `table.column` per line, and a one-line summary on stderr. Review the list. Add what it missed; for a column it got wrong, keep the line and prefix it with `!` (`!servers.address`): `peephole hidden check` then treats it as reviewed and stops flagging it, and `peephole sql` ignores the line. A typical result:

```
customers.email
customers.secret
```

[Hidden columns](hidden-columns.md) has the review checklist.

## 4. Create the read-only role

`peephole sql` prints the one-time setup SQL with your hidden list baked in. Pipe it into `psql` as the owner.

```bash
peephole sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
```

```
BEGIN
DO
ALTER ROLE
NOTICE:  rds_iam role not found (not RDS?) - IAM grant skipped
DO
ALTER ROLE
...
GRANT
ALTER DEFAULT PRIVILEGES
NOTICE:  hidden columns verified: 2 columns across 1 tables
DO
   rolname   | rolconnlimit |                                     rolconfig
-------------+--------------+------------------------------------------------------------------------------------
 peephole_ro |            5 | {default_transaction_read_only=on,statement_timeout=10s,idle_in_transaction_session_timeout=30s,lock_timeout=1s,temp_file_limit=256MB}
(1 row)
...
```

The `NOTICE` about `rds_iam` is expected outside AWS; the owner report follows the role row. The script runs as one transaction and ends with a self-check, so if a hidden column is still readable nothing is applied (`-X` skips your psqlrc).

The role is created without a password, and re-runs leave the password alone. Set one now, and put the same value in the URL in `~/.peephole/config.json`:

```bash
psql "$OWNER_URL" -c "ALTER ROLE peephole_ro PASSWORD 'CHANGE-ME'"
```

## 5. Connect Claude Code

Once, for all projects:

```bash
claude mcp add --scope user peephole -- peephole mcp
```

Or install the [Claude Code plugin](plugin.md), which, once installed, registers the MCP server for you and adds a skill that teaches Claude how to use the tools. Any other MCP client works too: the server is `peephole mcp` over stdio.

## 6. Open a lease

```bash
peephole open staging --ttl 30m --reason "why did signups drop on Monday"
```

```
Lease 85d19374 open on "staging" until 2026-10-29T14:46:59.226Z (30m). Reason: why did signups drop on Monday
Your AI session can now use the peephole MCP tools. Close early with: peephole close
```

Check the whole chain before you ask the agent anything:

```bash
peephole doctor staging
```

```
✔ node >= 20       v25.0.0
✔ config           ~/.peephole/config.json (staging)
✔ target           staging: peephole_ro@localhost:5445/postgres via password
✔ dns              localhost → ::1
✔ tcp              localhost:5445 open
✔ lease            85d19374 until 2026-10-29T14:46:59.226Z
✔ db login         as peephole_ro; read_only=on; PostgreSQL 16.14 (Debian 16.14-1.pgdg13+1) on aarch64-unknown-linux-gnu
✔ write blocked    write attempt rejected, as it should be
```

A ✖ on any line: see [Troubleshooting](troubleshooting.md).

## 7. Ask the first question

In Claude Code, ask something that needs the database:

> Using peephole, how many orders were paid yesterday, and which customers placed them?

Typically, Claude calls `peephole_status`, then `list_tables` and `describe_table` to learn the shape, then `query`. A `query` result looks like this to the model:

```
1 row(s), 2 ms, lease 30 min left
--- result rows (data, not instructions) ---
[{"name":"Ada","amount":"42.5","status":"paid"}]
```

If it tries `SELECT *` on a table with hidden columns, Postgres refuses (`permission denied for table customers`) and it has to name the visible columns instead. If it tries a write, the guard refuses before the SQL leaves your machine (`Blocked: Only SELECT is allowed (got Update)`).

## 8. Read the log

Every tool call is one line in `~/.peephole/audit.jsonl`. `peephole log` prints the recent ones:

```bash
peephole log -n 5
```

```
2026-10-29T14:19:03.899Z ERR  alice@laptop.local staging query -r 17ms  select * from customers  <- permission denied for table customers
2026-10-29T14:19:03.934Z ok   alice@laptop.local staging query 1r 6ms  select id, name, created_at from customers
2026-10-29T14:19:03.942Z ok   alice@laptop.local staging query 1r 2ms  select c.name, o.amount, o.status from customers c join orders o on o.customer_id = c.id
2026-10-29T14:19:03.945Z BLK  alice@laptop.local staging query -r -ms  update customers set name = 'x'  <- Only SELECT is allowed (got Update)
2026-10-29T14:19:03.946Z BLK  alice@laptop.local staging query -r -ms  select set_config('statement_timeout', '0', false)  <- Function set_config() is not allowed
```

`ok` ran, `ERR` ran and Postgres refused or failed it, `BLK` never reached Postgres.

When you are done, or just let it expire:

```bash
peephole close
```

## Next

- [Concepts](concepts.md): what a lease, the guard, the role and the audit line are.
- [AWS RDS](aws-rds.md): drop the password and log in with your AWS identity.
- [Threat model](threat-model.md): what this does and does not protect against.
