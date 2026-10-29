# peephole-db 0.1.0

First release. Temporary, read-only, audited Postgres access for AI coding agents. A human
opens a lease; Claude Code (or any MCP client) gets `SELECT`-only tools until it expires.

## What is in it

- `peephole open|status|close|sweep|log|doctor|sql|init|mcp`
- MCP tools: `peephole_status`, `list_tables`, `describe_table`, `explain`, `query`
- Postgres only. Auth: AWS RDS IAM tokens (no stored password) or a connection URL /
  password for any other Postgres.
- Guard: real Postgres parser (`libpg-query`); one statement; `SELECT`/`EXPLAIN` only; blocks
  row locks, `SELECT INTO`, `EXPLAIN ANALYZE` and 30+ dangerous functions.
- Limits: 500 rows, 2 KB per cell, 1 MB per result, 10 s statement timeout, read-only
  session.
- TLS always verified; RDS targets pin the bundled AWS RDS CA. Audit `who` is the AWS caller
  ARN for IAM targets.
- Audit: one JSON line per call in `~/.peephole/audit.jsonl`.
- Optional: punch the caller's IP into an AWS security group for the lease and remove it
  after.

## Install

```bash
npm install -g peephole-db
peephole init                                            # writes ~/.peephole/config.json
claude mcp add --scope user peephole -- peephole mcp     # any MCP client: `peephole mcp` over stdio
```

Claude Code plugin (skills, `/peephole:peephole-status|log|hidden-check`, a PreToolUse hook
that refuses SQL naming PII-looking columns outside your hidden list, and a three-case
`claude plugin eval` suite):

```
/plugin marketplace add Sajal0208/peephole
/plugin install peephole@peephole
```

## One-time database setup

Generate the hidden-columns list from your Prisma schema or from the live catalog, then
read it before you trust it:

```bash
peephole hidden suggest --prisma prisma/schema.prisma > hidden-columns.txt   # or --live <target> / --url <owner url>
```

Then create the role as the database owner:

```bash
peephole sql --hide-file hidden-columns.txt | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
```

The script creates `peephole_ro` with `SELECT` on everything except the hidden columns,
sets `default_transaction_read_only`, the timeouts and `CONNECTION LIMIT 5`, and ends with
a self-check that fails if a hidden column is still readable. Safe to re-run.

## Verified

- On a real production database: 52 hidden columns denied, writes blocked, lease expiry
  enforced.
- 45 guard tests (`test/guard.test.ts`), plus a stdio smoke test that drives the MCP
  server end to end (`scripts/smoke.mjs`).

## Known limits

Read these before you run it against anything you care about.

- **The audit file can hold PII.** It stores the SQL text, and `WHERE phone = '...'` is
  SQL text. The file lives on the laptop that ran the query. A central audit table is on the
  roadmap.
- **Shared IAM identity.** The audit `who` is the AWS caller ARN. If your team shares one
  AWS login, the log cannot tell teammates apart and "leaving the company means losing
  access" does not hold.
- **New tables are visible until the SQL is re-run.** `ALTER DEFAULT PRIVILEGES` grants
  `SELECT` on tables created later, and only for tables created by the user who ran the
  script. A new table with a PII column is readable until you add the column to the list
  and re-run. Columns added to a table that already has a hidden column go the other way:
  hidden until re-run.
- **A column you forgot to list is not hidden.** The role setup is the wall; the hidden
  list is your responsibility. `peephole hidden suggest` and the Prisma check
  (`PEEPHOLE_HIDDEN_FILE=... PEEPHOLE_PRISMA_SCHEMA=... npm test`) reduce the chance, they
  do not remove it.
- **A lease is per laptop, not per Claude session.** Every Claude Code window on the
  machine has the tools while the lease is open.
- **Reads hit the primary.** The 10 s statement timeout and the 5-connection cap are the
  only load protection. A read-replica target is next.
- **Postgres only.**

## Reporting a hole

Email security@vocobase.com. Do not open a public issue for anything that lets an agent read a
hidden column, run a write, bypass a lease, escape the timeouts or leak a credential. Reply
within 3 working days; fix within 14 days for anything that weakens the read-only guarantee.
See `SECURITY.md`.

Links: https://github.com/Sajal0208/peephole · https://www.npmjs.com/package/peephole-db ·
<SITE_URL>

MIT. Built by Vocobase.
