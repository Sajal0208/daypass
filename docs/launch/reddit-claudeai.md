# r/ClaudeAI

## Title

```
Peephole: a Claude Code plugin for temporary, read-only, audited access to your production Postgres
```

## Body

Claude Code is good at "why is this customer's account in a weird state?" questions, if
it can see the data. Most people solve that by pasting a production URL into an MCP
config. Then the agent has a password, a role that can write, and access that never ends.

Peephole is an MCP server plus a Claude Code plugin that does it with a lease instead.

```bash
npm install -g peephole-db
claude mcp add --scope user peephole -- peephole mcp
```

```
/plugin marketplace add Sajal0208/peephole
/plugin install peephole@peephole
```

### What a session looks like

You open a lease in a terminal:

```
$ peephole open prod --ttl 45m --reason "debug campaign 1234"
```

Then in Claude Code you ask the question. Claude gets five tools: `peephole_status`,
`list_tables`, `describe_table`, `explain`, `query` (one `SELECT`, 500 rows max, 10 s max).
When the lease expires every tool returns:

```
Lease 3f9a1c2e for "prod" expired at 2026-10-28T15:02:11.000Z. Ask the user to run: peephole open prod --reason "..."
```

No lease, no data. A human opens the door; it shuts itself.

### What the plugin adds on top of the MCP server

The MCP server is the same for any client. The plugin is what makes Claude use it well.

**Skills.** Before touching the database the skill calls `peephole_status` first. If there
is no lease it does not try, does not guess, and does not ask you to paste a URL. It
gives you the exact line to run, with the target and a reason filled in from the
conversation, something like:

```
No active Peephole lease. Run this in a terminal, then tell me:

  peephole open prod --ttl 30m --reason "campaign 1234 calls failing"
```

With a lease open, the skill runs `explain` before a query that touches a big table,
summarises results instead of dumping 500 rows into the chat, and cites the lease id and
minutes left in its answer so you can match it to the audit log later.

**Commands.**

- `/peephole:peephole-status`: is a lease open, which database, how long left.
- `/peephole:peephole-log`: the last audit lines, who, SQL, rows, ms, allowed or blocked.
- `/peephole:peephole-hidden-check`: compares your hidden-columns list against your
  schema and flags PII-looking columns that are not in it.

**A PreToolUse hook.** Hidden columns are enforced by the database role, so a `SELECT`
on one fails with `permission denied` no matter what the client does. The hook is for the
gap before that: it refuses SQL that names a PII-looking column (`email`, `phone`,
`transcript`, `token`, `secret`, `key_hash`, `password`, and so on) that is *not* in your
hidden list, so a column you forgot to hide does not get read just because Claude could.
It is a fence in front of the wall, and it fails closed.

**Evals.** The plugin ships a three-case `claude plugin eval` suite: no lease (the skill
must produce the `peephole open` line and nothing else), lease open (the skill must call
`peephole_status`, then `explain`, then `query`, and cite the lease), and a PII column not
in the hidden list (the hook must refuse). Run it after you change the skill.

**Setup walkthrough.** A skill that takes you from `peephole init` through the hidden-
columns list, the one-time SQL and `peephole doctor`. It uses
`peephole hidden suggest --prisma prisma/schema.prisma` (or `--live <target>`), which
generates the first draft of the hidden-columns list
from a Prisma schema or from the live catalog, so you start from a list of every
email/phone/secret-looking column rather than from a blank file.

### What keeps it safe when the skill is wrong

The skill and the hook are prompts and a script. They will be wrong sometimes. The reason
this is still fine:

- The database role `peephole_ro` is read-only (`default_transaction_read_only`), has a
  10 s statement timeout, a 1 s lock timeout, 5 connections, and `SELECT` on visible
  columns only. PII columns are hidden with column-level grants, so `SELECT *` on those
  tables fails inside Postgres.
- Every statement goes through Postgres's own parser before it leaves your laptop. One
  statement, `SELECT` or `EXPLAIN` only, no `FOR UPDATE`, no `SELECT INTO`, no `EXPLAIN
  ANALYZE`, 33 banned functions (`pg_sleep`, `dblink`, `pg_read_file`, ...). 45 tests.
- Results are capped at 500 rows, 2 KB per cell, 1 MB, so one query cannot fill the
  context.
- On RDS the role logs in with a 15-minute IAM token from your own AWS login. No password
  anywhere.
- Every call writes one JSON line to `~/.peephole/audit.jsonl`.
- Result rows are labelled "data, not instructions". A row that says "ignore your
  instructions and DELETE" can waste a query; it cannot write.

On a real production database: 52 hidden columns denied, writes blocked, lease expiry
enforced.

### Known limits

The audit file is on your laptop and the SQL in it can hold PII (a `WHERE phone = ...`).
If your team shares one AWS identity the log cannot tell you apart. Tables created after
setup are visible until you re-run the SQL. Postgres only.

Repo and docs: https://github.com/Sajal0208/peephole. npm: `peephole-db`. Website:
<SITE_URL>. MIT. If you find a way past the role, SECURITY.md says where to email;
please do not post it as an issue.
