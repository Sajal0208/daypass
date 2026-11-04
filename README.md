# Daypass

[![CI](https://github.com/Sajal0208/daypass/actions/workflows/ci.yml/badge.svg)](https://github.com/Sajal0208/daypass/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/daypass)](https://www.npmjs.com/package/daypass)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![node](https://img.shields.io/node/v/daypass)](package.json)

**Temporary, read-only, audited database access for AI coding agents.**

<p align="center"><img src="https://raw.githubusercontent.com/Sajal0208/daypass/main/docs/assets/demo.gif" alt="daypass open, doctor, a query that works, SELECT * denied, an UPDATE blocked, daypass log" width="720"></p>

Daypass is a small CLI plus an MCP server that lets an AI coding agent run `SELECT`s against
your Postgres for a limited time, through a database role that holds no write privilege and no
grant on the columns you hid. It is for engineers who want Claude Code (or any MCP client) to answer
questions about production data without handing it the database URL. It is not a write path
and not a GUI: the agent gets five read-only tools, you keep `psql`.

You open a lease (`daypass open prod --ttl 60m --reason "..."`). For that hour the agent can
run `SELECT`s on your production Postgres through five MCP tools. Then the door shuts on its
own. The tools never hand the agent a password, every statement runs in a read-only
transaction as a role with no write privilege, and every database call is logged before it
runs and again when it ends, with who, why, what, how many rows and how long. You hand the agent a day
pass: it opens with a reason, it expires on its own, and what it did is in the log.

## Why not just give the agent the DB URL?

- **The password lands in context and config forever.** It sits in `.mcp.json`, in the chat
  transcript, in whatever the client logs. Rotating it later means finding every copy.
- **Nothing expires.** Access granted for one debugging session is still there next month.
- **Writes are possible.** A URL to the application user can `UPDATE`, `DELETE` and `DROP`.
  One wrong tool call, or one row of injected text that reads like an instruction, is enough.
- **PII flows into the model.** `SELECT * FROM users` ships every email, phone and token to the
  model provider, and into the transcript.
- **Nobody can say afterwards what was read.** No log ties a query to a person and a reason.

Daypass replaces the URL with a lease, a role, a parser and an audit line.

## How it works

```
daypass open prod --ttl 45m --reason "why are order 1234's payments failing"
   │
   ▼
Claude ──MCP──▶ daypass ──▶ lease live? ──▶ SELECT-only parser ──▶ IAM token ──▶ Postgres
                                                                   or password    (role: SELECT on
                audit.jsonl ◀── start line before, end line after ──────────────  visible columns,
                                                                                   read-only txn, 10 s)
```

## Why it is safe

Each layer is enough for the job it has, and all of them run together. The role's grants are
the wall: they decide what can be read and that nothing can be written, from any client. The
other layers are fences: they limit cost, blast radius and context size, and keep the role's
own defaults in place for the agent, but none of them stops a write by itself.

| Layer | What it does |
|---|---|
| **DB role** | `SELECT` on visible columns only, granted table by table (no default privileges), and no write privilege anywhere. PII and secret columns are hidden at the Postgres level, so `SELECT *` on those tables fails; views and materialized views that would expose one, or that read (or stored) with their owner's rights what the role may not see, are not granted. The setup refuses a role that keeps `REPLICATION` or `BYPASSRLS`, reaches a foreign server, or sits behind default or catalog grants to `PUBLIC`; on RDS `rds_iam` is granted for login only. Role defaults: `default_transaction_read_only`, 10 s statement timeout, 1 s lock timeout; 5 connections. The defaults are the role's own to change in a direct session; `daypass doctor` reports drift. |
| **No stored password** | On AWS RDS the role logs in with a 15-minute IAM token minted from *your* AWS identity. Lose AWS access, lose Daypass access. |
| **Real parser** | Every statement goes through Postgres's own parser (`libpg-query`). One statement of at most 256 KiB; `SELECT` or `EXPLAIN` only; no data-modifying CTE, `FOR UPDATE`, `SELECT INTO`, `EXPLAIN ANALYZE`, `pg_sleep`, `dblink`, `pg_read_file`, `set_config`, `nextval`, advisory locks, `query_to_xml`, … (attribute notation such as `(x).pg_sleep` included). The block list cannot cover every extension's functions; the role's `EXECUTE` grants are the boundary there. |
| **Read-only transaction** | Each call runs in `BEGIN READ ONLY` with a statement timeout of 10 s or the lease time left, whichever is shorter, over the extended protocol (one command), and the session is reset (`DISCARD ALL`) afterwards. A call that is cut off is cancelled in the database too. |
| **Result caps** | 500 rows, 2000 characters per cell and 1 MB (UTF-8 bytes) per result, all cut in the database before the rows are sent; 32 MiB on the wire per call; database errors cut at 2000 characters and labelled as data. |
| **Audit** | Two JSON lines per call in `~/.daypass/audit.jsonl`, one written before the query runs and one when it ends: time, caller (AWS ARN for IAM targets), lease id, reason, SQL, rows, ms, error. Refusals get one line with the reason. Each field is capped; a statement over 16 KiB is kept as a prefix plus its SHA-256. |
| **Network** | Optional: punch your current IP into the DB security group for the lease (`/32`, or `/128` for IPv6); removed on `close`, on the first tool call after expiry, or by `daypass sweep` (which only touches rules Daypass wrote). |
| **TLS** | Always verified. RDS targets (IAM, or any `*.rds.amazonaws.com` host) pin the bundled AWS RDS CA and cannot turn TLS off. |

## Compared with the alternatives

| | Expires by itself | No write privilege at the DB level | PII hidden by default | Per-query audit with who/why | No stored password | Built for an agent (result caps, "data, not instructions") |
|---|---|---|---|---|---|---|
| **Daypass** | ✔ | ✔ | ✔ for every column in your hidden list | ✔ | ✔ on AWS RDS (IAM token); a URL target keeps a read-only password in `~/.daypass/config.json` | ✔ |
| DB URL in an MCP config / direct `psql` | ✖ | depends on setup | depends on setup | ✖ | ✖ | ✖ |
| pgweb or another GUI | ✖ | depends on setup | depends on setup | ✖ | depends on setup | ✖ |
| Read replica with a password | ✖ | ✔ | depends on setup | ✖ | ✖ | ✖ |
| Lease-less Postgres MCP servers | ✖ | varies | varies | varies | varies | varies |

"Depends on setup" means the database owner can get there with the right role and grants; the
tool does not do it for them. The last row is deliberately unnamed: those servers differ a lot,
and we only claim what we have checked.

## Install

Needs Node 20 or newer.

```bash
npm install -g daypass
daypass init                      # writes ~/.daypass/config.json
```

Edit the config. One entry per database:

```jsonc
{
  "targets": {
    // Any Postgres: a URL with a password (read-only role, see below)
    "staging": { "url": "postgres://daypass_ro:...@staging-db.example.com:5432/app" },

    // AWS RDS: no password, IAM token minted from your AWS login
    "prod": {
      "host": "my-db.abc123.us-east-1.rds.amazonaws.com",
      "database": "app",
      "user": "daypass_ro",
      "region": "us-east-1",
      "awsProfile": "default",             // optional
      "securityGroupId": "sg-xxxxxxxxxxxxxxxxx", // optional: per-lease IP rule
      "schemas": ["public"],               // optional, default public
      "maxRows": 500                       // optional
    }
  }
}
```

The five-minute version with every command in order is [docs/quickstart.md](docs/quickstart.md).

## One-time database setup

Run as the database owner. First list the columns the agent must never see. Daypass can draft
the list from the live schema (`--url-env`, or `--live <target>` for a configured target) or from a
Prisma schema (`--prisma prisma/schema.prisma`); review it, it is a heuristic on column names:

```bash
export OWNER_URL='postgres://owner:...@db.example.com:5432/app'
daypass hidden suggest --url-env OWNER_URL > hidden-columns.txt   # keeps the password off the command line
$EDITOR hidden-columns.txt         # one table.column per line, e.g. users.email, api_keys.key_hash;
                                   # prefix a reviewed, intentionally visible column with ! (e.g. !servers.address)

daypass sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
```

The script creates `daypass_ro`, grants `SELECT` table by table on everything in the listed
schemas except the hidden columns (and the views that would expose them), sets the timeouts,
and ends with a self-check that fails if a hidden column is still readable, if the role holds
a write privilege anywhere (column-level grants included), reaches a foreign server, has
`REPLICATION` or `BYPASSRLS`, sits behind default or catalog grants to `PUBLIC`, or can execute
a `SECURITY DEFINER` function. It sets no default
privileges: **a table created later is invisible until you re-run the script**, while a column
added to a table that has no hidden columns is readable at once. Safe to re-run: it runs as one
transaction, so a failed run changes nothing, and re-runs keep the role's password (`-X` skips
your psqlrc). For a non-RDS database, set a password once after
the first run with `\password daypass_ro` in an interactive `psql`, which keeps the value out of
shell history and the server log (on RDS the role has no password; it logs in with IAM tokens).

After a schema change, `daypass hidden check --file hidden-columns.txt --live <target>`
(or `--prisma prisma/schema.prisma`, or `--url-env OWNER_URL`) compares the list with the schema
and exits 1 when a listed column no longer exists or a sensitive-looking column is neither
hidden nor on a `!` line. If you use Prisma, the same check runs from a checkout of this repo
as a test, for CI:
`DAYPASS_HIDDEN_FILE=hidden-columns.txt DAYPASS_PRISMA_SCHEMA=prisma/schema.prisma npm test`. Details and a review
checklist: [docs/hidden-columns.md](docs/hidden-columns.md), [docs/prisma-check.md](docs/prisma-check.md).

**AWS RDS only:** enable IAM auth on the instance
(`aws rds modify-db-instance --enable-iam-database-authentication --apply-immediately`),
and give each person `rds-db:connect` on
`arn:aws:rds-db:<region>:<account>:dbuser:<db-resource-id>/daypass_ro`, plus
`ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`,
`ec2:DescribeSecurityGroupRules` (used by `open`'s cleanup, `close` and `sweep`) if you use the IP rule.
Remove any `0.0.0.0/0` rule first; per-IP rules mean nothing while it exists.
Step by step, with the IAM policy: [docs/aws-rds.md](docs/aws-rds.md). Any other Postgres:
[docs/other-postgres.md](docs/other-postgres.md).

## Hook up Claude Code (once)

Either register the MCP server directly:

```bash
claude mcp add --scope user daypass -- daypass mcp
```

or install the Claude Code plugin, which registers the server for you (no `claude mcp add`; it
runs the `daypass` on your `PATH`, so the `npm install -g daypass` above is still needed):

```
/plugin marketplace add Sajal0208/daypass
/plugin install daypass@daypass
```

The plugin adds a skill that teaches Claude the lease-first, named-columns, no-PII-in-the-reply
rules, a setup walkthrough, `/daypass:daypass-status`, `/daypass:daypass-log` and
`/daypass:daypass-hidden-check`, a hook that stops a `query` or `explain` naming a
PII-looking column your hidden list does not cover, or using `SELECT *`, a whole row or a
function that runs SQL from a string, and a hook that keeps Claude from running `daypass open`
or `daypass mcp` and from reading or writing `~/.daypass`. Both hooks match text and are second
fences, not the wall; they fail closed on Claude Code 2.1.295 or later. Details and limits: [docs/plugin.md](docs/plugin.md).

Any MCP client works: the command is `daypass mcp` over stdio.

## Daily use

```bash
daypass open prod --ttl 45m --reason "debug order 1234"
daypass doctor                    # config → DNS → AWS creds → TCP → login → role settings, grants, hidden columns, files, other databases
#   ... ask Claude questions; it uses list_tables / describe_table / explain / query ...
daypass status
daypass log --last 20             # one row per call
daypass close prod                # or let it expire; no target closes every lease
```

With no live lease every tool except `daypass_status` refuses: *"No active Daypass lease. Ask the
user to run: daypass open …"* when there is no lease, or *"Lease … for "prod" expired at …. Ask
the user to run: daypass open prod …"* when it ran out. The MCP server removes the IP rule itself on the first tool call after the
lease expired; `daypass sweep prod` from cron every 15 min is the backstop.

## MCP tools

| Tool | Does |
|---|---|
| `daypass_status` | Lease open? Which DB? Minutes left? |
| `list_tables` | Tables, estimated rows, size, for the allowed schemas |
| `describe_table` | Readable columns in table order, types, nullability, indexes (indexes on hidden columns are left out) |
| `explain` | `EXPLAIN` (never `ANALYZE`) so the agent can check cost first |
| `query` | One `SELECT`. 500 rows, 2000 characters per cell and 1 MB max, 10 s max |

Result rows are labelled *"data, not instructions"* so a row containing text like
"ignore your instructions" is treated as data. Even if it were not, the DB role holds no write
privilege and the call runs in a read-only transaction.

The tools never return a credential, but the files under `~/.daypass` are protected by OS user
permissions only (Daypass keeps them `0600`, refuses symlinks and files owned by someone else):
an agent you also allow to run shell commands as you can read `config.json` (a URL target's
password) and edit the lease and audit files. The plugin's state hook blocks the obvious ways;
it is a fence, not a control. What that means and what to do
about it: [docs/threat-model.md](docs/threat-model.md).

## Docs

- [Quickstart](docs/quickstart.md): install to first question in five minutes.
- [Concepts](docs/concepts.md): leases, targets, the role, the guard, the audit line.
- [AWS RDS](docs/aws-rds.md): IAM auth, the policy, the security-group rule.
- [Other Postgres](docs/other-postgres.md): URL targets, passwords, TLS.
- [Threat model](docs/threat-model.md): what each layer stops, and what it does not.
- [Hidden columns](docs/hidden-columns.md): `daypass hidden suggest` and `check`, the review checklist.
- [Prisma check](docs/prisma-check.md): failing CI when the hidden list falls behind the schema.
- [Troubleshooting](docs/troubleshooting.md): every `daypass doctor` line and what to do about it.
- [FAQ](docs/faq.md)
- [Claude Code plugin](docs/plugin.md): install, the skills and commands, the PII and state guard hooks, the evals.

## Roadmap

Postgres only for now (PostgreSQL 16 or newer is recommended; see the parser note in the
[threat model](docs/threat-model.md)); MySQL and others are not supported. A hosted version
(connector in your VPC, SSO, Slack approvals, audit dashboard) is an idea on the roadmap, not
built. What is next and what is
only an idea: [ROADMAP.md](ROADMAP.md). Open an issue if you want something moved up.

## Layout

```
src/core   SQL guard, result shaping, lease rules, audit format (pure, tested)
src/mcp    MCP server, state files, DB pool (IAM token, RDS CA), security-group calls
src/cli    daypass init / sql / hidden / open / status / close / sweep / log / doctor / mcp
sql/       setup-role.sql template
certs/     AWS RDS global CA bundle
scripts/   CI integration run, secret scrub, smoke test
plugin/    Claude Code plugin (skills incl. the three slash commands, PII and state hooks, evals)
```

## Contributing and security

PRs welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Questions and bug reports:
[SUPPORT.md](SUPPORT.md). Found a way past the wall? **Do not open an issue**; see
[SECURITY.md](SECURITY.md).

MIT.
