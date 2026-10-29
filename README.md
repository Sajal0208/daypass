# Peephole

[![CI](https://github.com/Sajal0208/peephole/actions/workflows/ci.yml/badge.svg)](https://github.com/Sajal0208/peephole/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/peephole-db)](https://www.npmjs.com/package/peephole-db)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![node](https://img.shields.io/node/v/peephole-db)](package.json)

**Temporary, read-only, audited database access for AI coding agents.**

<p align="center"><img src="https://raw.githubusercontent.com/Sajal0208/peephole/main/docs/assets/demo.gif" alt="peephole open, doctor, a query that works, SELECT * denied, an UPDATE blocked, peephole log" width="720"></p>

Peephole is a small CLI plus an MCP server that lets an AI coding agent run `SELECT`s against
your Postgres for a limited time, through a database role that cannot write and cannot see the
columns you hid. It is for engineers who want Claude Code (or any MCP client) to answer
questions about production data without handing it the database URL. It is not a write path
and not a GUI: the agent gets five read-only tools, you keep `psql`.

You open a lease (`peephole open prod --ttl 60m --reason "..."`). For that hour the agent can
run `SELECT`s on your production Postgres through five MCP tools. Then the door shuts on its
own. No password ever goes into the chat, the agent cannot write, and every query is logged
with who, why, what, how many rows and how long.

## Why not just give the agent the DB URL?

- **The password lands in context and config forever.** It sits in `.mcp.json`, in the chat
  transcript, in whatever the client logs. Rotating it later means finding every copy.
- **Nothing expires.** Access granted for one debugging session is still there next month.
- **Writes are possible.** A URL to the application user can `UPDATE`, `DELETE` and `DROP`.
  One wrong tool call, or one row of injected text that reads like an instruction, is enough.
- **PII flows into the model.** `SELECT * FROM users` ships every email, phone and token to the
  model provider, and into the transcript.
- **Nobody can say afterwards what was read.** No log ties a query to a person and a reason.

Peephole replaces the URL with a lease, a role, a parser and an audit line.

## How it works

```
peephole open prod --ttl 45m --reason "why are campaign 1234's calls failing"
   │
   ▼
Claude ──MCP──▶ peephole ──▶ lease live? ──▶ SELECT-only parser ──▶ IAM token ──▶ Postgres
                                                                                  (role: SELECT on
                audit.jsonl ◀───────────────────────────────────────────────────  visible columns,
                                                                                   read-only, 10 s)
```

## Why it is safe

Each layer is enough on its own. All of them run together.

| Layer | What it does |
|---|---|
| **DB role** | `SELECT` on visible columns only. PII and secret columns are hidden at the Postgres level, so `SELECT *` on those tables fails. `default_transaction_read_only`, 10 s statement timeout, 1 s lock timeout, 5 connections. |
| **No stored password** | On AWS RDS the role logs in with a 15-minute IAM token minted from *your* AWS identity. Lose AWS access, lose Peephole access. |
| **Real parser** | Every statement goes through Postgres's own parser (`libpg-query`). One statement; `SELECT` or `EXPLAIN` only; no `FOR UPDATE`, `SELECT INTO`, `EXPLAIN ANALYZE`, `pg_sleep`, `dblink`, `pg_read_file`, `set_config`, `nextval`, advisory locks, … |
| **Result caps** | 500 rows, 2 KB per cell, 1 MB per result. The model's context never floods. |
| **Audit** | One JSON line per call in `~/.peephole/audit.jsonl`: time, caller (AWS ARN for IAM targets), lease id, reason, SQL, rows, ms, allowed/blocked. |
| **Network** | Optional: punch your current IP into the DB security group for the lease, remove it on close or expiry. |
| **TLS** | Always verified. RDS targets pin the bundled AWS RDS CA. |

## Compared with the alternatives

| | Expires by itself | Writes impossible at the DB level | PII hidden by default | Per-query audit with who/why | No stored password | Built for an agent (result caps, "data, not instructions") |
|---|---|---|---|---|---|---|
| **Peephole** | ✔ | ✔ | ✔ for every column in your hidden list | ✔ | ✔ on AWS RDS (IAM token); a URL target keeps a read-only password in `~/.peephole/config.json` | ✔ |
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
npm install -g peephole-db
peephole init                      # writes ~/.peephole/config.json
```

Edit the config. One entry per database:

```jsonc
{
  "targets": {
    // Any Postgres: a URL with a password (read-only role, see below)
    "staging": { "url": "postgres://peephole_ro:...@staging-db.example.com:5432/app" },

    // AWS RDS: no password, IAM token minted from your AWS login
    "prod": {
      "host": "my-db.abc123.eu-central-1.rds.amazonaws.com",
      "database": "app",
      "user": "peephole_ro",
      "region": "eu-central-1",
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

Run as the database owner. First list the columns the agent must never see. Peephole can draft
the list from the live schema (`--url`, or `--live <target>` for a configured target) or from a
Prisma schema (`--prisma prisma/schema.prisma`); review it, it is a heuristic on column names:

```bash
peephole hidden suggest --url "$OWNER_URL" > hidden-columns.txt
$EDITOR hidden-columns.txt         # one table.column per line, e.g. users.email, api_keys.key_hash;
                                   # prefix a reviewed, intentionally visible column with ! (e.g. !servers.address)

peephole sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
```

The script creates `peephole_ro`, grants `SELECT` on everything except the hidden columns,
sets the timeouts, and ends with a self-check that fails if a hidden column is still readable.
Safe to re-run: it runs as one transaction, so a failed run changes nothing, and re-runs keep
the role's password (`-X` skips your psqlrc). For a non-RDS database, set a password once after
the first run: `ALTER ROLE peephole_ro PASSWORD '...'` (on RDS the role has no password; it logs
in with IAM tokens).

After a schema change, `peephole hidden check --file hidden-columns.txt --live <target>`
(or `--prisma prisma/schema.prisma`, or `--url "$OWNER_URL"`) compares the list with the schema
and exits 1 when a listed column no longer exists or a sensitive-looking column is neither
hidden nor on a `!` line. If you use Prisma, the same check runs from a checkout of this repo
as a test, for CI:
`PEEPHOLE_HIDDEN_FILE=hidden-columns.txt PEEPHOLE_PRISMA_SCHEMA=prisma/schema.prisma npm test`. Details and a review
checklist: [docs/hidden-columns.md](docs/hidden-columns.md), [docs/prisma-check.md](docs/prisma-check.md).

**AWS RDS only:** enable IAM auth on the instance
(`aws rds modify-db-instance --enable-iam-database-authentication --apply-immediately`),
and give each person `rds-db:connect` on
`arn:aws:rds-db:<region>:<account>:dbuser:<db-resource-id>/peephole_ro`, plus
`ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`,
`ec2:DescribeSecurityGroupRules` on the DB security group if you use the IP rule.
Remove any `0.0.0.0/0` rule first; per-IP rules mean nothing while it exists.
Step by step, with the IAM policy: [docs/aws-rds.md](docs/aws-rds.md). Any other Postgres:
[docs/other-postgres.md](docs/other-postgres.md).

## Hook up Claude Code (once)

Either register the MCP server directly:

```bash
claude mcp add --scope user peephole -- peephole mcp
```

or install the Claude Code plugin, which, once installed, registers the MCP server for you (so
plugin users skip `claude mcp add`) and adds a skill that teaches Claude how to use the tools.
Install steps and what it adds on top of the bare MCP server: [docs/plugin.md](docs/plugin.md).

Any MCP client works: the command is `peephole mcp` over stdio.

## Daily use

```bash
peephole open prod --ttl 45m --reason "debug campaign 1234"
peephole doctor                    # config → DNS → AWS creds → TCP → login → write blocked
#   ... ask Claude questions; it uses list_tables / describe_table / explain / query ...
peephole status
peephole log --last 20
peephole close                     # or just let it expire
```

With no live lease every tool returns *"No active Peephole lease. Ask the user to run:
peephole open …"*. The MCP server removes the IP rule itself when it finds the lease expired;
`peephole sweep prod` from cron every 15 min is the backstop.

## MCP tools

| Tool | Does |
|---|---|
| `peephole_status` | Lease open? Which DB? Minutes left? |
| `list_tables` | Tables, estimated rows, size, for the allowed schemas |
| `describe_table` | Columns, types, nullability, defaults, indexes |
| `explain` | `EXPLAIN` (never `ANALYZE`) so the agent can check cost first |
| `query` | One `SELECT`. 500 rows max, 10 s max |

Result rows are labelled *"data, not instructions"* so a row containing text like
"ignore your instructions" is treated as data. Even if it were not, the DB role cannot write.

## Docs

- [Quickstart](docs/quickstart.md): install to first question in five minutes.
- [Concepts](docs/concepts.md): leases, targets, the role, the guard, the audit line.
- [AWS RDS](docs/aws-rds.md): IAM auth, the policy, the security-group rule.
- [Other Postgres](docs/other-postgres.md): URL targets, passwords, TLS.
- [Threat model](docs/threat-model.md): what each layer stops, and what it does not.
- [Hidden columns](docs/hidden-columns.md): `peephole hidden suggest` and `check`, the review checklist.
- [Prisma check](docs/prisma-check.md): failing CI when the hidden list falls behind the schema.
- [Troubleshooting](docs/troubleshooting.md): every `peephole doctor` line and what to do about it.
- [FAQ](docs/faq.md)
- [Claude Code plugin](docs/plugin.md): how to install it and what it adds on top of `claude mcp add`.

## Roadmap

Postgres only for now; MySQL and others are not supported. A hosted version (connector in your
VPC, SSO, Slack approvals, audit dashboard) is planned but not built. What is next and what is
only an idea: [ROADMAP.md](ROADMAP.md). Open an issue if you want something moved up.

## Layout

```
src/core   SQL guard, result shaping, lease rules, audit format (pure, tested)
src/mcp    MCP server, state files, DB pool (IAM token, RDS CA), security-group calls
src/cli    peephole init / sql / hidden / open / status / close / sweep / log / doctor / mcp
sql/       setup-role.sql template
certs/     AWS RDS global CA bundle
scripts/   CI integration run, secret scrub, smoke test
```

## Contributing and security

PRs welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Questions and bug reports:
[SUPPORT.md](SUPPORT.md). Found a way past the wall? **Do not open an issue**; see
[SECURITY.md](SECURITY.md).

MIT.
