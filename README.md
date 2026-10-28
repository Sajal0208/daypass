# Peephole

[![CI](https://github.com/Sajal0208/peephole/actions/workflows/ci.yml/badge.svg)](https://github.com/Sajal0208/peephole/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/peephole-db)](https://www.npmjs.com/package/peephole-db)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Temporary, read-only, audited database access for AI coding agents.**

You open a lease (`peephole open prod --ttl 60m --reason "..."`). For that hour, Claude Code
(or any MCP client) can run `SELECT`s on your production Postgres through four tools. Then the
door shuts on its own. No password ever goes into the chat, the agent cannot write, and every
query is logged with who, why, what, how many rows and how long.

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

## Install

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
      "securityGroupId": "sg-0123…",       // optional: per-lease IP rule
      "schemas": ["public"],               // optional, default public
      "maxRows": 500                       // optional
    }
  }
}
```

## One-time database setup

Run as the database owner. Lists the columns the agent must never see:

```bash
cat > hidden-columns.txt <<'EOF'
users.email
users.phone
sessions.transcript
api_keys.key_hash
EOF

peephole sql --hide-file hidden-columns.txt | psql "$DATABASE_URL" -v ON_ERROR_STOP=1
```

The script creates `peephole_ro`, grants `SELECT` on everything except the hidden columns,
sets the timeouts, and ends with a self-check that fails if a hidden column is still readable.
Safe to re-run. For a non-RDS database, set a password afterwards:
`ALTER ROLE peephole_ro PASSWORD '...'`.

If you use Prisma, keep the list honest:
`PEEPHOLE_HIDDEN_FILE=hidden-columns.txt PEEPHOLE_PRISMA_SCHEMA=prisma/schema.prisma npm test`
fails when a phone/email/secret-looking column is not in the list.

**AWS RDS only:** enable IAM auth on the instance
(`aws rds modify-db-instance --enable-iam-database-authentication --apply-immediately`),
and give each person `rds-db:connect` on
`arn:aws:rds-db:<region>:<account>:dbuser:<db-resource-id>/peephole_ro`, plus
`ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`,
`ec2:DescribeSecurityGroupRules` on the DB security group if you use the IP rule.
Remove any `0.0.0.0/0` rule first; per-IP rules mean nothing while it exists.

## Hook up Claude Code (once)

```bash
claude mcp add --scope user peephole -- peephole mcp
```

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

## Not covered (yet)

- MySQL and others: Postgres only for now.
- A hosted version (connector in your VPC, SSO, Slack approvals, audit dashboard) is on the
  roadmap. Open an issue if you want it.

## Layout

```
src/core   SQL guard, result shaping, lease rules, audit format (pure, tested)
src/mcp    MCP server, state files, DB pool (IAM token, RDS CA), security-group calls
src/cli    peephole init / sql / open / status / close / sweep / log / doctor / mcp
sql/       setup-role.sql template
certs/     AWS RDS global CA bundle
```

## Contributing and security

PRs welcome: see `CONTRIBUTING.md`. Found a way past the wall? **Do not open an issue**; see
`SECURITY.md`.

MIT.
