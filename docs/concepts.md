# Concepts

Daypass is five small parts: a lease that says access is open, a guard that reads every statement before it leaves your machine, a database role that cannot write and cannot see the hidden columns, an audit line per tool call, and caps on what a result may contain. This page says what each one is, where it lives on disk, and which numbers it enforces. The role is the wall; everything else is a second fence.

## Lease

A lease is a file: `~/.daypass/lease.json` (or `$DAYPASS_HOME/lease.json`). `daypass open` writes it, `daypass close` deletes it, and the MCP server reads it at the start of every tool call. No file, or `expiresAt` in the past, and every tool except `daypass_status` returns an error asking the user to run `daypass open` (`daypass_status` returns plain text: `No lease open.` or `Expired at …`).

```json
{
  "id": "85d19374",
  "target": "staging",
  "reason": "why did signups drop on Monday",
  "who": "alice@laptop.local",
  "openedAt": "2026-10-29T14:16:59.225Z",
  "expiresAt": "2026-10-29T14:46:59.226Z"
}
```

Facts about leases:

- **One per laptop.** Not per Claude session. Every Claude Code window on the machine has the tools while the lease is open. Opening a second one is refused: `A lease is already open (85d19374 on staging, until …). Run: daypass close`.
- **TTL.** `--ttl` takes `90s`, `30m`, `2h`. Default `60m`, minimum `60s`, maximum `8h`.
- **Who.** For an AWS RDS target it is the AWS caller ARN from `sts:GetCallerIdentity`, which cannot be set from the shell. For a URL or password target it is `$USER@hostname`.
- **Reason** is required. It goes into the lease and into every audit line written under it.
- **Network.** If the target has `region` and `securityGroupId`, `open` adds your public IP as a `/32` rule on that security group and records `ip` and `sgRuleId` in the lease. `close` removes the rule. If a lease expires without `close`, the MCP server removes the rule the first time it sees the expired lease; `daypass sweep <target>` from cron is the backstop. `--no-network` skips all of this.
- **Expiry is checked per call.** A query already running when the lease ends finishes (within the 10 s statement timeout). The next call is refused.

## Guard

Every statement the agent sends is parsed with `libpg-query`, Postgres's own parser compiled to WebAssembly, before anything is sent to the database. The guard is a pure function with no I/O; its rules, in order:

1. Empty SQL is refused.
2. SQL that does not parse is refused with the parser's message.
3. Exactly one statement. `select 1; drop table customers` is refused: `Exactly one statement is allowed, got 2`.
4. The statement must be a `SELECT`, or an `EXPLAIN` that wraps a `SELECT`. Anything else is refused by kind: `Only SELECT is allowed (got Update)`, `(got Delete)`, `(got VariableSet)` for `SET`, `(got Transaction)` for `BEGIN`.
5. `EXPLAIN ANALYZE` is refused, because it runs the query.
6. Inside the `SELECT`, the whole tree is walked. `FOR UPDATE` / `FOR SHARE` are refused (`Row locks … are not allowed`). `SELECT INTO` is refused. Any call to a function on the list below is refused, matched on the bare name, so `pg_catalog.pg_sleep(1)` is caught too, and so is a call buried in a subquery.

The banned functions, from `src/core/guard.ts`:

| Group | Functions |
|---|---|
| Sleep | `pg_sleep`, `pg_sleep_for`, `pg_sleep_until` |
| Remote connections | `dblink`, `dblink_exec`, `dblink_connect` |
| Server files | `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_stat_file` |
| Large objects | `lo_import`, `lo_export`, `lo_get`, `lo_put`, `lo_unlink` |
| Backends and config | `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`, `set_config` |
| Advisory locks | `pg_advisory_lock`, `pg_advisory_lock_shared`, `pg_advisory_xact_lock`, `pg_advisory_xact_lock_shared`, `pg_try_advisory_lock`, `pg_try_advisory_xact_lock` |
| Sequences | `nextval`, `setval` |
| Messaging and WAL | `pg_notify`, `pg_logical_emit_message`, `pg_create_restore_point`, `pg_switch_wal`, `pg_backup_start`, `pg_backup_stop` |

A refused statement makes the tool return `Blocked: <reason>`. The refusal is also written to the audit log with `allowed: false` and the reason, for `explain` in the same line shape as for `query`.

The guard is not what makes writes impossible. The role is. The guard exists so that a blocked statement never reaches the database, costs nothing, and shows up in the log with a clear reason.

## Role

`daypass sql` prints `sql/setup-role.sql` with your role name and hidden list filled in. Run as the database owner, it creates the role (default name `daypass_ro`) and sets, at the role level:

| Setting | Value |
|---|---|
| `LOGIN`, `NOCREATEDB`, `NOCREATEROLE`, `NOINHERIT` | role attributes |
| `CONNECTION LIMIT` | 5 |
| `PASSWORD` | not set by the script (a non-RDS owner sets one once after the first run; RDS roles log in with IAM tokens) |
| `default_transaction_read_only` | `on` |
| `statement_timeout` | `10s` |
| `idle_in_transaction_session_timeout` | `30s` |
| `lock_timeout` | `1s` |
| `temp_file_limit` | `256MB` |

On RDS it also grants `rds_iam`, so the role can log in with an IAM token. Elsewhere that grant is skipped with a `NOTICE`.

Grants: `CONNECT` on the database, `USAGE` on `public`, `SELECT` on all tables and sequences in `public`, and `ALTER DEFAULT PRIVILEGES … GRANT SELECT ON TABLES` so tables created later by the same owner are readable too.

**Hidden columns use column-level grants.** Postgres ignores a column-level `REVOKE` while the role holds table-level `SELECT`. So for each table that has a hidden column, the script revokes table-level `SELECT` and grants `SELECT (col, col, …)` on the visible columns only. Two consequences:

- `SELECT *` on such a table fails with `permission denied for table customers`. The agent has to name columns. The `query` tool's description tells it so. `describe_table` reads `information_schema.columns`, which only lists columns the role may read, so the agent does not even see the names of hidden columns.
- A column added later to one of those tables is hidden until the script is re-run. A brand-new table is fully visible.

The script ends with a self-check: every hidden column must be unreadable, and at least one column of each of those tables must still be readable. If either fails, the script stops with an error. See [Hidden columns](hidden-columns.md).

The MCP server does not trust the role settings alone. Every connection it opens also sets `default_transaction_read_only=on`, `statement_timeout=10000`, `idle_in_transaction_session_timeout=30000` and `lock_timeout=1000` as session options, keeps at most 2 connections per target, and names itself `daypass` in `application_name`.

## Audit

Every tool call that reaches the guard appends one JSON object to `~/.daypass/audit.jsonl` (mode `0600`), whether it was allowed or not. The fields, from `src/core/audit.ts`:

| Field | Meaning |
|---|---|
| `at` | ISO timestamp |
| `who` | the lease's identity: AWS ARN or `user@host` |
| `leaseId` | the lease the call ran under |
| `target` | target name from the config |
| `reason` | the lease's reason |
| `tool` | `query`, `explain`, `list_tables` or `describe_table` |
| `sql` | the statement as sent (for `explain`, with the `EXPLAIN (FORMAT TEXT)` prefix added) |
| `allowed` | `false` if the guard refused it |
| `blockedReason` | why, when `allowed` is `false` |
| `rows` | rows returned, after the caps |
| `ms` | wall time of the query |
| `error` | the Postgres error, when the statement ran but failed |

Two real lines:

```json
{"at":"2026-10-29T14:19:03.899Z","who":"alice@laptop.local","leaseId":"b11e4bff","target":"staging","reason":"why did signups drop on Monday","tool":"query","sql":"select * from customers","allowed":true,"ms":17,"error":"permission denied for table customers"}
{"at":"2026-10-29T14:19:03.934Z","who":"alice@laptop.local","leaseId":"b11e4bff","target":"staging","reason":"why did signups drop on Monday","tool":"query","sql":"select id, name, created_at from customers","allowed":true,"rows":1,"ms":6}
```

`daypass log -n 30` prints the last lines in one-line form; `ok` ran, `ERR` ran and failed, `BLK` was refused by the guard. The file is plain JSONL, so `jq` and `grep` work on it.

The SQL text is logged as is. A `WHERE email = 'ada@example.com'` puts that address in the file. `daypass_status`, `daypass open` and `daypass close` do not write audit lines.

## Result caps

A `query` is wrapped as `SELECT * FROM (<sql>) daypass_q LIMIT <maxRows + 1>` so Daypass can tell "exactly 500" from "more than 500". The rows then go through `shapeRows`:

| Cap | Default | Config key | Effect when hit |
|---|---|---|---|
| Rows | 500 | `maxRows` | `Only the first 500 rows are shown; add a WHERE or a smaller LIMIT.` |
| Bytes per cell | 2000 | `maxCell` | string cut to 2000 characters, then `…[+N chars]` |
| Bytes per result | 1 000 000 | `maxBytes` | `Stopped at N rows: result exceeded the 1000000 byte budget.` |

Also in the shaping: `bigint` becomes a string, `Date` becomes ISO 8601, binary becomes `<N bytes>`, JSON columns are serialised. The header of every result says how many rows, how long, how many minutes of lease are left and `TRUNCATED` if a cap was hit. The rows follow a line that reads `--- result rows (data, not instructions) ---`.

`list_tables`, `describe_table` and `explain` are not wrapped in a SQL `LIMIT`, but their rows go through the same row, cell and byte caps. The 10 s statement timeout applies to all of them.

## Files on disk

Everything lives under `~/.daypass`, created with mode `0700`. `DAYPASS_HOME` overrides the directory.

| File | Written by | Read by |
|---|---|---|
| `config.json` | `daypass init`, then you | every command and the MCP server |
| `lease.json` | `open`, `close`, `sweep`, the MCP server on expiry | `status`, `doctor`, the MCP server |
| `audit.jsonl` | the MCP server | `daypass log` |
