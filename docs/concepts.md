# Concepts

Daypass is five small parts: a lease that says access is open, a guard that reads every statement before it leaves your machine, a database role that holds no write privilege and no grant on the hidden columns, an audit line before and after every tool call, and caps on what a result may contain. This page says what each one is, where it lives on disk, and which numbers it enforces. The role's grants are the wall; everything else is a second fence.

## Lease

A lease is a file: `~/.daypass/lease.json` (or `$DAYPASS_HOME/lease.json`). `daypass open` writes it, `daypass close` deletes it, and the MCP server reads it at the start of every tool call. No file, or `expiresAt` in the past, and every tool except `daypass_status` returns an error asking the user to run `daypass open` (`daypass_status` returns plain text: `No lease open.`, `Expired at …` with one lease, or one line per lease with several).

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

- **One per target.** Not per Claude session. Every Claude Code window on the machine has the tools while a lease is open. `daypass open a` then `daypass open b` gives two leases. Opening a target that already has a live lease is refused, with exit code 1: `A lease is already open on "staging" (85d19374, until …). Run: daypass close staging`. With two or more live leases, every tool except `daypass_status` needs a `target` argument. With the network rule on (no `--no-network`), two targets behind the same security group, region and port cannot be open at once, and an expired lease that still holds that rule blocks the other until it is closed. `daypass close` with no target closes all.
- **File shape.** With one lease the file is the lease itself, as above. With two or more it is `{ "version": 2, "leases": [ … ] }`, at most one entry per target. Daypass 0.2.0 reads the second shape as a corrupt lease file.
- **TTL.** `--ttl` takes `90s`, `30m`, `2h`. Default `60m`, minimum `60s`, maximum `8h`.
- **Who.** For an AWS RDS target it is the AWS caller ARN from `sts:GetCallerIdentity`, which cannot be set from the shell. For a URL or password target it is the OS account name of the process (not the `USER` variable, which any shell can set) `@hostname`.
- **Reason** is required. It goes into the lease and into every audit line written under it.
- **Network.** If the target has `region` and `securityGroupId`, `open` adds your public IP as a `/32` rule (`/128` for an IPv6 address) on that security group and records `ip`, `sgRuleId` and where the rule lives (`sgRegion`, `sgGroupId`, `sgProfile`) in the lease. `close` removes the rule in that group, even if the target's config changed since (a lease from an older version, without those fields, falls back to the config and warns if the rule is not found there). Both revoke the rule only if its description is still exactly the one `open` wrote; otherwise `close` warns and still clears the lease. If a lease expires without `close`, the MCP server removes the rule on the first tool call after expiry (waiting at most 10 s for AWS; a failure there is silent); `daypass sweep <target>` from cron is the backstop. Until one of those runs, the rule stays. `--no-network` skips all of this.
- **Expiry is checked per call, and bounds the call.** The lease is checked when a tool call starts. A query's statement timeout is 10 s or the time the lease has left once a connection is checked out, whichever is shorter, so a query cannot run past the lease; if the lease ran out while waiting for a connection, the call fails with `The lease expired before the query could start.` The next call after expiry is refused.
- **The lease is a file you own.** It is mode `0600` under your OS user, like the config and the audit log, and is replaced atomically (written to a temporary file, then renamed) under a lock file, `.lease.lock`, so `open`, `close` and the server's cleanup cannot overwrite each other (a lock older than 5 s is treated as left by a dead process). Anything running as you, including an agent you allow to run shell commands, can edit it. See [Threat model](threat-model.md).
- **A corrupt lease stops everything.** A `lease.json` that is not a lease makes every tool and `daypass status` answer `The lease file … is corrupt. Run: daypass close`; `close` deletes it (and reminds you to run `daypass sweep <target>` in case it held a security-group rule).

## Guard

Every statement the agent sends is parsed with `libpg-query`, Postgres's own parser compiled to WebAssembly, before anything is sent to the database. The guard is a pure function with no I/O; its rules, in order:

1. Empty SQL is refused.
2. SQL over 256 KiB (262,144 UTF-8 bytes) is refused before parsing: `SQL is too long (N bytes; the limit is 262144)`. This applies to `query` and `explain`.
3. SQL that does not parse is refused with the parser's message.
4. Exactly one statement. `select 1; drop table customers` is refused: `Exactly one statement is allowed, got 2`.
5. The statement must be a `SELECT`, or an `EXPLAIN` that wraps a `SELECT`. Anything else is refused by kind: `Only SELECT is allowed (got Update)`, `(got Delete)`, `(got VariableSet)` for `SET`, `(got Transaction)` for `BEGIN`.
6. `EXPLAIN ANALYZE` is refused, because it runs the query. `EXPLAIN (ANALYZE false)` (also `off`, `no`, `0`) is allowed; `ANALYZE` with no value or a true value is refused.
7. Inside the statement, the whole tree is walked. A data-modifying statement anywhere in it is refused (`WITH d AS (DELETE … RETURNING *) SELECT …`, and `INSERT`, `UPDATE` or `MERGE` in a CTE, under `EXPLAIN` too): `Data-modifying statements are not allowed (DELETE in a WITH clause)`. `FOR UPDATE` / `FOR SHARE` are refused (`Row locks … are not allowed`). `SELECT INTO` is refused. Any call to a function on the list below is refused, matched on the lower-cased bare name, so `pg_catalog.PG_SLEEP(1)` is caught too, and so is a call buried in a subquery. Attribute notation counts as a call: Postgres reads `(x).f` and `t.f` as `f(x)` and `f(t)`, so `(1).pg_sleep` is refused, and so is a column whose name matches a banned pattern when it is written qualified (`select c.pg_sleep from customers c`); write such a column unqualified.

The guard fails closed: very deep nesting, a NUL byte, control characters the scanner cannot encode, lone UTF-16 surrogates and the parser running out of memory each end in a refusal (`SQL could not be checked: …`, `Guard error: …` or a parse error), and the guard keeps working for the next call.

What passes is canonicalised with the parser's own scanner: comments and trailing semicolons are removed, so `select 1 -- why` and `select 1;` are accepted. That canonical SQL is what runs, what `explain` explains and what the audit line records.

The banned functions, from `BANNED_FUNCTION_PATTERNS` in `src/core/guard.ts` (patterns on the bare name; `^` means "starts with"):

| Group | Patterns |
|---|---|
| Sleep | `^pg_sleep` |
| Advisory locks | `^pg_(try_)?advisory_` (every flavour, shared and unlock included) |
| Remote connections | `^dblink` |
| Large objects | `^lo_`, `lowrite`, `loread` |
| Server files and logs | `^pg_ls_`, `^pg_read_`, `pg_stat_file`, `^pg_file_`, `pg_logdir_ls` (adminpack) |
| Backends, config, statistics | `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`, `set_config`, `^pg_stat_reset`, `setseed` (the seed survives `DISCARD ALL`), `pg_restore_relation_stats`, `pg_restore_attribute_stats`, `^pg_clear_…_stats` |
| Sequences and transaction ids | `nextval`, `setval`, `txid_current`, `pg_current_xact_id` |
| Replication, WAL, backups | `^pg_…(replication\|wal_replay\|promote\|rotate_logfile\|log_backend)`, `^pg_logical_slot_`, `pg_logical_emit_message`, `pg_log_standby_snapshot`, `pg_create_restore_point`, `pg_switch_wal`, `pg_backup_start`/`stop`, `pg_start_backup`/`stop_backup` |
| Index maintenance | `^brin_(summarize\|desummarize)`, `gin_clean_pending_list` |
| Messaging | `pg_notify` |
| SQL from a string | `^query_to_xml`, `^cursor_to_xml`, `^(table\|schema\|database)_to_xml`, `ts_stat`, `ts_rewrite`, `^crosstab` and `connectby` (tablefunc), `xpath_table` (xml2) |
| Common extensions | `query_export_to_s3` (aws_s3), `^pgr_` (pgRouting), `^dbms_pipe` and `^dbms_alert` (orafce), `^hypopg` |

The list **cannot cover every extension**. Any function the role may execute and the guard does not know runs with the role's privileges, and one that takes SQL as text runs whatever it is handed. The role's `EXECUTE` grants are the real boundary: review the functions of every extension you install, and see "Functions the role can call" in the [threat model](threat-model.md).

A refused statement makes the tool return `Blocked: <reason>`. The refusal is also written to the audit log with `allowed: false` and the reason, for `explain` in the same line shape as for `query`.

The guard is not what stops writes; the role's grants and the read-only transaction are. The guard exists so that a blocked statement never reaches the database, costs nothing, and shows up in the log with a clear reason, and so that the agent cannot change the session settings that bound it.

## Role

`daypass sql` prints `sql/setup-role.sql` with your role name and hidden list filled in. Run as the database owner, it creates the role (default name `daypass_ro`) and sets, at the role level:

| Setting | Value |
|---|---|
| `LOGIN`, `NOCREATEDB`, `NOCREATEROLE`, `NOINHERIT` | role attributes |
| `NOSUPERUSER`, `NOREPLICATION`, `NOBYPASSRLS` | removed on every run if set (only a superuser can; otherwise the run stops and names the `ALTER ROLE` to run) |
| `CONNECTION LIMIT` | 5 |
| `PASSWORD` | not set by the script (a non-RDS owner sets one once after the first run; RDS roles log in with IAM tokens) |
| `default_transaction_read_only` | `on` |
| `statement_timeout` | `10s` |
| `idle_in_transaction_session_timeout` | `30s` |
| `lock_timeout` | `1s` |
| `temp_file_limit` | `256MB` |

On RDS it also grants `rds_iam`, so the role can log in with an IAM token. On PostgreSQL 16 and newer the grant is `WITH INHERIT FALSE, SET FALSE` (an older grant is narrowed the same way), so the role can neither use `rds_iam`'s privileges nor `SET ROLE` to it; before 16 that cannot be prevented, so the run fails if `rds_iam` holds anything. Elsewhere the grant is skipped with a `NOTICE`. On PostgreSQL 16 and newer, only a superuser or a role holding `ADMIN OPTION` on `daypass_ro` may alter it; the user that created it holds that automatically, and anyone else gets an error naming the `GRANT … WITH ADMIN OPTION` to run.

The settings above are **defaults**: Postgres lets a role change its own session defaults (`SET`, `ALTER ROLE … SET`, `ALTER ROLE … RESET ALL`) and its own password. Through Daypass the guard refuses `SET`, `ALTER` and `set_config`, and the client sends the same settings again on every connection, so they hold for the agent. In a direct `psql` session as `daypass_ro` they do not. `daypass doctor` reads `pg_roles.rolconfig` and the per-database overrides and reports drift; a re-run of the setup restores them (it starts with `RESET ALL` and removes every per-database setting). On RDS, `rds.restrict_password_commands = 1` in the parameter group stops the password change.

Before anything else the script refuses a role that owns any object in the database (it could have planted a function or operator while it held `CREATE`) or that is a member of another role (`SET ROLE` would reach that role's privileges; `NOINHERIT` does not stop it), and it refuses a database whose `pg_stats_ext` views predate the CVE-2024-4317 fix. It pins `search_path` to `pg_catalog, pg_temp` for its own transaction, so nothing planted in your schemas runs as the owner while it executes.

Grants: `CONNECT` on the database (other databases on the server are untouched; see "Other databases" in the [threat model](threat-model.md)), `USAGE` on each schema in `--schemas` (default `public`), and `SELECT` on each table, partitioned table and sequence there (except a sequence owned by a hidden column), plus each view and materialized view that does not expose a hidden column. A plain view over a table with row-level security (unless `security_invoker`, PostgreSQL 15+) or over a relation the role is not granted is withheld, since a view reads its tables with its owner's rights. A materialized view is also withheld when what it stored depended on its owner's rights (it reads a catalog view that filters by caller, a table with row-level security, or calls a function outside `pg_catalog`, an extension's function, or a non-immutable built-in outside a short allow-list). Every run first revokes what the role held anywhere, and sets no default privileges, so a table created later is invisible until the owner re-runs the script. Foreign tables are never granted. What else is withheld, and why, is in [Hidden columns](hidden-columns.md#what-else-the-script-withholds).

Three options change what the script does to `PUBLIC`, which every role inherits from: `--revoke-public-temp` (`REVOKE TEMP ON DATABASE … FROM PUBLIC`), `--revoke-public-create` (`REVOKE CREATE ON SCHEMA … FROM PUBLIC` on each listed schema; PostgreSQL 14 and older grant it on `public`), and `--allow-definer-functions` (accept `SECURITY DEFINER` functions the role can execute instead of failing). All three are off by default, because the first two can break other roles. The report at the end says whether the role can create temp tables, objects in a schema, or large objects (core Postgres needs no privilege for `lo_create`; `REVOKE EXECUTE ON FUNCTION lo_create(oid), lo_creat(integer), lo_from_bytea(oid, bytea) FROM PUBLIC` blocks that for every role), and how many functions outside `pg_catalog` it can execute.

**Hidden columns use column-level grants.** Postgres ignores a column-level `REVOKE` while the role holds table-level `SELECT`. So for each table that has a hidden column, the script revokes table-level `SELECT` and grants `SELECT (col, col, …)` on the visible columns only. Two consequences:

- `SELECT *` on such a table fails with `permission denied for table customers`. The agent has to name columns. The `query` tool's description tells it so. `describe_table` lists only columns the role may read (in table order, with full type names such as `character varying(64)`), answers `Table "x" not found in schema "public", or this lease cannot read any of its columns.` for anything else, and leaves out every index that touches a hidden column (it shows `(N index(es) on hidden columns omitted)` instead). That is cosmetic: the role can still read the system catalog (`pg_indexes`, `pg_attribute`, view definitions, defaults, constraints), so the *names* of hidden columns, and any constant written into such a definition, are visible to a query that asks for them. Values in the column are not.
- A column added later to one of those tables is hidden, and the next run stops until it is listed or marked `!table.column`. A column added to a table *without* hidden columns is readable at once (table-level `SELECT`). A brand-new table is invisible until the script is re-run.

The script ends with a self-check: every hidden column must be unreadable, at least one column of each of those tables must still be readable, no withheld view may be readable, nothing outside `--schemas` may be readable, the role may hold no write privilege anywhere (from any grantor, `PUBLIC` included; column-level `INSERT`/`UPDATE` too), no large object may be granted to it and `lo_compat_privileges` must be off, it may reach no foreign server (no `USAGE` on a server or wrapper, no user mapping for it or `PUBLIC`), no default privilege may grant `PUBLIC` access to new tables, sequences or schemas, the system catalogs may carry no grant to `PUBLIC` or the role beyond a fresh cluster's, it may own no object, belong to no other role or hold `SUPERUSER`/`REPLICATION`/`BYPASSRLS`/`CREATEDB`/`CREATEROLE`, its `rds_iam` membership must reach nothing, and no `SECURITY DEFINER` function may be executable (unless acknowledged). If any fails, the script stops with an error and changes nothing. It then stores the list it applied on the role (`COMMENT ON ROLE`, per database), which `daypass doctor` checks later. See [Hidden columns](hidden-columns.md).

## How a call runs

The MCP server does not trust the role settings alone. Every connection it opens sets `default_transaction_read_only=on`, `statement_timeout=10000`, `idle_in_transaction_session_timeout=30000`, `lock_timeout=1000` and `standard_conforming_strings=on` as startup options and names itself `daypass` in `application_name`. If the database stops answering (network gone, server stalled), a call fails about 5 s after its statement timeout with `No answer from the database 15 s into the call; connection closed.`, and the next call gets a fresh connection. Each server process holds **one** connection per target, because the role's `CONNECTION LIMIT 5` is shared by every Daypass process (one per AI session): concurrent calls queue for it (up to 15 s including the wait), and an idle connection is closed after 5 s. When the limit is full anyway the call fails with `too many connections for role "daypass_ro": the Daypass role's connection limit is reached. …`. For IAM targets a token is minted when a connection needs one and reused for up to 10 minutes. TLS is always verified; RDS targets (with `region`, or any `*.rds.amazonaws.com` host) pin the AWS RDS CA bundle shipped in the package, `sslCa` overrides it, and `ssl: false` / `sslmode=disable` is refused for them.

Each allowed call then gets its own checked-out connection and runs as:

```sql
BEGIN READ ONLY;
SET LOCAL standard_conforming_strings = on;
SET LOCAL statement_timeout = <min(10 s, lease time left)>;
<the canonical statement, sent over the extended protocol>
COMMIT;
SELECT pg_advisory_unlock_all();
DISCARD ALL;
```

- The extended protocol carries exactly one command; the server refuses more, so even SQL that fooled the guard cannot add a `COMMIT` or a second statement.
- On PostgreSQL 14 and newer, where the platform supports it (Linux; not macOS), `client_connection_check_interval = 1s` is also set for the transaction, so the backend notices a vanished client within a second.
- `DISCARD ALL` resets every session setting, `LISTEN`, prepared statement and temp object, so session state a call set up does not reach the next one (the one known exception, the `random()` seed, is why `setseed` is banned). A connection that cannot be reset is dropped.
- At most 32 MiB may arrive on the socket for one call (`MAX_WIRE_BYTES`). Past that the connection is destroyed and the call fails with `Result exceeded 33554432 bytes on the wire; connection closed. Select fewer or smaller columns.` This covers `explain` and the catalog tools too.
- A call that is cut off (the wire cap, a server shutdown, an internal crash handler) is also cancelled in the database: Daypass sends Postgres's protocol cancel request over a separate connection, so the backend stops within about a second instead of running on to the statement timeout. On shutdown the pool is closed for good.
- Limits Postgres enforces show up as ordinary errors and the server keeps serving: a value over about 256 MB fails with `string too long…`, and a plan that spills past `temp_file_limit` with `temporary file size exceeds temp_file_limit (262144kB)`.
- In stdio mode anything printed with `console.log` goes to stderr, so stdout carries only MCP messages. A message over the MCP SDK's 10 MiB limit closes the transport; so does the client going away (stdin ends). Either way the server writes a `server` audit line, ends calls in flight and exits.

The guard's parser follows the PostgreSQL 16+ grammar. On PostgreSQL 15 and older a few literals parse differently: `select 0x1F` means `0 AS x1f` there (the guard reads 31), and `1_000` is a syntax error. Such a query can only return a different value or fail; it cannot get past the guard. PostgreSQL 16 or newer is recommended.

## Audit

Every tool call that reaches the guard is written to `~/.daypass/audit.jsonl` (mode `0600`), one JSON object per line.

- **An allowed call writes two lines** that share a `callId` (8 hex characters). The `start` line (`phase: "start"`, `allowed: true`, no `rows` or `ms`) is written before the statement reaches the database; if it cannot be written, the statement is not run (`Not run: the audit log could not be written (…)`). The `end` line (`phase: "end"`) carries `rows` and `ms`, or `ms` and `error`. There is exactly one end line per `callId`, also when the server is stopped mid-call. If the end line cannot be written, it goes to stderr instead (`daypass: audit write failed (…); end line: {…}`) and the call still returns its result.
- **A refusal writes one line** with no `phase`, `allowed: false` and `blockedReason`. An exception inside the guard is a refusal too (`Guard error: …`). A refused statement over 256 KiB is audited as its first 2000 characters plus `…[N bytes in total; the rest is not audited]` and `sqlSha256`.
- **Every field is capped**, so a line stays small and is appended with a single write that concurrent servers cannot interleave: `sql` at 16 KiB (longer statements keep a prefix, `…[+N chars not stored; sqlSha256 is the hash of the full statement]`, and `sqlSha256`), `error` and `blockedReason` at 4 KiB, `reason` at 2 KiB, the rest smaller.
- **Server events** are lines with `tool: "server"`, `sql: null`, `allowed: true` and `error` set to `uncaughtException: …` or `unhandledRejection: …` (the server keeps serving), or `MCP transport closed[: <last error>]` or `MCP transport closed (stdin ended)` (the client went away or sent a message over the 10 MiB limit; the server exits).
- **On SIGINT/SIGTERM** every call in flight gets its end line with `error: "server stopped (SIGTERM) while the call was in flight"`, its backend is cancelled, and new calls are refused with `Daypass is stopping; the query was not run.`
- A process killed outright (`kill -9`, a power cut) cannot write anything: its last calls keep a `start` line with no `end` line. The statement was sent; Postgres ends it at the statement timeout at the latest (within about a second on Linux, where the connection check is on). Postgres's own log, if enabled, has the rest.

The fields, from `src/core/audit.ts`:

| Field | Meaning |
|---|---|
| `at` | ISO timestamp |
| `who` | the lease's identity: AWS ARN or `user@host` |
| `leaseId` | the lease the call ran under (`null` on a server line with no lease) |
| `target` | target name from the config |
| `reason` | the lease's reason |
| `tool` | `query`, `explain`, `list_tables`, `describe_table`, or `server` |
| `sql` | the canonical statement (for `explain`, with the `EXPLAIN (FORMAT TEXT)` prefix added); `null` on server lines |
| `allowed` | `false` if the guard refused it |
| `blockedReason` | why, when `allowed` is `false` |
| `rows` | rows returned, after the caps (end lines) |
| `ms` | wall time of the call (end lines) |
| `error` | the Postgres or Daypass error (cut at 2000 characters), when the statement ran but failed, or the server event |
| `phase` | `start` or `end` on allowed calls; absent on refusals, server lines and logs from 0.1.0 |
| `callId` | pairs a `start` line with its `end` line |
| `sqlSha256` | SHA-256 of the full statement, present when `sql` was cut |

Two real calls, the first refused by Postgres, the second allowed:

```json
{"at":"2026-10-29T14:19:03.882Z","who":"alice@laptop.local","leaseId":"b11e4bff","target":"staging","reason":"why did signups drop on Monday","tool":"query","sql":"select * from customers","allowed":true,"phase":"start","callId":"3c0e9a51"}
{"at":"2026-10-29T14:19:03.899Z","who":"alice@laptop.local","leaseId":"b11e4bff","target":"staging","reason":"why did signups drop on Monday","tool":"query","sql":"select * from customers","allowed":true,"phase":"end","ms":17,"error":"permission denied for table customers","callId":"3c0e9a51"}
{"at":"2026-10-29T14:19:03.928Z","who":"alice@laptop.local","leaseId":"b11e4bff","target":"staging","reason":"why did signups drop on Monday","tool":"query","sql":"select id, name, created_at from customers","allowed":true,"phase":"start","callId":"d41f0b7e"}
{"at":"2026-10-29T14:19:03.934Z","who":"alice@laptop.local","leaseId":"b11e4bff","target":"staging","reason":"why did signups drop on Monday","tool":"query","sql":"select id, name, created_at from customers","allowed":true,"phase":"end","rows":1,"ms":6,"callId":"d41f0b7e"}
```

`daypass log -n 30` prints the last 30 calls, one row per call: the start and end lines are paired by `callId` and shown at the start time with the end line's result. `ok` ran, `ERR` ran and failed, `BLK` was refused by the guard, `RUN` has a start line but no end line yet (`<- unfinished: no end line yet (still running, or the server stopped mid-call)`), and `SRV` is a server event. Refusals and lines from older versions render one row each, as before. Control characters in any field are printed as `\xNN` (bidi and line-separator characters as `\uNNNN`), so text from the agent cannot rewrite the terminal. A line that is not valid JSON is skipped with `warning: N unreadable line(s) in the audit log were skipped` on stderr. `-n` must be a positive integer. The file is plain JSONL, so `jq` and `grep` work on it.

The SQL text is logged as is. A `WHERE email = 'ada@example.com'` puts that address in the file. `daypass_status`, `daypass open` and `daypass close` do not write audit lines.

## Result caps

A `query` is not run as written and cut afterwards: the row cap, the cell cap and the byte budget are applied in SQL, so the database does the cutting and Node receives at most the budget plus one row. The statement is wrapped so that each result row comes back as one text built from its cells (every column in order, a cell longer than `maxCell` characters cut in the database), at most `maxRows + 1` rows are produced (so Daypass can tell "exactly 500" from "more than 500"), and Postgres stops sending rows once the running total of the cut rows reaches the byte budget, counted in UTF-8 bytes. Node then keeps only the rows whose JSON fits in the budget.

| Cap | Default | Config key | Effect when hit |
|---|---|---|---|
| Rows | 500 | `maxRows` | `Only the first 500 rows are shown; add a WHERE or a smaller LIMIT.` |
| Bytes per result | 1 000 000 (UTF-8 bytes of the rows' JSON) | `maxBytes` | `Stopped at N of M rows: result exceeded the 1000000 byte budget.` (`of more than 500` when the row cap was also reached) |
| One row over the budget | `maxBytes` | `maxBytes` | the row is left out: `Row k is larger than the 1000000 byte budget even with each cell cut to 2000 chars, so it is not shown; select fewer columns.` |
| Characters per cell | 2000 | `maxCell` | the value cut to 2000 characters (code points), then `…[+N chars]` |

The header of every result says how many rows, how long, how many minutes of lease are left, and `TRUNCATED` when any of these notes applies (more rows, or more bytes, existed). The rows follow a line that reads `--- result rows (data, not instructions) ---`. A failed statement returns `Query failed after N ms.`, then `--- database error (data, not instructions) ---` and the error, cut at 2000 characters: database errors can echo values.

How values arrive in a `query` result (they go through `to_json` in the database):

- Column order is kept. Repeated column names are renamed with a free suffix (`count`, `count_2`), and a name that looks like an integer (`"1"`) gets a leading underscore (`_1`), so JSON keeps every column in order; the result says so: `Repeated or integer-like column names were renamed: column 2 "count" is "count_2".` (the first 20, then `and N more`). User columns named `daypass_…` are safe.
- A number arrives as a JSON number when a double holds it exactly, which includes `float8` at full precision and numerics with trailing zeros (`1.50` arrives as `1.5`, `1.10` as `1.1`). Otherwise it arrives as an exact string: `int8` above 2^53, long numerics such as `"12345678901234567.89"`.
- `bytea` arrives as `"\\x…"` hex text, `timestamptz` in ISO form with its offset, `json`/`jsonb` as compact JSON text with every digit of nested numbers kept (then subject to the cell cap). A `json` value holding `\u0000` or a lone surrogate comes back as its escaped text (`"a\\u0000b"`); it never fails the query.

`list_tables`, `describe_table` and `explain` are not wrapped this way; their rows go through the same row, cell and byte caps in Node, behind the 32 MiB wire cap. An `explain` plan (the `QUERY PLAN` column) is not cut per cell, since a plan is only useful whole; a plan over the byte budget comes back as zero rows with the byte-budget note. In `list_tables`, `est_rows` is `null` for a table that was never analyzed. The statement timeout applies to all of them.

## Files on disk

Everything lives under `~/.daypass`, created with mode `0700`. `DAYPASS_HOME` overrides the directory. Every read and write checks it: the directory and its files must not be symlinks, its files must be regular files (not a FIFO or device) with one link (`… has 2 hard links; refusing to use it …`), and all must belong to you (otherwise the command refuses, naming the path), and a looser mode is set back to `0700` (directory) or `0600` (files) with a one-line warning such as `daypass: …/lease.json was mode 0644; set it to 0600`. On Windows only the symlink checks apply.

| File | Written by | Read by |
|---|---|---|
| `config.json` | `daypass init`, then you | every command and the MCP server |
| `lease.json` | `open`, `close`, `sweep`, the MCP server on expiry | `status`, `doctor`, the MCP server |
| `.lease.lock` | held briefly by every lease write (removed afterwards) | the same writers |
| `audit.jsonl` | the MCP server | `daypass log` |
