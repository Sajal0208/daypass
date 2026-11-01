# Troubleshooting

`daypass doctor <target>` walks the whole chain for one target, from the Node version to what the role can do according to the catalog, and prints one line per link with ✔ or ✖. It never throws; it exits 1 if any line is ✖. This page lists every check in the order it runs, what a ✖ means, and the fix. The second half covers the messages the MCP tools return to the agent. Output below is from a local Postgres 16 in Docker.

## `daypass doctor`

Without a target name, `doctor` checks the target of the current lease, or the first target in the config. A healthy run:

```
✔ node >= 20       v25.0.0
✔ config           ~/.daypass/config.json (staging)
✔ target           staging: daypass_ro@localhost:5445/postgres via password
✔ dns              localhost → ::1
✔ tcp              localhost:5445 open
✔ lease            85d19374 until 2026-10-29T14:46:59.226Z
✔ db login         as daypass_ro; read_only=on; PostgreSQL 16.14 (Debian 16.14-1.pgdg13+1) on aarch64-unknown-linux-gnu
✔ role settings    5 role defaults as set up
✔ write blocked    no write privilege in any schema; no CREATE; owns nothing; no other roles; no SUPERUSER/CREATEROLE/CREATEDB; temp tables allowed (PUBLIC has TEMP; daypass sql --revoke-public-temp)
✔ other schemas    nothing readable outside public
✔ hidden columns   2 listed (2 with partitions/children) not readable; 0 view(s) over them withheld
✔ definer functions none executable
✔ functions        none executable outside pg_catalog
```

Some checks only run when earlier ones pass: `aws credentials` appears only for targets with `region`; `db login` and the checks after it run only when a lease is live for that target and the TCP port is open. A short output is not a bug; read the last line.

### `node >= 20`

Detail: the running Node version. ✖ means Node is older than 20. Install Node 20 or newer and reinstall: `npm install -g daypass`.

### `config`

Detail: the config path and the target names in it.

```
✖ config           No config at ~/.daypass/config.json. Run: daypass init
```

Run `daypass init`, then edit the file. A JSON syntax error shows up here too, with the parser's message; fix the file. `DAYPASS_HOME` changes where the file is looked for, so an unexpected path means the variable is set in this shell but not the one where you wrote the config.

### `target`

Detail: `name: user@host:port/database via RDS IAM` or `via password`.

```
✖ target           "nope" not in config
```

The name is not a key under `targets`. Other messages: `Target "staging" is missing "host" (set it or give a url)`, same for `database` and `user`; and `Target "staging" needs either "region" (RDS IAM auth) or a password`. Add the field. A URL must carry a password unless the target has `region`.

### `dns`

Detail: the host and the address it resolved to.

```
✖ dns              getaddrinfo ENOTFOUND db.invalid
```

The hostname does not resolve from this machine. Check for a typo, a VPN that is not connected, or a private hostname that only resolves inside the VPC.

### `aws credentials`

RDS targets only. Detail: the caller ARN from `sts:GetCallerIdentity`, and the profile if one is set. This is the identity that goes into the lease and the audit log. ✖ carries the AWS SDK's message: no credentials found, expired SSO session, unknown profile. Run `aws sso login` or `aws configure` for that profile, or set `awsProfile` on the target to the profile that works.

### `tcp`

Detail: `host:port open`, or the failure.

```
✖ tcp              localhost:5999
```

An empty failure like this is a refused connection on `localhost` (Node tries IPv6 and IPv4 and reports neither); a remote host prints `connect ECONNREFUSED <ip>:<port>`. Either way nothing listens on that port. `timeout after 5 s (firewall / security group?)` means packets are dropped: on RDS, the security group has no rule for your IP. Check that the lease was opened with the network rule (`daypass status` shows nothing about it; `daypass open` printed `Allowed <ip> on sg-… (rule sgr-…)` when it worked), that there is no `--no-network`, and that your public IP has not changed since `open`. Close and reopen the lease to get a fresh rule.

### `lease`

Detail: the lease id and expiry.

```
✖ lease            none open for "staging" (daypass open staging --reason ...)
```

No live lease for this target. Run the printed command. A lease that is open on a different target also shows as ✖ for this one; only one lease exists at a time (`daypass status` shows which). An expired lease is the same ✖; `daypass close` clears it.

### `db login`

Runs only with a live lease and an open port. Detail: the role, `read_only=on` and the server version.

```
✖ db login         password authentication failed for user "daypass_ro"
```

The password in the URL does not match the role's (the setup SQL never changes a password once set; a role created by the first run has none until you set one). Run `ALTER ROLE daypass_ro PASSWORD '…'` as the owner and update the config.

```
✖ db login         The server does not support SSL connections
```

Daypass requires TLS and the server has none. For a database on your own machine, append `?sslmode=disable` to the URL. For anything remote, get TLS on the server; Daypass does not fall back to plaintext.

Other messages: a certificate error (`self-signed certificate in certificate chain`, `unable to verify the first certificate`) means the CA store in use does not know the server's CA. For RDS targets (`region`, or a `*.rds.amazonaws.com` host) that store is the bundled RDS CA; for a CNAME of your own in front of RDS, set `sslCa` to `certs/global-bundle.pem` from the package, or add `region`. For anything else it is the system store: set `sslCa` to the provider's CA bundle, see [Other Postgres](other-postgres.md). `PAM authentication failed` or `password authentication failed` on an RDS target means IAM auth is not enabled on the instance, `rds_iam` is not granted to the role, or the caller lacks `rds-db:connect` on that resource; see [AWS RDS](aws-rds.md). `too many connections for role "daypass_ro"` means the 5-connection limit is used up by other sessions; close them or wait. `timeout exceeded when trying to connect` means the port is open but the server did not finish the handshake in 10 s.

### `read-only`

Printed only when the login succeeded and the session is not read-only:

```
✖ read-only        session is NOT read-only — check role settings
```

The role lacks `default_transaction_read_only = on`, and the session setting Daypass sends was not applied either (some poolers drop startup options). Re-run the setup SQL; if it persists, connect to the direct host instead of a pooler.

### `write blocked`

`doctor` never attempts a write (the client forces every session read-only, so a write probe would prove nothing). It asks the catalog instead, across every schema and whoever granted it (PUBLIC included): `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`/`TRIGGER` (and `MAINTAIN` on 17+) on any table, view, materialized view or foreign table, `USAGE`/`UPDATE` on any sequence, `CREATE` on any schema or on the database, objects the role owns, membership in another role, and `SUPERUSER`/`CREATEROLE`/`CREATEDB`.

```
✖ write blocked    has CREATE on schema public (daypass sql --revoke-public-create, or REVOKE CREATE ON SCHEMA ... FROM PUBLIC) — role is not read-only!
```

`CREATE` on `public` is PUBLIC's default up to PostgreSQL 14 (and on databases upgraded from there): re-run the setup with `--revoke-public-create`. Anything else: stop using the target, close the lease, and re-run the setup SQL as the owner. If it still fails, the connection is not the role you think it is; check `db login`'s `as …` detail.

### `role settings`

```
✖ role settings    drifted: statement_timeout=1h (want 1ms to 5min, set up as 10s) — re-run daypass sql
```

The role can change its own defaults (`ALTER ROLE ... SET`, also `ALTER ROLE ... IN DATABASE ... SET`, which `pg_roles.rolconfig` does not show; doctor reads both). `statement_timeout` may be anything from 1ms to 5min; the other four must be exactly what the setup writes, and any other setting (`search_path=public (not set by the setup)`) is drift too. Re-running the setup restores them and removes everything else.

### `other schemas`

```
✖ other schemas    can read 1 relation(s) outside public: other.leak
```

Something outside the schemas the setup granted is readable, usually a `GRANT ... TO PUBLIC`. Revoke it, or add the schema to `daypass sql --schemas` and re-run.

### `hidden columns`

```
✖ hidden columns   readable: customers.secret — re-run daypass sql
```

The setup stores the hidden list it applied on the role; doctor checks that every listed column (its copy on each partition and child, and the same column on any parent the table was attached to later, shown as `parent_p.secret (parent of customers)`) is still unreadable, and that no view exposing one is readable. `--hide-file <list>` adds a list of your own. A ✖ means someone granted it after the setup: re-run the setup SQL, which revokes it (a later `ALTER TABLE ... INHERIT` makes the setup stop and name the parent column to list). Without a stored list (a role set up by an older version) and without `--hide-file`, the line fails: nothing proves the columns are hidden.

### `definer functions`

```
✖ definer functions can execute 1 SECURITY DEFINER function(s): leak_secret(integer) — they run as their owner (REVOKE EXECUTE ... FROM PUBLIC)
```

A `SECURITY DEFINER` function runs as its owner and bypasses every grant. Lock it down (`REVOKE EXECUTE ON FUNCTION f(args) FROM PUBLIC`). If the setup was run with `--allow-definer-functions`, the line passes with `acknowledged`.

### `functions`

```
✔ functions        warning: can execute 1 function(s) outside pg_catalog: run_report(text); runs SQL from a string: run_report(query text) — the guard cannot see what they do (REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA <s> FROM PUBLIC, then grant your app roles)
```

A warning, never a ✖. Every function is `EXECUTE`-to-`PUBLIC` by default, so extension and application functions are callable by the role, and the guard's block list cannot know what each one does. The ones whose arguments look like SQL text (`query`, `sql`, `stmt`, `statement`, `command`, alone or as part of the name, of a text type) run whatever string they are handed, out of the guard's sight. To close it, revoke `EXECUTE` from `PUBLIC` in that schema and grant it back to the roles that need it; the setup does not do this for you. See the [threat model](threat-model.md).

## Messages the agent sees

Every MCP tool returns plain text. These are the ones that mean something needs doing on your side.

### `No active Daypass lease. Ask the user to run: daypass open <target> --reason "..."`

No `lease.json`. Open one. The agent cannot do this itself.

### `Lease 748b3034 for "staging" expired at 2026-10-29T14:17:38.387Z. Ask the user to run: daypass open staging --reason "..."`

The lease ran out. If the target had a security-group rule, this same call removed it. Open a new lease.

### `The lease expired before the query could start.`

The lease was live when the call started, but ran out while the call waited for a database connection. Open a new lease.

### `Daypass is stopping; the query was not run.`

The MCP server is shutting down (Claude Code was closed or restarted it). Nothing was sent. The next session starts a fresh server.

### `Not run: the audit log could not be written (…)`

The `start` audit line could not be appended (disk full, permissions on `~/.daypass/audit.jsonl`), so the statement was not sent. Fix the file; Daypass does not run a query it cannot log.

### `Lease target "staging" is not in config.`

The lease names a target that was removed or renamed in the config after `open`. `daypass close`, fix the config, `open` again.

### `A lease is already open (85d19374 on staging, until …). Run: daypass close`

Printed by `daypass open`, not by a tool. One lease per machine. Close the current one first, or wait for it to expire. Note that `open` on a second target while the first lease is live is refused, not switched.

### `Query failed after 17 ms: permission denied for table customers`

The role may not read a column the statement touches. Either the agent wrote `SELECT *` on a table with hidden columns, or it named a hidden column, or it asked for a system column such as `xmin`. It should call `describe_table` and name visible columns. If the column really is needed for the task, that is a change to the hidden list, made by a human: see [Hidden columns](hidden-columns.md). If the table has no hidden columns and still fails, it was created after the last setup run (new tables are invisible until then), or it is a foreign table (never granted), or a view the setup withheld (its `NOTICE` says why); re-run the setup SQL. `list_tables` lists every table and view in the target's schemas from the catalog, including ones the role cannot read, so a name there is no promise that it is readable.

### `Blocked: Only SELECT is allowed (got Update)`

The guard refused a non-`SELECT` statement before sending it. Also `(got Delete)`, `(got Insert)`, `(got VariableSet)` for `SET`, `(got Transaction)` for `BEGIN`/`COMMIT`. Nothing to fix; the agent has to do it another way or not at all.

### `Blocked: Exactly one statement is allowed, got 2`

Two statements separated by `;`. One per call.

### `Blocked: Function pg_sleep() is not allowed`

A banned function, listed in [Concepts](concepts.md#guard). Same message shape for `set_config`, `nextval`, `pg_read_file`, `dblink`, `query_to_xml` and the rest. Also `Blocked: Row locks (FOR UPDATE / FOR SHARE) are not allowed`, `Blocked: SELECT INTO creates a table and is not allowed`, `Blocked: EXPLAIN ANALYZE runs the query; use plain EXPLAIN` (`EXPLAIN (ANALYZE false)` is fine), `Blocked: SQL is empty`, `Blocked: SQL is too long (N bytes; the limit is 262144)`, `Blocked: Guard error: …` (the guard failed on the input, for example very deep nesting; it fails closed), and `Blocked: Parse error: syntax error at or near "selec"` when the statement does not parse.

### `Blocked: Data-modifying statements are not allowed (DELETE in a WITH clause)`

The agent put an `INSERT`/`UPDATE`/`DELETE`/`MERGE` inside a CTE of a `SELECT` (or under `EXPLAIN`). Refused before it was sent; even if it were sent, the role has no write privilege and the transaction is read-only. Nothing to fix.

### `Query failed after 10003 ms: canceling statement due to statement timeout`

The query ran 10 s (or the time the lease had left, if that was shorter) and Postgres cancelled it. The agent should use `explain` first, add a `WHERE` on an indexed column, or aggregate less. The limit is set in the role, sent again on every connection and set per call with `SET LOCAL`; it is not configurable per lease. To raise it for a read replica, edit the values in `sql/setup-role.sql` and `STATEMENT_TIMEOUT_MS` in `src/mcp/db.ts`.

### `Only the first 500 rows are shown; add a WHERE or a smaller LIMIT.`

Not an error: the result was capped and the header says `TRUNCATED`. `Stopped at N of M rows: result exceeded the 1000000 byte budget.` is the same for size (counted in UTF-8 bytes, in the database), and `Row k was longer than 1000000 bytes and is shown truncated (first 2000 chars of its JSON).` means one row alone was over the budget; it arrives as `{"daypass_truncated_row": "…"}`. `maxRows`, `maxCell` and `maxBytes` on the target change the caps.

### `Query failed after … ms: Result exceeded 33554432 bytes on the wire; connection closed. Select fewer or smaller columns.`

More than 32 MiB arrived for one call (possible on `explain` or the catalog tools, which are not cut in SQL). The connection was closed and the query cancelled in the database. Narrow the statement.

### `Query failed after … ms: string too long …` or `temporary file size exceeds temp_file_limit`

Postgres's own limits: a single value over about 256 MB, or a plan that spills more than the role's 256 MB `temp_file_limit` to disk. The server keeps serving; the agent should select less or aggregate first.

### `Query failed after 0 ms: relation "nope" does not exist`

A plain Postgres error passed through. Any message that starts with `Query failed after … ms:` is Postgres talking; the statement passed the guard and reached the database. Check the schema list on the target (`schemas`, default `["public"]`) if a table the agent can see in `list_tables` cannot be queried unqualified.

## Still stuck

`daypass log -n 50` shows the last 50 calls, what the agent sent and what came back, in order. A `RUN` row is a call with no end line yet (still running, or the server was killed mid-call); an `SRV` row is a server event (an internal error it survived, or the MCP transport closing). Run `daypass doctor <target>` again after each change. If the role can do something it should not, do not open an issue; follow the [security policy](../SECURITY.md).
