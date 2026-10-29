# r/PostgreSQL

## Title

```
A read-only role for AI coding agents: column-level grants, timeouts, a parser allow-list. Please review the SQL.
```

## Body

We give Claude Code a time-boxed, read-only window onto our production Postgres. The
client side is an MCP server; the part I want this sub to look at is the role. The
setup script is 120 lines of SQL and I would rather hear about a hole here than from an
agent.

Repo: https://github.com/Sajal0208/peephole. Script: `sql/setup-role.sql`. MIT.

### The gotcha that shaped the script

The first draft hid PII columns like this:

```sql
GRANT SELECT ON ALL TABLES IN SCHEMA public TO peephole_ro;
REVOKE SELECT (email, phone) ON users FROM peephole_ro;
```

That does nothing. Postgres checks table-level privilege first, and the role still holds
table-level `SELECT`, so `SELECT email FROM users` succeeds. A column-level `REVOKE` only
removes a column-level grant that was there before. The script now does, per table that
has a hidden column:

```sql
REVOKE SELECT ON TABLE public.users FROM peephole_ro;
GRANT SELECT (id, created_at, plan, country) ON TABLE public.users TO peephole_ro;
```

Two consequences we accepted. `SELECT *` on those tables fails with `permission denied`,
so the agent has to name columns. And a column added later to one of those tables is
hidden until the script is re-run, which is the safe direction. New tables are the other
way round: `ALTER DEFAULT PRIVILEGES ... GRANT SELECT ON TABLES` makes them visible, and
only for tables created by the user who ran the script. The script ends with an owner
report so you can see whether a migration user owns tables it does not cover.

The script also refuses to run if a listed column does not exist (a typo would otherwise
hide nothing) and ends with a `has_column_privilege` self-check for every hidden column,
plus a check that the role can still read at least one column on each of those tables.

### Role settings

```sql
ALTER ROLE peephole_ro WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 5 PASSWORD NULL;
ALTER ROLE peephole_ro SET default_transaction_read_only = on;
ALTER ROLE peephole_ro SET statement_timeout = '10s';
ALTER ROLE peephole_ro SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE peephole_ro SET lock_timeout = '1s';
ALTER ROLE peephole_ro SET temp_file_limit = '256MB';
```

Notes:

- `default_transaction_read_only` is a GUC, so the role could `SET` it off. The client
  rejects `SET` (below), and the role has no write grants anyway. If you know a path from
  "role-level read_only plus no write privileges" to a write, I want to hear it.
- 10 s is short on purpose: Peephole reads the live primary today. Raise it once it points
  at a replica.
- `CONNECTION LIMIT 5` so a runaway session cannot take the pool.
- `NOSUPERUSER`, `NOREPLICATION`, `NOBYPASSRLS` are not written out. A new role never has
  them, and on RDS the master user is not a superuser, so even `NOSUPERUSER` is refused.
  That was a real failure on the first RDS run.
- On RDS the role gets `GRANT rds_iam` and logs in with a 15-minute IAM token. No
  password is stored. On plain Postgres you set a password after the script.

### The client-side allow-list

Every statement goes through Postgres's own parser (`libpg-query`, the WASM build) before
it is sent. The rule: exactly one statement, of type `SelectStmt` or `ExplainStmt` without
`ANALYZE`, then a walk of the AST for `lockingClause`, `intoClause` and `FuncCall` names
in a banned set of 33 functions. Examples from the 45 tests:

| SQL | Result |
|---|---|
| `select 1; drop table users` | Blocked: Exactly one statement is allowed, got 2 |
| `update users set x = 1` | Blocked: Only SELECT is allowed (got Update) |
| `set default_transaction_read_only = off` | Blocked: Only SELECT is allowed (got VariableSet) |
| `copy users to '/tmp/x'` | Blocked: Only SELECT is allowed (got Copy) |
| `select * from users for update` | Blocked: Row locks (FOR UPDATE / FOR SHARE) are not allowed |
| `with a as (select * from users for update) select * from a` | Blocked: Row locks ... |
| `select 1 into t` | Blocked: SELECT INTO creates a table and is not allowed |
| `explain analyze select 1` | Blocked: EXPLAIN ANALYZE runs the query; use plain EXPLAIN |
| `select pg_catalog.pg_sleep(10)` | Blocked: Function pg_sleep() is not allowed |
| `select * from users where id = (select pg_sleep(1))` | Blocked: Function pg_sleep() is not allowed |
| `select set_config('x', 'y', false)` | Blocked: Function set_config() is not allowed |
| `select nextval('s')` | Blocked: Function nextval() is not allowed |

Banned: `pg_sleep*`, `dblink*`, `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`,
`pg_stat_file`, `lo_*`, `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`,
`set_config`, advisory locks, `nextval`, `setval`, `pg_notify`, `pg_logical_emit_message`,
`pg_create_restore_point`, `pg_switch_wal`, `pg_backup_start`, `pg_backup_stop`.

The allow-list is a fence, not the wall. If it let `pg_sleep` through, the 10 s statement
timeout stops it; if it let an `UPDATE` through, the role has no `UPDATE` privilege and the
transaction is read-only. The design rule is that the client never has to be right for the
database to stay safe.

After the parser: the query is wrapped as `SELECT * FROM (<sql>) peephole_q LIMIT 501`, and
the result is cut to 500 rows, 2 KB per cell, 1 MB total before the model sees it.

### What I would like reviewed

1. `sql/setup-role.sql`, top to bottom. It runs as the DB owner or RDS master user with
   `-v ON_ERROR_STOP=1`. Is there a path for `peephole_ro` to read a hidden column or write
   anything? Views, functions with `SECURITY DEFINER`, sequences, RLS and
   `pg_catalog` are the places I am least sure about.
2. Anything in `pg_catalog` or `information_schema` that leaks hidden column *values*
   (statistics in `pg_stats` are the obvious one; the role gets no explicit grant on it,
   but it is readable by default for tables the role can select from. If you know whether
   column-level grants are respected there, say so).
3. Functions missing from the banned set that are callable by an ordinary role and can
   block, write, or read files.

If what you find weakens the read-only guarantee, SECURITY.md asks for an email to
security@vocobase.com rather than a public issue. Design notes and the list of known
limits are in `docs/plans/2026-10-28-peephole-design.md`.

On a real production database the setup denied 52 hidden columns, blocked writes and
enforced lease expiry. That is one database. Yours is different, which is why I am asking.
