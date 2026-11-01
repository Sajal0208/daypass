# r/PostgreSQL

## Title

```
A read-only role for AI coding agents: column-level grants, timeouts, a parser allow-list. Please review the SQL.
```

## Body

We give Claude Code a time-boxed, read-only window onto our production Postgres. The
client side is an MCP server; the part I want this sub to look at is the role. The
setup script is about 770 lines of SQL, most of it checks, and I would rather hear about a
hole here than from an agent.

Repo: https://github.com/Sajal0208/daypass. Script: `sql/setup-role.sql`. MIT.

### The gotcha that shaped the script

The first draft hid PII columns like this:

```sql
GRANT SELECT ON ALL TABLES IN SCHEMA public TO daypass_ro;
REVOKE SELECT (email, phone) ON users FROM daypass_ro;
```

That does nothing. Postgres checks table-level privilege first, and the role still holds
table-level `SELECT`, so `SELECT email FROM users` succeeds. A column-level `REVOKE` only
removes a column-level grant that was there before. The script now does, per table that
has a hidden column:

```sql
REVOKE SELECT ON TABLE public.users FROM daypass_ro;
GRANT SELECT (id, created_at, plan, country) ON TABLE public.users TO daypass_ro;
```

### The second gotcha: everything around the table

The 0.1.0 script still started from `GRANT SELECT ON ALL TABLES` and `ALTER DEFAULT
PRIVILEGES`, and a review showed what that misses: a view, a materialized view, a partition
or an inheritance child over `users` returned `email` happily, as did any `SECURITY DEFINER`
function that read it. The current script:

- grants nothing in bulk. Every run revokes what the role holds anywhere, then grants
  `SELECT` per table and partitioned table in the listed schemas, column lists on tables
  with hidden columns, no default privileges (so a new table is invisible until a re-run);
- hides the column on every partition and child (`pg_inherits`, recursively), and refuses a
  column hidden on a child only, since the parent would still return it;
- withholds every view and materialized view whose `ON SELECT` rule depends on a hidden
  column (`pg_depend` on `pg_rewrite`), reads a whole row of such a table (a `:varattno 0`
  Var in the stored rule), reads a schema that is not listed, a foreign table or a catalog
  the role cannot read itself, or reads a withheld view; and materialized views that call a
  function outside `pg_catalog` or a built-in that reads data by name, because what they
  store was computed with the owner's rights;
- requires generated columns computed from a hidden column to be listed, and does not grant
  sequences owned by a hidden column;
- fails its self-check if the role can execute any `SECURITY DEFINER` function (unless the
  owner passes `--allow-definer-functions`), holds any write privilege from any grantor,
  owns an object, belongs to another role, or can read anything outside the listed schemas;
- prints a `NOTICE` for every default, `CHECK` constraint, index predicate or policy that
  mentions a hidden column, since the role can read that catalog text;
- stops on the unpatched `pg_stats_ext` views of CVE-2024-4317.

### Role settings

```sql
ALTER ROLE daypass_ro WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 5;
ALTER ROLE daypass_ro RESET ALL;
ALTER ROLE daypass_ro SET default_transaction_read_only = on;
ALTER ROLE daypass_ro SET statement_timeout = '10s';
ALTER ROLE daypass_ro SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE daypass_ro SET lock_timeout = '1s';
ALTER ROLE daypass_ro SET temp_file_limit = '256MB';
```

Notes:

- These are defaults, and the role can change them for itself: `SET`, `ALTER ROLE ... SET`,
  `ALTER ROLE ... RESET ALL`, and its own password. No core GUC prevents that. So the claim
  is narrower than "the role is read-only": the GRANTs are the wall (no write privilege on
  any table, no hidden column, from any client); the settings hold for the agent because the
  client refuses `SET`/`set_config`, sends the same values as startup options and runs each
  call in `BEGIN READ ONLY`. `daypass doctor` compares `rolconfig` and
  `pg_db_role_setting` with what the script wrote. On RDS, `rds.restrict_password_commands`
  covers the password.
- With read-only off, a direct session can still create temp tables (PUBLIC's `TEMP`),
  large objects (no privilege needed in core), and on PG 14 and older objects in `public`.
  The script reports each and has opt-in flags to revoke `TEMP` and `CREATE` from PUBLIC; it
  does not do that by default because it would break other roles.
- 10 s is short on purpose: Daypass reads the live primary today. Raise it once it points
  at a replica.
- `NOSUPERUSER`, `NOREPLICATION`, `NOBYPASSRLS` are not written out. A new role never has
  them, and on RDS the master user is not a superuser, so even `NOSUPERUSER` is refused.
  That was a real failure on the first RDS run.
- On RDS the role gets `GRANT rds_iam` and logs in with a 15-minute IAM token. No
  password is stored. On plain Postgres you set a password after the script.
- On PG 16+ altering the role needs ADMIN OPTION on it; the script checks and says which
  `GRANT` to run.

### The client-side allow-list

Every statement goes through Postgres's own parser (`libpg-query`, the WASM build) before
it is sent. The rule: exactly one statement of at most 256 KiB, of type `SelectStmt` or
`ExplainStmt` without `ANALYZE`, then a walk of the AST for data-modifying CTEs,
`lockingClause`, `intoClause` and `FuncCall` names matching a list of banned patterns.
Examples:

| SQL | Result |
|---|---|
| `select 1; drop table users` | Blocked: Exactly one statement is allowed, got 2 |
| `update users set x = 1` | Blocked: Only SELECT is allowed (got Update) |
| `set default_transaction_read_only = off` | Blocked: Only SELECT is allowed (got VariableSet) |
| `copy users to '/tmp/x'` | Blocked: Only SELECT is allowed (got Copy) |
| `with d as (delete from users returning *) select * from d` | Blocked: Data-modifying statements are not allowed (DELETE in a WITH clause) |
| `select * from users for update` | Blocked: Row locks (FOR UPDATE / FOR SHARE) are not allowed |
| `select 1 into t` | Blocked: SELECT INTO creates a table and is not allowed |
| `explain analyze select 1` | Blocked: EXPLAIN ANALYZE runs the query; use plain EXPLAIN |
| `select pg_catalog.pg_sleep(10)` | Blocked: Function pg_sleep() is not allowed |
| `select query_to_xml('select pg_sleep(3)', true, false, '')` | Blocked: Function query_to_xml() is not allowed |
| `select pg_try_advisory_lock_shared(42)` | Blocked: Function pg_try_advisory_lock_shared() is not allowed |
| `select set_config('x', 'y', false)` | Blocked: Function set_config() is not allowed |

Banned, as patterns on the bare name: `pg_sleep*`, `pg_(try_)advisory_*`, `dblink*`,
`lo_*`, `pg_ls_*`, `pg_read_*`, `pg_stat_file`, `pg_stat_reset*`, `set_config`, `nextval`,
`setval`, `pg_terminate_backend`, `pg_cancel_backend`, `pg_reload_conf`, `pg_notify`,
`txid_current`, the replication/WAL/backup family, the SQL-from-a-string family
(`query_to_xml*`, `cursor_to_xml*`, `table|schema|database_to_xml*`, `ts_stat`,
`ts_rewrite`, tablefunc's `crosstab*`/`connectby`, xml2's `xpath_table`), `setseed`, and a
few extensions (`pgr_*`, `query_export_to_s3`, orafce's `dbms_pipe`/`dbms_alert`, `hypopg`).
The full list is `BANNED_FUNCTION_PATTERNS` in `src/core/guard.ts`. It cannot cover every
extension; the role's `EXECUTE` grants are the real boundary, and `doctor` lists the
functions the role can execute.

The allow-list is a fence, not the wall. If it let an `UPDATE` through, the role has no
`UPDATE` privilege and the transaction is read-only. If it let `pg_sleep` through, the
timeout stops it.

After the parser: the query runs inside `BEGIN READ ONLY` over the extended protocol, with
`SET LOCAL statement_timeout` = min(10 s, lease time left), wrapped so that each row comes
back as `to_json` text and the row cap (500) and byte budget (1 MB, `octet_length`) are
applied by Postgres with window aggregates. Afterwards `pg_advisory_unlock_all()` and
`DISCARD ALL`.

### What I would like reviewed

1. `sql/setup-role.sql`, top to bottom. It runs as the DB owner or RDS master user with
   `-v ON_ERROR_STOP=1`, in one transaction, with `search_path` pinned to `pg_catalog`. Is
   there still a path for `daypass_ro` to read a hidden column or write to a table? The
   view-dependency analysis (`pg_depend` on `ev_type = '1'` rules, the `:varattno 0` test for
   whole-row Vars, function oids scraped from `ev_action` for matviews) is the part I am
   least sure about. RLS and rules other than `ON SELECT` are the next.
2. Anything else in `pg_catalog` or `information_schema` that leaks hidden column
   *values* to an ordinary role. We know about catalog text (defaults, constraints, index
   predicates, view definitions) and say so; `pg_stats` filters on `has_column_privilege`;
   the CVE-2024-4317 views are checked.
3. Functions callable by an ordinary role that can block, write, or read files and are not
   in the banned list.

If what you find weakens the read-only guarantee, SECURITY.md describes how to report it
privately rather than as a public issue. Design notes are in
`docs/plans/2026-10-28-daypass-design.md`; the threat model with its "not covered" list is
`docs/threat-model.md`.

On a real production database the 0.1.0 setup denied 52 hidden columns, blocked writes and
enforced lease expiry. That run did not exercise views or definer functions, which is why I
am asking.
