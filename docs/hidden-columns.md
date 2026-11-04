# Hidden columns

The hidden list is the set of `table.column` names the agent must never read. It is the one piece of Daypass's safety that you write yourself, and the one that is enforced inside Postgres rather than on the laptop: for each listed table the read-only role gets `SELECT` on the visible columns only. This page covers what to put on the list, how to generate a first draft, how to apply and verify it, and how to keep it current when the schema changes.

## What to hide

Anything that identifies a person or unlocks a system:

- contact details: phone, email, postal address
- identity numbers: SSN, tax id, passport, IBAN, card numbers, date of birth
- free text written by or about people: transcripts, messages, support notes, chat and log text
- credentials in any form: API keys, key hashes, password hashes, OAuth tokens, refresh tokens, webhook secrets, encrypted blobs
- anything a privacy review in your company already classified

Not on the list: ids, timestamps, statuses, counts, amounts, foreign keys. The agent needs those to answer questions, and they identify nothing on their own. Be aware that visible rows can still be joined to a person through an id; hiding columns limits what the agent reads, it does not anonymise the database.

The list is per column, not per row. There is no row masking. If a whole table is sensitive, list every column except the primary key; the setup refuses a table with no visible column left.

## Generate a first draft

`daypass hidden suggest` reads column names from a Prisma schema or from a live database, flags names that look personal or secret, and prints a `#` comment header followed by one `table.column` per line (schema-prefixed outside `public`, double-quoted where the name needs it). From a live database it also adds generated columns computed from a flagged column, leaves out a child's column when its parent's is already listed, and leaves out views the setup will withhold anyway. Redirect it to a file:

```bash
daypass hidden suggest --prisma prisma/schema.prisma > hidden-columns.txt   # from a Prisma schema
daypass hidden suggest --url-env OWNER_URL > hidden-columns.txt            # from a live database, as the owner
daypass hidden suggest --live staging > hidden-columns.txt                  # from a target in ~/.daypass/config.json
```

The owner URL carries a password, so keep it off the command line, where the process list and shell history would show it: `--url-env OWNER_URL` reads it from that environment variable (`--url-env` alone reads `DAYPASS_OWNER_URL`), and `--url -` reads it from the first line of stdin. `--url <url>` still works and prints a warning when the URL has a password. TLS follows the same rules as a target: always verified, the bundled CA for RDS hosts, `sslmode=disable` refused for them.

`--schemas analytics,public` picks the schemas to scan with `--live`, `--url` or `--url-env` (default: the target's `schemas`, else `public`). `--live` needs no lease; it is an admin command that connects the way the MCP server does. But a target that uses the per-lease security-group rule is only reachable while a lease is open; open one first or run from inside the VPC.

The heuristic, from `looksSensitive` in `src/core/hidden.ts`, splits the name into snake_case parts (camelCase too: `phoneNumber` becomes `phone_number`, `Address1` becomes `address_1`), reads a plural sensitive word as its singular (`secrets`, `api_keys`, `addresses`), splits a run-together part made entirely of known words (`emailaddress`, `apikeyid`, `dateofbirth`; `keyboard` stays whole), and flags it when a part is a word such as `phone`, `mobile`, `email`, `mail`, `token`, `secret`, `key`, `password`, `address`, `postal`, `zip`, `ssn`, `iban`, `card`, `cvv`, `dob`, `birth`, `passport`, `license`, `ip`, `surname`, `username`, `gender`, `religion`, `notes`, `body`, `payload`, `metadata`, `transcript`, `recording`, `lat`/`lng`, `encrypted` (the full list is `WORDS` in that file), or when the name matches a special form: `first_name`/`last_name`/`full_name` and similar, `user_agent`, `health_*`, `encrypted_*`, `credentials` and a few other exact names (`SPECIAL` in that file). A name ending in a safe tail is left alone: `_verified`, `_confirmed`, `_count`, `_used`, `_at`, `_id`, `_type`, `_status`, `_enabled`, `_country`, `_country_code`, `_prefix`, `_expires`, `_last_4` and others (so `email_verified`, `phone_country_code`, `key_prefix`, `card_last_4`, `tokens_used` and the foreign key `address_id` are not flagged), except that a strong word (`email`, `secret`, `key`, `token`, `password`) beats an `_id` or `_type` tail (`email_id` is flagged). Storage and public keys (`public_key`, `s3_key`, `cache_key`, `idempotency_key`, ...) are not flagged. Always flagged despite the tail: `national_id`, `tax_number` and the like, `account_number`, `device_id`, `stripe_customer_id`. It reads names only, never values. A summary goes to stderr, so it does not land in the file: `daypass hidden suggest: 2 of 9 columns flagged`.

The file format is the one `daypass sql --hide-file` reads:

- one `table.column` or `schema.table.column` per line, spelled exactly as the catalog has it. Unquoted names keep their case (a Prisma field without `@map` keeps its camelCase name, `AppUser.phoneNumber`, and `daypass sql` quotes it, so case matters). Double-quote a part that is not a plain identifier: `"order-items"."ship.address"`, `""` for an embedded quote
- `#` to end of line is a comment; blank lines are ignored
- a line starting with `!` is an allow line: `!documents.s3_key` means "reviewed, intentionally visible". `daypass hidden check` stops flagging that column (and reports a stale `!` entry under `Listed (hidden or !allowed) but not in the schema`); `daypass sql --hide-file` ignores the line
- an entry without a schema is in `public`. An entry in another schema needs that schema in `daypass sql --schemas` (the setup stops and says so otherwise)
- a column may be on a table, partitioned table, view, materialized view or foreign table; listing a parent's column hides it on every partition and child

## Review checklist

The draft is a starting point. Go through it with the schema open:

1. **Every table.** Scan each table's columns, not only the ones the heuristic flagged. `notes`, `body`, `payload`, `metadata`, `raw` and `data` are the usual places where personal data hides under a neutral name.
2. **Every flagged name is real.** A column that no longer exists stops the setup script. `daypass hidden check` finds these before you run it.
3. **False positives.** `address` on a `servers` table may be an IP; `key` on a `settings` table may be a config key. Do not just delete the line: `hidden check` would flag the column again on the next run. Turn it into an allow line so the decision is recorded:

   ```
   users.email
   users.phone
   !servers.address      # IP of the host, not a person
   !documents.s3_key     # object path, not a credential
   ```

   When in doubt, keep it hidden: the agent can ask you to widen the list, it cannot ask for a leak back.
4. **Secrets that are hashed are still secrets.** `password_hash` and `key_hash` go on the list.
5. **Whole-table cases.** For a table that is nothing but PII, leave the primary key and the timestamps visible so counts and joins still work.
6. **Commit the file.** Keep `hidden-columns.txt` in the repo that owns the schema, next to the migrations, so it is reviewed with them.

## Apply it

```bash
daypass sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
```

`--hide table.column …` adds entries on the command line; `--role NAME` changes the role name from `daypass_ro`; `--schemas public,analytics` sets the schemas the role may read (default `public`); `--allow-definer-functions`, `--revoke-public-temp` and `--revoke-public-create` are described in [Concepts](concepts.md#role). The generated SQL carries the list as a Postgres array of `schema|table|column` entries; this is what the relevant part looks like for a two-line list:

```sql
DO $$
DECLARE
  hidden_in     text[]  := ARRAY[
    'public|customers|email',
    'public|customers|secret'
  ];
```

What the script does with it, in order: checks that every entry exists (`hidden column "customers.nope" does not exist (as a table, partitioned table, view, materialized view or foreign table column in schema public) - fix the list` and stop otherwise) and that its schema is listed; extends each entry to every partition and inheritance child; stops on a generated column derived from a hidden one, a hidden column on a child only, a column added since the last run, or a `PUBLIC` grant on a hidden table; revokes everything the role held and grants afresh (for each table on the list, `SELECT (…)` on the remaining columns only); then runs the self-check.

### The column-grant gotcha

The obvious approach, `REVOKE SELECT (email) ON customers FROM daypass_ro`, does nothing. Postgres evaluates a column-level `REVOKE` only against column-level grants; a role that holds table-level `SELECT` keeps reading every column. That is why the script drops the table-level grant on each affected table and grants the visible columns explicitly. Two side effects follow:

- `SELECT *` on those tables fails with `permission denied for table customers`. The agent has to name columns; `describe_table` lists only the ones it may read.
- A column added later to one of those tables stays hidden, because nothing granted it, and the next run stops and names it until you list it (hidden) or mark it `!table.column` (visible). A column added to a table *without* hidden columns is readable at once, because that table has table-level `SELECT`: run `daypass hidden check` after every migration. A brand-new table is invisible until you re-run: the script sets no default privileges, and removes any that an older Daypass version set.

### What else the script withholds

- **Views and materialized views** that read a hidden column, read the whole row of a table with a hidden column (`SELECT c FROM customers c`, `row_to_json(c)`), read a table in a schema that is not in `--schemas`, read a catalog the role cannot read itself (`pg_statistic`, `pg_authid`), or read such a view. Each one is named in a `NOTICE ... not granted`. `count(*)` over a hidden table is fine.
- **Materialized views that stored what only their owner could see.** A materialized view stores what its query returned when the owner last refreshed it, so everything in that query ran with the owner's rights, including the views it reads, followed all the way down. It is withheld when that tree
  - reads a system catalog or `information_schema` relation other than a few plain catalog tables the role can read in full itself (`pg_namespace`, `pg_class`, `pg_attribute`, `pg_type`, `pg_index`, `pg_constraint`, `pg_inherits`, `pg_description`, `pg_enum`): views such as `pg_stats`, `pg_stats_ext` and `pg_stat_activity` filter rows by the caller, so the owner's refresh stored rows the role could never see;
  - reads a table with row-level security (the owner's refresh stored the rows the owner may see);
  - calls a function outside `pg_catalog`, a built-in that reads data by name (`query_to_xml`, `table_to_xml`, `ts_stat`, `lo_get`, `pg_read_file`, `current_setting`, `dblink`, `crosstab`, ...), or any other built-in that is not immutable, except a short list of clock, date/time, formatting and JSON builders (`now`, `date_trunc`, `to_char`, `format`, `json_build_object`, `jsonb_agg`, ...).

  The walk follows functions reached through operators, row comparisons, type conversions, subscripts and domain `CHECK` constraints too, and any function or operator that belongs to an extension withholds the view (the `NOTICE` says so). The `NOTICE` names the reason and the view it came through (`reads pg_catalog.pg_stats through view public.v`). There is no override. Immutable built-ins (`upper`, `length`, ...) are fine.
- **Plain views that read with their owner's rights.** A view reads its tables as its owner, so one (at any depth) over a table with row-level security is withheld unless it is `security_invoker` (PostgreSQL 15+): `NOTICE:  view public.notes_v reads public.tenant_notes, which has row-level security (a view reads its tables with its owner's rights; only a security_invoker view, PostgreSQL 15+, reads them as the caller): not granted`. So is a view over a relation in `--schemas` the role is not granted, such as a sequence owned by a hidden column: `view public.key_counter reads public.accounts_api_key_id_seq, which the role is not granted (a sequence owned by a hidden column): not granted`.
- **Sequences owned by a hidden column** (`serial`, identity): `last_value` would show the latest value and roughly how many rows exist. Every other sequence in `--schemas` gets `SELECT`.
- **Partitions and inheritance children** get the parent's hidden column hidden too. The reverse is refused: hiding a column on a child only would leave it readable through the parent, so list the parent's column.
- **Schemas no longer listed** lose every grant the role held there, and the run fails if anything outside `--schemas` is still readable (a grant to `PUBLIC`, or by another role). `--schemas` takes plain identifiers only (`[A-Za-z_][A-Za-z0-9_]*`).
- **Foreign tables** are never granted. Their columns may be listed; a view over a foreign table is withheld (it would read remote data with the view owner's user mapping).
- **Generated columns** computed from a hidden column (`hint text GENERATED ALWAYS AS (left(secret, 4)) STORED`) carry part of its value: the run stops until you list them too. `hidden suggest` includes them and `hidden check` flags them.
- **Catalog text.** The role can read every view definition, default, `CHECK` constraint, index predicate and policy. The run prints `catalog text: ... mentions hidden column ...` for each one that mentions a hidden column, so you can check it holds no real value. A row-level policy on a hidden column reveals one bit per row (whether the row passes).

The run also refuses a role that owns any object (it could have planted a function or operator while it held `CREATE`; `DROP OWNED BY daypass_ro` as the owner, then re-run) or that is a member of another role (`SET ROLE` would reach that role's privileges), and any write privilege the role holds in any schema, from whatever grantor (`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`/`TRIGGER`, `MAINTAIN` on 17+, column-level `INSERT`/`UPDATE`, `USAGE`/`UPDATE` on a sequence). It removes `SUPERUSER`, `REPLICATION` and `BYPASSRLS` from the role if set (a logical replication slot reads every row, and `BYPASSRLS` skips row-level security), and stops with the `ALTER ROLE` to run when it is not allowed to. It also refuses:

- **Foreign servers** the role can reach: `USAGE` on a server or foreign-data wrapper, or a user mapping for the role or `PUBLIC` (`postgres_fdw` and `dblink` would log in elsewhere with stored credentials).
- **Default privileges for `PUBLIC`** on tables, sequences or schemas (a table created later would be readable before anyone reviewed it). `EXECUTE` on functions and `USAGE` on types, Postgres's own defaults, are accepted.
- **System-catalog grants beyond a fresh cluster's** to `PUBLIC` or the role, compared with `pg_init_privs` (`SELECT` on `pg_statistic` or `pg_authid`, `EXECUTE` on `pg_read_file`, ...).
- **On RDS, an `rds_iam` membership that reaches anything.** From PostgreSQL 16 the setup grants `rds_iam WITH INHERIT FALSE, SET FALSE`; before 16 it requires that `rds_iam` holds nothing. See [AWS RDS](aws-rds.md). The script pins `search_path` to `pg_catalog` for its own transaction, so nothing in your schemas can run as the owner while it executes. Creating large objects needs no privilege in core Postgres; the report says so, and `REVOKE EXECUTE ON FUNCTION lo_create(oid), lo_creat(integer), lo_from_bytea(oid, bytea) FROM PUBLIC` blocks it for every role if you need that.

Every other function outside `pg_catalog` is also callable by the role (functions are `EXECUTE`-to-`PUBLIC` by default), and the report prints how many: a function that takes SQL as text runs whatever it is handed, out of the guard's sight. `daypass doctor` lists them as a warning and flags the SQL-from-a-string ones. Locking them down (`REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA <s> FROM PUBLIC`, then `GRANT EXECUTE` to your app roles) is left to you; see the [threat model](threat-model.md).

The run also fails if the role can execute a `SECURITY DEFINER` function in any schema (a view can call it for the role), unless you pass `--allow-definer-functions`, and it reports whether the role can create temp tables (`--revoke-public-temp`) or objects in a schema (`--revoke-public-create`; PostgreSQL 14 and older let PUBLIC create in `public`).

## The self-check

The run stores the list it applied on the role (`COMMENT ON ROLE`, per database; a comment that is not Daypass's own is printed in a `NOTICE` before it is replaced), and `daypass doctor` reads it: the `hidden columns` check fails if any listed column, its copy on a partition or child, the same column on a parent the table was attached to later (`ALTER TABLE ... INHERIT`), or a view exposing one, has become readable since. `daypass doctor --hide-file <list>` checks a list of your own on top. With no stored list and no `--hide-file`, the check fails.

The run also stops on a database whose `pg_stats_ext` / `pg_stats_ext_exprs` views predate the CVE-2024-4317 fix (clusters created before 14.12, 15.7 or 16.3): those views show sample values of columns the caller cannot read. Run `share/fix-CVE-2024-4317.sql` from your Postgres installation in the database, as its release notes describe.

The script ends with a `DO` block that asserts, as the database:

- for every entry, `has_column_privilege('daypass_ro', table, column, 'SELECT')` is false;
- for every table on the list, at least one column is still readable.

- no view or materialized view the script withheld is readable, no default privileges remain for the role or `PUBLIC`, and it holds no privilege outside `--schemas`;
- it holds no write privilege (column-level included), reaches no foreign server, and the catalogs carry no extra grant;
- no `SECURITY DEFINER` function is executable by the role (unless acknowledged);
- just before `COMMIT`: it owns nothing, belongs to no other role, has none of `SUPERUSER`, `REPLICATION`, `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, and its `rds_iam` membership reaches nothing.

Success prints `NOTICE:  hidden columns verified: 2 columns across 1 relations ...`. Failure raises `self-check failed: daypass_ro can still read customers.email` (or `cannot read any column of customers`) and, with `-v ON_ERROR_STOP=1`, `psql` exits non-zero. It then prints the role's settings and an owner report: a `GRANT` by someone who does not own the table does not take effect, so run the script as the owner of your tables (`owned_by_you = f` rows are the ones to check).

### One transaction

The generated script pins `\set ON_ERROR_STOP on` and `\set ON_ERROR_ROLLBACK off` and runs as one transaction (`BEGIN` … `COMMIT`), so on any error (a stale entry, a typo) nothing is applied and the previous grants stay as they were. Run it with `psql -X … -v ON_ERROR_STOP=1`; `-X` skips your psqlrc.

## After a schema change

The setup is safe to re-run and should be re-run after any migration that adds a table or a column. Three steps:

```bash
daypass hidden suggest --prisma prisma/schema.prisma   # or --url-env / --live; compare with the committed list
daypass hidden check --file hidden-columns.txt --prisma prisma/schema.prisma
daypass sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
```

`hidden check` compares the file with the schema and prints what has drifted: `Listed (hidden or !allowed) but not in the schema` (renamed or dropped columns, which would stop the setup script), `Sensitive-looking but not hidden` (new columns the list does not cover, minus those on a `!` allow line), and, from a live database, `Generated from a hidden column - hide these too`, `Hidden on a partition/child only - …` and `Columns both hidden and !allowed`. It exits 1 if any of those is non-empty (a `Views the setup withholds` list is information only); otherwise it prints `hidden list matches the schema (N hidden, M columns scanned)` and exits 0, so it fits in CI. `--prisma`, `--live`, `--url` and `--url-env` pick the schema source exactly as for `suggest`. From a live database the information-only `Views the setup withholds` list names each view and why, with the same rules as the setup (`view mv_stats reads pg_catalog.pg_stats (a materialized view stores what the owner could read)`, `view notes_v reads public.tenant_notes, which has row-level security (…)`, `view key_counter reads accounts_api_key_id_seq, a sequence owned by a hidden column`). [Prisma check](prisma-check.md) shows the equivalent `npm test` form and a CI job.

Re-runs keep the role's password.

Two things a re-run is for, besides new hidden columns: **new tables** (the role cannot read a table created since the last run until you re-run) and **new columns on a table that has hidden columns** (the run stops and names each one; list it, or mark it `!table.column`). A column added to a table *without* hidden columns needs no re-run: it is readable at once, which is why `daypass hidden check` belongs in the migration routine.

### Upgrading a role set up by Daypass 0.1.0

The 0.1.0 script granted `SELECT ON ALL TABLES` and set `ALTER DEFAULT PRIVILEGES`, which exposes views, materialized views, partitions and children over hidden columns. Re-run the current setup once with your list: it revokes everything the role held, removes those default privileges, and grants table by table. Expect it to stop on things 0.1.0 let through (a `SECURITY DEFINER` function the role can execute, a view over a hidden column you listed, a column on a child only), each with the fix in the message. Until you re-run, `daypass doctor`'s `hidden columns` line fails, because no list is stored on the role (`--hide-file <list>` checks one by hand).

## Verify from the agent's side

With a lease open, the fastest check is `daypass doctor <target>`: its `role settings`, `write blocked`, `other schemas`, `rds_iam`, `foreign servers`, `default privileges`, `catalog grants`, `materialized views`, `views as owner`, `other databases`, `hidden columns` (against the list the setup stored on the role, plus `--hide-file <list>` if you pass one) and `definer functions` lines check the role in the catalog. Then one query through the MCP tools, or `psql` as `daypass_ro`:

```sql
select email from customers;   -- ERROR:  permission denied for table customers
select id, name from customers; -- works
```

What a hidden column still gives away: its name (the role can read `information_schema.columns`, `pg_attribute` and `pg_indexes`; `describe_table` leaving out indexes on hidden columns is cosmetic), and any constant written into catalog text that mentions it (see [What else the script withholds](#what-else-the-script-withholds)). Its values stay unreadable.
