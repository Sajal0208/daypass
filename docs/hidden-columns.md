# Hidden columns

The hidden list is the set of `table.column` names the agent must never read. It is the one piece of Daypass's safety that you write yourself, and the one that is enforced inside Postgres rather than on the laptop: for each listed table the read-only role gets `SELECT` on the visible columns only. This page covers what to put on the list, how to generate a first draft, how to apply and verify it, and how to keep it current when the schema changes.

## What to hide

Anything that identifies a person or unlocks a system:

- contact details: phone, email, postal address
- identity numbers: SSN, tax id, passport, IBAN, card numbers, date of birth
- free text written by or about people: transcripts, messages, support notes, prompt snapshots, bot logs
- credentials in any form: API keys, key hashes, password hashes, OAuth tokens, refresh tokens, webhook secrets, encrypted blobs
- anything a privacy review in your company already classified

Not on the list: ids, timestamps, statuses, counts, amounts, foreign keys. The agent needs those to answer questions, and they identify nothing on their own. Be aware that visible rows can still be joined to a person through an id; hiding columns limits what the agent reads, it does not anonymise the database.

The list is per column, not per row. There is no row masking. If a whole table is sensitive, list every column except the primary key; the setup refuses a table with no visible column left.

## Generate a first draft

`daypass hidden suggest` reads column names from a Prisma schema or from a live database, flags names that look personal or secret, and prints a `#` comment header followed by one `table.column` per line. Redirect it to a file:

```bash
daypass hidden suggest --prisma prisma/schema.prisma > hidden-columns.txt   # from a Prisma schema
daypass hidden suggest --url "$OWNER_URL" > hidden-columns.txt              # from a live database, as the owner
daypass hidden suggest --live staging > hidden-columns.txt                  # from a target in ~/.daypass/config.json
```

`--live` needs no lease; it is an admin command that connects the way the MCP server does. But a target that uses the per-lease security-group rule is only reachable while a lease is open; open one first or run from inside the VPC.

The heuristic, from `src/core/hidden.ts`, splits the name into snake_case parts (camelCase too: `phoneNumber` becomes `phone_number`) and flags it when a part is one of `phone`, `mobile`, `email`, `token`, `secret`, `key`, `transcript`, `password`, `passwd`, `address`, `ssn`, `iban`, `card`, `dob`, `birth`, `birthday`, `birthdate`, `salt`, `otp`, `pin`, `passport`, `license`, `licence`, `routing`, `national`, or when the name starts with `encrypted_` or is exactly `prompt_snapshot`, `lines` or `credentials`. A name ending in a safe tail is left alone: `_verified`, `_confirmed`, `_count`, `_used`, `_at`, `_id`, `_type`, `_status`, `_enabled`, `_required`, `_country`, `_layout`, `_limit`, `_prefix`, `_version`, `_expiry`, `_expires`, `_expiration`, `_rounds`, `_domain` (so `email_verified`, `phone_country`, `key_prefix` and `tokens_used` are not flagged). The exceptions that are always flagged despite the tail: `national`, `tax` or `government` followed by `_id` or `_number`, and `account_number` / `bank_account_number` (`account_id` is an ordinary foreign key and is not flagged). It reads names only, never values. A summary goes to stderr, so it does not land in the file: `daypass hidden suggest: 2 of 9 columns flagged`.

The file format is the one `daypass sql --hide-file` reads:

- one `table.column` per line, spelled exactly as the catalog has it. A Prisma field without `@map` keeps its camelCase name (`AppUser.phoneNumber`), and `daypass sql` quotes it, so case matters
- `#` to end of line is a comment; blank lines are ignored
- a line starting with `!` is an allow line: `!documents.s3_key` means "reviewed, intentionally visible". `daypass hidden check` stops flagging that column (and reports a stale `!` entry under `Listed (hidden or !allowed) but not in the schema`); `daypass sql --hide-file` ignores the line
- tables are in the `public` schema; the setup SQL handles `public` only

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

`--hide table.column …` adds entries on the command line; `--role NAME` changes the role name from `daypass_ro`. The generated SQL carries the list as a Postgres array; this is what the relevant part looks like for a two-line list:

```sql
DO $$
DECLARE
  hidden text[] := ARRAY[
    'customers.email',
    'customers.secret'
  ];
```

What the script does with it, in order: checks that every entry exists (`hidden column "customers.nope" does not exist in schema public - fix the list` and stop otherwise); for each table on the list, revokes table-level `SELECT` and grants `SELECT (…)` on the remaining columns; then runs the self-check.

### The column-grant gotcha

The obvious approach, `REVOKE SELECT (email) ON customers FROM daypass_ro`, does nothing. Postgres evaluates a column-level `REVOKE` only against column-level grants; a role that holds table-level `SELECT` keeps reading every column. That is why the script drops the table-level grant on each affected table and grants the visible columns explicitly. Two side effects follow:

- `SELECT *` on those tables fails with `permission denied for table customers`. The agent has to name columns; `describe_table` lists only the ones it may read.
- A column added later to one of those tables stays hidden, because nothing granted it. A brand-new table, by contrast, is fully visible through `ALTER DEFAULT PRIVILEGES`.

## The self-check

The script ends with a `DO` block that asserts, as the database:

- for every entry, `has_column_privilege('daypass_ro', table, column, 'SELECT')` is false;
- for every table on the list, at least one column is still readable.

Success prints `NOTICE:  hidden columns verified: 2 columns across 1 tables`. Failure raises `self-check failed: daypass_ro can still read customers.email` (or `cannot read any column of customers`) and, with `-v ON_ERROR_STOP=1`, `psql` exits non-zero. It then prints the role's settings and an owner report: tables owned by a user other than the one running the script are not covered by the `ALTER DEFAULT PRIVILEGES` rule, so a `covered_by_default_privileges = f` row means tables that owner creates later will not be readable until you re-run.

### One transaction

The generated script pins `\set ON_ERROR_STOP on` and `\set ON_ERROR_ROLLBACK off` and runs as one transaction (`BEGIN` … `COMMIT`), so on any error (a stale entry, a typo) nothing is applied and the previous grants stay as they were. Run it with `psql -X … -v ON_ERROR_STOP=1`; `-X` skips your psqlrc.

## After a schema change

The setup is safe to re-run and should be re-run after any migration that adds a table or a column. Three steps:

```bash
daypass hidden suggest --prisma prisma/schema.prisma   # or --url / --live; compare with the committed list
daypass hidden check --file hidden-columns.txt --prisma prisma/schema.prisma
daypass sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
```

`hidden check` compares the file with the schema and prints up to two lists: `Listed (hidden or !allowed) but not in the schema` (renamed or dropped columns, which would stop the setup script) and `Sensitive-looking but not hidden` (new columns the list does not cover, minus those on a `!` allow line). It exits 1 if either is non-empty; otherwise it prints `hidden list matches the schema (N hidden, M columns scanned)` and exits 0, so it fits in CI. `--prisma`, `--live` and `--url` pick the schema source exactly as for `suggest`. [Prisma check](prisma-check.md) shows the equivalent `npm test` form and a CI job.

Re-runs keep the role's password.

## Verify from the agent's side

With a lease open, the fastest check is `daypass doctor <target>` for the role settings, and one query through the MCP tools, or `psql` as `daypass_ro`:

```sql
select email from customers;   -- ERROR:  permission denied for table customers
select id, name from customers; -- works
```
