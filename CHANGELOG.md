# Changelog

## [0.2.1](https://github.com/Sajal0208/daypass/compare/v0.2.0...v0.2.1) (2026-11-04)


Several leases at once, one per target: `daypass open a`, then `daypass open b`. Nothing changes until you open a second lease. Upgrade every daypass on the machine and restart Claude Code sessions first (0.2.0 reads a file with two leases as corrupt); to downgrade with several leases open, run `daypass close` with 0.2.1 first.

### Features

* several leases at once, one per target ([#29](https://github.com/Sajal0208/daypass/issues/29)) ([31dc070](https://github.com/Sajal0208/daypass/commit/31dc070b347275b3e82b0e3875b32440d0f86b2d))

### Leases (`open`, `close`, `sweep`, `status`, `doctor`)

- One live lease per target. `open` refuses only when the same target already has a live lease, and refuses, before any AWS call, a second target behind the same security group, region and port. A lease closed while AWS was still making its rule is never brought back: the new rule is revoked and `open` fails.
- `~/.daypass/lease.json` keeps its path and, with one lease, its 0.2.0 shape. With two or more it is `{ "version": 2, "leases": [ … ] }`, at most one per target. Every write is a read-modify-write under the lease lock; a stale lock is broken by one waiter, atomically. A corrupt file never drops another target's lease or its security-group rule id silently.
- `close <target>` closes one lease; bare `close` closes all and keeps going past a lease whose rule AWS could not revoke (it lists them and exits 1). Only bare `close` removes a corrupt file; `close <target>` refuses.
- `sweep <target>` sweeps AWS first, then reports a corrupt lease file (exit 1), and keeps an expired lease whose rule lives in another group. `status` lists every lease. `doctor` checks the lease of the named target.

### MCP server

- `list_tables`, `describe_table`, `query` and `explain` take an optional `target`. With one live lease it is optional; with two or more and no `target`, the call is refused and nothing runs. `daypass_status` prints one line per lease and a `Pass target: …` hint.
- One connection pool per target. A call on a live lease no longer waits for another, expired lease's rule to be revoked, and a revoke that failed is not tried again on every call (once a minute).

### Plugin

- The skill passes `target` whenever the question names a database, asks which database when it does not, and suggests `daypass close <target>`. New evals `two-leases` and `lease-on-other-db`.
- Known limit: the PII hook still uses one hidden-columns list for every target (`DAYPASS_HIDDEN_FILE`, else `~/.daypass/hidden-columns.txt`). Each target's role grants are the wall and are unchanged.

## [0.2.0](https://github.com/Sajal0208/daypass/compare/v0.1.1...v0.2.0) (2026-11-04)

Security fixes from the 2026-10-30 and 2026-11-01 reviews (advisory [GHSA-rjrr-9c6p-6wxc](https://github.com/Sajal0208/daypass/security/advisories/GHSA-rjrr-9c6p-6wxc)). **Everyone on 0.1.x: upgrade, then re-run the role setup** (`daypass sql --hide-file … | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1`) and `daypass doctor`. The 0.1.0 role can read hidden columns through views, materialized views, partitions, inheritance children and `SECURITY DEFINER` functions that touch them, and can write through a `SECURITY DEFINER` function that writes.

### ⚠ BREAKING CHANGES

* the role setup must be re-run; grants are now explicit per relation with no default privileges.

### Role setup (`sql/setup-role.sql`)

- Grants are explicit, per relation, in the listed schemas; no `GRANT … ON ALL TABLES` and no default privileges (those an older version set are removed). A table created later is invisible until the setup is re-run. A column added to a table *without* hidden columns is readable at once; one added to a table *with* hidden columns stops the next run until it is listed or marked `!table.column`.
- Hidden columns are hidden on every partition and inheritance child; hiding a column on a child only is refused. Views and materialized views that read a hidden column, a whole row of a table with hidden columns, a table outside `--schemas`, a foreign table, or a catalog the role cannot read are not granted; nor are materialized views that call non-catalog or data-reading functions. Generated columns computed from a hidden column must be listed. Sequences owned by a hidden column are not granted. Foreign tables are never granted.
- The self-check also fails when the role holds any write privilege from any grantor, can read anything outside `--schemas`, can execute a `SECURITY DEFINER` function (unless `--allow-definer-functions`), owns an object, is a member of another role, has large-object grants, or when `lo_compat_privileges` is on; the run also stops on a database with the unpatched CVE-2024-4317 statistics views and on a `PUBLIC` grant on a hidden table.
- New options: `--schemas`, `--allow-definer-functions`, `--revoke-public-temp`, `--revoke-public-create`. Hidden entries accept `schema.table.column` and `"quoted"` identifiers.
- Role settings are reset (`RESET ALL`, per-database overrides removed) and re-applied on every run; `search_path` is pinned for the setup transaction; PostgreSQL 16+ needs ADMIN OPTION on the role to alter it (clear error). The report says what `PUBLIC` still allows (temp tables, `CREATE`, large objects, executable functions) and stores the applied list on the role for `doctor`.

### `daypass doctor`

- No longer probes writes through its own read-only session (which proved nothing). It checks the catalog: role settings drift (incl. per-database overrides), write privileges in any schema, `CREATE`, owned objects, role membership, anything readable outside the schemas, the stored hidden list (`--hide-file` adds one; with neither the check fails), executable `SECURITY DEFINER` functions, and, as a warning, every other executable function outside `pg_catalog`.

### MCP server and guard

- Results are cut in the database: row cap and byte budget (UTF-8 bytes) in SQL; a row still over the budget is left out with a note; 32 MiB wire cap per call; SQL over 256 KiB refused. A huge value no longer crashes the server.
- Each call runs in `BEGIN READ ONLY` over the extended protocol with a statement timeout of min(10 s, lease time left), then `pg_advisory_unlock_all()` and `DISCARD ALL`. Cut-off calls are cancelled in the database; shutdown ends in-flight calls cleanly.
- Audit: a `start` line before each allowed call and an `end` line after it, paired by `callId`; `server` lines for crashes caught and transport close. `daypass log` shows one row per call (`RUN` for a start without an end, `SRV` for server events); `-n` counts calls.
- Guard: data-modifying CTEs refused; many more banned functions (all advisory-lock and large-object functions, `query_to_xml` and the other SQL-from-a-string functions, `setseed`, several extensions); `EXPLAIN (ANALYZE false)` allowed; trailing comments and semicolons accepted (canonical SQL is run and audited); guard errors fail closed.
- `query` values: column order kept, exact numbers kept (big ones as strings).
- `describe_table` leaves out indexes on hidden columns. The MCP version comes from `package.json`.
- TLS: URL/password targets on `*.rds.amazonaws.com` also pin the bundled RDS CA. IPv6 callers get a `/128` security-group rule.
- Lease and audit `who` on URL targets is the OS account name, no longer the `USER` variable.

### Plugin

- The PII hook covers `explain` too, tokenizes quoting, dollar quoting and escapes, blocks `SELECT *`, whole-row references, SQL-from-a-string functions and planner statistics, and fails closed on Claude Code 2.1.295+.
- The state guard also covers the `Monitor` tool, which runs a command in the same shell as `Bash`; before, a `Monitor` call could read `config.json` or run `daypass open` with no hook at all.

### Release

- The release workflow is split into build and publish jobs, SHA-pinned, and set up for npm trusted publishing behind a reviewed environment. That maintainer setup is still pending (see CONTRIBUTING.md).

### Commits

* security fixes from the 2026-10-30 and 2026-11-01 reviews ([#26](https://github.com/Sajal0208/daypass/issues/26)) ([e66e6b0](https://github.com/Sajal0208/daypass/commit/e66e6b08c7a13b4c8edfb5f8cdc2aaced4c1162f))

## [0.1.1](https://github.com/Sajal0208/daypass/compare/v0.1.0...v0.1.1) (2026-11-01)


### Bug Fixes

* address the 2026-10-30 full security review ([#19](https://github.com/Sajal0208/daypass/issues/19)) ([a07b773](https://github.com/Sajal0208/daypass/commit/a07b7733f20d49b00b434e9694935a6af58a25e4))


### Documentation

* document the staged npm publishing flow ([#18](https://github.com/Sajal0208/daypass/issues/18)) ([5ccf9e1](https://github.com/Sajal0208/daypass/commit/5ccf9e17502618a21a6e01828eaaa80377a5b82c))

## 0.1.0 — 2026-10-28

First release.

- `daypass open|status|close|sweep|log|doctor|sql|init|mcp|hidden`
- `daypass hidden suggest|check`: generate the hidden-columns list from a Prisma schema or the live catalog (`--prisma`, `--live <target>`, `--url`), and verify an existing list against it (exit 1 on drift). A line starting with `!` (`!documents.s3_key`) marks a reviewed, intentionally visible column: `check` stops flagging it and `sql --hide-file` ignores it. The Prisma parser and the sensitive-name heuristic live in `daypass/core`.
- `daypass sql --hide`/`--hide-file` accept camelCase and PascalCase names (`AppUser.phoneNumber`); the role SQL quotes every identifier.
- `sql/setup-role.sql` runs as one transaction (`BEGIN` … `COMMIT`) with `ON_ERROR_STOP on` / `ON_ERROR_ROLLBACK off` pinned, so a run that fails part-way (e.g. on a stale entry in the hidden-column list) changes nothing. `scripts/ci-integration.sh` proves the failed-run case.
- `sql/setup-role.sql` sets `PASSWORD NULL` only when it creates the role; re-runs keep a password set on a non-RDS database.
- A guard-refused `explain` call is written to `audit.jsonl` (`allowed: false`, `blockedReason`), the same as a refused `query`.
- MCP tools: `daypass_status`, `list_tables`, `describe_table`, `explain`, `query`
- Claude Code plugin (`plugin/`): bundles the MCP server; `daypass` skill (lease first, named columns, no PII in the reply, sign-off with the lease), `daypass-setup` skill, `/daypass:daypass-status`, `/daypass:daypass-log [N]`, `/daypass:daypass-hidden-check <target>`, a `PreToolUse` PII guard hook on `query` that blocks a sensitive-looking column the hidden list does not cover (`DAYPASS_HIDDEN_FILE`, `DAYPASS_PII_HOOK=off`), and a mocked eval suite for `claude plugin eval` (no lease, simple question, hidden column). Guide: `docs/plugin.md`.
- Marketplace catalog (`.claude-plugin/marketplace.json`): `/plugin marketplace add Sajal0208/daypass`, then `/plugin install daypass@daypass`.
- Postgres only. Auth: AWS RDS IAM tokens (no stored password) or a connection URL / password for any other Postgres.
- Guard: real Postgres parser (`libpg-query`); one statement; `SELECT`/`EXPLAIN` only; blocks row locks, `SELECT INTO`, `EXPLAIN ANALYZE` and 30+ dangerous functions.
- Limits: 500 rows, 2 KB per cell, 1 MB per result, 10 s statement timeout, read-only session.
- TLS always verified; IAM (`region`) targets pin the bundled AWS RDS CA. Audit `who` is the AWS caller ARN for IAM targets.
- Audit: one JSON line per completed call in `~/.daypass/audit.jsonl`.
- Optional: punch the caller's IP into an AWS security group for the lease; removed on `close`, on the first tool call after expiry, or by `daypass sweep`.
