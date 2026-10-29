# Changelog

## Unreleased

## 0.1.0 — 2026-10-28

First release.

- `peephole open|status|close|sweep|log|doctor|sql|init|mcp`
- `peephole hidden suggest|check`: generate the hidden-columns list from a Prisma schema or the live catalog (`--prisma`, `--live <target>`, `--url`), and verify an existing list against it (exit 1 on drift). A line starting with `!` (`!documents.s3_key`) marks a reviewed, intentionally visible column: `check` stops flagging it and `sql --hide-file` ignores it. The Prisma parser and the sensitive-name heuristic live in `peephole-db/core`.
- `peephole sql --hide`/`--hide-file` accept camelCase and PascalCase names (`AppUser.phoneNumber`); the role SQL quotes every identifier.
- `sql/setup-role.sql` runs as one transaction (`BEGIN` … `COMMIT`) with `ON_ERROR_STOP on` / `ON_ERROR_ROLLBACK off` pinned, so a run that fails part-way (e.g. on a stale entry in the hidden-column list) changes nothing. `scripts/ci-integration.sh` proves the failed-run case.
- `sql/setup-role.sql` sets `PASSWORD NULL` only when it creates the role; re-runs keep a password set on a non-RDS database.
- A guard-refused `explain` call is written to `audit.jsonl` (`allowed: false`, `blockedReason`), the same as a refused `query`.
- MCP tools: `peephole_status`, `list_tables`, `describe_table`, `explain`, `query`
- Postgres only. Auth: AWS RDS IAM tokens (no stored password) or a connection URL / password for any other Postgres.
- Guard: real Postgres parser (`libpg-query`); one statement; `SELECT`/`EXPLAIN` only; blocks row locks, `SELECT INTO`, `EXPLAIN ANALYZE` and 30+ dangerous functions.
- Limits: 500 rows, 2 KB per cell, 1 MB per result, 10 s statement timeout, read-only session.
- TLS always verified; RDS targets pin the bundled AWS RDS CA. Audit `who` is the AWS caller ARN for IAM targets.
- Audit: one JSON line per call in `~/.peephole/audit.jsonl`.
- Optional: punch the caller's IP into an AWS security group for the lease and remove it after.
