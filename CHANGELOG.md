# Changelog

## Unreleased

## 0.1.0 — 2026-10-28

First release.

- `peephole open|status|close|sweep|log|doctor|sql|init|mcp`
- MCP tools: `peephole_status`, `list_tables`, `describe_table`, `explain`, `query`
- Postgres only. Auth: AWS RDS IAM tokens (no stored password) or a connection URL / password for any other Postgres.
- Guard: real Postgres parser (`libpg-query`); one statement; `SELECT`/`EXPLAIN` only; blocks row locks, `SELECT INTO`, `EXPLAIN ANALYZE` and 30+ dangerous functions.
- Limits: 500 rows, 2 KB per cell, 1 MB per result, 10 s statement timeout, read-only session.
- TLS always verified; RDS targets pin the bundled AWS RDS CA. Audit `who` is the AWS caller ARN for IAM targets.
- Audit: one JSON line per call in `~/.peephole/audit.jsonl`.
- Optional: punch the caller's IP into an AWS security group for the lease and remove it after.
