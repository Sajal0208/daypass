---
name: peephole-log
description: Use when the user runs /peephole:peephole-log to summarise the recent Peephole audit log (what the agent queried, what was blocked, what failed).
disable-model-invocation: true
argument-hint: "[N]"
---

# Peephole log

`$ARGUMENTS` is an optional count N, default 20. Run with Bash, substituting it:

```bash
peephole log -n ${ARGUMENTS:-20}
```

Each line is `<at> <ok|ERR|BLK> <who> <target> <tool> <rows>r <ms>ms  <sql>  <- <reason>`; `-r`/`-ms`
mean unknown, SQL is cut at 120 chars. Say when fewer than N lines exist. Report, in this order:

1. **Queries per table** — every line (`ok`, `ERR` and `BLK`), with the table parsed from the SQL
   (`FROM x`, `JOIN y`, `UPDATE x`, `DROP TABLE x`; aliases stripped); `list_tables`/`describe_table`
   calls count under their tool name.
2. **Blocked (`BLK`)** — one line each with the `<- reason` (guard refusal: not a SELECT, two statements,
   lease expired, ...).
3. **Errors (`ERR`)** — one line each with the `<- reason` (`permission denied` usually means a hidden
   column or a `SELECT *` on a table with hidden columns).
4. **Slowest query** and **total rows** across `ok` lines (`-r` is unknown, not zero; `500r` means the
   row cap was hit).
5. Empty output: say the log (`~/.peephole/audit.jsonl`) is empty, no lease has been used yet.

**Do not echo SQL that contains literals that look like PII**: phone numbers, email addresses, names, long
hex/base64 tokens, card or id numbers. The audit log stores SQL as sent, so these literals are in the
file; keep them out of the transcript. Describe the query instead: "a query on users filtering by
phone", "a lookup on api_keys by key_hash". SQL with only ids, dates, statuses and counts may be
quoted, and the `<- reason` text is always safe to quote. When unsure, describe.

Read-only: this command never runs `peephole open`/`close`, never edits `audit.jsonl`, and never
re-runs a query from the log.
