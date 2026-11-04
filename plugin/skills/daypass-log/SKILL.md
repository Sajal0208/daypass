---
name: daypass-log
description: Use when the user runs /daypass:daypass-log to summarise the recent Daypass audit log (what the agent queried, what was blocked, what failed).
disable-model-invocation: true
argument-hint: "[N]"
---

# Daypass log

`$ARGUMENTS` is an optional count N. Run exactly one of these with Bash (the CLI rejects a bare
`-n`, so never pass an empty argument):

```bash
daypass log -n 20              # when $ARGUMENTS is empty
daypass log -n "$ARGUMENTS"    # when the user gave a number
```

If `$ARGUMENTS` is anything other than a whole number, do not put it on the command line: use
`-n 20` and say so.

`daypass log` prints one row per call: the server writes a start and an end line for each allowed
call, and the CLI pairs them by call id into one row at the start time with the end's result.
`-n N` counts rows (calls), not raw audit lines. The row kinds:

- `<at> <ok|ERR|BLK> <who> <target> <tool> <rows>r <ms>ms  <sql>  <- <reason>`: a finished call
  (`ok`), a call that failed in the database (`ERR`), or a refusal that never reached it (`BLK`,
  one line, no start/end pair). `-r`/`-ms` mean unknown; SQL is cut at 120 chars.
- `<at> RUN  <who> <target> <tool> -r -ms  <sql>  <- unfinished: no end line yet (still running, or the server stopped mid-call)`:
  a start with no end in the log. Either the call is still running or the server died mid-call;
  the log cannot tell which, so say both.
- `<at> SRV  <who> <target or -> server  <- <error>`: a server event, not a query (for example an
  uncaught error). It has no table, rows or SQL.

Say when fewer than N rows exist. Report, in this order:

1. **Queries per table**: every `ok`, `ERR`, `BLK` and `RUN` row, with the table parsed from the SQL
   (`FROM x`, `JOIN y`, `UPDATE x`, `DROP TABLE x`; aliases stripped); `list_tables`/`describe_table`
   calls count under their tool name.
2. **Blocked (`BLK`)**: one line each with the `<- reason` (guard refusal: not a SELECT, two statements,
   lease expired, ...).
3. **Errors (`ERR`)**: one line each with the `<- reason` (`permission denied` usually means a hidden
   column or a `SELECT *` on a table with hidden columns).
4. **Unfinished (`RUN`)**: one line each with its time and tool; if one is older than the role's statement
   timeout (10 s as set up), it did not finish and the server most likely stopped mid-call.
5. **Server events (`SRV`)**: one line each with the `<- error` text, if any.
6. **Slowest query** and **total rows** across `ok` rows (`-r` is unknown, not zero; `500r` means the
   row cap was hit).
7. Empty output: say the log (`~/.daypass/audit.jsonl`) is empty, no lease has been used yet.

**Do not echo SQL that contains literals that look like PII**: phone numbers, email addresses, names, long
hex/base64 tokens, card or id numbers. The audit log stores SQL as sent, so these literals are in the
file; keep them out of the transcript. Describe the query instead: "a query on users filtering by
phone", "a lookup on api_keys by key_hash". SQL with only ids, dates, statuses and counts may be
quoted. The `<- reason` text follows the same rule: a guard refusal (`not a SELECT`, `lease expired`)
may be quoted, but a database error can carry the values it choked on (`invalid input syntax for type
integer: "+49 151 ..."`, a failing key in `duplicate key value`), so describe those. When unsure,
describe.

Read-only: this command never runs `daypass open`/`close`, never reads or edits `audit.jsonl`
directly (only through `daypass log`), and never re-runs a query from the log.
