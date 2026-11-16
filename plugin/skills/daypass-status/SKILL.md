---
name: daypass-status
description: Use when the user runs /daypass:daypass-status to see whether a Daypass lease is open, who holds it, on which target, and how long is left.
disable-model-invocation: true
---

# Daypass status

Run with Bash:

```bash
daypass status
```

The CLI prints `No lease.` or one line per lease; report each line as described (with several
lines, report each lease):

- `Lease <id> on "<target>" by <who>: <N> min left. Reason: <reason>` — a live lease. One line per
  field: lease id, target, who, reason, minutes left. Say the MCP tools (`query`, `explain`,
  `list_tables`, `describe_table`) work until it expires.
- `Lease <id> on "<target>" expired at <ISO>. Run: daypass close <target>` — expired. Tell the user
  to run that exact `daypass close <target>` line, then print the `daypass open` line exactly as in
  the next case.
- `No lease.` — print the exact line the user can paste. The target is a name from the conversation
  (ask the user when it is not there); the reason goes into every audit line, so it must say why,
  in one short phrase (`"why did signups drop on Monday"`, a ticket id):

  ```bash
  daypass open <target> --ttl 45m --reason "<why>"
  ```

  Fill `<target>` and `<why>` from the conversation when known; otherwise ask for them and print the line
  with placeholders. Keep `--ttl 45m` unless the user named a duration.

Never run `daypass open`, `daypass close` or any MCP tool from this command: opening a lease is the
user's decision, and the audit log records it under their identity. Never read `~/.daypass/config.json`
(URL targets keep the role's password in it) or `~/.daypass/lease.json`, and never write to
`~/.daypass/hidden-columns.txt`, least of all a `!table.column` allow line: the human edits that file. A failing `daypass status`
(command not found, config error) is reported verbatim with the hint `npm i -g daypass`.
