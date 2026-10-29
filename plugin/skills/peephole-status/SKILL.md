---
name: peephole-status
description: Use when the user runs /peephole:peephole-status to see whether a Peephole lease is open, who holds it, on which target, and how long is left.
disable-model-invocation: true
---

# Peephole status

Run with Bash:

```bash
peephole status
```

The CLI prints exactly one of these; report it as described:

- `Lease <id> on "<target>" by <who>: <N> min left. Reason: <reason>` — a live lease. One line per
  field: lease id, target, who, reason, minutes left. Say the MCP tools (`query`, `explain`,
  `list_tables`, `describe_table`) work until it expires.
- `Lease <id> on "<target>" expired at <ISO>. Run: peephole close` — expired. Tell the user to run
  `peephole close`, then print the `peephole open` line exactly as in the next case.
- `No lease.` — print the exact line the user can paste. The target is a name from the conversation
  (`~/.peephole/config.json` lists them); the reason goes into every audit line, so it must say why,
  in one short phrase (`"why did signups drop on Monday"`, a ticket id):

  ```bash
  peephole open <target> --ttl 45m --reason "<why>"
  ```

  Fill `<target>` and `<why>` from the conversation when known; otherwise ask for them and print the line
  with placeholders. Keep `--ttl 45m` unless the user named a duration.

Never run `peephole open`, `peephole close` or any MCP tool from this command: opening a lease is the
user's decision, and the audit log records it under their identity. A failing `peephole status`
(command not found, config error) is reported verbatim with the hint `npm i -g peephole-db`.
