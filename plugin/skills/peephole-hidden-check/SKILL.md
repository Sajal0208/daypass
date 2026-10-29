---
name: peephole-hidden-check
description: Use when the user runs /peephole:peephole-hidden-check <target> to verify the Peephole hidden-columns list against a live database schema after a migration.
disable-model-invocation: true
argument-hint: "<target>"
---

# Peephole hidden check

`$ARGUMENTS` is the target name from `~/.peephole/config.json`; ask for it if missing. Run with Bash:

```bash
peephole hidden check --file "${PEEPHOLE_HIDDEN_FILE:-$HOME/.peephole/hidden-columns.txt}" --live <target>
```

No lease is needed. Exit 0 prints `hidden list matches the schema (...)`: report it and stop. Exit 1
prints up to two lists; explain each and propose the fix, as text only (`#` to end of line is a comment
on any line of the file):

- **`Listed (hidden or !allowed) but not in the schema (n):`** — renamed or dropped columns. They stop
  `peephole sql` (`hidden column "x" does not exist`). Propose removing each line, or renaming it to the
  new column when the migrations next to the list (the repo that owns the schema) show the rename.
- **`Sensitive-looking but not hidden (n):`** — new columns whose name looks like PII or a credential.
  For each, propose the exact line to append: `table.column` to hide it, or `!table.column  # <why>` when
  the user says it is fine (an IP, an object path, a config key). Default to hiding when unsure and
  offer the `!` form as the alternative.

Then show the re-apply command the user runs after editing the file, as the database owner
(`$OWNER_URL` is the owner connection string; Peephole never stores it):

```bash
peephole sql --hide-file "${PEEPHOLE_HIDDEN_FILE:-$HOME/.peephole/hidden-columns.txt}" | psql -X "$OWNER_URL" -1 -v ON_ERROR_STOP=1
```

Never edit the hidden list file and never run `peephole sql` or `psql` yourself: both change what the
production role can read. If the file is missing (`ENOENT`), point at
`peephole hidden suggest --live <target> > <file>` and the review checklist in `docs/hidden-columns.md`.
Report any other error (unknown target, connection refused, exit code other than 0/1) verbatim.
