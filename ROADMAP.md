# Roadmap

Where Daypass is going, in rough order. No dates: items move when they are ready and when
people ask for them. Each item carries a status and, once scheduled, a
[milestone](https://github.com/Sajal0208/daypass/milestones).

Status words: **idea** (we would take a PR), **planned** (on a milestone, not started),
**in progress** (a branch exists).

## Now (0.1)

What ships today, so the rest of this page has a baseline.

- CLI: `daypass init | sql | open | status | close | sweep | log | doctor | mcp`.
- Five MCP tools: `daypass_status`, `list_tables`, `describe_table`, `explain`, `query`.
- Postgres only. Auth is an AWS RDS IAM token minted from your own AWS identity, or a
  connection URL / password for any other Postgres.
- The guard: Postgres's own parser, one statement, `SELECT` or `EXPLAIN` only, a block list of
  dangerous functions, no row locks, no `SELECT INTO`, no `EXPLAIN ANALYZE`.
- Caps: 500 rows, 2 KB per cell, 1 MB per result, 10 s statement timeout, read-only session.
- Audit: one JSON line per call in `~/.daypass/audit.jsonl`.
- Optional per-lease security-group rule for your current IP, removed on close or expiry.
- A Claude Code plugin that registers the MCP server and ships the usage skill.

## Next (0.2)

Milestone: [v0.2](https://github.com/Sajal0208/daypass/milestone/1).

- **`hidden suggest` improvements.** Emit schema-qualified names, so a column list from a
  database with more than one schema is unambiguous and applies cleanly. *Status: planned.*
- **MySQL / MariaDB target type.** The same lease, guard and audit over a second engine, with
  a parser-backed guard rather than a regex. *Status: idea.*
- **Read-replica target option.** Point a target at a replica while the lease, audit and
  hidden-column role stay exactly as they are; the replica is extra distance, not a
  replacement for the wall. *Status: idea.*
- **Audit to a Postgres table.** Write each audit line to a table in a database of your
  choosing as well as the local file, so a team can query who looked at what. *Status:
  planned.*
- **Per-query row-level masking.** Hash or partially mask visible columns at query time
  (`em***@example.com`), for columns that are needed for joins but not for reading. *Status:
  idea.*

## Later (1.0)

Milestone: [v1.0](https://github.com/Sajal0208/daypass/milestone/2).

- **Approval flow for `daypass open`.** A second person approves a lease from Slack (or a
  similar channel) before it goes live, with the reason and TTL in the message. *Status: idea.*
- **Hosted connector.** A small service that runs inside your network, connects outbound only,
  and keeps the database credential there; agents never hold it. *Status: idea.*
- **Audit dashboard.** Leases, queries, blocked statements and who ran them, across a team,
  in one place. *Status: idea.*
- **SSO.** Open leases with your identity provider instead of a local AWS login. *Status: idea.*

## Not planned

- Writes of any kind, even behind a flag. Daypass is the read-only path; use a different tool
  for migrations.
- Loosening the result caps by default. They exist to keep the model's context small.

## How to influence this

Open an issue with the `roadmap` label and say what you are trying to do, not just which item
you want. Items get pulled forward by people who need them; a PR for an item marked *idea* is
welcome, but say so in an issue first so nobody duplicates the work.
