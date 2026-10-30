# Daypass plugin for Claude Code

Temporary, read-only, audited production-database access for Claude Code. The plugin
bundles the Daypass MCP server and adds skills, commands and a hook on top of it. What
Daypass is and how to set up the database role: the [main README](../README.md).

## Requirements

The plugin runs `daypass mcp`, so the `daypass` command must be on `PATH`:

```bash
npm install -g daypass
daypass init            # then edit ~/.daypass/config.json and run the role setup
```

## Install

From the marketplace, inside Claude Code:

```
/plugin marketplace add Sajal0208/daypass
/plugin install daypass@daypass
```

From a shell:

```bash
claude plugin marketplace add Sajal0208/daypass && claude plugin install daypass@daypass
```

For local development, from a checkout of this repo:

```bash
claude --plugin-dir ./plugin
```

If you also registered the server by hand with `claude mcp add daypass`, remove it
(`claude mcp remove daypass`): the plugin already bundles the server, and keeping both
gives Claude two copies of every tool.

## What the plugin adds

The bare MCP server gives Claude five tools: `daypass_status`, `list_tables`,
`describe_table`, `explain`, `query`. The plugin adds:

| Piece | What it does |
|---|---|
| `daypass` skill | How to answer a data question safely: check the lease first, name columns, `explain` before scanning a big table, keep PII out of the reply, end with the lease id and reason. Triggers on questions that need production data. |
| `daypass-setup` skill | Walks a first-time user through config, the hidden-columns list, the role setup SQL and the first lease. |
| `/daypass:daypass-status` | Is a lease open, on which target, how long is left. |
| `/daypass:daypass-log` | The last audit entries: who, why, what SQL, rows, ms. |
| `/daypass:daypass-hidden-check` | Compares `hidden-columns.txt` with the schema and reports drift. |
| PII guard hook | `PreToolUse` on `query`: before the SQL leaves Claude Code it pulls every identifier out of the statement, ignoring string literals and comments, checks each against the same name heuristic `daypass hidden suggest` uses, and blocks the call when one looks like personal or secret data and the hidden-columns list says nothing about it. |
| Evals | Scenarios under `evals/` that check the skills behave as documented (no lease, lease open, hidden column). |

## Daily use

```bash
daypass open staging --ttl 45m --reason "why did signups drop on Monday"
# ask Claude the question; it uses the tools until the lease expires
daypass log --last 20
daypass close
```

With no lease open, every tool except `daypass_status` answers
*"No active Daypass lease. Ask the user to run: daypass open …"*, and the skill replies
with the exact `daypass open` line to run.
