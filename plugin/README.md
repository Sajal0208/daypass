# Peephole plugin for Claude Code

Temporary, read-only, audited production-database access for Claude Code. The plugin
bundles the Peephole MCP server and adds skills, commands and a hook on top of it. What
Peephole is and how to set up the database role: the [main README](../README.md).

## Requirements

The plugin runs `peephole mcp`, so the `peephole` command must be on `PATH`:

```bash
npm install -g peephole-db
peephole init            # then edit ~/.peephole/config.json and run the role setup
```

## Install

From the marketplace, inside Claude Code:

```
/plugin marketplace add Sajal0208/peephole
/plugin install peephole@peephole
```

From a shell:

```bash
claude plugin marketplace add Sajal0208/peephole && claude plugin install peephole@peephole
```

For local development, from a checkout of this repo:

```bash
claude --plugin-dir ./plugin
```

If you also registered the server by hand with `claude mcp add peephole`, remove it
(`claude mcp remove peephole`): the plugin already bundles the server, and keeping both
gives Claude two copies of every tool.

## What the plugin adds

The bare MCP server gives Claude five tools: `peephole_status`, `list_tables`,
`describe_table`, `explain`, `query`. The plugin adds:

| Piece | What it does |
|---|---|
| `peephole` skill | How to answer a data question safely: check the lease first, name columns, `explain` before scanning a big table, keep PII out of the reply, end with the lease id and reason. Triggers on questions that need production data. |
| `peephole-setup` skill | Walks a first-time user through config, the hidden-columns list, the role setup SQL and the first lease. |
| `/peephole:peephole-status` | Is a lease open, on which target, how long is left. |
| `/peephole:peephole-log` | The last audit entries: who, why, what SQL, rows, ms. |
| `/peephole:peephole-hidden-check` | Compares `hidden-columns.txt` with the schema and reports drift. |
| PII guard hook | Runs on every `query` result and warns when a column that looks like personal data or a secret came back, even though the database let it through. |
| Evals | Scenarios under `evals/` that check the skills behave as documented (no lease, lease open, hidden column). |

## Daily use

```bash
peephole open staging --ttl 45m --reason "why did signups drop on Monday"
# ask Claude the question; it uses the tools until the lease expires
peephole log --last 20
peephole close
```

With no lease open, every tool except `peephole_status` answers
*"No active Peephole lease. Ask the user to run: peephole open …"*, and the skill replies
with the exact `peephole open` line to run.
