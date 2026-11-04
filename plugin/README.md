# Daypass plugin for Claude Code

Temporary, read-only, audited production-database access for Claude Code. The plugin
registers the Daypass MCP server (it runs the `daypass` command you installed with npm; it
does not ship one) and adds skills, commands and a hook on top of it. What
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
(`claude mcp remove daypass`): the plugin already registers the server, and keeping both
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
| PII guard hook | `PreToolUse` on `query` and `explain`: before the SQL leaves Claude Code it tokenizes the statement (quoting, dollar quoting, escapes and comments included), blocks `SELECT *`, `TABLE x`, column alias lists on tables, whole-row references, planner statistics and the functions that run SQL from a string or dump whole tables, and checks every identifier against the same name heuristic `daypass hidden suggest` uses, blocking the call when one looks like personal or secret data and the hidden-columns list says nothing about it. It fails closed. |
| State guard hook | `PreToolUse` on `Bash`, `Monitor` (which runs a command in the same shell as `Bash`) and the file tools (`Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Grep`, `Glob`): keeps Claude away from Daypass's own state. It blocks `daypass open` and `daypass mcp` from Bash (behind wrappers such as `sudo`, `sh -c`, `xargs` or `npx` too), shell commands that name `~/.daypass` or `$DAYPASS_HOME` (in any case, through quotes, brace expansion or a matching glob), writes to that directory or to `$DAYPASS_HIDDEN_FILE`, reading `config.json` or `lease.json`, and `Grep`/`Glob` over the directory. `daypass status`, `log`, `doctor`, `close`, `hidden` and `sql` stay allowed. It fails closed. |
| Evals | Scenarios under `evals/` that check the skills behave as documented (no lease, lease open, hidden column). |

## Daily use

```bash
daypass open staging --ttl 45m --reason "why did signups drop on Monday"
# ask Claude the question; it uses the tools until the lease expires
daypass log --last 20
daypass close
```

With no lease open, every tool except `daypass_status` answers
*"No active Daypass lease. Ask the user to run: daypass open …"* (or, after expiry,
*"Lease … expired at …. Ask the user to run: daypass open …"*), and the skill replies
with the exact `daypass open` line to run.

## When the hook blocks, and when it fails

The PII guard runs on every `query` and `explain` call. It blocks, with a one-line reason
Claude relays to you, when the SQL:

- selects `*` or `alias.*` anywhere (only `count(*)` is fine), uses `TABLE x`, or renames a
  table's columns by position with an alias list (`from users u(a, b, c)`): name the columns;
- uses a table or its alias as a whole row (`to_jsonb(u)`, `row_to_json(u)`, `(u).x`,
  `u::text`, `select u from users u`, `json_object('k' VALUE u)`, attribute notation such as
  `u.to_jsonb` or `u.any_value`): name the columns;
- calls `query_to_xml`, `table_to_xml`, `schema_to_xml`, `database_to_xml`, `xmltable`,
  `ts_stat`, `ts_rewrite`, their `*_xmlschema` / `cursor_to_xml` relatives, or the `dblink` /
  `crosstab` extension functions (also in attribute notation, `('select …').ts_stat`), which run
  SQL from a string or return whole rows the guard cannot inspect, or reads planner statistics (`pg_stats`, `pg_statistic`), which hold sample
  column values;
- has a `'...'` literal with a backslash before a quote whose end depends on
  `standard_conforming_strings`: write `''` or `E'...'`;
- names a column that looks like personal or secret data (`phone`, `email`, `token`, `ssn`,
  `card_number`, ...) and the hidden-columns list (`DAYPASS_HIDDEN_FILE`, else
  `$DAYPASS_HOME/hidden-columns.txt`, else `~/.daypass/hidden-columns.txt`) neither hides it
  nor lists it on a `!` allow line. The reason says which line to add.

It fails closed: no list file, an unreadable list, stdin that is not a tool call, a tool input
without a string `sql`, a crash or the 10 s timeout all block the call (`onFailure: block` in
`hooks/hooks.json`). The one switch is `DAYPASS_PII_HOOK=off` (also `false` or `0`) in the
environment Claude Code runs in, which lets everything through for that session.

It is name-based: a PII column with a name the heuristic does not know (`raw`, `data`,
`content`) is not flagged, `users.phone` in the list also covers `tickets.phone`, and a
user-defined function on a table's row type called as `u.f` is not recognised. The database role is the wall; the hook
is the fence in front of it.

The state guard is a fence of the same kind: it matches command text, so it stops mistakes
and injected instructions, not a determined shell command. It has no off switch. When it
blocks something you meant to do (opening a lease, editing the hidden list), run that command
in your own terminal; Claude prints it for you.
