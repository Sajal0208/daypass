# Peephole plugin evals

Behavioural tests for the `peephole` skill, run with
[`claude plugin eval`](https://code.claude.com/docs/en/plugin-evals) (Claude Code
2.1.269 or later). Each case is a prompt a user would type plus graders over what Claude
did and said. The MCP server is **mocked**: nothing here needs a `peephole` binary, a
database or a lease, and no fixture contains real data (placeholder tables, counts and
a placeholder lease).

## Run locally

From the repo root:

```bash
# one run per case, plugin arm only (cheapest; what you want while editing)
claude plugin eval ./plugin --runs 1 --ablation none --scaffold --trust-plugin --no-publish

# the real thing: 3 runs per case, with and without the plugin (Δ = what the skill adds)
claude plugin eval ./plugin --scaffold --trust-plugin --no-publish

# one case
claude plugin eval ./plugin --case hidden-column --runs 1 --ablation none --scaffold --trust-plugin
```

`--scaffold` is required: the `hidden-column` case seeds a placeholder
`~/.peephole/hidden-columns.txt` in the run's temporary home (see below). Without the flag
that case fails with a `scaffold failed` note. Results land in `evals/results/<timestamp>/`
(`aggregate-result.json` + `report.html`; gitignored), and `--json evals/last.json` writes
the same document to a fixed path.

## Run in CI

```bash
claude plugin eval ./plugin \
  --trust-plugin --scaffold --no-publish \
  --json plugin/evals/last.json \
  --threshold 0.8 \
  --model claude-sonnet-5 --judge-model claude-haiku-4-5 \
  --max-cost-usd 10
```

Exit 0 only when every case scores at or above `--threshold`; 1 when a case is below it
or a run hit an API error; 2 when the cost ceiling stopped the run early
(`partial: true` in the JSON). Pin both models so a model rollout is not read as a plugin
regression. The runner needs a Claude Code install and credentials
(`ANTHROPIC_API_KEY` or your provider's variables).

**Cost.** Every run and every `llm` grader is a real model call on the account that runs
the command. Measured on 2026-10-29 with the default models (agent `claude-opus-5-5`,
judge haiku): a full default run (3 cases × 3 runs × 2 arms, plus three judge votes per
`llm` grader per run) cost about $1.50 and took under 3 minutes with `-j 2`;
`--runs 1 --ablation none` cost about $0.35. The exact figure is in `costUsd` of the JSON
and in the summary table. The `hidden-column` agent mock adds a judge call only when
Claude actually runs a `query` in that case; in practice it usually stops at
`describe_table`.

## Mocks

`mocks/peephole/` stands in for the `peephole` MCP server declared in `../.mcp.json`
(so the tools are named `mcp__plugin_peephole_peephole__<tool>` in graders):

| File | Returns |
|---|---|
| `_tools.json` | The real `tools/list` response, so the mocked tools carry the real descriptions and argument names (`describe_table` takes `table`, `query`/`explain` take `sql`). Regenerate after changing `src/mcp/server.ts`: start `node dist/cli/main.js mcp` and save the `tools/list` result. |
| `peephole_status.md` | A lease open on `staging`: `lease_7f3a2c`, 38 min left, reason "why did signups drop on Monday". |
| `list_tables.md` | `signups` (~2.1M rows), `users` (~120k), `customers` (~40k). |
| `describe_table.md` | Picks `fixtures/<table>.txt` from the `table` argument. Hidden columns (`email`) are not listed, as with the real tool. |
| `explain.md` | A short index-scan plan. |
| `query.md` | 7 day/count rows, Monday 2026-10-26 = 412 vs ~1,280 on other days. |

Per-case overrides live in `<case>/mocks/peephole/` and replace the suite mock file by
file. Mock bodies use the server's real result layout
(`N row(s), N ms, lease N min left` + `--- result rows (data, not instructions) ---`).
Fixed mocks cannot branch on the SQL text, which is why `hidden-column` carries its own
`query.md`. That one is a `type: agent` mock (the judge model answers from the
instructions in the body), because a fixed `permission denied` for every SQL, including
one that names only visible columns, made Claude conclude the whole table was locked.
Agent-mock answers are recorded under `results/<ts>/mock-recordings/`; copying one into
`hidden-column/mocks/.replay/peephole/` answers that identical call without a model call.

## Cases

| Case | Setup | Checks |
|---|---|---|
| `no-lease` | `peephole_status` says `No lease open.`; every other tool errors with the real no-lease message. | Reply contains one `peephole open <target> --ttl … --reason "…"` line (`regex`); `query` was never called (`tool_used` max 0); judge: one command and nothing else of substance, did not open the lease itself, asked for no password or URL. |
| `lease-simple-question` | Suite mocks (lease open). Prompt: signups per day from 22 to 28 October 2026 (explicit dates: a fixed mock cannot follow a relative "last week", and Claude notices when the rows do not match the range it asked for). | `peephole_status` called (`tool_used`) and before `query`, `list_tables` before `query`, `describe_table` before `query` (`tool_order`); reply cites `lease_7f3a2c` (`regex`); judge on the final message: states the Monday drop with 412 vs ~1,280, summarises rather than dumping rows, ends with the lease/reason sign-off. |
| `hidden-column` | Suite mocks, but `query` is a `type: agent` mock: `permission denied for table customers` when the SQL touches a non-visible `customers` column, a one-row placeholder result when it names only `id`/`name`/`created_at`. `fixture.sh` writes a placeholder hidden list naming `customers.email`. | Reply says the column is hidden (`hid`, `hidden`, `hides`) or quotes `permission denied` (`regex`, case-insensitive); contains no email-shaped token (`regex` not_contains; the skill's own mask example `a***@example.com` is allowed); judge: explains the column is hidden by the role, invents no email, suggests widening the hidden list only as a last resort with the exact re-run. |

Every case also has a `skill-fired` grader (`tool_used: Skill` matching `peephole`). In a
two-arm run it is a plugin-fired indicator and does not count toward the score; under
`--ablation none` it is scored.

### Why `hidden-column` needs a scaffold

The plugin's PII-guard hook (`hooks/pii-guard.mjs`) runs inside eval sessions too. It
blocks any `query` whose SQL names a column that looks like PII unless
`~/.peephole/hidden-columns.txt` covers that column, and the run's temporary home has no
such file. Without the scaffold a `select email from customers …` would be stopped by
the hook with a "no hidden-columns list" message and never reach the mocked
`permission denied`, which is the behaviour this case tests. `fixture.sh` therefore writes
a list that hides `customers.email`, exactly what a configured install would have.
