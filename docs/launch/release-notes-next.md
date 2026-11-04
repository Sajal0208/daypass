# daypass 0.2.0

Security release. Temporary, read-only, audited Postgres access for AI coding agents. A human
opens a lease; Claude Code (or any MCP client) gets `SELECT`-only tools until it expires.

**Upgrade, re-run the role setup, then run `daypass doctor`.** A review on 2026-11-01 found
gaps in the role setup and in `daypass doctor`, in the client-side guard and the plugin hook,
and in how the CLI handles its own files. Under some setups a hidden column's values, or data
only the database owner could see, were reachable by the read-only role; several of the
checks that should have caught that did not. This release closes them. The role's grants
remain the wall; most fixes are in the setup script, so they take effect only after you
re-run it.

```bash
npm install -g daypass@0.2.0
export OWNER_URL='postgres://owner:...@db.example.com:5432/app'
daypass sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
daypass open <target> --ttl 15m --reason "verify upgrade" && daypass doctor <target>
```

Expect the re-run to stop on grants an earlier version accepted; each message names what to
revoke. If you use the Claude Code plugin, update it too (`/plugin marketplace update daypass`,
then `/plugin update daypass@daypass`) and restart Claude Code.

## What changed

- **Role setup.**
  - Removes `SUPERUSER`, `REPLICATION` and `BYPASSRLS` from the role if set, and stops with the
    `ALTER ROLE` to run when it is not allowed to.
  - Refuses column-level `INSERT` / `UPDATE` grants (to the role or `PUBLIC`), foreign servers
    the role can reach (server or wrapper `USAGE`, user mappings), default privileges that give
    `PUBLIC` new tables, sequences or schemas, and system-catalog grants beyond a fresh
    cluster's.
  - Withholds more materialized views: any whose stored rows depended on the owner's rights
    (reading a catalog view that filters by caller, a table with row-level security, or a
    function that is not a plain immutable built-in), followed through the views it reads.
  - On RDS with PostgreSQL 16 or newer, grants `rds_iam` `WITH INHERIT FALSE, SET FALSE`
    (login only) and narrows an older grant. Before 16 it requires `rds_iam` to hold nothing.
  - Withholds plain views (at any depth) over a table with row-level security, unless they are
    `security_invoker` (PostgreSQL 15+), and views over a relation the role is not granted.
  - The materialized-view walk also follows operators, row comparisons, type conversions,
    subscripts and domain checks; extension functions withhold the view.
- **`daypass doctor`** has new checks: `files` (owner, mode, links of the state files),
  `audit log` (unreadable lines, a warning), `tls` (a disabled-TLS RDS target fails and skips
  the database checks), `rds_iam`, `foreign servers`, `default privileges`, `catalog grants`,
  `materialized views`, `views as owner`, and `other databases` (a warning: databases on the
  server the role can connect to, which the setup does not cover). It reports `REPLICATION` /
  `BYPASSRLS` and column-level write grants under `write blocked`. `daypass hidden check`
  lists the views the setup withholds, with the same rules.
- **Guard.** Banned functions are also caught in attribute notation (`(x).f`, `t.f`). A column
  whose name matches a banned function is refused when written qualified; write it
  unqualified. An input the guard cannot check is refused instead of throwing.
- **Results.** Each cell is now cut to 2000 characters in the database, and the 1 MB budget
  counts the cut rows, so a row with one huge value comes back with that cell cut instead of
  as a cut JSON preview. A row still over the budget is left out with a note; the
  `daypass_truncated_row` placeholder is gone. Repeated
  and integer-like column names are kept and renamed (`count_2`, `_1`) with a note.
  `json`/`jsonb` values keep every digit, and a `json` value with `\u0000` comes back as text
  instead of failing the query. An `explain` plan is not cut per cell. Database errors are cut at 2000
  characters and labelled as data, since they can echo values.
- **MCP server.** One database connection per process (the role's 5-connection limit is shared
  by every session), closed after 5 idle seconds, with a clear message when the limit is full.
  IAM tokens are minted per connection and reused for up to 10 minutes. A call fails about
  5 s after its timeout if the database stops answering, and the next call reconnects. The
  server exits when its client goes away. `describe_table` lists columns in table order with full type names and
  says so when a table is missing; `list_tables` shows an unknown row estimate as `null`.
- **Files and leases.** `~/.daypass` and its files must be yours, not symlinks, not hard
  linked and regular files; looser modes are tightened with a warning. The lease is written
  atomically under a lock file (`.lease.lock`) and records the security group its rule was
  created in, so `close` and expiry cleanup revoke it there even if the config changed, and
  only if the rule's description is still the one Daypass wrote. Expiry cleanup waits at most
  10 s for AWS. A corrupt lease is reported (`daypass close` removes it). `daypass
  open` exits 1 when that target already has a live lease. Audit fields are capped, a long statement is
  stored as a prefix plus its SHA-256, and `daypass log` escapes control characters and skips
  unreadable lines with a warning. `daypass log -n` takes positive integers only.
- **AWS.** `daypass sweep` removes only rules whose description is exactly the one Daypass
  writes. `close` and the MCP server's expiry cleanup now call
  `ec2:DescribeSecurityGroupRules` too: **add it to the IAM policy of everyone who opens leases
  with the IP rule** (docs/aws-rds.md has the policy). TLS cannot be turned off for an RDS or
  IAM target, in any AWS partition; outside the commercial partition set `sslCa`, since the
  bundled CA covers commercial regions only.
- **CLI.** `daypass hidden suggest|check` takes the owner URL from an environment variable
  (`--url-env`, default `DAYPASS_OWNER_URL`) or stdin (`--url -`), and warns when a password is
  passed on the command line. IPv6 hosts and percent-encoded database names in URLs work.
- **Plugin.**
  - A new state guard hook keeps Claude from running `daypass open` or `daypass mcp` and from
    reading or writing `~/.daypass` and the hidden-columns list. It sees through common
    wrappers, `sh -c`, quoting, brace expansion and globs. Like the PII hook it fails closed;
    it matches command text, so variables and scripts get past it: a fence, not a wall.
  - The PII hook follows Postgres's scanner more closely, recognises more whole-row forms and
    newer whole-row functions, and blocks SQL-from-a-string functions in attribute notation.
  - The name heuristic (CLI and hook) reads plurals and run-together names (`secrets`,
    `emailaddress`).
  - The skills no longer read `config.json` or `lease.json`, and never write the hidden list.
- **Docs.** Set the role's password with `\password daypass_ro` in `psql`, not
  `ALTER ROLE ... PASSWORD` on the command line, which lands in shell history and the server
  log.

## Maintainer TODO before publishing

- Re-record `docs/assets/demo.gif` and `docs/assets/demo-output.txt` with
  `scripts/record-demo.sh`, then copy the text to `website/src/components/demo-output.txt`:
  the recording still shows the old `Query failed after N ms: …` line and no `SRV` line in
  `daypass log`.

## Known limits

Read these before you run it against anything you care about. The full list is
`docs/threat-model.md`.

- **The role's settings are defaults.** In a direct `psql` session with the role's password
  or token, the role can turn read-only off and lift its timeouts. It still has no write
  privilege on any table and cannot read a hidden column, but it can create temp tables and
  large objects. Through Daypass the client keeps the settings in place.
- **Functions the role can call.** Functions are `EXECUTE`-to-`PUBLIC` by default, and the
  guard's block list cannot cover every extension. `daypass doctor` lists what the role can
  execute; locking that down is yours to do.
- **The catalog is readable.** Hidden column names, and constants in defaults, constraints,
  index predicates and view text, are visible to the role. Values in hidden columns are not.
- **Your files are protected by your OS user only.** An agent you also allow to run shell
  commands can read `~/.daypass/config.json` and edit the lease and audit files. The plugin's
  state hook blocks the plain forms of that; it is not a security boundary.
- **The audit file can hold PII.** It stores the SQL text, and `WHERE phone = '...'` is
  SQL text.
- **Other databases on the server.** The setup covers one database; by default the role can
  connect to the others. `daypass doctor` lists them; `REVOKE CONNECT ON DATABASE <db> FROM
  PUBLIC` closes it.
- **Shared IAM identity.** The audit `who` is the AWS caller ARN. If your team shares one
  AWS login, the log cannot tell teammates apart.
- **A column you forgot to list is not hidden.** `daypass hidden suggest` and
  `daypass hidden check` reduce the chance; they read names, not values.
- **Reads hit whatever host you configure.** On a primary, the 10 s timeout and the
  5-connection cap are the only load protection; point the target at a replica if you can.
- **Postgres only.** PostgreSQL 16 or newer is recommended (the guard parses with the 16+
  grammar, and only 16+ can grant `rds_iam` for login only).

## Reporting a hole

See `SECURITY.md`: email security@vocobase.com, or a private GitHub vulnerability report once that is enabled.
Please do not open a public issue for anything that lets an agent read a hidden column, run
a write, bypass a lease, escape the timeouts or leak a credential.

Links: https://github.com/Sajal0208/daypass · https://www.npmjs.com/package/daypass ·
https://daypass-lac.vercel.app

MIT. Built by Vocobase.
