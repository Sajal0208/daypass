# daypass <VERSION>

Security release. Temporary, read-only, audited Postgres access for AI coding agents. A human
opens a lease; Claude Code (or any MCP client) gets `SELECT`-only tools until it expires.

**If you ran 0.1.0: upgrade, then re-run the role setup and `daypass doctor`.** A review on
2026-10-30 found that the 0.1.0 role setup left hidden columns readable through views,
materialized views, partitions, inheritance children and `SECURITY DEFINER` functions that
touch them, that a writing `SECURITY DEFINER` function let the role change data in a direct
session, that the role could reset its own timeouts and read-only default, that
`daypass doctor` could not detect a misconfigured role, and that one large `SELECT` could
crash the MCP server before it wrote an audit line. This release fixes those. The full list
is in `CHANGELOG.md`.

```bash
npm install -g daypass@<VERSION>
daypass sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1
daypass open <target> --ttl 15m --reason "verify upgrade" && daypass doctor <target>
```

Expect the re-run to stop on things 0.1.0 let through (a `SECURITY DEFINER` function the role
can execute, a view over a hidden column you listed, a column hidden on a child only); each
message says what to do.

## What changed

- **Role setup.** Grants are explicit, per relation, in the schemas you list
  (`--schemas`); no bulk grants and no default privileges, so a table created later is
  invisible until you re-run. Views and materialized views that would expose a hidden column
  are withheld and named; partitions and children inherit the hidden column; generated
  columns derived from one must be listed. The self-check fails on any write privilege (from
  any grantor), an executable `SECURITY DEFINER` function (unless
  `--allow-definer-functions`), owned objects, membership in another role, anything readable
  outside the schemas, and the unpatched CVE-2024-4317 views. Opt-in
  `--revoke-public-temp` / `--revoke-public-create`. Hidden entries accept
  `schema.table.column` and quoted identifiers.
- **`daypass doctor`** checks the role in the catalog: settings drift, write privileges,
  `CREATE`, owned objects, membership, other schemas, the hidden list the setup stored on the
  role (`--hide-file` adds one), definer functions, and (a warning) every other function the
  role can execute.
- **MCP server.** Each call runs in `BEGIN READ ONLY` with a timeout of min(10 s, lease time
  left), over the extended protocol, then `DISCARD ALL`. Rows and bytes are cut in the
  database (500 rows, 1 MB); 32 MiB wire cap; SQL over 256 KiB refused; cut-off calls are
  cancelled in Postgres.
- **Audit.** A `start` line before each call and an `end` line after it, paired by `callId`;
  `server` lines for caught crashes and transport close. `daypass log` shows one row per call.
- **Guard.** Data-modifying CTEs refused; more banned functions (all advisory-lock and
  large-object functions, `query_to_xml` and the other SQL-from-a-string functions,
  `setseed`, several extensions); `EXPLAIN (ANALYZE false)` and trailing comments accepted.
- **TLS and network.** URL targets on `*.rds.amazonaws.com` pin the bundled RDS CA too. IPv6
  callers get a `/128` rule.
- **Plugin.** The PII hook also covers `explain`, tokenizes SQL the way Postgres does, blocks
  `SELECT *`, whole-row references and SQL-from-a-string functions, and fails closed on
  Claude Code 2.1.295 or later.

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
  commands can read `~/.daypass/config.json` and edit the lease and audit files.
- **The audit file can hold PII.** It stores the SQL text, and `WHERE phone = '...'` is
  SQL text.
- **Shared IAM identity.** The audit `who` is the AWS caller ARN. If your team shares one
  AWS login, the log cannot tell teammates apart.
- **A column you forgot to list is not hidden.** `daypass hidden suggest` and
  `daypass hidden check` reduce the chance; they read names, not values.
- **Reads hit whatever host you configure.** On a primary, the 10 s timeout and the
  5-connection cap are the only load protection; point the target at a replica if you can.
- **Postgres only.** PostgreSQL 16 or newer is recommended (the guard parses with the 16+
  grammar).

## Reporting a hole

See `SECURITY.md`: a private GitHub vulnerability report, or email security@vocobase.com.
Please do not open a public issue for anything that lets an agent read a hidden column, run
a write, bypass a lease, escape the timeouts or leak a credential.

Links: https://github.com/Sajal0208/daypass · https://www.npmjs.com/package/daypass ·
<SITE_URL>

MIT. Built by Vocobase.
