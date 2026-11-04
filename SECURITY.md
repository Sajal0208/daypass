# Security policy

Daypass exists to put a wall between an AI agent and a production database. A hole in that
wall matters more than any other bug.

## Supported versions

Only the latest minor line gets security fixes. Upgrade before reporting if you are behind.

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| anything older | No |

## Reporting a vulnerability

Please **do not open a public issue** for anything that could let an agent read a hidden column,
modify data in a table, bypass a lease, escape the timeouts or limits *through Daypass* (the MCP
server or CLI), or leak a credential. A direct `psql` session as the read-only role can change
its own session settings by design (`daypass doctor` reports that drift); that is only a bug
when it happens through Daypass.

- **Email** **security@vocobase.com**. This always works, and is the route to use if you are
  unsure.
- **GitHub private report** at
  <https://github.com/Sajal0208/daypass/security/advisories/new>, once private vulnerability
  reporting is switched on for the repository (it is being enabled). It keeps the report, the
  discussion and the fix in one place and lets us publish an advisory with a CVE when the fix
  ships. If the page shows no report form, use email.

Either way, include:

- what you found and how to reproduce it (SQL, config, versions),
- what an attacker could do with it.

You will get a reply within 3 working days. We aim to ship a fix within 14 days for anything
that weakens the read-only guarantee, and we will credit you in the changelog unless you prefer
not to be named.

## How releases are protected

`daypass@0.1.0` carries [npm provenance](https://docs.npmjs.com/generating-provenance-statements)
and was published by GitHub Actions with a long-lived npm token (the earlier workflow);
`npm audit signatures` verifies a download. Ignore `0.0.0-stage`: it is a leftover from testing
the publish flow, not a release.

Releases after 0.1.0 are meant to go out by npm trusted publishing (OIDC); the package page on
npmjs.com shows how each version was published. A SHA-pinned workflow builds and tests in one
job and publishes the checked tarball from a separate job that runs in the `npm-publish` GitHub environment, which requires a maintainer's approval and only admits `v*`
tags. The workflow holds no npm token. Retiring the token the earlier workflow used, and setting
npm to refuse token-based publishing, are still pending (see *Maintainer setup* in
CONTRIBUTING.md).

## Scope

In scope: the `daypass` package, `sql/setup-role.sql`, the MCP server and CLI, and the Claude
Code plugin hooks (`plugin/hooks/pii-guard.mjs`, `plugin/hooks/state-guard.mjs`). A bypass of
a hook is in scope, but the hooks are backup layers behind the role's grants (the state guard
matches command text and says so), so they are rated lower than a hole in the grants.

Out of scope: your own database configuration (e.g. forgetting to list a column in the hidden
list), weaknesses in Postgres or AWS themselves, and denial of service against your own database
by running many expensive `SELECT`s (that is what `statement_timeout` and `CONNECTION LIMIT` are
for; tune them).

## Design notes for reviewers

The role's grants are the wall; everything in the client is a second fence. `setup-role.sql`
guarantees that `daypass_ro` holds no INSERT, UPDATE, DELETE, TRUNCATE or TRIGGER on any
relation, no USAGE or UPDATE on any sequence (no `nextval`/`setval`), no SELECT on a hidden
column or table, owns no objects, is a member of no other role (on RDS, `rds_iam` for login
only), has no `SUPERUSER`, `REPLICATION` or `BYPASSRLS`, and can reach no foreign server (the
script refuses to run otherwise). If you can show that `daypass_ro` can read a hidden column or modify data in a
table, that is a critical issue even if the client would have blocked the statement.

It does not stop everything a direct session can do, by design: a `psql` session as the role can
create temporary tables (unless the owner revokes PUBLIC's TEMP, `--revoke-public-temp`, or never
grants it) and large objects (`lo_create` cannot be revoked per role), and can change its own
session settings. Those are documented limits, not vulnerabilities.

Known limits are listed in `docs/threat-model.md`.
