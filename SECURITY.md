# Security policy

Daypass exists to put a wall between an AI agent and a production database. A hole in that
wall matters more than any other bug.

## Reporting a vulnerability

Please **do not open a public issue** for anything that could let an agent read a hidden column,
run a write, bypass a lease, escape the timeouts or leak a credential.

Email **security@vocobase.com** with:

- what you found and how to reproduce it (SQL, config, versions),
- what an attacker could do with it.

You will get a reply within 3 working days. We aim to ship a fix within 14 days for anything
that weakens the read-only guarantee, and we will credit you in the changelog unless you prefer
not to be named.

## Scope

In scope: the `daypass` package, `sql/setup-role.sql`, the MCP server and CLI.

Out of scope: your own database configuration (e.g. forgetting to list a column in the hidden
list), weaknesses in Postgres or AWS themselves, and denial of service against your own database
by running many expensive `SELECT`s (that is what `statement_timeout` and `CONNECTION LIMIT` are
for; tune them).

## Design notes for reviewers

The database role is the wall; everything in the client is a second fence. If you can show that
`daypass_ro`, set up by `setup-role.sql`, can read a hidden column or write anything, that is a
critical issue even if the client would have blocked the statement.

Known limits are listed in `docs/threat-model.md`.
