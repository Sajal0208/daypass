# Peephole docs

Peephole gives an AI coding agent temporary, read-only, audited access to a Postgres database. A human opens a lease from the terminal; for that time Claude Code (or any MCP client) can run `SELECT`s through a small set of tools; then the door shuts on its own. These guides cover setup, the safety layers, and what to do when something fails. The [package README](../README.md) covers installation, the one-time database setup and the MCP tools.

## Guides

- [Quickstart](quickstart.md): install, create the role, connect Claude Code, open a lease, ask a question. Five minutes.
- [Concepts](concepts.md): lease, guard, role, audit, result caps. What each one does and where it lives.
- [AWS RDS](aws-rds.md): IAM login without a password, the IAM policy, the per-lease IP rule, the sweep cron.
- [Other Postgres](other-postgres.md): password role, your own CA, Supabase, Neon, Railway, local dev.
- [Threat model](threat-model.md): which layer stops which threat, and what is not covered.
- [Hidden columns](hidden-columns.md): choosing, generating, applying and re-checking the list of columns the agent never sees.
- [Prisma check](prisma-check.md): keep the hidden list honest against `schema.prisma` in your own CI.
- [Troubleshooting](troubleshooting.md): every `peephole doctor` check and every MCP tool message, with the fix.
- [FAQ](faq.md): read replicas, other MCP clients, MySQL, cost, expiry mid-query, revoking everything.
- [Claude Code plugin](plugin.md): install from the marketplace, the `peephole` and `peephole-setup` skills, the three commands, the PII guard hook and its limits, the evals.

## Also in the repo

- [Security policy](../SECURITY.md): how to report a way past the wall.
- [Design](plans/2026-10-28-peephole-design.md): why it is built this way.
