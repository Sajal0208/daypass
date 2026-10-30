# X thread (6 posts)

Character counts are for the text inside each block, without the trailing newline, with
every URL (including the `<SITE_URL>` placeholder) counted as 23 characters, which is what
X charges for any link. Limit is 280. Replace `<SITE_URL>` before posting.

## 1 (pitch, attach the GIF) — 272 chars

```
We let Claude Code read our production Postgres. Not by pasting a URL into a config.

daypass open prod --ttl 45m --reason "debug campaign 1234"

Read-only. PII columns hidden by the database. Every query logged. The door shuts on its own.

Open source, MIT. Thread. [GIF]
```

## 2 (layer: the role) — 276 chars

```
The wall is the DB role, not the client.

daypass_ro: default_transaction_read_only, 10 s statement timeout, 1 s lock timeout, 5 connections, SELECT on visible columns only.

A column REVOKE does nothing while the role holds table-level SELECT. Our first draft got that wrong.
```

## 3 (layer: credentials) — 272 chars

```
No stored password.

On RDS the role logs in with a 15-minute IAM token minted from your own AWS login. TLS is always verified and RDS targets pin the AWS RDS CA.

Lose AWS access, lose Daypass access. With per-person IAM identities, nothing to rotate when someone leaves.
```

## 4 (layer: the parser) — 264 chars

```
Before SQL leaves the laptop it goes through Postgres's own parser (libpg-query).

One statement. SELECT or EXPLAIN. No FOR UPDATE, SELECT INTO, EXPLAIN ANALYZE, pg_sleep, dblink, pg_read_file, set_config, nextval.

33 banned functions. 45 tests full of nasty SQL.
```

## 5 (layer: caps and audit) — 236 chars

```
Results are capped: 500 rows, 2 KB per cell, 1 MB total. One query cannot flood the model's context.

Every call writes one JSON line to ~/.daypass/audit.jsonl: who (AWS ARN), lease id, reason, SQL, rows, ms, allowed or blocked and why.
```

## 6 (link) — 260 chars (each URL counted as 23, as X does)

```
On a real production database: 52 hidden columns denied, writes blocked, lease expiry enforced. Postgres only for now.

npm install -g daypass
https://github.com/Sajal0208/daypass
<SITE_URL>

Find a hole? Email security@vocobase.com, not the issue tracker.
```
