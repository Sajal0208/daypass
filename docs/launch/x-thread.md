# X thread (7 posts)

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

## 2 (layer: the role) — 250 chars

```
The wall is the DB role's grants, not the client.

daypass_ro: SELECT table by table on visible columns, no write privilege, no default privileges.

A column REVOKE does nothing while the role holds table-level SELECT. Our first draft got that wrong.
```

## 3 (the second wrong draft) — 255 chars

```
Then a review after 0.1.0: hidden columns leaked through views, partitions and SECURITY DEFINER functions, and the role could reset its own timeouts.

The next release withholds those views, fails setup on definer functions, and doctor checks the catalog.
```

## 4 (layer: credentials) — 267 chars

```
No stored password.

On RDS the role logs in with a 15-minute IAM token minted from your own AWS login. TLS is always verified; RDS hosts pin the AWS RDS CA.

Lose AWS access, lose Daypass access. With per-person IAM identities, nothing to rotate when someone leaves.
```

## 5 (layer: the parser) — 242 chars

```
Before SQL leaves the laptop it goes through Postgres's own parser (libpg-query).

One SELECT or EXPLAIN, in a read-only transaction. No data-modifying CTE, FOR UPDATE, SELECT INTO, EXPLAIN ANALYZE, pg_sleep, dblink, set_config, query_to_xml.
```

## 6 (layer: caps and audit) — 236 chars

```
Results are cut in the database: 500 rows, 1 MB. One query cannot flood the model's context or the server.

Every query is logged to ~/.daypass/audit.jsonl before it runs and when it ends: who (AWS ARN), lease id, reason, SQL, rows, ms.
```

## 7 (link) — 221 chars

```
Postgres only for now. Known limits are in the threat model, first.

npm install -g daypass
https://github.com/Sajal0208/daypass
<SITE_URL>

Find a hole? SECURITY.md has the private reporting route, not the issue tracker.
```
