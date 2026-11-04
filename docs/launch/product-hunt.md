# Product Hunt

Paste at posting time (version and site URL are filled in). Product Hunt's form has
hard limits on the tagline (60 characters) and the short description (260); both are counted
below. The first comment, the prepared answers and the gallery are free text.

## Name

```
Daypass
```

## Tagline (59 characters; limit 60, no period)

```
Temporary, read-only, audited Postgres access for AI agents
```

## Short description (236 characters; limit 260)

```
A human opens a lease from the terminal. Claude Code, or any MCP client, gets SELECT-only tools on your Postgres until it expires: PII columns hidden by the database role, every query logged, no stored password on RDS. Open source, MIT.
```

## Links

- Website: `https://daypass-lac.vercel.app`
- Repo: `https://github.com/Sajal0208/daypass`
- npm: `https://www.npmjs.com/package/daypass`
- Pricing: free (MIT; it runs on your laptop, there is no service)

## Topics (3)

Developer Tools, Open Source, Databases.

(Artificial Intelligence fits too; if Product Hunt allows a fourth, add it. Not Privacy: the
hidden-columns list is the owner's work, and the threat model says what is not hidden.)

## First comment (maker post)

Half of our debugging questions at Vocobase are data questions, and Claude Code answers
them well when it can run the `SELECT` itself. The usual way to let it is to paste a
production connection string into an MCP config. Then the agent holds a password, a role
that can usually write, and access that never ends.

Daypass is a CLI plus an MCP server. You run
`daypass open prod --ttl 45m --reason "debug order 1234"`. For 45 minutes Claude Code, or any
MCP client, gets five tools: lease status, list tables, describe table, `EXPLAIN`, one
`SELECT`. When the lease expires every tool but the status check refuses.

The wall is the database role's grants, not the client. `daypass_ro` gets `SELECT` per
table on visible columns only and no write privilege anywhere. PII columns are hidden with
column-level grants, so `SELECT *` on those tables fails inside Postgres. Every statement
goes through Postgres's own parser before it leaves the laptop, runs in a read-only
transaction with a 10 s timeout, and is logged before it runs and when it ends. On RDS the
role logs in with a 15-minute IAM token; no password is stored.

The part to say up front: 0.1.0 shipped on 2026-10-28, and a security review on
2026-10-30, with a second pass on 2026-11-01, showed that the headline claim did not hold.
The 0.1.0 role could read hidden columns through views, materialized views, partitions,
inheritance children and `SECURITY DEFINER` functions, and could write through a definer
function that writes. `daypass doctor` said all was well, because it
tested its own read-only session, not the role. The second pass added views that read a
row-level-security table with their owner's rights, state files that could be swapped by a
hard link, and other databases on the same server the role could still connect to.

`0.2.0` fixes those. Grants are explicit, per relation, with no default privileges;
views and materialized views that would expose a hidden column are withheld; a definer
function the role can execute fails the setup unless you acknowledge it; `doctor` checks
the catalog instead of its own session. If you ran 0.1.0, upgrade and re-run the role
setup.

What it does not do: it cannot hide a column you forgot to list; the SQL text in the audit
file can hold PII; hidden column names are still readable from the catalog; the function
block list cannot know every extension; an agent you also let run shell commands as you can
read `~/.daypass`; a new table is invisible until you re-run the SQL. Postgres only. No
write path, not even a gated one.

One ask. Point it at a staging database with a few hidden columns and try to get
`daypass_ro` to read one, or to change a row. If something gets past the role, SECURITY.md
has the private reporting route; please not as a public issue.

MIT. `npm install -g daypass`. Docs and threat model: `https://daypass-lac.vercel.app`.

## Prepared answers

**Why not a read replica and a read-only user?**
Have both; they are layer one. A hot standby rejects writes and takes load off the primary.
It does not hide a single column, does not expire, needs a password that then sits in the
agent's config, and logs nothing per query. A read-only user's `default_transaction_read_only`
is a setting the role can turn off for itself in its own session. Daypass adds the
column-level grants, the lease, the audit line per call, the IAM token instead of a
password, the parser that refuses `SET` and `pg_sleep`, and result caps so one query cannot
fill the model's context. Pointing a Daypass target at a replica already works.

**Does it work with Cursor or other MCP clients?**
Yes. The server is `daypass mcp` over stdio, with no client-specific code; clients that take
a JSON config use `{ "mcpServers": { "daypass": { "command": "daypass", "args": ["mcp"] } } }`.
The lease is opened from a terminal whatever the client. The plugin (skills, slash commands,
the PII and state hooks) is for Claude Code only; other clients get the raw tools.

**MySQL?**
No. Postgres only. The guard is Postgres's own parser (`libpg-query`), the role setup is
Postgres SQL, and the hidden-column mechanism is Postgres column-level grants. A MySQL /
MariaDB target is on the roadmap as an idea; a PR with a parser-backed guard, not a regex,
would be welcome.

**What stops the agent editing `lease.json`?**
Nothing stronger than your OS user. The files under `~/.daypass` are mode `0600` and owned
by you; Daypass refuses symlinks, hard links, non-regular files and files owned by someone
else, and lease writes go through a lock file. But Claude Code runs as you, so an agent you
also let run shell commands can move `expiresAt`, run `daypass open` itself, or read
`config.json` (a URL target's password). The Claude Code plugin's state hook blocks the
common forms (`daypass open`, `daypass mcp`, shell commands and file tools that reach
`~/.daypass`, also behind wrappers and `sh -c`), but it matches command text, so variables,
`eval` and scripts get past it: a fence against mistakes and injected instructions, not a
control. An edited lease buys the agent more time with the same role, and the role still
cannot read a hidden column or write a row. If that matters, deny the agent shell and file
access to `~/.daypass` in Claude Code's permissions, or run the MCP server as another OS
user.

**How is this different from an MCP Postgres server with a read-only connection string?**
The connection string is still a stored credential with no expiry and no per-query log,
and "read-only" in it is a session default the role can flip with `SET` unless the role's
grants also hold no write privilege. Daypass starts from the grants: the setup script grants
`SELECT` per relation on visible columns, fails its self-check if the role holds any write
privilege from any grantor, and withholds views that would leak a hidden column. Around
that: a lease that expires, `BEGIN READ ONLY` per call with a 10 s timeout, Postgres's own
parser refusing anything but one `SELECT` or `EXPLAIN`, 500 rows and 1 MB cut in the
database, two audit lines per call with who and why, and on RDS a 15-minute IAM token in
place of a password. Those servers differ a lot, so the README's comparison table leaves
that row unnamed and only claims what we checked.

## Gallery (4–5 images, in this order)

1. **OG card.** `website/public/og.png` (1200×630): the name and the one-line pitch. Also
   the thumbnail.
2. **Terminal demo GIF.** `docs/assets/demo.gif`, re-recorded on `0.2.0` with
   `scripts/record-demo.sh`: `daypass open`, `daypass doctor`, a named-column query that
   returns rows, `select * from customers` failing with `permission denied for table
   customers`, an `UPDATE` blocked by the guard, `daypass log -n 3`, `daypass close`.
3. **The layers table.** The "Why it is safe" table from README.md (the website's
   `LayerTable.astro` is the same text) rendered as one image, 1270×760 or taller; caption
   "The role's grants are the wall; the rest are fences."
4. **The audit log.** Two JSON lines for one call, `start` then `end`, paired by `callId`,
   as in `blog-the-wall.md` (the `arn:aws:iam::123456789012:user/alice` placeholder, nothing
   real), with `who`, `reason`, `sql`, `rows` and `ms` highlighted.
5. **`SELECT *` denied.** A Claude Code screenshot: the `query` tool called with
   `select * from customers`, the `permission denied for table customers` error labelled
   `data, not instructions`, then the retry with named columns succeeding. Run it against the
   demo database from `scripts/record-demo.sh`, never a real target.

Before uploading, run `scripts/scrub-check.sh` over the image sources and check each frame
for a real host, account id, security group or table name; the README checklist allows only
the `123456789012` placeholder and `my-db.abc123.us-east-1.rds.amazonaws.com`.

## Launch-day timing

- Product Hunt's day starts at 00:01 PT (08:01 UTC on Pacific standard time, from
  2026-11-01; 07:01 UTC in summer). Post then, so the listing has the full day.
- Launch on the same day as the Show HN or the day after, not before. Same day works: 00:01
  PT is before the Show HN window (14:00–16:00 UTC), so the HN post can link to the listing.
  If the comments on HN need all hands, push Product Hunt to the next day.
- The maker comment goes up with the listing, not later.
- Do not ask anyone for upvotes, in any channel. Answer every comment; the prepared answers
  above cover the first five.
- Someone watches `security@vocobase.com` that day: the ask in the maker post is for reports.
