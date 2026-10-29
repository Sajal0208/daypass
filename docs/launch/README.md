# Launch material for peephole-db 0.1.0

Everything in this folder is a draft to paste at posting time. Nothing here is published
by itself.

## Before posting anything

- [ ] Replace every `<SITE_URL>` with the real website URL. `grep -rn '<SITE_URL>' docs/launch`
      must come back empty before you post.
- [ ] `scripts/scrub-check.sh` is clean, and a manual grep of `docs/launch` for security-group ids, 12-digit account ids and RDS hosts shows only the
      `123456789012` account placeholder and the README's own placeholder host
      `my-db.abc123.eu-central-1.rds.amazonaws.com`, or nothing. No real host, account,
      security group, ARN or internal table name goes into a post.
- [ ] `npm view peephole-db version` prints `0.1.0` and `npm install -g peephole-db` works on a
      clean machine.
- [ ] The GitHub release `v0.1.0` exists with `release-notes-v0.1.0.md` as its body.
- [ ] The Claude Code plugin installs with `/plugin marketplace add Sajal0208/peephole` then
      `/plugin install peephole@peephole`, and `claude plugin eval` passes all three cases.
- [ ] `peephole hidden suggest` runs against a Prisma schema and against a live catalog.
- [ ] The GIF for X post 1 is recorded: `peephole open`, one question in Claude Code, one
      `SELECT *` that fails on a hidden column, `peephole log`.
- [ ] `security@vocobase.com` is monitored. SECURITY.md promises a reply within 3 working days.
- [ ] Someone is free to answer comments for the first 6 hours after the Show HN goes up.

## Posting order

1. **GitHub release** `v0.1.0`: `release-notes-v0.1.0.md`. Do this first so every other post
   links to something that exists.
2. **Show HN**: `show-hn.md`. Tuesday to Thursday, 14:00–16:00 UTC. Title is 79 characters
   (HN's limit is 80; "for AI coding agents" would make it 86, so the title says "for AI
   agents"). Do not ask anyone to upvote.
3. **X thread**: `x-thread.md`, within an hour of the HN post. Post 1 carries the GIF.
4. **r/PostgreSQL**: `reddit-postgresql.md`, same day. It asks for a review of
   `sql/setup-role.sql`; be ready to act on what comes back.
5. **r/ClaudeAI**: `reddit-claudeai.md`, the next day, so the two Reddit posts do not compete.
6. **Blog**: `blog-the-wall.md` goes on the website at `<SITE_URL>`. Publish it before the Show HN
   if the site is ready, otherwise within the same week and link it from the HN thread.

## Tone

Threat model first. Say what the tool does not protect against before the reader has to
ask. No superlatives. If a claim is not in `README.md`, `CHANGELOG.md`, `SECURITY.md`,
`sql/setup-role.sql`, `src/core/guard.ts`, `test/guard.test.ts` or the design doc, it does not
go into a post.

## Numbers used in these posts and where they come from

| Claim | Source |
|---|---|
| 52 hidden columns denied, writes blocked, expiry enforced on a real production database | first production run, 2026-10-28 |
| 45 guard tests | `test/guard.test.ts` |
| 33 banned functions | `BANNED_FUNCTIONS` in `src/core/guard.ts` |
| 500 rows, 2 KB per cell, 1 MB per result | `DEFAULTS` in `src/mcp/server.ts`, README |
| 10 s statement timeout, 1 s lock timeout, 30 s idle-in-transaction, 256 MB temp files, 5 connections | `sql/setup-role.sql` |
| 15-minute IAM token | README, design doc |
| TTL between 60 s and 8 h | `parseTtl` in `src/core/lease.ts` |
| Reply within 3 working days, fix within 14 days | `SECURITY.md` |
