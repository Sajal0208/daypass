# Launch material for daypass

Everything in this folder is a draft to paste at posting time. Nothing here is published
by itself.

**Launch on the release after 0.1.0, not on 0.1.0.** 0.1.0 is published, but a security
review on 2026-10-30 found holes in its role setup (see `release-notes-v0.1.0.md` and
`CHANGELOG.md`). The posts describe the fixed release and refer to it as `<VERSION>`.

## Before posting anything

- [ ] The fixed release is out. Replace every `<VERSION>` with its version and every
      `<SITE_URL>` with the real website URL. `grep -rn '<SITE_URL>\|<VERSION>' docs/launch`
      must come back empty before you post.
- [ ] `scripts/scrub-check.sh` is clean, and a manual grep of `docs/launch` for security-group ids, 12-digit account ids and RDS hosts shows only the
      `123456789012` account placeholder and the README's own placeholder host
      `my-db.abc123.eu-central-1.rds.amazonaws.com`, or nothing. No real host, account,
      security group, ARN or internal table name goes into a post.
- [ ] `npm view daypass version` prints `<VERSION>` and `npm install -g daypass` works on a
      clean machine.
- [ ] The GitHub release `v<VERSION>` exists with `release-notes-next.md` as its body (or the
      release-please body with it appended), and the `v0.1.0` release body carries the
      superseded note from `release-notes-v0.1.0.md`.
- [ ] Nothing in a post claims the release came through npm trusted publishing unless the
      *Maintainer setup (pending)* steps in CONTRIBUTING.md are done.
- [ ] `docs/assets/demo.gif` and `docs/assets/demo-output.txt` are re-recorded with
      `scripts/record-demo.sh` on the fixed release (the 0.1.0 recording shows the old
      `doctor` output).
- [ ] The Claude Code plugin installs with `/plugin marketplace add Sajal0208/daypass` then
      `/plugin install daypass@daypass`, and `claude plugin eval` passes all three cases.
- [ ] `daypass hidden suggest` runs against a Prisma schema and against a live catalog.
- [ ] The GIF for X post 1 is recorded: `daypass open`, one question in Claude Code, one
      `SELECT *` that fails on a hidden column, `daypass log`.
- [ ] `security@vocobase.com` is monitored and GitHub private vulnerability reporting is
      on. SECURITY.md promises a reply within 3 working days.
- [ ] Someone is free to answer comments for the first 6 hours after the Show HN goes up.

## Posting order

1. **GitHub release** `v<VERSION>`: `release-notes-next.md`. Do this first so every other post
   links to something that exists.
2. **Show HN**: `show-hn.md`. Tuesday to Thursday, 14:00–16:00 UTC. Title is 78 characters
   (HN's limit is 80; "for AI coding agents" would make it 85, so the title says "for AI
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
`docs/threat-model.md`, `sql/setup-role.sql`, `src/core/guard.ts`, the tests under `test/` or
the design doc, it does not go into a post. Say "the role's grants are the wall", not "the
role is the wall": the role's settings are defaults it can change in a direct session.

## Numbers used in these posts and where they come from

| Claim | Source |
|---|---|
| 52 hidden columns denied, writes blocked, expiry enforced on a real production database | first production run, 2026-10-28, with the 0.1.0 script (it did not test views or definer functions; say so if you use it) |
| Banned function patterns (45 at the time of writing; the posts do not give a number) | `BANNED_FUNCTION_PATTERNS` in `src/core/guard.ts` |
| 500 rows, 1 MB per result (cut in SQL), 2000 characters per cell, 32 MiB on the wire | `DEFAULTS` in `src/mcp/server.ts`, `MAX_WIRE_BYTES` in `src/mcp/db.ts` |
| 256 KiB SQL limit | `MAX_SQL_BYTES` in `src/core/guard.ts` |
| 10 s statement timeout, 1 s lock timeout, 30 s idle-in-transaction, 256 MB temp files, 5 connections | `sql/setup-role.sql` |
| 15-minute IAM token | README, design doc |
| TTL between 60 s and 8 h | `parseTtl` in `src/core/lease.ts` |
| Reply within 3 working days, fix within 14 days | `SECURITY.md` |
