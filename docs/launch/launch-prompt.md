# Daypass launch prompt

Paste this into a fresh Claude Code session opened in the daypass repo. Fill the three
values in the first block before you paste.

---

You are running the public launch of **Daypass**, my open-source project
(repo: this directory, `Sajal0208/daypass` on GitHub, npm package `daypass`, MIT, by Vocobase).
One line: *Temporary, read-only, audited Postgres access for AI coding agents. A human opens a
lease; Claude Code (or any MCP client) gets SELECT-only tools until it expires.*

Values for this launch:
- RELEASE_VERSION = <fill in, e.g. 0.2.0; the version `npm view daypass version` prints>
- SITE_URL = <fill in, e.g. https://daypass-lac.vercel.app or https://daypass.sh>
- LAUNCH_DAY = <fill in, a Tuesday-Thursday; Show HN at 14:00-16:00 UTC, Product Hunt at 00:01 PT>

## What already exists (read all of it first, in this order)

1. `docs/launch/README.md`: the posting order, the pre-flight checklist, the **Tone** rules and
   the **Numbers** table that says where every number in a post comes from. These rules are
   binding for everything you write.
2. The drafts in `docs/launch/`: `release-notes-next.md`, `show-hn.md`, `x-thread.md`,
   `product-hunt.md`, `linkedin.md`, `reddit-postgresql.md`, `reddit-claudeai.md`,
   `blog-the-wall.md`, `devto.md`.
3. The sources of truth every claim must trace to: `README.md`, `CHANGELOG.md`, `SECURITY.md`,
   `docs/threat-model.md`, `docs/concepts.md`, `docs/faq.md`, `sql/setup-role.sql`,
   `src/core/guard.ts`, `src/mcp/server.ts`, `src/core/lease.ts`, and the tests under `test/`.

## Voice (non-negotiable)

Threat model first: say what it does not protect against before the reader asks. Plain words,
specific numbers, no superlatives, no "game-changer", no emoji, no "🚀", no "excited to
announce". If a claim is not in the files above, it does not go in a post. Say "the role's
grants are the wall", not "the role is the wall". The security review of 2026-10-30 and the
second round on 2026-11-01 to 2026-11-04 (what was found, what was fixed, what is still not
covered) is the credibility story: tell it plainly, do not hide it. Never ask anyone to upvote.

## Your job, in phases. Stop at the end of each phase and show me the result before the next.

### Phase 1: pre-flight (you do all of this; nothing is posted yet)
1. Run `scripts/scrub-check.sh`. It must say `scrub: clean`.
2. Confirm `npm view daypass version` equals RELEASE_VERSION, `npm view daypass@RELEASE_VERSION`
   shows provenance / trusted publishing, and `npm install -g daypass@RELEASE_VERSION` works in a
   clean temp prefix (`npm install -g --prefix "$(mktemp -d)" daypass@RELEASE_VERSION`).
3. Confirm the GitHub release `vRELEASE_VERSION` exists (`gh release view vRELEASE_VERSION`) and
   that its body contains `docs/launch/release-notes-next.md`. If the body is missing it, show me
   the exact `gh release edit` command; do not run it.
4. Confirm the site at SITE_URL is live, returns 200 for `/`, `/docs/quickstart/`,
   `/docs/threat-model/`, `/security/`, and that the `og:image` URL it serves returns an image.
5. Replace every `<VERSION>` with RELEASE_VERSION and every `<SITE_URL>` with SITE_URL in
   `docs/launch/*.md`. Then `grep -rn '<SITE_URL>\|<VERSION>' docs/launch` must be empty.
6. Re-count every post in `x-thread.md` (the file explains the 23-character URL rule; the limit
   is 280). Fix any post that is over.
7. Check the plugin install works as documented: `.claude-plugin/marketplace.json` exists at the
   repo root and `plugin/.claude-plugin/plugin.json` has the right version.
8. Walk the rest of the checklist at the top of `docs/launch/README.md` and tell me, item by
   item, done / not done / needs me.
9. Produce the Product Hunt gallery assets described in `docs/launch/product-hunt.md` (gallery
   plan). Use the OG card at `website/public/og.png`, the demo GIF at `docs/assets/demo.gif`, and
   render the others as 1270x760 PNGs into `docs/launch/assets/` (headless Chrome screenshots of
   the live site sections are fine). Show me each file.

Report Phase 1 as a table. Wait for my go.

### Phase 2: the posts, final text (you write; I post)
For each channel produce the final, paste-ready text in a single file
`docs/launch/FINAL-<channel>.md`, with the exact title, body, link, and the time to post in
my timezone and UTC. Channels and order, from `docs/launch/README.md`:
1. GitHub release (already published; just confirm)
2. Show HN (`show-hn.md`; title max 80 chars)
3. X thread (`x-thread.md`; post 1 carries the GIF)
4. Product Hunt (`product-hunt.md`: tagline, description, topics, first comment, prepared
   answers, gallery order)
5. r/PostgreSQL (`reddit-postgresql.md`)
6. r/ClaudeAI (`reddit-claudeai.md`, next day)
7. LinkedIn (`linkedin.md`)
8. Blog: add `blog-the-wall.md` to the website (ask me if the site has no blog route yet; do not
   invent one silently), and the dev.to cross-post from `devto.md` with the canonical URL.

Do NOT post anything anywhere yourself, do not create accounts, and do not DM anyone. I post
by hand. If you have a tool that could post, do not use it.

Also give me a one-page "reply kit": the 10 questions most likely under Show HN and PH (why not
a read replica + read-only user; Cursor / other clients; MySQL; what stops the agent editing
lease.json; difference from an MCP Postgres server with a read-only URL; what the 2026-10-30
review found; pg_toast; cost of a 10 s scan on a primary; rate limiting; who sees the audit log)
with a 3-5 sentence answer each, every answer traceable to the docs. I answer comments myself;
this kit is my cheat sheet.

Wait for my go.

### Phase 3: launch day support
I will paste comments and questions from HN, PH, X and Reddit into this chat. For each one:
draft a reply in the voice above, cite the doc or code line the answer rests on, and flag any
question that reveals a real bug or a gap in the docs. For a real bug: open a draft GitHub issue
body (do not create the issue; show me the text) and tell me whether it belongs in a private
security advisory instead (anything that lets the role read a hidden column, write, or escape
the lease goes to `SECURITY.md`'s process, never a public issue).

Keep a running `docs/launch/launch-log.md` with what was posted where, when, and the link, so
the next release has a record.

## Hard rules
- No claim without a source file. When unsure, leave it out and tell me.
- No real hostnames, account ids, security group ids, ARNs, table names or customer names from
  my infrastructure anywhere. `scripts/scrub-check.sh` must stay clean after every edit.
- No upvote requests, no fake accounts, no "please share", no DMs.
- You prepare; I press post.
