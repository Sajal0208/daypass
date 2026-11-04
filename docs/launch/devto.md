# dev.to cross-post of "The wall"

The article body is `blog-the-wall.md`, unchanged; do not maintain a second copy here. This
file holds only the dev.to front matter and the short intro that goes above the article on
dev.to, so a reader who lands there knows where the original lives.

Publish the blog post on the website first (the canonical URL must resolve before dev.to
indexes the cross-post), then on dev.to a day or two after the Show HN. Keep
`published: false` on the first save and read the preview; dev.to renders the `jsonc` block
in the article as plain `json`, which is fine.

## Front matter

```yaml
---
title: We gave Claude read access to prod. Here is the wall we built.
published: false
description: Temporary, read-only, audited Postgres access for AI coding agents, and the two drafts of the role setup that were wrong.
tags: postgres, security, ai, opensource
canonical_url: https://daypass-lac.vercel.app/blog/the-wall/
cover_image: https://daypass-lac.vercel.app/og.png
---
```

Four tags is dev.to's maximum. `cover_image` is the site's Open Graph card
(`website/public/og.png`, 1200×630). `canonical_url` points at the website copy; the site
must publish the post at exactly that path, or change both.

## Intro (above the article)

```
This post first appeared on the Daypass site at https://daypass-lac.vercel.app/blog/the-wall/. Daypass is open source under MIT (https://github.com/Sajal0208/daypass, `npm install -g daypass`): temporary, read-only, audited Postgres access for AI coding agents. A human opens a lease; Claude Code (or any MCP client) gets SELECT-only tools until it expires. What follows is the design, the two drafts of the database role that were wrong, and what the tool does not protect against. If you find a way past the role, SECURITY.md in the repo says how to report it privately.
```

## Body

Paste the body of `blog-the-wall.md` from its first `##` heading onward, below the intro.
The article's own italic lead (`_Daypass is open source under MIT…_`) is covered by the intro
above, so leave it out. The site URL in the article is already filled in.
