# LinkedIn

One post from the maker's own account, plain text, no hashtags beyond the two at the end.
LinkedIn cuts the preview after about 210 characters, so the first line carries the claim.
Limit 1300 characters; the count below is for the text inside the block, with `https://daypass-lac.vercel.app`
counted as 23 characters (LinkedIn shows the link in full; the count is conservative).
Version (0.2.0) and site URL are filled in. Post it the same day as the Show HN,
after it is up, and link the HN thread in a comment rather than in the post.

## Post (1291 characters; limit 1300)

```
We let Claude Code read our production Postgres. Not by pasting a connection string into an MCP config.

I open a lease from the terminal: daypass open prod --ttl 45m --reason "debug order 1234". For 45 minutes Claude Code (or any MCP client) gets five read-only tools. Then the door shuts on its own.

The wall is the database role's grants, not the client: SELECT per table on visible columns, no write privilege anywhere, PII columns hidden by column-level grants, so SELECT * on those tables fails in Postgres. Every statement goes through Postgres's own parser, runs in a read-only transaction with a 10 s timeout, and is logged before it runs and when it ends. On RDS the role logs in with a 15-minute IAM token; no password is stored.

The honest part: a security review after 0.1.0 found hidden columns readable through views, partitions and SECURITY DEFINER functions, and doctor could not tell. 0.2.0 fixes that. If you ran 0.1.0, upgrade and re-run the role setup.

What it does not cover comes first in the threat model: a column you forgot to list, PII in the audit file's SQL text, an agent you also let run shell commands reading ~/.daypass. Postgres only.

MIT, by Vocobase. If you get daypass_ro past the role, SECURITY.md has the private route.

https://daypass-lac.vercel.app
```
