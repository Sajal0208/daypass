# Support

Daypass is maintained by a small team at Vocobase. Support is best effort, but a clear report
gets a quick answer.

## Where to ask

| You have | Go to |
|---|---|
| A question (how do I, does it work with, is this expected) | [GitHub Discussions](https://github.com/Sajal0208/daypass/discussions) |
| A bug (it does not do what the docs say) | [New issue](https://github.com/Sajal0208/daypass/issues/new/choose), using the *Bug* template |
| An idea | [New issue](https://github.com/Sajal0208/daypass/issues/new/choose), using the *Feature request* template, or a Discussion |
| Anything that weakens the wall (hidden column readable, a write goes through, a lease bypass, a leaked credential) | **Not an issue.** See [SECURITY.md](SECURITY.md) and email security@vocobase.com |

## What to include

The more of this you paste, the fewer round trips:

1. `daypass --version`, plus Node version, OS, and Postgres version (RDS or plain).
2. The output of `daypass doctor <target>`. It prints hostnames and your AWS identity; redact
   them (replace with `db.example.com`, `arn:aws:...`) before posting.
3. For a blocked or failed query: the audit line for that call from `~/.daypass/audit.jsonl`
   (`daypass log --last 5` shows the recent ones). It carries the SQL, the verdict and the
   error, which is usually enough to see what happened. Redact anything in the SQL you would
   not paste in public.
4. What you expected instead.

Never paste a connection URL with a password, an IAM token, or a real security-group id.

## What to expect

- Discussions and issues: best effort, usually within a few days. Smaller, reproducible
  reports get looked at first.
- Security reports: a reply within 3 working days and a fix target of 14 days for anything
  that weakens the read-only guarantee, as set out in [SECURITY.md](SECURITY.md).
- Pull requests: see [CONTRIBUTING.md](CONTRIBUTING.md). A PR that touches the guard or the
  role SQL needs a line on how you proved the agent still cannot write or read hidden columns.

There is no paid support plan and no SLA. If you need one, open a Discussion and say so;
demand is how the roadmap gets decided.
