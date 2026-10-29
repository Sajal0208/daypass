# Prisma check

If your schema lives in `prisma/schema.prisma`, Peephole's own test suite can check your hidden list against it: every listed column (hidden or `!` allowed) must exist, and every column whose name looks like a phone, email, secret, token, password hash or transcript must be hidden or allowed. The test is skipped unless two environment variables point it at your files, so it costs nothing in Peephole's own CI and runs in yours when you want it to. The same check is also available as `peephole hidden check`.

## Run it by hand

From a checkout of the Peephole repo:

```bash
PEEPHOLE_HIDDEN_FILE=/path/to/app/hidden-columns.txt \
PEEPHOLE_PRISMA_SCHEMA=/path/to/app/prisma/schema.prisma \
npm test
```

The test, `test/hidden-columns.test.ts`, uses the same core functions as the CLI (`parsePrismaColumns`, `parseHiddenFile`, `diffHidden` from `src/core/hidden.ts`): it parses `model` blocks, honours `@@map` and `@map` so it compares database names rather than Prisma field names, scans every scalar field of every model (relation fields are skipped), understands `!` allow lines, and reports in two assertions:

- `every hidden or allowed column exists in the schema`: fails with the list of entries that no longer match a column. These would stop `peephole sql | psql` with `hidden column "…" does not exist`.
- `every sensitive-looking column is hidden or allowed`: fails with the list of columns whose name matches the sensitive pattern but is on neither a hidden nor a `!` line.

Fix the list, or, for a false positive, record the decision as an allow line (`!servers.address`, see [Hidden columns](hidden-columns.md)); both the test and `peephole hidden check` then stop flagging it.

Without the variables, `npm test` reports those two tests as skipped.

## The same check from the CLI

The installed package exposes the same logic without a checkout:

```bash
peephole hidden check --file hidden-columns.txt --prisma prisma/schema.prisma
```

It prints the `Listed (hidden or !allowed) but not in the schema` and `Sensitive-looking but not hidden` lists and exits 1 if either is non-empty. `--live <target>` and `--url "$OWNER_URL"` do the same against a running database instead of the Prisma file, which also catches tables that were created outside Prisma. See [Hidden columns](hidden-columns.md).

## In your app's CI

Add a job to the repo that owns the schema and the hidden list. It needs Node 20+ and nothing else. The CLI form is the shortest; save it as `.github/workflows/peephole-hidden.yml`:

```yaml
name: peephole hidden list
on:
  pull_request:
    paths:
      - prisma/schema.prisma
      - hidden-columns.txt
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm install -g peephole-db
      - run: peephole hidden check --file hidden-columns.txt --prisma prisma/schema.prisma
```

If you prefer the vitest form (for example to pin Peephole's version through a lockfile), check out Peephole as a second repository and run its `npm test` with the two variables set to absolute paths in your checkout.

The job tells you the list is out of date. It does not apply anything. After it passes, someone with owner rights still has to run `peephole sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1` against each database.

## What the heuristic matches

Column names, never values. The heuristic, from `src/core/hidden.ts`, splits the name into snake_case parts (camelCase too: `phoneNumber` becomes `phone_number`) and flags it when a part is one of `phone`, `mobile`, `email`, `token`, `secret`, `key`, `transcript`, `password`, `passwd`, `address`, `ssn`, `iban`, `card`, `dob`, `birth`, `birthday`, `birthdate`, `salt`, `otp`, `pin`, `passport`, `license`, `licence`, `routing`, `national`, or when the name starts with `encrypted_` or is exactly `prompt_snapshot`, `lines` or `credentials`. A name ending in a safe tail is left alone: `_verified`, `_confirmed`, `_count`, `_used`, `_at`, `_id`, `_type`, `_status`, `_enabled`, `_required`, `_country`, `_layout`, `_limit`, `_prefix`, `_version`, `_expiry`, `_expires`, `_expiration`, `_rounds`, `_domain` (so `email_verified`, `phone_country`, `key_prefix` and `tokens_used` are not flagged). The exceptions that are always flagged despite the tail: `national`, `tax` or `government` followed by `_id` or `_number`, and `account_number` / `bank_account_number` (`account_id` is an ordinary foreign key and is not flagged). The list is shared by the test and the CLI. A phone number inside a `metadata` JSON column is found only if the column itself is named for it.
