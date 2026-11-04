# Prisma check

If your schema lives in `prisma/schema.prisma`, Daypass's own test suite can check your hidden list against it: every listed column (hidden or `!` allowed) must exist, and every column whose name looks like a phone, email, secret, token, password hash or transcript must be hidden or allowed. The test is skipped unless two environment variables point it at your files, so it costs nothing in Daypass's own CI and runs in yours when you want it to. The same check is also available as `daypass hidden check`.

## Run it by hand

From a checkout of the Daypass repo:

```bash
DAYPASS_HIDDEN_FILE=/path/to/app/hidden-columns.txt \
DAYPASS_PRISMA_SCHEMA=/path/to/app/prisma/schema.prisma \
npm test
```

The test, `test/hidden-columns.test.ts`, uses the same core functions as the CLI (`parsePrismaColumns`, `parseHiddenFile`, `diffHidden` from `src/core/hidden.ts`): it parses `model` blocks, honours `@@map` and `@map` so it compares database names rather than Prisma field names, scans every scalar field of every model (relation fields are skipped), understands `!` allow lines, and reports in two assertions:

- `every hidden or allowed column exists in the schema`: fails with the list of entries that no longer match a column. These would stop `daypass sql | psql` with `hidden column "…" does not exist`.
- `every sensitive-looking column is hidden or allowed`: fails with the list of columns whose name matches the sensitive pattern but is on neither a hidden nor a `!` line.

Fix the list, or, for a false positive, record the decision as an allow line (`!servers.address`, see [Hidden columns](hidden-columns.md)); both the test and `daypass hidden check` then stop flagging it.

Without the variables, `npm test` reports those two tests as skipped.

## The same check from the CLI

The installed package exposes the same logic without a checkout:

```bash
daypass hidden check --file hidden-columns.txt --prisma prisma/schema.prisma
```

It prints the `Listed (hidden or !allowed) but not in the schema` and `Sensitive-looking but not hidden` lists, plus `Columns both hidden and !allowed`, and exits 1 if any is non-empty. `--live <target>` and `--url-env OWNER_URL` do the same against a running database instead of the Prisma file, which also catches tables that were created outside Prisma, generated columns derived from a hidden column, columns hidden on a partition or child only, and (for information) the views the setup will withhold. See [Hidden columns](hidden-columns.md).

## In your app's CI

Add a job to the repo that owns the schema and the hidden list. It needs Node 20+ and nothing else. The CLI form is the shortest; save it as `.github/workflows/daypass-hidden.yml`:

```yaml
name: daypass hidden list
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
      - run: npm install -g daypass
      - run: daypass hidden check --file hidden-columns.txt --prisma prisma/schema.prisma
```

If you prefer the vitest form (for example to pin Daypass's version through a lockfile), check out Daypass as a second repository and run its `npm test` with the two variables set to absolute paths in your checkout.

The job tells you the list is out of date. It does not apply anything. After it passes, someone with owner rights still has to run `daypass sql --hide-file hidden-columns.txt | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1` against each database.

## What the heuristic matches

Column names, never values. The heuristic is `looksSensitive` in `src/core/hidden.ts`; [Hidden columns](hidden-columns.md#generate-a-first-draft) lists the words, the special names, the safe tails and the always-flagged exceptions. The list is shared by the test and the CLI. A column named `metadata`, `payload`, `body` or `notes` is flagged as free text; a phone number inside a column called `data` or `raw` is not found.
