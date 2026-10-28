# Contributing

Thanks for helping. Peephole is small on purpose; please keep it that way.

## Setup

```bash
git clone https://github.com/Sajal0208/peephole && cd peephole
npm install
npm run build && npm test          # unit tests, no database needed
npm link                           # `peephole` on your PATH, pointing at dist/
```

End-to-end against a real Postgres (Docker is easiest):

```bash
docker run --rm -d --name pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
OWNER_URL=postgres://postgres:postgres@localhost:5432/postgres scripts/ci-integration.sh
```

## Rules of the road

- **The database role is the wall.** Anything that touches `sql/setup-role.sql` needs a line in
  the PR saying how you proved the role still cannot write or read hidden columns
  (`scripts/ci-integration.sh` does this; extend it).
- **Guard changes need tests.** Add the SQL you are allowing or blocking to `test/guard.test.ts`.
  When in doubt, block.
- **No new dependencies without a reason** in the PR. The install footprint matters for a tool
  people put next to their prod credentials.
- **Postgres first.** MySQL etc. are welcome as a follow-up once the Postgres path is boring.
- Commit messages: `feat:`, `fix:`, `docs:`, `chore:`; add a `CHANGELOG.md` line under *Unreleased*.

## Releasing (maintainers)

```bash
npm version patch|minor      # bumps package.json, creates tag vX.Y.Z
git push && git push --tags  # .github/workflows/release.yml publishes to npm
```

## Code of conduct

See `CODE_OF_CONDUCT.md`. Be kind; assume good faith.
