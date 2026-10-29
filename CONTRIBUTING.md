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
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `perf:`, `docs:`, `chore:`, with an optional scope (`fix(guard): …`).
  The type decides the version bump and the changelog section, so pick it honestly. Add a
  `CHANGELOG.md` line under *Unreleased* when the change is worth a sentence a user would
  read; it is folded into the release notes at release time (below).

## Releasing (maintainers)

Releases are cut by [release-please](https://github.com/googleapis/release-please). Nobody runs
`npm version` or pushes a tag by hand (except once, for `v0.1.0`, see below).

1. Merge PRs to `main` with conventional-commit titles (PRs are squash-merged, so the PR title
   is the commit message that counts).
2. release-please keeps a `chore(main): release x.y.z` PR open. It bumps `package.json`,
   `.release-please-manifest.json` and writes a `## [x.y.z](compare-url) (date)` section in
   `CHANGELOG.md` from the commits since the last tag.
3. Keep the *Unreleased* bullets short. While the release PR is open, move any *Unreleased*
   bullets into the generated section by committing to `main`; release-please regenerates the
   PR on every push to `main` and force-pushes it, so do not hand-edit the PR branch.
   release-please inserts its section directly under `# Changelog`, so after each release
   move the empty `## Unreleased` heading back to the top.
4. Merge the release PR. release-please creates the `vx.y.z` tag and the GitHub release, then
   dispatches `.github/workflows/release.yml` on the tag, which runs build + tests, checks the
   tag matches `package.json`, publishes to npm with provenance, and fills in the release
   notes. The release PR itself does not trigger CI (it is opened with the default token), so
   merge it only when `main` is green.

Pre-1.0 semantics are on (`bump-minor-pre-major`, `bump-patch-for-minor-pre-major`): a `feat`
bumps the minor, a `fix` the patch, and a `!` / `BREAKING CHANGE` bumps the minor, not the
major.

The release-please workflow is a no-op while the repository is private. The first public
release, `v0.1.0`, is tagged by hand (`git tag v0.1.0 && git push --tags`); release-please
finds that tag and takes over from the next merge.

## Code of conduct

See `CODE_OF_CONDUCT.md`. Be kind; assume good faith.
