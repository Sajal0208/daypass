# Contributing

Thanks for helping. Daypass is small on purpose; please keep it that way.

## Setup

```bash
git clone https://github.com/Sajal0208/daypass && cd daypass
npm install
npm test                           # unit tests, no database needed; rebuilds dist/ first when it is stale
npm link                           # `daypass` on your PATH, pointing at dist/
```

End-to-end against a real Postgres (Docker is easiest):

```bash
docker run --rm -d --name pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
npm run build                      # ci-integration.sh runs dist/cli/main.js and does not build it
DAYPASS_CI_OWNER_URL=postgres://postgres:postgres@localhost:5432/postgres scripts/ci-integration.sh
```

The script creates and drops schemas, tables and roles, so it reads its own variable,
`DAYPASS_CI_OWNER_URL`, and ignores the `OWNER_URL` the user docs have you export for a real
database. Every host the URL names (the host part, `host=` / `hostaddr=` parameters, comma
lists) must be `localhost`, `127.0.0.1` or `::1`, or it refuses to start. Point it only at a
throwaway container. (`DAYPASS_CI_ALLOW_REMOTE=1` lifts the host check for a disposable remote
server; never use it against a database you care about.)

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
- **Merges are squash-only.** Every change arrives through a pull request, CI
  (`build + unit tests (node 20)`, `build + unit tests (node 22)`,
  `role SQL + doctor + MCP against real Postgres`, `no private identifiers`) must be green, and
  the PR is squash-merged. The PR title becomes the commit message on `main`, so it has to be a
  valid conventional-commit line. (A ruleset that enforces this is still pending, see
  *Maintainer setup* below; until then it is a rule we follow, not one GitHub enforces.)
- **No private identifiers, anywhere in history.** `scripts/scrub-check.sh` runs in CI on the
  working tree, the index and the PR's commits. With `SCRUB_HISTORY=1` it scans every commit
  reachable from *any* ref (local branches, remote-tracking branches, tags and the latest stash
  entry; older stash entries are not scanned) plus annotated tag messages, and names the ref
  each hit came from. Before pushing a new
  branch, run `SCRUB_HISTORY=1 scripts/scrub-check.sh` and make sure no hit comes from a commit
  you are about to push. Hits from refs you are not pushing (an old local backup branch, a stale
  remote-tracking branch) do not block your push, but delete those refs when you can: the full
  scan only passes once every ref on your machine is clean, and on a maintainer's clone it does
  not pass yet (see the clean-up note under *Maintainer setup*).

## Releasing (maintainers)

Releases are cut by [release-please](https://github.com/googleapis/release-please). Nobody runs
`npm version`, `npm publish` or pushes a tag by hand (`v0.1.0` was the one exception).

1. Merge PRs to `main` with conventional-commit titles (PRs are squash-merged, so the PR title
   is the commit message that counts).
2. release-please (`.github/workflows/release-please.yml`) keeps a `chore(main): release x.y.z`
   PR open. It bumps `package.json`, `.release-please-manifest.json` and writes a
   `## [x.y.z](compare-url) (date)` section in `CHANGELOG.md` from the commits since the last tag.
3. Keep the *Unreleased* bullets short. While the release PR is open, move any *Unreleased*
   bullets into the generated section by committing to `main`; release-please regenerates the
   PR on every push to `main` and force-pushes it, so do not hand-edit the PR branch.
   release-please inserts its section directly under `# Changelog`, so after each release
   move the empty `## Unreleased` heading back to the top.
4. Get CI green on the release PR. It is opened with the workflow token, which does not trigger
   `pull_request` workflows, so the required checks never appear by themselves: close the PR and
   reopen it (the reopen counts as your event and runs CI), then squash-merge it.
5. Merging creates the `vx.y.z` tag and the GitHub release and dispatches
   `.github/workflows/release.yml` on the tag. Its `build` job (read-only token, no publish
   credential) checks that the tag matches `package.json`, builds, runs the tests, packs the
   tarball, installs it into an empty directory and runs `daypass --version` and
   `daypass sql --role daypass_smoke_role` from it (what users will install is tested, not the
   checkout), then uploads the tarball with its sha256.
6. Approve the publish. The `publish` job runs in the `npm-publish` GitHub environment, which
   has a required reviewer and only admits `v*` tags, so the run waits
   under *Actions* until a maintainer approves it. It runs no repository or dependency code: it
   downloads the tarball, checks the sha256, and runs
   `npm publish <tarball> --provenance --access public` using **npm trusted publishing** (OIDC):
   npm trusts this repository's `release.yml` running in the `npm-publish` environment and
   issues a short-lived credential for that run. The workflow uses no npm token. `npm stage` /
   staged publishing is **not** used. A last `release-notes` job fills in the GitHub release
   notes.

If a publish has to be redone (a flaky test, an approval that timed out), re-run `release.yml`
from the *Actions* tab with the tag as the ref; it refuses to run on anything that is not a tag
matching `package.json`.

Pre-1.0 semantics are on (`bump-minor-pre-major`, `bump-patch-for-minor-pre-major`): a `feat`
bumps the minor, a `fix` the patch, and a `!` / `BREAKING CHANGE` bumps the minor, not the
major.

### Maintainer setup

Done:

1. GitHub: the `npm-publish` environment exists with a required reviewer and a deployment policy
   that only admits tags matching `v*`, so every publish waits for a maintainer's approval.

Check (believed set up, not yet proven by a release):

1. npmjs.com: the package trusts `release.yml` in this repository, running in the `npm-publish`
   environment (*Settings* > *Trusted Publisher* > GitHub Actions, user `Sajal0208`, repository
   `daypass`, workflow `release.yml`, environment `npm-publish`). The first OIDC publish is the
   proof; until then, confirm it on npmjs.com.
2. GitHub: *Settings* > *Actions* > *General* > "Allow GitHub Actions to create and approve pull
   requests" is on (release-please opens the release PR with the workflow token).

Pending, in this order:

1. Delete the `NPM_TOKEN` repository secret (left over from the first release workflow, which
   used it) and revoke that token on npmjs.com.
2. npmjs.com: set the package's publishing access to "require two-factor authentication and
   disallow tokens", so trusted publishing is the only way to publish.
3. GitHub: a branch ruleset on `main`: pull request required, the four CI checks above
   required, no force-push or deletion. The Claude Code plugin installs from `main`, so this
   protects plugin users too.
4. GitHub: a tag ruleset on `v*` so only maintainers can create, move or delete release tags.
5. GitHub: *Settings* > *Security* > enable private vulnerability reporting (SECURITY.md offers
   it next to email), and secret scanning with push protection and Dependabot security updates.

Clean-up for the full history scan (`SCRUB_HISTORY=1`): delete local backup branches made
before the history was squashed, and delete the remaining `dependabot/*` branches on `origin`
(their PRs are already closed; some were cut from the pre-squash history, and their
`refs/pull/<n>/head` stay fetchable until GitHub Support removes them). Then
`git fetch --prune origin` so stale remote-tracking refs stop being scanned.

Already in place: every action in `.github/workflows/` is pinned to a commit SHA with a
`# vX.Y.Z` comment, and Dependabot (`.github/dependabot.yml`, `github-actions` ecosystem)
proposes pin updates.

## Code of conduct

See `CODE_OF_CONDUCT.md`. Be kind; assume good faith.
