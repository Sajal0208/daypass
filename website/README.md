# Peephole website

The site and docs for [`peephole-db`](https://github.com/Sajal0208/peephole), built with
[Astro](https://astro.build) and [Starlight](https://starlight.astro.build), styled with
Tailwind 4. It is its own npm project; the root `npm test` and `npm run build` do not touch it,
and it is excluded from the published npm tarball.

## Run it

```bash
cd website
npm install
npm run dev        # http://localhost:4321
npm run build      # static output in dist/
npm run preview    # serve dist/ locally
npm run check      # astro check (TypeScript + content schema)
```

Node 22.23.4 or newer (Astro 7's requirement).

## How docs get in

Nothing under `src/content/docs/docs/` is written by hand. `scripts/sync-docs.mjs` runs before
every `dev` and `build` (`predev` / `prebuild`) and copies the repo's Markdown in:

| Source (repo root)   | Page            |
| -------------------- | --------------- |
| `docs/README.md`     | `/docs/`        |
| `docs/<name>.md`     | `/docs/<name>/` |
| `CHANGELOG.md`       | `/changelog/`   |
| `SECURITY.md`        | `/security/`    |
| `ROADMAP.md`         | `/roadmap/`     |
| `SUPPORT.md`         | `/support/`     |
| `docs/assets/*`      | `/assets/*`     |

Only the top level of `docs/` is synced; `docs/plans/` and other subfolders stay in the repo.
For each file the first `# Title` becomes the page title, the first paragraph becomes the meta
description, and relative links (`quickstart.md`, `../SECURITY.md`, `assets/demo.gif`, …) are
rewritten to site URLs. Links to files that have no page here (`../README.md`,
`../CONTRIBUTING.md`, source files) go to GitHub. Each page's "Edit page" link points at its
Markdown source in the repo.

Missing sources are skipped with a notice, so the site builds on a checkout with no docs at
all. The generated files are git-ignored; edit the source Markdown instead. The sidebar order
of guides is the `GUIDE_ORDER` list in the script; unknown guides follow alphabetically.

`DOCS_SRC=<dir> npm run sync-docs` points the script at another directory laid out like the
repo root (for testing the sync itself).

`src/content/docs/index.mdx` is the landing page and is committed.

## Environment variables

| Variable                  | Purpose                                                                                                   |
| ------------------------- | --------------------------------------------------------------------------------------------------------- |
| `PUBLIC_SITE_URL`         | Canonical site origin for `<link rel=canonical>`, the sitemap and `robots.txt`. Defaults to `https://peephole.dev` (placeholder until a domain is chosen). |
| `PUBLIC_PLAUSIBLE_DOMAIN` | When set, the Plausible script is injected with this `data-domain`. Unset by default, so local and preview builds send nothing. |

Both are read at build time only.

## Deploy

Deployed by the Vercel GitHub app with the project's **Root Directory** set to `website`.
`vercel.json` sets the framework, clean URLs with trailing slashes (matching Astro's
`trailingSlash: 'always'`), and an `ignoreCommand` that skips the build when neither this
directory nor the synced sources (`../docs`, `../CHANGELOG.md`, `../SECURITY.md`,
`../ROADMAP.md`, `../SUPPORT.md`) changed in the commit. Set the environment variables above
in the Vercel project settings. No CLI deploys are needed.
