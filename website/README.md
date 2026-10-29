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

The landing page (`/`) is `src/pages/index.astro`, a plain Astro page (not a Starlight route) that imports the same `global.css`; its components live in `src/components/`. The demo transcript it shows as the text alternative to `/assets/demo.gif` is `src/components/demo-output.txt`, a copy of `docs/assets/demo-output.txt`.

## Open Graph image and icons

`public/og.png` (the 1200×630 link-preview card), `public/favicon.ico` and
`public/apple-touch-icon.png` are generated with [sharp](https://sharp.pixelplumbing.com) and
committed, so CI and Vercel never render them:

```bash
npm run og       # scripts/og.mjs  -> public/og.png from an inline SVG template
npm run icons    # scripts/icons.mjs -> favicon.ico (32×32) + apple-touch-icon.png (180×180) from favicon.svg
```

The card's text and the image URL come from `src/lib/meta.ts`, which also feeds the
`og:*`/`twitter:*` tags in `astro.config.mjs` (Starlight adds `og:title`, `og:description`,
`og:url` and the canonical link per page) and is importable from any page. The SVG names only
generic font families (`system-ui`, `ui-monospace`, …) because sharp uses the fonts installed
on the machine running it; re-run `npm run og` on macOS when the text changes and check the
PNG before committing (it should stay well under 300 KB).

## Lighthouse CI

```bash
npm run build
npm run lhci     # lhci autorun, config in lighthouserc.json
```

Serves `dist/` and runs Lighthouse twice on `/`, `/docs/`, `/docs/quickstart/`,
`/docs/threat-model/`, `/changelog/`, `/security/` and `/roadmap/`. Performance,
accessibility, best practices and SEO must each score at least 0.95 on every page or the run
fails. Reports upload to Lighthouse's temporary public storage (a link is printed); pass
`-- --upload.target=filesystem --upload.outputDir=<dir>` to keep them local instead. The run
needs Chrome and writes a git-ignored `.lighthouseci/` folder.

`.github/workflows/site.yml` runs `npm ci`, `npm run build`, `npm run lhci` and a
[linkinator](https://github.com/JustinBeckwith/linkinator) crawl of `dist/` on every pull
request and push to `main` that touches `website/` or the synced Markdown. The link check skips
`github.com`, `npmjs.com`, `plausible.io` and the site's own origin (the canonical and `og:url`
tags point at `PUBLIC_SITE_URL`, which is a placeholder until a domain is live).

## Environment variables

| Variable                  | Purpose                                                                                                   |
| ------------------------- | --------------------------------------------------------------------------------------------------------- |
| `PUBLIC_SITE_URL`         | Canonical site origin for `<link rel=canonical>`, the sitemap and `robots.txt`. Defaults to `https://peepholedb.com` (placeholder until a domain is chosen; recommended, not yet registered). |
| `PUBLIC_PLAUSIBLE_DOMAIN` | When set, the Plausible script is injected with this `data-domain`. Unset by default, so local and preview builds send nothing. |

Both are read at build time only.

## Deploy

Deployed by the Vercel GitHub app with the project's **Root Directory** set to `website`.
`vercel.json` sets the framework, clean URLs with trailing slashes (matching Astro's
`trailingSlash: 'always'`), and an `ignoreCommand` that skips the build when neither this
directory nor the synced sources (`../docs`, `../CHANGELOG.md`, `../SECURITY.md`,
`../ROADMAP.md`, `../SUPPORT.md`) changed in the commit. Set the environment variables above
in the Vercel project settings. No CLI deploys are needed.
