/**
 * Site-wide metadata, shared by astro.config.mjs (Starlight `head`), scripts/og.mjs and any
 * page that renders its own `<head>` or needs the pitch text.
 *
 * `siteUrl` follows PUBLIC_SITE_URL at build time (see website/README.md); the default is a
 * placeholder until a domain is chosen.
 */
export const siteUrl: string = (process.env.PUBLIC_SITE_URL ?? 'https://peepholedb.com').replace(/\/+$/, '');

export const siteTitle = 'Peephole';

/** One-line pitch, used as the default description and on the Open Graph image. */
export const siteTagline = 'Temporary, read-only, audited database access for AI coding agents.';

export const siteDescription =
	'Temporary, read-only, audited Postgres access for AI coding agents. A human opens a lease; Claude Code (or any MCP client) gets SELECT-only tools until it expires.';

export const installCommand = 'npm install -g peephole-db';

export const repoUrl = 'https://github.com/Sajal0208/peephole';

/** Rendered by `npm run og` (scripts/og.mjs) into public/og.png. */
export const ogImage = {
	path: '/og.png',
	url: `${siteUrl}/og.png`,
	width: 1200,
	height: 630,
	alt: `${siteTitle}: ${siteTagline}`,
} as const;
