// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import tailwindcss from '@tailwindcss/vite';

const REPO = 'https://github.com/Sajal0208/peephole';

// Placeholder until a domain is chosen. Set PUBLIC_SITE_URL (e.g. in Vercel project settings)
// to override it; it feeds canonical URLs, the sitemap and robots.txt.
const site = process.env.PUBLIC_SITE_URL ?? 'https://peephole.dev';

// Plausible is only injected when a domain is configured, so local and preview builds stay silent.
const plausibleDomain = process.env.PUBLIC_PLAUSIBLE_DOMAIN;

// https://astro.build/config
export default defineConfig({
	site,
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'Peephole',
			description:
				'Temporary, read-only, audited Postgres access for AI coding agents. A human opens a lease; Claude Code (or any MCP client) gets SELECT-only tools until it expires.',
			social: [{ icon: 'github', label: 'GitHub', href: REPO }],
			sidebar: [
				// Pages under src/content/docs/docs/ are generated from ../docs by scripts/sync-docs.mjs.
				{ label: 'Docs', items: [{ autogenerate: { directory: 'docs' } }] },
				{ label: 'Changelog', link: '/changelog/' },
				{ label: 'Security', link: '/security/' },
				{ label: 'Roadmap', link: '/roadmap/' },
				{ label: 'Support', link: '/support/' },
			],
			customCss: ['./src/styles/global.css'],
			head: plausibleDomain
				? [
						{
							tag: 'script',
							attrs: {
								defer: true,
								'data-domain': plausibleDomain,
								src: 'https://plausible.io/js/script.js',
							},
						},
					]
				: [],
			lastUpdated: false,
			// Pages committed in this directory (e.g. the splash page) edit here. Synced pages carry
			// their own `editUrl` pointing at the Markdown source in the repo (docs/*.md etc).
			editLink: { baseUrl: `${REPO}/edit/main/website/` },
		}),
	],
	vite: {
		plugins: [tailwindcss()],
	},
});
