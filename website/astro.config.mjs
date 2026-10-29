// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import tailwindcss from '@tailwindcss/vite';
import { ogImage, repoUrl, siteDescription, siteUrl } from './src/lib/meta.ts';

// Placeholder until a domain is chosen. Set PUBLIC_SITE_URL (e.g. in Vercel project settings)
// to override it; it feeds canonical URLs, the sitemap, robots.txt and the Open Graph image URL.
// Defined in src/lib/meta.ts so pages and scripts/og.mjs read the same values.
const site = siteUrl;

const plausibleDomain = process.env.PUBLIC_PLAUSIBLE_DOMAIN;

// Starlight already emits <title>, canonical, og:title, og:description, og:url and og:locale
// per page; entries here override its defaults with the same name/property (og:type,
// og:site_name, twitter:card) and add the image and touch icon.
/** @type {NonNullable<import('@astrojs/starlight/types').StarlightUserConfig['head']>} */
const head = [
	{ tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
	{ tag: 'meta', attrs: { property: 'og:type', content: 'website' } },
	{ tag: 'meta', attrs: { property: 'og:site_name', content: 'Peephole' } },
	{ tag: 'meta', attrs: { property: 'og:image', content: ogImage.url } },
	{ tag: 'meta', attrs: { property: 'og:image:width', content: String(ogImage.width) } },
	{ tag: 'meta', attrs: { property: 'og:image:height', content: String(ogImage.height) } },
	{ tag: 'meta', attrs: { property: 'og:image:alt', content: ogImage.alt } },
	{ tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
	{ tag: 'meta', attrs: { name: 'twitter:image', content: ogImage.url } },
];
// Plausible is only injected when a domain is configured, so local and preview builds stay silent.
if (plausibleDomain) {
	head.push({
		tag: 'script',
		attrs: { defer: true, 'data-domain': plausibleDomain, src: 'https://plausible.io/js/script.js' },
	});
}

// https://astro.build/config
export default defineConfig({
	site,
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'Peephole',
			description: siteDescription,
			social: [{ icon: 'github', label: 'GitHub', href: repoUrl }],
			sidebar: [
				// Pages under src/content/docs/docs/ are generated from ../docs by scripts/sync-docs.mjs.
				{ label: 'Docs', items: [{ autogenerate: { directory: 'docs' } }] },
				{ label: 'Changelog', link: '/changelog/' },
				{ label: 'Security', link: '/security/' },
				{ label: 'Roadmap', link: '/roadmap/' },
				{ label: 'Support', link: '/support/' },
			],
			customCss: ['./src/styles/global.css'],
			head,
			lastUpdated: false,
			// Pages committed in this directory (e.g. the splash page) edit here. Synced pages carry
			// their own `editUrl` pointing at the Markdown source in the repo (docs/*.md etc).
			editLink: { baseUrl: `${repoUrl}/edit/main/website/` },
		}),
	],
	vite: {
		plugins: [tailwindcss()],
	},
});
