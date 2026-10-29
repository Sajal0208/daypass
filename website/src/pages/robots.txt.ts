import type { APIRoute } from 'astro';

// Generated at build time from `site` in astro.config.mjs, so the sitemap URL follows
// PUBLIC_SITE_URL instead of being hard-coded.
export const GET: APIRoute = ({ site }) => {
	const sitemap = new URL('sitemap-index.xml', site).href;
	const body = ['User-agent: *', 'Allow: /', '', `Sitemap: ${sitemap}`, ''].join('\n');
	return new Response(body, {
		headers: { 'Content-Type': 'text/plain; charset=utf-8' },
	});
};
