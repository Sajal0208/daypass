#!/usr/bin/env node
/**
 * Renders public/og.png (1200×630), the Open Graph / Twitter card image, from an inline SVG
 * with sharp. Run with `npm run og`; the PNG is committed, so CI never renders it.
 *
 * Text, colours and sizes come from src/lib/meta.ts and public/favicon.svg so the card, the
 * meta tags and the site stay in step. No web fonts: sharp's SVG rasteriser (librsvg) uses the
 * fonts installed on the machine running this, so only generic families are named and the
 * result differs slightly between macOS and Linux. Re-run it on macOS for a release.
 */
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';
import { installCommand, ogImage, siteTagline, siteTitle, siteUrl } from '../src/lib/meta.ts';

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const out = path.join(publicDir, 'og.png');

const { width, height } = ogImage;

// Palette: the site's dark background and the teal accent (Tailwind teal-400/600/950 shades).
const BG = '#0b1215';
const PANEL = '#101a1e';
const BORDER = '#1f3137';
const ACCENT = '#2dd4bf';
const ACCENT_DEEP = '#0f766e';
const TEXT = '#ffffff';
const MUTED = '#8aa0a6';

const SANS = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif";
const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

/** Split the tagline into two balanced-ish lines on a word boundary. */
function twoLines(text) {
	const words = text.split(' ');
	let best = [text, ''];
	let bestDiff = Infinity;
	for (let i = 1; i < words.length; i++) {
		const a = words.slice(0, i).join(' ');
		const b = words.slice(i).join(' ');
		const diff = Math.abs(a.length - b.length);
		if (diff < bestDiff) {
			bestDiff = diff;
			best = [a, b];
		}
	}
	return best;
}

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const [line1, line2] = twoLines(siteTagline).map(esc);
const wordmark = siteTitle.toLowerCase();

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
  <defs>
    <radialGradient id="glow" cx="0.88" cy="0.12" r="0.75">
      <stop offset="0" stop-color="${ACCENT_DEEP}" stop-opacity="0.45"/>
      <stop offset="1" stop-color="${BG}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="${width}" height="${height}" fill="${BG}"/>
  <rect width="${width}" height="${height}" fill="url(#glow)"/>

  <!-- Peephole mark (same geometry as favicon.svg, scaled 32 -> 88). -->
  <g transform="translate(80 84) scale(2.75)">
    <rect width="32" height="32" rx="7" fill="${ACCENT_DEEP}"/>
    <circle cx="16" cy="16" r="9" fill="none" stroke="${TEXT}" stroke-width="2.5"/>
    <circle cx="16" cy="16" r="4" fill="${TEXT}"/>
  </g>
  <text x="196" y="151" font-family="${SANS}" font-size="72" font-weight="700" fill="${ACCENT}" letter-spacing="-1">${wordmark}</text>

  <text font-family="${SANS}" font-size="46" font-weight="600" fill="${TEXT}">
    <tspan x="80" y="300">${line1}</tspan>
    <tspan x="80" y="362">${line2}</tspan>
  </text>

  <!-- Install command. -->
  <rect x="80" y="430" width="700" height="88" rx="14" fill="${PANEL}" stroke="${BORDER}" stroke-width="2"/>
  <text x="112" y="486" font-family="${MONO}" font-size="32" fill="${MUTED}">$ <tspan fill="${TEXT}">${esc(installCommand)}</tspan></text>

  <text x="${width - 80}" y="${height - 48}" text-anchor="end" font-family="${MONO}" font-size="24" fill="${MUTED}">${esc(new URL(siteUrl).host)}</text>
</svg>`;

const png = await sharp(Buffer.from(svg), { density: 144 })
	.resize(width, height)
	.png({ compressionLevel: 9, palette: true })
	.toBuffer();
await writeFile(out, png);
console.log(`[og] wrote public/og.png (${width}×${height}, ${Math.round(png.length / 1024)} KB)`);
