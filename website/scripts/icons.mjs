#!/usr/bin/env node
/**
 * Renders the raster icons from public/favicon.svg with sharp:
 *
 *   public/favicon.ico           32×32 (a PNG wrapped in an ICO container; every current
 *                                browser reads PNG-in-ICO, and it is what /favicon.ico
 *                                requests from old clients and link previews expect)
 *   public/apple-touch-icon.png  180×180, flattened on the accent colour (iOS ignores
 *                                transparency and rounds the corners itself)
 *
 * Run with `npm run icons` after changing favicon.svg. The outputs are committed.
 */
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const svg = await readFile(path.join(publicDir, 'favicon.svg'));

/** Same as the `<rect fill>` in favicon.svg: fills the rounded corners of the touch icon. */
const ACCENT = '#0f766e';

/** Wrap one PNG in an ICO container (ICONDIR + one ICONDIRENTRY + the PNG bytes). */
function pngToIco(png, size) {
	const header = Buffer.alloc(6);
	header.writeUInt16LE(0, 0); // reserved
	header.writeUInt16LE(1, 2); // type: 1 = icon
	header.writeUInt16LE(1, 4); // image count

	const entry = Buffer.alloc(16);
	entry.writeUInt8(size === 256 ? 0 : size, 0); // width (0 means 256)
	entry.writeUInt8(size === 256 ? 0 : size, 1); // height
	entry.writeUInt8(0, 2); // colour palette size
	entry.writeUInt8(0, 3); // reserved
	entry.writeUInt16LE(1, 4); // colour planes
	entry.writeUInt16LE(32, 6); // bits per pixel
	entry.writeUInt32LE(png.length, 8); // image data size
	entry.writeUInt32LE(header.length + entry.length, 12); // image data offset

	return Buffer.concat([header, entry, png]);
}

const favicon32 = await sharp(svg).resize(32, 32).png().toBuffer();
await writeFile(path.join(publicDir, 'favicon.ico'), pngToIco(favicon32, 32));

const touch = await sharp(svg)
	.resize(180, 180)
	.flatten({ background: ACCENT })
	.png({ compressionLevel: 9 })
	.toBuffer();
await writeFile(path.join(publicDir, 'apple-touch-icon.png'), touch);

console.log('[icons] wrote public/favicon.ico (32×32) and public/apple-touch-icon.png (180×180)');
