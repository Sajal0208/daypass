#!/usr/bin/env node
/**
 * Copies the repo's Markdown docs into Starlight's content collection.
 *
 *   ../docs/README.md        -> src/content/docs/docs/index.md      (/docs/)
 *   ../docs/<name>.md        -> src/content/docs/docs/<name>.md     (/docs/<name>/)
 *   ../CHANGELOG.md          -> src/content/docs/changelog.md       (/changelog/)
 *   ../SECURITY.md           -> src/content/docs/security.md        (/security/)
 *   ../ROADMAP.md            -> src/content/docs/roadmap.md         (/roadmap/)
 *   ../SUPPORT.md            -> src/content/docs/support.md         (/support/)
 *   ../docs/assets/*         -> public/assets/*                     (/assets/<file>)
 *
 * Only the top level of docs/ is copied (not plans/, launch/, assets/ or any other subfolder).
 *
 * For each file the first `# H1` becomes the frontmatter `title` (and is removed from the body),
 * the first paragraph after it becomes `description` (and stays in the body), and relative links
 * are rewritten to site URLs or, for files that are not published here, to GitHub.
 *
 * Missing sources are skipped with a notice; the script never fails because a file is absent.
 * Runs automatically before `astro dev` and `astro build` (see package.json).
 *
 * DOCS_SRC=<dir> points the script at a different repo root (a directory holding docs/ and the
 * root Markdown files). Only meant for testing the sync itself.
 *
 * No dependencies: Node 20+ built-ins only.
 */
import { existsSync } from 'node:fs';
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_URL = 'https://github.com/Sajal0208/peephole';
const BRANCH = 'main';

const websiteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = process.env.DOCS_SRC
	? path.resolve(process.env.DOCS_SRC)
	: path.resolve(websiteDir, '..');

const contentDir = path.join(websiteDir, 'src', 'content', 'docs');
const guidesOutDir = path.join(contentDir, 'docs');
const assetsOutDir = path.join(websiteDir, 'public', 'assets');

/** Root Markdown files that get their own page. Key: file name in the repo root; value: slug. */
const ROOT_PAGES = {
	'CHANGELOG.md': 'changelog',
	'SECURITY.md': 'security',
	'ROADMAP.md': 'roadmap',
	'SUPPORT.md': 'support',
};

/**
 * Preferred sidebar order for guides. Names not listed sort alphabetically after these.
 * `index` is docs/README.md.
 */
const GUIDE_ORDER = [
	'index',
	'quickstart',
	'concepts',
	'aws-rds',
	'other-postgres',
	'hidden-columns',
	'prisma-check',
	'plugin',
	'threat-model',
	'troubleshooting',
	'faq',
];

const log = (msg) => console.log(`[sync-docs] ${msg}`);

async function exists(p) {
	try {
		await stat(p);
		return true;
	} catch {
		return false;
	}
}

/** Map a repo-relative path (posix, no leading ./) to a URL on this site, or on GitHub. */
function repoPathToUrl(repoPath) {
	if (repoPath === 'docs/README.md') return '/docs/';
	let m = /^docs\/([^/]+)\.md$/.exec(repoPath);
	if (m) return `/docs/${m[1]}/`;
	m = /^docs\/assets\/([^/]+)$/.exec(repoPath);
	if (m) return `/assets/${m[1]}`;
	if (ROOT_PAGES[repoPath]) return `/${ROOT_PAGES[repoPath]}/`;
	if (repoPath === 'README.md') return `${REPO_URL}#readme`;
	return `${REPO_URL}/blob/${BRANCH}/${repoPath}`;
}

/**
 * Rewrite one link target found in `sourceRepoPath` (e.g. `docs/quickstart.md`).
 * External URLs, anchors, absolute paths and mail links are returned untouched.
 */
function rewriteTarget(target, sourceRepoPath) {
	if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return target; // https:, mailto:, …
	if (target.startsWith('#') || target.startsWith('/')) return target;

	const hashIndex = target.indexOf('#');
	const file = hashIndex === -1 ? target : target.slice(0, hashIndex);
	const hash = hashIndex === -1 ? '' : target.slice(hashIndex);
	if (!file) return target;

	// Resolve relative to the source file's folder and normalise to a repo-relative posix path.
	const toRepoPath = (p) => {
		const n = path.posix.normalize(p);
		return n === '..' || n.startsWith('../') ? null : n.replace(/^\.\//, '');
	};
	const folderRelative = toRepoPath(path.posix.join(path.posix.dirname(sourceRepoPath), file));
	const rootRelative = toRepoPath(file);
	if (folderRelative === null) return target; // escapes the repo: leave it alone

	// Prefer the file that actually exists: authors sometimes write repo-root-relative paths
	// (e.g. `docs/foo.md` from inside docs/). Fall back to the folder-relative reading.
	let repoPath = folderRelative;
	if (!existsSync(path.join(repoRoot, folderRelative))) {
		if (rootRelative !== null && existsSync(path.join(repoRoot, rootRelative))) {
			repoPath = rootRelative;
		} else {
			log(`notice: ${sourceRepoPath} links to ${target}, which does not exist in the repo`);
		}
	}
	return repoPathToUrl(repoPath) + hash;
}

function rewriteLinksInProse(markdown, sourceRepoPath) {
	// Inline links and images: `](target)` or `](target "title")`.
	let out = markdown.replace(
		/\]\(([^()\s]+)((?:\s+"[^"]*")?)\)/g,
		(_, target, title) => `](${rewriteTarget(target, sourceRepoPath)}${title})`,
	);
	// Reference definitions: `[id]: target`.
	out = out.replace(
		/^(\[[^\]]+\]:\s*)(\S+)/gm,
		(_, prefix, target) => `${prefix}${rewriteTarget(target, sourceRepoPath)}`,
	);
	return out;
}

const isFence = (line) => /^\s{0,3}(```|~~~)/.test(line);

/** Rewrite links outside fenced code blocks; code samples are left exactly as written. */
function rewriteLinks(markdown, sourceRepoPath) {
	const out = [];
	let prose = [];
	let inFence = false;
	const flush = () => {
		if (prose.length) out.push(rewriteLinksInProse(prose.join('\n'), sourceRepoPath));
		prose = [];
	};
	for (const line of markdown.split('\n')) {
		if (isFence(line)) {
			if (!inFence) flush();
			inFence = !inFence;
			out.push(line);
			continue;
		}
		if (inFence) out.push(line);
		else prose.push(line);
	}
	flush();
	return out.join('\n');
}

/** Strip inline Markdown so a heading or paragraph reads as plain text. */
function plainText(md) {
	return md
		.replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
		.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
		.replace(/\[([^\]]+)\]\[[^\]]*\]/g, '$1')
		.replace(/`([^`]*)`/g, '$1')
		.replace(/\*\*(.+?)\*\*/g, '$1')
		.replace(/\*(.+?)\*/g, '$1')
		// Underscore emphasis only as whole words, so `peephole_ro` and `snake_case` survive.
		.replace(/(?<![\w`])__(.+?)__(?![\w`])/g, '$1')
		.replace(/(?<![\w`])_(.+?)_(?![\w`])/g, '$1')
		.replace(/<[^>]+>/g, '')
		.replace(/\s+/g, ' ')
		.trim();
}

/** YAML double-quoted scalar. JSON string syntax is a subset of YAML, so this is always safe. */
const yamlString = (s) => JSON.stringify(s);

function titleFromFileName(repoPath) {
	const stem = path.posix.basename(repoPath, '.md');
	return stem === 'README' ? 'Docs' : stem.replace(/[-_]+/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

/**
 * Turn a repo Markdown file into a Starlight page: frontmatter + body with the H1 removed
 * and links rewritten.
 */
function convert(source, repoPath, { sidebarOrder } = {}) {
	let text = source.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
	// Drop any existing frontmatter so ours is the only one.
	text = text.replace(/^---\n[\s\S]*?\n---\n/, '');

	const lines = text.split('\n');
	let title;
	let h1Index = -1;
	let inFence = false;
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		if (isFence(line)) inFence = !inFence;
		if (inFence) continue;
		const m = /^#\s+(.+?)\s*#*\s*$/.exec(line);
		if (m) {
			title = plainText(m[1]);
			h1Index = i;
			break;
		}
	}
	if (h1Index === -1) {
		title = titleFromFileName(repoPath);
		log(`notice: ${repoPath} has no "# Title" line; using "${title}"`);
	} else {
		lines.splice(h1Index, 1);
	}

	// Summary paragraph: the first run of prose lines between the H1 and the first `##`.
	// Fences, lists, quotes, tables, badge/image rows and raw HTML are skipped; if the file has
	// no summary paragraph there is no description (Starlight falls back to the site's).
	let description = '';
	inFence = false;
	for (let i = Math.max(h1Index, 0); i < lines.length; i++) {
		const line = lines[i];
		if (isFence(line)) {
			inFence = !inFence;
			continue;
		}
		if (inFence || line.trim() === '') continue;
		if (/^#{2,}\s/.test(line)) break;
		if (/^(#|>|[-*+]\s|\d+[.)]\s|\||<|!\[|\[!\[)/.test(line.trim())) {
			// Not prose; keep scanning (skip the whole block).
			while (i + 1 < lines.length && lines[i + 1].trim() !== '') i++;
			continue;
		}
		const para = [line];
		while (i + 1 < lines.length && lines[i + 1].trim() !== '' && !/^#/.test(lines[i + 1])) {
			para.push(lines[++i]);
		}
		description = plainText(para.join(' '));
		break;
	}

	const body = rewriteLinks(lines.join('\n').replace(/^\n+/, ''), repoPath);

	const fm = [`title: ${yamlString(title)}`];
	if (description) fm.push(`description: ${yamlString(description)}`);
	fm.push(`editUrl: ${yamlString(`${REPO_URL}/edit/${BRANCH}/${repoPath}`)}`);
	if (sidebarOrder !== undefined) fm.push('sidebar:', `  order: ${sidebarOrder}`);

	return `---\n${fm.join('\n')}\n---\n\n${body.trimEnd()}\n`;
}

async function syncGuides() {
	await rm(guidesOutDir, { recursive: true, force: true });
	await mkdir(guidesOutDir, { recursive: true });

	const docsDir = path.join(repoRoot, 'docs');
	if (!(await exists(docsDir))) {
		log(`notice: ${path.relative(websiteDir, docsDir)} not found; no guides synced`);
		return 0;
	}
	const entries = await readdir(docsDir, { withFileTypes: true });
	const files = entries
		.filter((e) => e.isFile() && e.name.toLowerCase().endsWith('.md'))
		.map((e) => e.name)
		.sort();
	if (files.length === 0) {
		log('notice: docs/ has no top-level Markdown files; no guides synced');
		return 0;
	}

	for (const name of files) {
		const repoPath = `docs/${name}`;
		const stem = name === 'README.md' ? 'index' : name.slice(0, -3);
		const orderIndex = GUIDE_ORDER.indexOf(stem);
		const sidebarOrder = orderIndex === -1 ? GUIDE_ORDER.length + 1 : orderIndex;
		const source = await readFile(path.join(docsDir, name), 'utf8');
		await writeFile(path.join(guidesOutDir, `${stem}.md`), convert(source, repoPath, { sidebarOrder }));
	}
	log(`synced ${files.length} guide(s) from docs/`);
	return files.length;
}

async function syncRootPages() {
	let count = 0;
	for (const [file, slug] of Object.entries(ROOT_PAGES)) {
		const src = path.join(repoRoot, file);
		const dest = path.join(contentDir, `${slug}.md`);
		if (!(await exists(src))) {
			log(`notice: ${file} not found; skipping /${slug}/`);
			await rm(dest, { force: true });
			continue;
		}
		const source = await readFile(src, 'utf8');
		await writeFile(dest, convert(source, file));
		count++;
	}
	log(`synced ${count} root page(s)`);
}

async function syncAssets() {
	await rm(assetsOutDir, { recursive: true, force: true });
	const src = path.join(repoRoot, 'docs', 'assets');
	if (!(await exists(src))) {
		log('notice: docs/assets/ not found; no assets copied');
		return;
	}
	await cp(src, assetsOutDir, { recursive: true });
	const n = (await readdir(assetsOutDir)).length;
	log(`copied ${n} asset(s) to public/assets/`);
}

log(`source: ${repoRoot}`);
await mkdir(contentDir, { recursive: true });
await syncGuides();
await syncRootPages();
await syncAssets();
