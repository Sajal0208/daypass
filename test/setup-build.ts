import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * The CLI tests run dist/cli/main.js, and `vitest run` alone does not build. Rebuild when dist is
 * missing or older than any file under src/ or sql/, so a test never passes against stale code.
 * (Not a test file itself: vitest only collects *.test.ts.)
 */
const ROOT = resolve(__dirname, '..');
export const CLI = join(ROOT, 'dist', 'cli', 'main.js');

function newest(dir: string): number {
  let t = 0;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    t = Math.max(t, e.isDirectory() ? newest(p) : statSync(p).mtimeMs);
  }
  return t;
}

export function ensureBuilt(): void {
  const stale = !existsSync(CLI) || statSync(CLI).mtimeMs < Math.max(newest(join(ROOT, 'src')), newest(join(ROOT, 'sql')));
  if (stale) execFileSync('npx', ['tsc', '-p', 'tsconfig.json'], { cwd: ROOT, stdio: 'inherit' });
}

/** vitest globalSetup (vitest.config.ts): build once, before any test file runs, so no two files rebuild at once. */
export default function setup(): void {
  ensureBuilt();
}
