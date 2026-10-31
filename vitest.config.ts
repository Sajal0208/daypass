import { defineConfig } from 'vitest/config';
// globalSetup rebuilds dist once, before any file runs, when it is older than src/ or sql/:
// the CLI tests run dist/cli/main.js and must never see a stale build.
export default defineConfig({ test: { include: ['test/**/*.test.ts'], globalSetup: ['test/setup-build.ts'] } });
