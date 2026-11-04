import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

const json = (p: string) => JSON.parse(readFileSync(p, 'utf8'));

describe('plugin manifest version', () => {
  it('matches package.json', () => {
    expect(json('plugin/.claude-plugin/plugin.json').version).toBe(json('package.json').version);
  });
  it('is bumped by release-please together with package.json', () => {
    const extra = json('release-please-config.json').packages['.']['extra-files'] ?? [];
    expect(extra).toContainEqual({ type: 'json', path: 'plugin/.claude-plugin/plugin.json', jsonpath: '$.version' });
  });
});
