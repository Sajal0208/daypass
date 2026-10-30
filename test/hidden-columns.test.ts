import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { parsePrismaColumns, parseHiddenFile, diffHidden } from '../src/core/index.js';

/**
 * Keeps your hidden-column list honest against a Prisma schema: every hidden (or `!` allowed)
 * column must exist, and every sensitive-looking column must be hidden or allowed. Same check as
 * `daypass hidden check --file hidden-columns.txt --prisma prisma/schema.prisma`.
 *   DAYPASS_HIDDEN_FILE=hidden-columns.txt DAYPASS_PRISMA_SCHEMA=prisma/schema.prisma npm test
 * Skipped when either env var is unset.
 */
const HIDDEN = process.env.DAYPASS_HIDDEN_FILE ? resolve(process.env.DAYPASS_HIDDEN_FILE) : '';
const SCHEMA = process.env.DAYPASS_PRISMA_SCHEMA ? resolve(process.env.DAYPASS_PRISMA_SCHEMA) : '';

const enabled = !!HIDDEN && !!SCHEMA && existsSync(SCHEMA) && existsSync(HIDDEN);

describe.skipIf(!enabled)('hidden columns vs prisma schema', () => {
  const { hidden, allow } = enabled ? parseHiddenFile(readFileSync(HIDDEN, 'utf8')) : { hidden: [], allow: [] };
  const cols = enabled ? parsePrismaColumns(readFileSync(SCHEMA, 'utf8')) : [];
  const diff = diffHidden(hidden, cols, allow);

  it('every hidden or allowed column exists in the schema', () => {
    expect(diff.missingFromSchema).toEqual([]);
  });

  it('every sensitive-looking column is hidden or allowed', () => {
    expect(diff.sensitiveNotHidden).toEqual([]);
  });
});
