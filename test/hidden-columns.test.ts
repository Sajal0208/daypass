import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Keeps your hidden-column list honest against a Prisma schema: every hidden column
 * must exist, and every sensitive-looking String/Json column must be hidden.
 *   PEEPHOLE_HIDDEN_FILE=hidden-columns.txt PEEPHOLE_PRISMA_SCHEMA=prisma/schema.prisma npm test
 * Skipped when either env var is unset.
 */
const HIDDEN = process.env.PEEPHOLE_HIDDEN_FILE ? resolve(process.env.PEEPHOLE_HIDDEN_FILE) : '';
const SCHEMA = process.env.PEEPHOLE_PRISMA_SCHEMA ? resolve(process.env.PEEPHOLE_PRISMA_SCHEMA) : '';

const SENSITIVE = /(^|_)(phone|email|transcript|key_hash|secret|token|password|api_key|lines)$|^encrypted_|_number$|^prompt_snapshot$/;
const SCALAR = /^(String|Json|Bytes)\??$/;

function hiddenList(text: string): string[] {
  return text.split('\n').map((l) => l.replace(/#.*/, '').trim()).filter(Boolean);
}

/** table.column for every scalar field, using @@map / @map names when present. */
function prismaColumns(schema: string): Map<string, string> {
  const out = new Map<string, string>(); // "table.column" -> prisma type
  for (const block of schema.matchAll(/^model (\w+) \{([\s\S]*?)^\}/gm)) {
    const [, model, body] = block;
    const table = /@@map\("([^"]+)"\)/.exec(body)?.[1] ?? model;
    for (const line of body.split('\n')) {
      const f = /^\s+(\w+)\s+([\w\[\]?]+)(.*)$/.exec(line);
      if (!f || !SCALAR.test(f[2])) continue;
      const col = /@map\("([^"]+)"\)/.exec(f[3])?.[1] ?? f[1];
      out.set(`${table}.${col}`, f[2]);
    }
  }
  return out;
}

const enabled = !!HIDDEN && !!SCHEMA && existsSync(SCHEMA) && existsSync(HIDDEN);

describe.skipIf(!enabled)('hidden columns vs prisma schema', () => {
  const hidden = enabled ? hiddenList(readFileSync(HIDDEN, 'utf8')) : [];
  const cols = enabled ? prismaColumns(readFileSync(SCHEMA, 'utf8')) : new Map<string, string>();

  it('every hidden column exists in the schema', () => {
    const missing = hidden.filter((h) => !cols.has(h));
    expect(missing).toEqual([]);
  });

  it('every sensitive-looking column is hidden', () => {
    const shouldHide = [...cols.keys()].filter((k) => SENSITIVE.test(k.split('.')[1]));
    const unhidden = shouldHide.filter((k) => !hidden.includes(k));
    expect(unhidden).toEqual([]);
  });
});

