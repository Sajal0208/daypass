import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * The SQL itself can only be proven against a real Postgres (scripts/ci-integration.sh does
 * that). This checks the shape of the template the same way `peephole sql` renders it:
 * one transaction, password set only on create, the three DO blocks still present.
 */
function render(role = 'peephole_ro', hidden: string[] = ['customers.secret']): string {
  const tpl = readFileSync(resolve(__dirname, '..', 'sql', 'setup-role.sql'), 'utf8');
  const arr = hidden.length ? `ARRAY[\n    ${hidden.map((c) => `'${c}'`).join(',\n    ')}\n  ]` : 'ARRAY[]::text[]';
  return tpl.replace(/__ROLE__/g, role).replace('__HIDDEN__', arr);
}

/** Top-level statements: non-comment, non-blank, non-meta-command lines outside DO $$ ... $$ bodies. */
function statements(sql: string): string[] {
  const out: string[] = [];
  let inBody = false;
  for (const raw of sql.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('--') || line.startsWith('\\')) continue;
    if (!inBody && /^DO \$\$/.test(line)) { inBody = true; out.push(line); continue; }
    if (inBody) { if (/^END \$\$;/.test(line)) inBody = false; continue; }
    out.push(line);
  }
  return out;
}

describe('sql/setup-role.sql template', () => {
  const sql = render();
  const stmts = statements(sql);

  it('substitutes the role and the hidden list', () => {
    expect(sql).not.toContain('__ROLE__');
    expect(sql).not.toContain('__HIDDEN__');
    expect(sql).toContain(`'customers.secret'`);
    expect(render('other_ro')).toContain('"other_ro"');
  });

  it('runs as one transaction: first statement BEGIN;, last COMMIT;', () => {
    expect(stmts[0]).toBe('BEGIN;');
    expect(stmts[stmts.length - 1]).toBe('COMMIT;');
    expect(stmts.filter((s) => s === 'BEGIN;')).toHaveLength(1);
    expect(stmts.filter((s) => s === 'COMMIT;')).toHaveLength(1);
  });

  it('pins ON_ERROR_STOP on and ON_ERROR_ROLLBACK off before BEGIN, so a psqlrc cannot undo the transaction', () => {
    const at = (needle: string) => {
      const hits = [...sql.matchAll(new RegExp(`^${needle.replace(/\\/g, '\\\\')}$`, 'gm'))];
      expect(hits, needle).toHaveLength(1);
      return hits[0].index!;
    };
    const begin = at('BEGIN;');
    expect(at('\\set ON_ERROR_STOP on')).toBeLessThan(begin);
    expect(at('\\set ON_ERROR_ROLLBACK off')).toBeLessThan(begin);
  });

  it('sets PASSWORD NULL only when the role is created, never on a re-run', () => {
    const hits = [...sql.matchAll(/PASSWORD NULL/g)].map((m) => m.index!);
    expect(hits).toHaveLength(1);
    const createBranch = /IF NOT EXISTS \(SELECT 1 FROM pg_roles WHERE rolname = 'peephole_ro'\) THEN([\s\S]*?)END IF;/.exec(sql);
    expect(createBranch).not.toBeNull();
    const start = createBranch!.index;
    const end = start + createBranch![0].length;
    expect(hits[0]).toBeGreaterThan(start);
    expect(hits[0]).toBeLessThan(end);
    // The unconditional ALTER ROLE keeps the attribute lock-down but not the password reset.
    const alter = /^ALTER ROLE "peephole_ro" WITH [^\n]*$/m.exec(sql)?.[0];
    expect(alter).toMatch(/LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 5/);
    expect(alter).not.toMatch(/PASSWORD/);
  });

  it('keeps the three DO blocks (create role, rds_iam grant, hide + self-check)', () => {
    expect(sql.match(/^DO \$\$/gm)).toHaveLength(3);
    expect(sql).toContain('self-check failed');
  });
});
