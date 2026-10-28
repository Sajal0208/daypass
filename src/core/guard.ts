import { loadModule, parseSync } from 'libpg-query';

let loaded: Promise<void> | null = null;
/** libpg-query is WASM; it must be initialised once before parseSync works. */
function ready(): Promise<void> {
  if (!loaded) loaded = loadModule();
  return loaded;
}

export type SqlKind = 'select' | 'explain';
export type GuardResult = { ok: true; kind: SqlKind } | { ok: false; reason: string };

/**
 * Functions that are read-only in name but can block, write, leak files or
 * escape the role's settings. Matched on the bare function name, so
 * `pg_catalog.pg_sleep` is caught too.
 */
const BANNED_FUNCTIONS = new Set([
  'pg_sleep',
  'pg_sleep_for',
  'pg_sleep_until',
  'dblink',
  'dblink_exec',
  'dblink_connect',
  'pg_read_file',
  'pg_read_binary_file',
  'pg_ls_dir',
  'pg_stat_file',
  'lo_import',
  'lo_export',
  'lo_get',
  'lo_put',
  'lo_unlink',
  'pg_terminate_backend',
  'pg_cancel_backend',
  'pg_reload_conf',
  'set_config',
  'pg_advisory_lock',
  'pg_advisory_lock_shared',
  'pg_advisory_xact_lock',
  'pg_advisory_xact_lock_shared',
  'pg_try_advisory_lock',
  'pg_try_advisory_xact_lock',
  'nextval',
  'setval',
  'pg_notify',
  'pg_logical_emit_message',
  'pg_create_restore_point',
  'pg_switch_wal',
  'pg_backup_start',
  'pg_backup_stop',
]);

/** Only SELECT and EXPLAIN (without ANALYZE) get through. Pure function: no I/O. */
export async function checkSql(sql: string): Promise<GuardResult> {
  await ready();
  if (!sql || sql.trim() === '') return { ok: false, reason: 'SQL is empty' };

  let tree: any;
  try {
    tree = parseSync(sql);
  } catch (e: any) {
    return { ok: false, reason: `Parse error: ${e?.message ?? String(e)}` };
  }

  const stmts: any[] = tree?.stmts ?? [];
  if (stmts.length !== 1) return { ok: false, reason: `Exactly one statement is allowed, got ${stmts.length}` };

  const stmt = stmts[0]?.stmt ?? {};
  let kind: SqlKind;
  let body: any;

  if (stmt.SelectStmt) {
    kind = 'select';
    body = stmt.SelectStmt;
  } else if (stmt.ExplainStmt) {
    kind = 'explain';
    const ex = stmt.ExplainStmt;
    for (const opt of ex.options ?? []) {
      const name = String(opt?.DefElem?.defname ?? '').toLowerCase();
      if (name === 'analyze') return { ok: false, reason: 'EXPLAIN ANALYZE runs the query; use plain EXPLAIN' };
    }
    if (!ex.query?.SelectStmt) return { ok: false, reason: 'EXPLAIN may only wrap a SELECT' };
    body = ex.query.SelectStmt;
  } else {
    const name = Object.keys(stmt)[0] ?? 'unknown';
    return { ok: false, reason: `Only SELECT is allowed (got ${name.replace(/Stmt$/, '')})` };
  }

  const problem = walk(body);
  if (problem) return { ok: false, reason: problem };
  return { ok: true, kind };
}

/** Depth-first scan of the AST for locking clauses, SELECT INTO and banned function calls. */
function walk(node: any): string | null {
  if (node === null || typeof node !== 'object') return null;
  if (Array.isArray(node)) {
    for (const n of node) {
      const p = walk(n);
      if (p) return p;
    }
    return null;
  }
  for (const [key, value] of Object.entries(node)) {
    if (key === 'lockingClause') return 'Row locks (FOR UPDATE / FOR SHARE) are not allowed';
    if (key === 'intoClause' && value) return 'SELECT INTO creates a table and is not allowed';
    if (key === 'FuncCall') {
      const parts: string[] = ((value as any)?.funcname ?? []).map((p: any) => p?.String?.sval ?? '');
      const bare = parts[parts.length - 1]?.toLowerCase();
      if (bare && BANNED_FUNCTIONS.has(bare)) return `Function ${bare}() is not allowed`;
    }
    const p = walk(value);
    if (p) return p;
  }
  return null;
}
