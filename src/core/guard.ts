import { loadModule, parseSync, scanSync } from 'libpg-query';

let loaded: Promise<void> | null = null;
/** libpg-query is WASM; it must be initialised once before parseSync works. */
function ready(): Promise<void> {
  if (!loaded) loaded = loadModule();
  return loaded;
}

export type SqlKind = 'select' | 'explain';
/**
 * `sql` on success is the canonical statement: the caller's text with leading/trailing
 * comments and trailing semicolons removed, so it can be wrapped or prefixed safely.
 */
export type GuardResult = { ok: true; kind: SqlKind; sql: string } | { ok: false; reason: string };

/**
 * Functions that are read-only in name but can block, write, leak files, run arbitrary
 * SQL or escape the role's settings. Matched as regexes against the bare, lower-cased
 * function name (last part of a qualified name), so `pg_catalog.PG_SLEEP` is caught too.
 * Exported so tests and docs can enumerate exactly what is banned.
 */
export const BANNED_FUNCTION_PATTERNS: readonly RegExp[] = [
  /^pg_sleep/, // pg_sleep, pg_sleep_for, pg_sleep_until
  /^pg_(try_)?advisory_/, // every advisory lock flavour (they outlive the statement on a pooled connection)
  /^dblink/, // dblink, dblink_exec, dblink_connect(_u), dblink_get_connections, ...
  /^lo_/, // large objects: lo_import, lo_export, lo_get, lo_put, lo_unlink, lo_from_bytea, ...
  /^lowrite$/,
  /^loread$/,
  /^pg_ls_/, // pg_ls_dir, pg_ls_waldir, pg_ls_logdir, pg_ls_tmpdir, ...
  /^pg_stat_reset/, // pg_stat_reset, pg_stat_reset_shared, pg_stat_reset_single_*
  /^pg_.*(replication|wal_replay|promote|rotate_logfile|log_backend)/, // slots, replay control, failover, log control
  /^pg_read_/, // pg_read_file, pg_read_binary_file
  /^pg_stat_file$/,
  /^set_config$/,
  /^nextval$|^setval$/, // sequences are state: nextval writes even in a read-only transaction
  /^pg_(terminate|cancel)_backend$/,
  /^pg_reload_conf$/,
  /^pg_notify$/,
  /^pg_logical_emit_message$/,
  /^pg_create_restore_point$/,
  /^pg_switch_wal$/,
  /^pg_backup_(start|stop)$/,
  /^pg_(start|stop)_backup$/, // PG <= 14 spelling of the above
  /^brin_(summarize|desummarize)/,
  /^gin_clean_pending_list$/,
  /^txid_current$/, // assigns a real xid
  /^pg_current_xact_id$/,
  /^pg_logical_slot_/, // get/peek (binary) changes: consume or read decoded WAL
  /^pg_file_/, // adminpack: pg_file_write, pg_file_unlink, pg_file_rename, pg_file_sync
  /^pg_logdir_ls$/, // adminpack
  // EVERY function that executes SQL handed to it as a string (or runs SPI over whole relations
  // or schemas) must be listed here: the guard only sees the outer statement, so such a call is
  // a complete escape (it ran pg_sleep and set_config(..., false) in review). Audited against
  // pg_proc on PG 14 core plus the tablefunc, dblink, xml2 and adminpack extensions; when adding
  // an extension to a target, check its functions for a `query text` / `sql text` argument.
  /^query_to_xml/, // query_to_xml, query_to_xml_and_xmlschema, query_to_xmlschema
  /^cursor_to_xml/, // cursor_to_xml, cursor_to_xmlschema
  /^(table|schema|database)_to_xml/, // SPI over a table / schema / database (+ _xmlschema variants)
  /^ts_stat$/, // ts_stat(query text [, weights text])
  /^ts_rewrite$/, // ts_rewrite(tsquery, query text); the 3-arg form is banned with it
  /^crosstab/, // tablefunc: crosstab(source_sql [, category_sql]), crosstab2/3/4
  /^connectby$/, // tablefunc: builds and runs SQL from its arguments
  /^xpath_table$/, // xml2: builds and runs SQL from its arguments
  // A cheap extra layer over common non-core extensions. This list CANNOT cover every extension
  // a database may have installed; the database role's EXECUTE grants are the real boundary.
  /^query_export_to_s3$/, // aws_s3: runs a query string and writes the result to S3
  /^pgr_/, // pgRouting: most functions take an SQL string
  /^dbms_pipe/, // orafce: cross-session messaging
  /^dbms_alert/, // orafce
  /^hypopg/, // hypopg: hypothetical indexes are per-backend state on a pooled connection
  // Core functions with side effects that outlive the call or touch shared state.
  /^setseed$/, // the random() seed survives DISCARD ALL and would leak to the next caller
  /^pg_log_standby_snapshot$/,
  /^pg_restore_(relation|attribute)_stats$/, // PG 18: writes planner statistics
  /^pg_clear_.*_stats$/, // PG 18: pg_clear_relation_stats, pg_clear_attribute_stats
];

/**
 * Longest SQL accepted, in UTF-8 bytes. The parser is WASM: a 3 MB statement cost 2.2 GB RSS
 * and blocked the event loop for 5 s, and a 6 MB one ran it out of memory.
 */
export const MAX_SQL_BYTES = 256 * 1024;

/** True when the bare (unqualified) function name matches a banned pattern. Case-insensitive. */
export function isBannedFunction(name: string): boolean {
  const bare = name.toLowerCase();
  return BANNED_FUNCTION_PATTERNS.some((p) => p.test(bare));
}

/** `EXPLAIN (ANALYZE <arg>)`: only an explicit false-ish value is harmless. */
const ANALYZE_OFF = new Set(['false', 'f', 'fa', 'fal', 'fals', 'off', 'of', 'no', 'n', '0']);
function analyzeIsOff(arg: any): boolean {
  if (!arg) return false; // bare ANALYZE means true
  if (arg.Integer) return (arg.Integer.ival ?? 0) === 0; // the JSON omits a zero ival
  if (arg.String) return ANALYZE_OFF.has(String(arg.String.sval).toLowerCase());
  return false;
}

/** Only SELECT and EXPLAIN (without ANALYZE) get through. Pure function: no I/O. */
export async function checkSql(sql: string): Promise<GuardResult> {
  await ready();
  if (!sql || sql.trim() === '') return { ok: false, reason: 'SQL is empty' };
  const bytes = Buffer.byteLength(sql, 'utf8');
  if (bytes > MAX_SQL_BYTES) return { ok: false, reason: `SQL is too long (${bytes} bytes; the limit is ${MAX_SQL_BYTES})` };

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
      if (name === 'analyze' && !analyzeIsOff(opt?.DefElem?.arg)) {
        return { ok: false, reason: 'EXPLAIN ANALYZE runs the query; use plain EXPLAIN' };
      }
    }
    if (!ex.query?.SelectStmt) return { ok: false, reason: 'EXPLAIN may only wrap a SELECT' };
    body = ex.query.SelectStmt;
  } else {
    const name = Object.keys(stmt)[0] ?? 'unknown';
    return { ok: false, reason: `Only SELECT is allowed (got ${name.replace(/Stmt$/, '')})` };
  }

  const problem = walk(body);
  if (problem) return { ok: false, reason: problem };
  return { ok: true, kind, sql: canonicalSql(sql) };
}

/** A SELECT can carry these in a WITH clause (`with d as (delete ... returning *) select ...`). */
const MODIFYING_NODES = new Set(['InsertStmt', 'UpdateStmt', 'DeleteStmt', 'MergeStmt']);

const COMMENT_TOKENS = new Set(['SQL_COMMENT', 'C_COMMENT']);

/**
 * The statement text without surrounding comments and trailing semicolons, found with the
 * parser's own scanner (so quotes, E'' escapes, $tag$ bodies and nested block comments are
 * handled exactly as Postgres does). Scanner offsets are byte offsets into the UTF-8 text.
 */
export function canonicalSql(sql: string): string {
  const tokens = scanSync(sql).tokens.filter((t) => !COMMENT_TOKENS.has(t.tokenName));
  let end = tokens.length;
  while (end > 0 && tokens[end - 1].text === ';') end--;
  if (end === 0) return sql.trim();
  const buf = Buffer.from(sql, 'utf8');
  return buf.subarray(tokens[0].start, tokens[end - 1].end).toString('utf8');
}

/**
 * Scan of the AST for locking clauses, SELECT INTO and banned function calls.
 * Iterative with an explicit stack: a deeply nested expression must not be able
 * to blow the JS call stack and turn a guard check into an exception.
 */
function walk(root: any): string | null {
  const stack: any[] = [root];
  while (stack.length) {
    const node = stack.pop();
    if (node === null || typeof node !== 'object') continue;
    if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i--) stack.push(node[i]);
      continue;
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === 'lockingClause') return 'Row locks (FOR UPDATE / FOR SHARE) are not allowed';
      if (key === 'intoClause' && value) return 'SELECT INTO creates a table and is not allowed';
      if (MODIFYING_NODES.has(key)) return `Data-modifying statements are not allowed (${key.replace(/Stmt$/, '').toUpperCase()} in a WITH clause)`;
      if (key === 'FuncCall') {
        const parts: string[] = ((value as any)?.funcname ?? []).map((p: any) => p?.String?.sval ?? '');
        const bare = parts[parts.length - 1]?.toLowerCase();
        if (bare && isBannedFunction(bare)) return `Function ${bare}() is not allowed`;
      }
      stack.push(value);
    }
  }
  return null;
}
