import { describe, it, expect } from 'vitest';
import { checkSql, BANNED_FUNCTION_PATTERNS, isBannedFunction, MAX_SQL_BYTES } from '../src/core/guard.js';
import { parseSync } from 'libpg-query';

const bad = async (sql: string, reason: RegExp) => {
  const r = await checkSql(sql);
  expect(r.ok).toBe(false);
  if (!r.ok) expect(r.reason).toMatch(reason);
};
const ok = async (sql: string) => expect(await checkSql(sql)).toMatchObject({ ok: true });

describe('banned function patterns', () => {
  it('are exported as regexes', () => {
    expect(BANNED_FUNCTION_PATTERNS.length).toBeGreaterThan(10);
    for (const p of BANNED_FUNCTION_PATTERNS) expect(p).toBeInstanceOf(RegExp);
  });
  it.each([
    'query_to_xml',
    'query_to_xml_and_xmlschema',
    'query_to_xmlschema',
    'cursor_to_xml',
    'cursor_to_xmlschema',
    'pg_advisory_lock',
    'pg_advisory_lock_shared',
    'pg_advisory_xact_lock_shared',
    'pg_try_advisory_lock_shared',
    'pg_try_advisory_xact_lock',
    'dblink',
    'dblink_connect_u',
    'dblink_get_connections',
    'lo_import',
    'lo_from_bytea',
    'lowrite',
    'loread',
    'pg_ls_dir',
    'pg_ls_waldir',
    'pg_ls_logdir',
    'pg_stat_reset',
    'pg_stat_reset_shared',
    'pg_create_physical_replication_slot',
    'pg_drop_replication_slot',
    'pg_wal_replay_pause',
    'pg_promote',
    'pg_rotate_logfile',
    'pg_log_backend_memory_contexts',
    'pg_sleep',
    'pg_sleep_for',
    'pg_sleep_until',
    'pg_read_file',
    'pg_read_binary_file',
    'pg_stat_file',
    'set_config',
    'nextval',
    'setval',
    'pg_terminate_backend',
    'pg_cancel_backend',
    'pg_reload_conf',
    'pg_notify',
    'pg_logical_emit_message',
    'pg_create_restore_point',
    'pg_switch_wal',
    'pg_backup_start',
    'pg_backup_stop',
    'pg_start_backup', // PG <= 14 names
    'pg_stop_backup',
    'brin_summarize_new_values',
    'brin_desummarize_range',
    'gin_clean_pending_list',
    'txid_current',
    'pg_current_xact_id',
  ])('bans %s', (fn) => {
    expect(isBannedFunction(fn)).toBe(true);
    expect(isBannedFunction(fn.toUpperCase())).toBe(true);
  });
  it.each(['now', 'count', 'lower', 'pg_typeof', 'pg_size_pretty', 'pg_total_relation_size', 'has_column_privilege', 'generate_series', 'to_jsonb', 'length', 'pg_get_indexdef', 'txid_current_snapshot', 'pg_current_wal_lsn'])(
    'allows %s',
    (fn) => expect(isBannedFunction(fn)).toBe(false),
  );
  it('catches schema-qualified and mixed-case calls', async () => {
    await bad("select pg_catalog.Query_To_XML('select 1', true, false, '')", /query_to_xml/i);
    await bad('select PG_TRY_ADVISORY_LOCK_SHARED(42)', /pg_try_advisory_lock_shared/i);
  });
  it('catches a banned call inside a FROM clause', () => bad("select * from pg_ls_waldir()", /pg_ls_waldir/i));
});

describe('EXPLAIN ANALYZE option argument', () => {
  it('allows (ANALYZE false)', () => ok('explain (analyze false) select 1'));
  it('allows (ANALYZE off)', () => ok('explain (analyze off) select 1'));
  it('allows (ANALYZE 0)', () => ok('explain (analyze 0) select 1'));
  it('allows (ANALYZE no, FORMAT JSON)', () => ok('explain (analyze no, format json) select 1'));
  it('refuses (ANALYZE)', () => bad('explain (analyze) select 1', /analyze/i));
  it('refuses (ANALYZE true)', () => bad('explain (analyze true) select 1', /analyze/i));
  it('refuses (ANALYZE on)', () => bad('explain (analyze on) select 1', /analyze/i));
  it('refuses (ANALYZE 1)', () => bad('explain (analyze 1) select 1', /analyze/i));
  it('refuses (ANALYZE yes)', () => bad('explain (analyze yes) select 1', /analyze/i));
  it('refuses (ANALYZE off, ANALYZE)', () => bad('explain (analyze off, analyze) select 1', /analyze/i));
  it('refuses an unknown argument value', () => bad("explain (analyze 'maybe') select 1", /analyze/i));
});

describe('deep nesting', () => {
  it('does not throw on 1000 nested NOTs', async () => {
    const sql = 'select ' + 'not '.repeat(1000) + 'true';
    const r = await checkSql(sql);
    expect(r.ok).toBe(true);
  });
  it('still finds a banned call under deep nesting', async () => {
    const sql = 'select ' + '('.repeat(500) + 'pg_sleep(1)' + ')'.repeat(500);
    await bad(sql, /pg_sleep/i);
  });
});

// Review 2026-10-30 (second pass): every function that runs SQL handed to it as a string (or runs
// SPI over whole relations) must be banned, or it is a full escape from the guard.
describe('functions that execute SQL from a string', () => {
  it.each([
    'ts_stat', // ts_stat(query text [, weights])
    'ts_rewrite', // ts_rewrite(tsquery, query text)
    'table_to_xml',
    'table_to_xmlschema',
    'table_to_xml_and_xmlschema',
    'schema_to_xml',
    'schema_to_xmlschema',
    'schema_to_xml_and_xmlschema',
    'database_to_xml',
    'database_to_xmlschema',
    'database_to_xml_and_xmlschema',
    'crosstab', // tablefunc
    'crosstab2',
    'crosstab3',
    'crosstab4',
    'connectby',
    'xpath_table', // xml2
    'dblink_exec',
  ])('bans %s', (fn) => expect(isBannedFunction(fn)).toBe(true));
  it('refuses the ts_stat escape seen in review', () =>
    bad("select * from ts_stat('select to_tsvector(pg_sleep(3)::text)')", /ts_stat/));
  it('refuses the ts_stat set_config escape seen in review', () =>
    bad("select * from ts_stat($$select to_tsvector(set_config('standard_conforming_strings','off',false))$$)", /ts_stat/));
  it('refuses ts_rewrite with a query string', () =>
    bad("select ts_rewrite('a'::tsquery, 'select ''a''::tsquery, ''b''::tsquery from (select pg_sleep(2)) s')", /ts_rewrite/));
  it('refuses database_to_xml and table_to_xml', async () => {
    await bad("select database_to_xml(true,false,'')", /database_to_xml/);
    await bad("select table_to_xml('customers', true, false, '')", /table_to_xml/);
  });
});

describe('logical decoding and adminpack', () => {
  it.each([
    'pg_logical_slot_get_changes',
    'pg_logical_slot_get_binary_changes',
    'pg_logical_slot_peek_changes',
    'pg_logical_slot_peek_binary_changes',
    'pg_replication_slot_advance',
    'pg_file_write',
    'pg_file_unlink',
    'pg_file_rename',
    'pg_file_sync',
    'pg_logdir_ls',
  ])('bans %s', (fn) => expect(isBannedFunction(fn)).toBe(true));
});

describe('data-modifying statements nested in a SELECT', () => {
  it('refuses a DELETE in a CTE', () => bad('with d as (delete from notes returning *) select * from d', /modif/i));
  it('refuses an UPDATE in a CTE', () => bad("with u as (update notes set body = 'x' returning id) select id from u", /modif/i));
  it('refuses an INSERT in a CTE', () => bad("with i as (insert into notes (body) values ('x') returning id) select id from i", /modif/i));
  it('refuses a data-modifying CTE under EXPLAIN', () => bad('explain with d as (delete from notes returning *) select * from d', /modif/i));
  it('refuses a data-modifying CTE nested in a subquery CTE', () =>
    bad('with a as (with d as (delete from notes returning id) select id from d) select * from a', /modif/i));
  it('allows a plain read-only CTE', () => ok('with a as (select 1 as x) select x from a'));
});

// Review 2026-10-30 (third pass).
describe('extra bans (cheap layer over non-core extensions)', () => {
  it.each([
    'query_export_to_s3', // aws_s3
    'pgr_dijkstra', // pgRouting runs SQL from strings
    'pgr_astar',
    'dbms_pipe_send_message', // orafce
    'dbms_alert_signal',
    'setseed', // the seed survives DISCARD ALL and would leak into the next caller's random()
    'pg_log_standby_snapshot',
    'pg_restore_relation_stats',
    'pg_restore_attribute_stats',
    'pg_clear_relation_stats',
    'pg_clear_attribute_stats',
    'hypopg_create_index',
    'hypopg_reset',
  ])('bans %s', (fn) => expect(isBannedFunction(fn)).toBe(true));
  it('still allows random()', () => expect(isBannedFunction('random')).toBe(false));
});

describe('SQL size cap', () => {
  it('is 256 KiB', () => expect(MAX_SQL_BYTES).toBe(256 * 1024));
  it('refuses SQL over the cap before parsing', async () => {
    const sql = 'select ' + Array(200_000).fill('1').join(',');
    const t0 = Date.now();
    await bad(sql, /too long.*262144/i);
    expect(Date.now() - t0).toBeLessThan(200);
  });
  it('counts bytes, not characters', async () => {
    const sql = "select '" + 'é'.repeat(140_000) + "'"; // 140k chars, 280k bytes
    await bad(sql, /too long/i);
  });
  it('accepts SQL just under the cap', async () => {
    const sql = "select '" + 'x'.repeat(MAX_SQL_BYTES - 20) + "'";
    expect((await checkSql(sql)).ok).toBe(true);
  });
});

describe('guard regressions (fail closed)', () => {
  it('refuses a NUL byte, including one hiding a second statement', () => bad('select 1\u0000; select pg_sleep(1)', /NUL/));
  it('lone surrogates do not hide a banned call', async () => {
    await bad("select 'A\ud800', pg_sleep(3), '\ud800'", /pg_sleep/);
    await bad("select 'A\ud800', set_config('daypass.pwn','1',false), '\ud800'", /set_config/);
  });
  it('20k nested + fails closed instead of throwing', async () => {
    const r = await checkSql('select ' + Array(20_000).fill('1').join('+'));
    expect(r.ok).toBe(false);
  });
  it('still works after the parser runs out of memory', async () => {
    // Straight to the parser (the size cap keeps checkSql from ever getting this far).
    try {
      parseSync('select ' + Array(6_000_000).fill('1').join(','));
    } catch {
      /* expected: libpg_query terminated */
    }
    await bad('select pg_sleep(1)', /pg_sleep/);
    expect(await checkSql('select 1 as one')).toMatchObject({ ok: true });
  }, 60_000);
});
