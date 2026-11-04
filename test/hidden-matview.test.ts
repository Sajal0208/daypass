import { describe, it, expect } from 'vitest';
import { viewLeaks, suggestHidden, diffHidden } from '../src/core/hidden.js';
import { MATVIEW_LEAKS_SQL, MATVIEW_TAINT_SQL, MATVIEW_SQL_PARAMS, MATVIEW_SAFE_CATALOGS } from '../src/core/matview.js';
import * as doctor from '../src/cli/doctor.js';

const dep = (view: string, refTable: string) => ({ schema: 'public', view, refSchema: 'public', refTable, refColumn: null });

describe('viewLeaks: materialized views stored as the owner (rule e)', () => {
  const matviews = [
    { schema: 'public', view: 'mv_stats', why: 'reads pg_catalog.pg_stats' },
    { schema: 'reports', view: 'mv_xml', why: 'calls function pg_catalog.query_to_xml(text,boolean,boolean,text) through view reports.v_xml' },
  ];
  it('withholds each tainted matview, and views over it', () => {
    expect(viewLeaks([], [dep('v_over', 'mv_stats')], { matviews })).toEqual([
      { view: 'mv_stats', column: 'reads pg_catalog.pg_stats', via: null, kind: 'matview' },
      { view: 'reports.mv_xml', column: matviews[1].why, via: null, kind: 'matview' },
      { view: 'v_over', column: 'reads pg_catalog.pg_stats', via: 'mv_stats', kind: 'matview' },
    ]);
  });
  it('a hidden-column taint wins over the matview reason', () => {
    const deps = [{ schema: 'public', view: 'mv_stats', refSchema: 'public', refTable: 'customers', refColumn: 'secret' }];
    expect(viewLeaks(['customers.secret'], deps, { matviews })[0]).toEqual({ view: 'mv_stats', column: 'customers.secret', via: null });
  });
  it('suggest and check treat columns of a withheld matview as covered', () => {
    const cols = [{ table: 'mv_stats', column: 'email' }];
    expect(suggestHidden(cols)).toEqual(['mv_stats.email']);
    expect(suggestHidden(cols, { matviews })).toEqual([]);
    expect(diffHidden([], cols, [], { matviews }).sensitiveNotHidden).toEqual([]);
  });
});

describe('matview SQL lives in core', () => {
  it('doctor re-exports the same objects', () => {
    expect(doctor.MATVIEW_LEAKS_SQL).toBe(MATVIEW_LEAKS_SQL);
    expect(doctor.MATVIEW_SAFE_CATALOGS).toBe(MATVIEW_SAFE_CATALOGS);
  });
  it('both queries walk the same tree with the same rules', () => {
    for (const q of [MATVIEW_LEAKS_SQL, MATVIEW_TAINT_SQL]) {
      expect(q).toMatch(/with recursive tree\(root, rel, via\)/);
      expect(q).toMatch(/relrowsecurity/);
      expect(q).toMatch(/p\.provolatile <> 'i'/);
    }
    expect(MATVIEW_TAINT_SQL).toMatch(/has_table_privilege\('public'/);
    expect(MATVIEW_LEAKS_SQL).toMatch(/has_table_privilege\(current_user/);
    expect(MATVIEW_SQL_PARAMS).toHaveLength(3);
  });
});

describe('viewLeaks: round 2 (views over RLS tables, sequences of hidden columns)', () => {
  it('a plain view over a row-level-security table is withheld as kind rls, and views over it', () => {
    const matviews = [{ schema: 'public', view: 'notes_v', why: 'reads public.tenant_notes, which has row-level security', kind: 'v' }];
    expect(viewLeaks([], [dep('notes_nested', 'notes_v')], { matviews })).toEqual([
      { view: 'notes_v', column: matviews[0].why, via: null, kind: 'rls' },
      { view: 'notes_nested', column: matviews[0].why, via: 'notes_v', kind: 'rls' },
    ]);
  });
  it('a view over a sequence owned by a hidden column is withheld; one over another sequence is not', () => {
    const seq = (view: string, refTable: string, seqOwner: string) => ({ ...dep(view, refTable), refColumn: 'last_value', refKind: 'S', seqOwner });
    const deps = [seq('key_counter', 'accounts_api_key_id_seq', 'accounts.api_key_id'), seq('id_counter', 'accounts_id_seq', 'accounts.id'), dep('kc2', 'key_counter')];
    expect(viewLeaks(['accounts.api_key_id'], deps)).toEqual([
      { view: 'key_counter', column: 'accounts_api_key_id_seq', via: null, kind: 'sequence' },
      { view: 'kc2', column: 'accounts_api_key_id_seq', via: 'key_counter', kind: 'sequence' },
    ]);
  });
});

describe('catalog queries: round 2', () => {
  it('views that are not security_invoker are roots for the row-level-security reason', () => {
    for (const q of [MATVIEW_LEAKS_SQL, MATVIEW_TAINT_SQL]) {
      expect(q).toMatch(/c\.relkind = 'm' or not coalesce\(\(select pg_catalog\.bool_or\(o ~\* '\^security_invoker=/);
      expect(q).toMatch(/b\.kind/);
    }
  });
  it('matviews: row comparisons, conversions through text, subscripts and domain CHECKs are followed', () => {
    for (const q of [MATVIEW_LEAKS_SQL, MATVIEW_TAINT_SQL]) {
      expect(q).toContain(`':opnos [(]o ([0-9 ]+)[)]'`);
      expect(q).toContain(`'[{]COERCEVIAIO '`);
      expect(q).toContain(`':refcontainertype ([0-9]+)'`);
      expect(q).toContain(`'[{]COERCETODOMAIN '`);
    }
  });
});
