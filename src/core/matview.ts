/**
 * Materialized views store what their OWNER saw at refresh. The catalog query that finds the ones
 * whose stored rows the role could not read itself, shared by `daypass doctor` and
 * `daypass hidden suggest|check`. Mirrors rule (e) of sql/setup-role.sql. No I/O here.
 */
import { DATA_READING_FUNCTIONS } from './hidden.js';

/** Schemas a role setup never reads or writes (SQL, with `n` = pg_namespace). */
export const USER_SCHEMA = `n.nspname not in ('pg_catalog', 'information_schema') and n.nspname !~ '^pg_(toast|temp)'`;

/**
 * Catalog tables a materialized view may read: plain tables the role can read in full itself, so
 * the owner's refresh stored the same rows the role sees. Every other pg_catalog /
 * information_schema relation (pg_stats, pg_stat_activity, information_schema.tables, ...) may
 * filter rows by the caller. Same list as sql/setup-role.sql (test/setup-sql.test.ts guards that).
 */
export const MATVIEW_SAFE_CATALOGS = ['pg_namespace', 'pg_class', 'pg_attribute', 'pg_type', 'pg_index', 'pg_constraint', 'pg_inherits', 'pg_description', 'pg_enum'];

/**
 * Built-ins that are not immutable but are harmless in a materialized view: clock, date/time,
 * formatting and JSON builders. Any other non-immutable built-in (current_setting, has_*_privilege,
 * pg_stat_get_*, nextval, ...) taints the matview: it ran as the owner at refresh. Same pattern as
 * sql/setup-role.sql (test/setup-sql.test.ts guards that).
 */
export const MATVIEW_SAFE_FUNCTIONS =
  /^(now|transaction_timestamp|statement_timestamp|clock_timestamp|timeofday|random|gen_random_uuid|date_trunc|date_part|date_bin|extract|to_char|to_timestamp|to_date|age|timezone|generate_series|concat|concat_ws|format|array_to_string|to_json|to_jsonb|row_to_json|array_to_json|json_build_object|json_build_array|jsonb_build_object|jsonb_build_array|json_object_agg|jsonb_object_agg|json_agg|jsonb_agg|textanycat|anytextcat|date|timestamptz|timestamp|time|timetz|(timestamptz|timestamp|date|time|timetz|interval)_[a-z0-9_]+)$/;

/** The parameters MATVIEW_LEAKS_SQL and MATVIEW_TAINT_SQL take, in order ($1, $2, $3). */
export const MATVIEW_SQL_PARAMS: unknown[] = [DATA_READING_FUNCTIONS.source, MATVIEW_SAFE_FUNCTIONS.source, MATVIEW_SAFE_CATALOGS];

/**
 * SQL (with `c` = pg_class): a view that reads its tables as the caller (security_invoker,
 * PostgreSQL 15+). Postgres stores the option as written (`on`, `TRUE`, ...).
 */
export const SECURITY_INVOKER = `coalesce((select pg_catalog.bool_or(o ~* '^security_invoker=(t|tr|tru|true|y|ye|yes|on|1)$') from pg_catalog.unnest(c.reloptions) o), false)`;

/**
 * `tree`: every view and matview in a user schema (root) and each relation its rule reads, through
 * every view or matview it reads, recursively. `bad`: per root, the first reason its rows are the
 * owner's. A matview root: the tree reaches a catalog that may filter by caller (a safe-listed
 * catalog table counts only when `grantee` can read it), a table with row-level security, a
 * function outside pg_catalog (also behind an operator, a row comparison, a domain CHECK), a
 * data-reading built-in, a non-immutable built-in outside the safe list, a conversion through text
 * with a type whose I/O functions are outside pg_catalog, or a subscript whose handler is. A plain
 * view root that is not security_invoker: the tree reaches a table with row-level security (the
 * view reads it with its owner's rights). `kind` is the root's relkind ('m' or 'v').
 * `grantee` is SQL: current_user (doctor, run as the role) or 'public' (hidden, run as the owner).
 */
function matviewCte(grantee: string): string {
  const rule = `
    join pg_catalog.pg_class c on c.oid = t.rel and c.relkind in ('v','m')
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace and n.nspname not in ('pg_catalog', 'information_schema')
    join pg_catalog.pg_rewrite rw on rw.ev_class = c.oid and rw.ev_type = '1'`;
  return `
with recursive tree(root, rel, via) as (
  select c.oid, c.oid, c.oid from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace
   where c.relkind in ('v','m') and ${USER_SCHEMA}
  union
  select t.root, f[1]::oid, t.rel
    from tree t
    join pg_catalog.pg_class c on c.oid = t.rel and c.relkind in ('v','m')
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace and n.nspname not in ('pg_catalog', 'information_schema')
    join pg_catalog.pg_rewrite rw on rw.ev_class = c.oid and rw.ev_type = '1',
    pg_catalog.regexp_matches(rw.ev_action::text, ':relid ([0-9]+)', 'g') f
   where f[1]::oid <> c.oid
), mvtree as (
  select t.* from tree t join pg_catalog.pg_class m on m.oid = t.root and m.relkind = 'm'
), why as (
  select t.root as mv, t.via, 1 as o, pg_catalog.format('reads %I.%I', tn.nspname, tc.relname) as what
    from mvtree t
    join pg_catalog.pg_class tc on tc.oid = t.rel join pg_catalog.pg_namespace tn on tn.oid = tc.relnamespace
   where tn.nspname in ('pg_catalog', 'information_schema')
     and not (tn.nspname = 'pg_catalog' and tc.relkind = 'r' and pg_catalog.has_table_privilege(${grantee}, tc.oid, 'SELECT')
              and tc.relname = any($3::text[]))
  union all
  select t.root, t.via, 2, pg_catalog.format('reads %s, which has row-level security', tc.oid::pg_catalog.regclass)
    from tree t join pg_catalog.pg_class c on c.oid = t.root and (c.relkind = 'm' or not ${SECURITY_INVOKER})
    join pg_catalog.pg_class tc on tc.oid = t.rel
   where tc.relkind in ('r','p') and tc.relrowsecurity
  union all
  select t.root, t.rel, 3, 'calls function ' || case when pn.nspname = 'pg_catalog' then 'pg_catalog.' else '' end || p.oid::pg_catalog.regprocedure::text
    from mvtree t${rule},
    lateral (select f[2]::oid as fn from pg_catalog.regexp_matches(rw.ev_action::text, ':(funcid|opfuncid|aggfnoid|winfnoid) ([0-9]+)', 'g') f
             union
             select o.oprcode::oid from pg_catalog.regexp_matches(rw.ev_action::text, ':(opno|sortop|eqop) ([0-9]+)', 'g') g
               join pg_catalog.pg_operator o on o.oid = g[2]::oid
             union
             select o.oprcode::oid from pg_catalog.regexp_matches(rw.ev_action::text, ':opnos [(]o ([0-9 ]+)[)]', 'g') l,
               pg_catalog.unnest(pg_catalog.string_to_array(l[1], ' ')) u join pg_catalog.pg_operator o on o.oid = u::oid
             union
             select case when k[1] in ('opno', 'sortop', 'eqop') then (select o.oprcode::oid from pg_catalog.pg_operator o where o.oid = k[2]::oid) else k[2]::oid end
               from pg_catalog.regexp_matches(rw.ev_action::text, ':resulttype ([0-9]+)', 'g') dt
               join pg_catalog.pg_constraint dc on dc.contypid = dt[1]::oid and dc.conbin is not null,
               pg_catalog.regexp_matches(dc.conbin::text, ':(funcid|opfuncid|opno) ([0-9]+)', 'g') k
              where rw.ev_action::text ~ '[{]COERCETODOMAIN ') x
    join pg_catalog.pg_proc p on p.oid = x.fn join pg_catalog.pg_namespace pn on pn.oid = p.pronamespace
   where pn.nspname <> 'pg_catalog' or p.proname ~ $1 or (p.provolatile <> 'i' and p.proname !~ $2)
  union all
  select t.root, t.rel, 4, pg_catalog.format('converts values through text with type %s, whose input/output functions are outside pg_catalog', bt.top::pg_catalog.regtype)
    from mvtree t${rule} and rw.ev_action::text ~ '[{]COERCEVIAIO ',
    lateral (with recursive ty(oid, top) as (
               select m[1]::oid, m[1]::oid from pg_catalog.regexp_matches(rw.ev_action::text, ':[a-z_]*type ([0-9]+)', 'g') m
               union
               select x.oid, ty.top
                 from ty join pg_catalog.pg_type y on y.oid = ty.oid,
                 lateral (select y.typelem union select y.typbasetype
                          union select rg.rngsubtype from pg_catalog.pg_range rg where rg.rngtypid = y.oid
                          union select a.atttypid from pg_catalog.pg_attribute a where a.attrelid = y.typrelid and a.attnum > 0) x(oid)
                where x.oid <> 0)
             select distinct ty.top from ty join pg_catalog.pg_type y on y.oid = ty.oid
              where exists (select 1 from pg_catalog.pg_proc p join pg_catalog.pg_namespace pn on pn.oid = p.pronamespace
                             where p.oid = any (array[y.typinput, y.typoutput, y.typreceive, y.typsend]::oid[])
                               and pn.nspname <> 'pg_catalog')) bt
  union all
  select t.root, t.rel, 5, pg_catalog.format('subscripts type %s, whose subscript handler is outside pg_catalog', y.oid::pg_catalog.regtype)
    from mvtree t${rule},
    pg_catalog.regexp_matches(rw.ev_action::text, ':refcontainertype ([0-9]+)', 'g') sr
    join pg_catalog.pg_type y on y.oid = sr[1]::oid
   where (pg_catalog.to_jsonb(y) ->> 'typsubscript') ~ '[.]'
), bad as (
  select distinct on (w.mv) w.mv, w.o, (select relkind::text from pg_catalog.pg_class where oid = w.mv) as kind,
         w.what || case when w.via <> w.mv then ' through view ' || w.via::pg_catalog.regclass::text else '' end as why
    from why w order by w.mv, w.o, w.what
)`;
}

/**
 * Readable views and materialized views whose rows are the owner's: the view itself (a matview
 * stored them, or a plain view read a row-level-security table with its owner's rights), or a view
 * over such a one. Run as the role. Params: MATVIEW_SQL_PARAMS. Rows: rel, mv, why, kind (of mv).
 */
export const MATVIEW_LEAKS_SQL = `${matviewCte('current_user')}
select distinct on (t.root) t.root::pg_catalog.regclass::text as rel, b.mv::pg_catalog.regclass::text as mv, b.why, b.kind
  from tree t join bad b on b.mv = t.rel
 where pg_catalog.has_any_column_privilege(current_user, t.root, 'SELECT')
 order by t.root, b.mv`;

/**
 * Every materialized view in a user schema whose stored rows are the owner's, whoever can read it,
 * and every plain view that reads a row-level-security table with its owner's rights: what the
 * setup withholds under rule (e). Run as the owner, so a safe-listed catalog table counts when
 * PUBLIC can read it. Params: MATVIEW_SQL_PARAMS. Rows: schema, view, why, kind ('m' or 'v').
 */
export const MATVIEW_TAINT_SQL = `${matviewCte(`'public'`)}
select n.nspname as schema, c.relname as view, b.why, b.kind
  from bad b join pg_catalog.pg_class c on c.oid = b.mv join pg_catalog.pg_namespace n on n.oid = c.relnamespace
 order by 1, 2`;

/**
 * Readable views and materialized views that read, with their OWNER's rights, a relation the role
 * cannot read at all (a sequence the setup withheld, a table granted to nobody, a foreign table).
 * One level is enough: a view in between that the role cannot read is itself such a relation.
 * security_invoker views read as the caller and are skipped. Run as the role. Rows: rel, ref.
 */
export const UNREADABLE_SOURCES_SQL = `
select distinct v.oid::pg_catalog.regclass::text as rel, t.oid::pg_catalog.regclass::text as ref
  from pg_catalog.pg_depend d join pg_catalog.pg_rewrite rw on rw.oid = d.objid
  join pg_catalog.pg_class v on v.oid = rw.ev_class join pg_catalog.pg_namespace vn on vn.oid = v.relnamespace
  join pg_catalog.pg_class t on t.oid = d.refobjid join pg_catalog.pg_namespace n on n.oid = t.relnamespace
 where d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass and d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
   and rw.ev_type = '1' and rw.ev_class <> d.refobjid
   and vn.nspname not in ('pg_catalog', 'information_schema') and vn.nspname !~ '^pg_(toast|temp)'
   and ${USER_SCHEMA} and t.relkind in ('r','p','v','m','f','S')
   and (v.relkind = 'm' or not ${SECURITY_INVOKER.replace(/\bc\.reloptions/, 'v.reloptions')})
   and pg_catalog.has_any_column_privilege(current_user, v.oid, 'SELECT')
   and not case when t.relkind = 'S' then pg_catalog.has_sequence_privilege(current_user, t.oid, 'SELECT')
                else pg_catalog.has_any_column_privilege(current_user, t.oid, 'SELECT') end
 order by 1, 2`;
