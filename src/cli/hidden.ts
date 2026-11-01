import { Command } from 'commander';
import { promises as fs } from 'node:fs';
import pg from 'pg';
import { canonicalEntries, diffHidden, parseHiddenEntry, parseHiddenFile, parsePrismaColumns, suggestHidden, viewLeaks, HIDDEN_RELKINDS } from '../core/hidden.js';
import type { ColumnInfo, GeneratedDep, RelDep, RelParent, RuleRef } from '../core/hidden.js';
import { readConfig, resolveTarget, getPool, closePool } from '../mcp/index.js';
import { rdsCa, isRdsHost } from '../mcp/db.js';

/** Where the column list comes from. Exactly one must be given. */
interface SourceOpts {
  prisma?: string;
  live?: string;
  url?: string;
  /** Comma-separated. Unset means: the target's configured schemas (--live) or public (--url). */
  schemas?: string;
}

/** What the catalog looks like from the list's point of view: columns, view → column edges, partition/child → parent edges. */
export interface Catalog {
  cols: ColumnInfo[];
  deps: RelDep[];
  inherits: RelParent[];
  generated: GeneratedDep[];
  refs: RuleRef[];
  /** The schemas that were scanned (a Prisma schema is public only). */
  schemas: string[];
}

/**
 * Every column of every table, partitioned table, view and materialized view in the given
 * schemas, regardless of grants. pg_attribute, not information_schema.columns (which omits
 * matviews): the same "exists" as sql/setup-role.sql.
 */
const CATALOG_SQL = `
SELECT n.nspname AS schema, c.relname AS table, a.attname AS column, pg_catalog.format_type(a.atttypid, a.atttypmod) AS type
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN (${HIDDEN_RELKINDS.map((k) => `'${k}'`).join(',')}) AND a.attnum > 0 AND NOT a.attisdropped AND n.nspname = ANY($1)
ORDER BY 1,2,3`;

/**
 * Which (relation, column) each view's or matview's ON SELECT rule (ev_type '1') reads, for every
 * view in the given schemas plus every view anywhere that reads a relation in them (a view in
 * another schema can still leak a hidden column to whoever can read it). refobjsubid 0 is a whole-
 * relation dependency, kept so nested views can be followed; with a whole-row Var in the rule
 * (whole_row) it exposes every column. Same tests as sql/setup-role.sql.
 */
const DEPS_SQL = `
SELECT vn.nspname AS schema, v.relname AS view, rn.nspname AS ref_schema, t.relname AS ref_table,
       CASE WHEN d.refobjsubid > 0 THEN a.attname END AS ref_column,
       (d.refobjsubid = 0 AND rw.ev_action::text ~ ':varattno 0 ') AS whole_row,
       t.relkind::text AS ref_kind
FROM pg_catalog.pg_depend d
JOIN pg_catalog.pg_rewrite rw ON rw.oid = d.objid
JOIN pg_catalog.pg_class v ON v.oid = rw.ev_class
JOIN pg_catalog.pg_namespace vn ON vn.oid = v.relnamespace
JOIN pg_catalog.pg_class t ON t.oid = d.refobjid
JOIN pg_catalog.pg_namespace rn ON rn.oid = t.relnamespace
LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid AND d.refobjsubid > 0
WHERE d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.refclassid = 'pg_catalog.pg_class'::regclass AND rw.ev_type = '1'
  AND rw.ev_class <> d.refobjid AND (vn.nspname = ANY($1) OR rn.nspname = ANY($1))
ORDER BY 1,2,3,4,5`;

/** Partition and inheritance edges touching the given schemas; the setup hides a listed column on every descendant. */
const INHERITS_SQL = `
SELECT cn.nspname AS schema, c.relname AS table, pn.nspname AS parent_schema, p.relname AS parent_table
FROM pg_catalog.pg_inherits i
JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid JOIN pg_catalog.pg_namespace cn ON cn.oid = c.relnamespace
JOIN pg_catalog.pg_class p ON p.oid = i.inhparent JOIN pg_catalog.pg_namespace pn ON pn.oid = p.relnamespace
WHERE cn.nspname = ANY($1) OR pn.nspname = ANY($1)
ORDER BY 1,2,3,4`;

/**
 * Generated columns and the column each is computed from (the setup refuses one derived from a
 * hidden column). Up to PG 15 pg_depend links column to column; from PG 16 it links the
 * generation expression (pg_attrdef) to the source column.
 */
const GENERATED_SQL = `
SELECT DISTINCT n.nspname AS schema, c.relname AS table, ga.attname AS column, ha.attname AS from_column
FROM (SELECT d.objid AS relid, d.objsubid AS attnum, d.refobjsubid AS refattnum
        FROM pg_catalog.pg_depend d
       WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.refclassid = 'pg_catalog.pg_class'::regclass
         AND d.objsubid > 0 AND d.refobjsubid > 0 AND d.objid = d.refobjid
      UNION
      SELECT ad.adrelid, ad.adnum, d.refobjsubid
        FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_attrdef ad ON ad.oid = d.objid
       WHERE d.classid = 'pg_catalog.pg_attrdef'::regclass AND d.refclassid = 'pg_catalog.pg_class'::regclass
         AND d.refobjid = ad.adrelid AND d.refobjsubid > 0 AND d.refobjsubid <> ad.adnum) g
JOIN pg_catalog.pg_class c ON c.oid = g.relid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute ga ON ga.attrelid = g.relid AND ga.attnum = g.attnum AND ga.attgenerated <> ''
JOIN pg_catalog.pg_attribute ha ON ha.attrelid = g.relid AND ha.attnum = g.refattnum
WHERE n.nspname = ANY($1)
ORDER BY 1,2,3,4`;

/**
 * Functions and catalog relations each view's stored rule names. Built-ins and catalogs are
 * pinned, so pg_depend does not record them; the oids come from pg_rewrite.ev_action, as in
 * sql/setup-role.sql. public_readable: can PUBLIC (so the role) SELECT the relation itself?
 */
const RULE_REFS_SQL = `
SELECT vn.nspname AS schema, v.relname AS view, v.relkind::text AS view_kind, 'function' AS ref_type,
       pn.nspname AS ref_schema, p.proname AS ref_name, NULL::boolean AS public_readable
FROM pg_catalog.pg_rewrite rw JOIN pg_catalog.pg_class v ON v.oid = rw.ev_class JOIN pg_catalog.pg_namespace vn ON vn.oid = v.relnamespace,
     pg_catalog.regexp_matches(rw.ev_action::text, ':(funcid|opfuncid|aggfnoid|winfnoid) ([0-9]+)', 'g') f
JOIN pg_catalog.pg_proc p ON p.oid = f[2]::oid JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
WHERE rw.ev_type = '1' AND v.relkind IN ('v','m') AND vn.nspname = ANY($1)
UNION
SELECT vn.nspname, v.relname, v.relkind::text, 'relation', tn.nspname, t.relname, pg_catalog.has_table_privilege('public', t.oid, 'SELECT')
FROM pg_catalog.pg_rewrite rw JOIN pg_catalog.pg_class v ON v.oid = rw.ev_class JOIN pg_catalog.pg_namespace vn ON vn.oid = v.relnamespace,
     pg_catalog.regexp_matches(rw.ev_action::text, ':relid ([0-9]+)', 'g') f
JOIN pg_catalog.pg_class t ON t.oid = f[1]::oid JOIN pg_catalog.pg_namespace tn ON tn.oid = t.relnamespace
WHERE rw.ev_type = '1' AND v.relkind IN ('v','m') AND vn.nspname = ANY($1) AND t.oid <> v.oid
  AND tn.nspname IN ('pg_catalog', 'information_schema')
ORDER BY 1,2,4,5,6`;

/**
 * Catalog reads run with search_path pinned to pg_catalog (and every name qualified), so a role
 * with CREATE somewhere cannot answer them with look-alike objects or operators.
 */
export const PIN_SEARCH_PATH = 'SET search_path = pg_catalog, pg_temp';

function parseSchemas(s: string | undefined, fallback: string[]): string[] {
  const schemas = s === undefined ? fallback : s.split(',').map((x) => x.trim()).filter(Boolean);
  if (!schemas.length) throw new Error('--schemas must name at least one schema');
  return schemas;
}

/** The catalog shape for `schemas`, over any query runner (a pool, a client). Used by `hidden` and `doctor`. */
export async function catalog(run: (sql: string, params: unknown[]) => Promise<pg.QueryResult>, schemas: string[]): Promise<Catalog> {
  const c = await run(CATALOG_SQL, [schemas]);
  const d = await run(DEPS_SQL, [schemas]);
  const i = await run(INHERITS_SQL, [schemas]);
  const g = await run(GENERATED_SQL, [schemas]);
  const rr = await run(RULE_REFS_SQL, [schemas]);
  return {
    cols: c.rows.map((row) => ({ schema: row.schema, table: row.table, column: row.column, type: row.type })),
    deps: d.rows.map((row) => ({
      schema: row.schema, view: row.view, refSchema: row.ref_schema, refTable: row.ref_table, refColumn: row.ref_column ?? null, wholeRow: row.whole_row === true,
      refKind: row.ref_kind,
    })),
    generated: g.rows.map((row) => ({ schema: row.schema, table: row.table, column: row.column, fromColumn: row.from_column })),
    refs: rr.rows.map((row) => ({
      schema: row.schema, view: row.view, viewKind: row.view_kind, refType: row.ref_type, refSchema: row.ref_schema, refName: row.ref_name,
      ...(row.public_readable === null ? {} : { publicReadable: row.public_readable }),
    })),
    inherits: i.rows.map((row) => ({ schema: row.schema, table: row.table, parentSchema: row.parent_schema, parentTable: row.parent_table })),
    schemas,
  };
}

/** Same connection path as the MCP server: config target, IAM token or password, pinned/verified TLS. */
async function liveCatalog(targetName: string, schemasOpt: string | undefined): Promise<Catalog> {
  const cfg = await readConfig();
  const raw = cfg.targets[targetName];
  if (!raw) throw new Error(`Unknown target "${targetName}". Known: ${Object.keys(cfg.targets).join(', ')}`);
  const t = resolveTarget(targetName, raw);
  const schemas = parseSchemas(schemasOpt, t.schemas ?? ['public']);
  const pool = await getPool(targetName, t);
  try {
    const client = await pool.connect();
    try {
      await client.query(PIN_SEARCH_PATH);
      return await catalog((sql, params) => client.query(sql, params), schemas);
    } finally {
      client.release(true);
    }
  } finally {
    await closePool();
  }
}

/**
 * Plain client on a URL (typically the owner URL used for `daypass sql | psql`). TLS follows the
 * URL-target rule: `sslmode=disable` turns it off, anything else is verified; an RDS host pins the
 * bundled RDS CA like an IAM target does. The URL is parsed into explicit fields so a
 * `sslmode=no-verify` in it cannot weaken that.
 */
async function urlCatalog(url: string, schemasOpt: string | undefined): Promise<Catalog> {
  const schemas = parseSchemas(schemasOpt, ['public']);
  const u = new URL(url.replace(/^postgresql:/, 'postgres:'));
  const ca = isRdsHost(u.hostname) ? rdsCa() : undefined;
  const ssl = u.searchParams.get('sslmode') === 'disable' ? false : { rejectUnauthorized: true as const, ...(ca ? { ca } : {}) };
  const client = new pg.Client({
    host: u.hostname,
    port: u.port ? Number(u.port) : 5432,
    database: u.pathname.replace(/^\//, '') || undefined,
    user: u.username ? decodeURIComponent(u.username) : undefined,
    password: u.password ? decodeURIComponent(u.password) : undefined,
    ssl,
    application_name: 'daypass',
    connectionTimeoutMillis: 10_000,
  });
  await client.connect();
  try {
    await client.query(PIN_SEARCH_PATH);
    return await catalog((sql, params) => client.query(sql, params), schemas);
  } finally {
    await client.end().catch(() => {});
  }
}

async function loadCatalog(opts: SourceOpts): Promise<Catalog> {
  const given = [opts.prisma, opts.live, opts.url].filter((x) => x !== undefined).length;
  if (given !== 1) throw new Error('give exactly one of --prisma <schema.prisma>, --live <target>, --url <postgres url>');
  // A Prisma schema has no views, so there is nothing to follow.
  if (opts.prisma) return { cols: parsePrismaColumns(await fs.readFile(opts.prisma, 'utf8')), deps: [], inherits: [], generated: [], refs: [], schemas: ['public'] };
  if (opts.live) return liveCatalog(opts.live, opts.schemas);
  return urlCatalog(opts.url!, opts.schemas);
}

function withSource(cmd: Command): Command {
  return cmd
    .option('--prisma <schema.prisma>', 'read columns from a Prisma schema')
    .option('--live <target>', 'read columns from a configured target (connects like the MCP server)')
    .option('--url <postgres url>', 'read columns from any Postgres URL')
    .option('--schemas <list>', "comma-separated schemas to scan (--live/--url only; default: the target's schemas, else public)");
}

export function hiddenCommand(): Command {
  const hidden = new Command('hidden').description('Generate or verify the hidden-columns list used by daypass sql --hide-file');

  withSource(
    hidden
      .command('suggest')
      .description('Print sensitive-looking columns as table.column (schema-prefixed outside public, quoted when needed; redirect to hidden-columns.txt)'),
  ).action(
    async (opts: SourceOpts) => {
      const { cols: all, deps, inherits, generated, refs, schemas } = await loadCatalog(opts);
      const cols = suggestHidden(all, { deps, inherits, generated, refs, schemas: opts.prisma ? undefined : schemas });
      console.error(`daypass hidden suggest: ${cols.length} of ${all.length} columns flagged`);
      const lines = [
        `# Suggested by daypass hidden suggest on ${new Date().toISOString()}. Review this list, then:`,
        '#   daypass sql --hide-file <this file> | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1',
        ...cols,
      ];
      process.stdout.write(lines.join('\n') + '\n');
    },
  );

  withSource(
    hidden
      .command('check')
      .description('Verify a hidden-columns list against the schema; exit 1 when it has drifted')
      .requiredOption('--file <hidden-columns.txt>', 'the list to verify (lines starting with ! are reviewed, intentionally visible columns)'),
  ).action(async (opts: SourceOpts & { file: string }) => {
    const { hidden: list, allow } = parseHiddenFile(await fs.readFile(opts.file, 'utf8'));
    const { cols, deps, inherits, generated, refs, schemas } = await loadCatalog(opts);
    const shape = { deps, inherits, generated, refs, schemas: opts.prisma ? undefined : schemas };
    const { missingFromSchema, sensitiveNotHidden, conflicts, childOnly, derived } = diffHidden(list, cols, allow, shape);
    const hiddenCount = new Set(canonicalEntries(list)).size;
    // Informational: the setup grants these views nothing, which is the point of hiding the column.
    const leaks = viewLeaks(list, deps, { schemas: shape.schemas, refs });
    if (leaks.length) {
      console.log(`Views the setup withholds (${leaks.length}):`);
      for (const l of leaks) {
        const what = (l.kind ? {
          foreign: `reads foreign table ${l.column}`,
          schema: `reads ${l.column}, outside --schemas`,
          function: `calls function ${l.column} (a materialized view stores what the owner could read)`,
          catalog: `reads ${l.column}, which the role cannot read itself`,
        }[l.kind] : undefined) ?? `exposes hidden column ${l.column}`;
        console.log(`  view ${l.view} ${what}${l.via ? ` through view ${l.via}` : ''}`);
      }
    }
    if (!missingFromSchema.length && !sensitiveNotHidden.length && !conflicts.length && !childOnly.length && !derived.length) {
      console.log(`hidden list matches the schema (${hiddenCount} hidden, ${cols.length} columns scanned)`);
      return;
    }
    if (conflicts.length) {
      console.log(`Columns both hidden and !allowed - keep one line per column (${conflicts.length}):`);
      for (const c of conflicts) console.log(`  ${c}`);
    }
    if (derived.length) {
      console.log(`Generated from a hidden column - hide these too (${derived.length}):`);
      for (const d of derived) console.log(`  ${d.entry} (generated from ${d.from})`);
    }
    if (childOnly.length) {
      console.log(`Hidden on a partition/child only - the parent still returns it; list the parent column instead (${childOnly.length}):`);
      for (const c of childOnly) console.log(`  ${c.entry} -> list ${c.parent}`);
    }
    if (missingFromSchema.length) {
      console.log(`Listed (hidden or !allowed) but not in the schema (${missingFromSchema.length}):`);
      for (const c of missingFromSchema) {
        const s = parseHiddenEntry(c).schema;
        console.log(`  ${c}${schemas.includes(s) ? '' : `  (schema ${s} was not scanned: add --schemas ${[...schemas, s].join(',')})`}`);
      }
    }
    if (sensitiveNotHidden.length) {
      console.log(`Sensitive-looking but not hidden (${sensitiveNotHidden.length}):`);
      for (const c of sensitiveNotHidden) console.log(`  ${c}`);
    }
    process.exitCode = 1;
  });

  return hidden;
}
