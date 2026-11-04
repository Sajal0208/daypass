import { Command } from 'commander';
import { promises as fs } from 'node:fs';
import pg from 'pg';
import { canonicalEntries, diffHidden, formatHiddenEntry, parseHiddenEntry, parseHiddenFile, parsePrismaColumns, suggestHidden, viewLeaks, HIDDEN_RELKINDS } from '../core/hidden.js';
import type { ColumnInfo, GeneratedDep, MatviewTaint, RelDep, RelParent, RuleRef } from '../core/hidden.js';
import { MATVIEW_SQL_PARAMS, MATVIEW_TAINT_SQL } from '../core/matview.js';
import { readConfig, resolveTarget, getPool, closePool, parsePostgresUrl } from '../mcp/index.js';
import { rdsCa, sslOptions } from '../mcp/db.js';
import { printable } from './log.js';

/** Where the column list comes from. Exactly one must be given. */
interface SourceOpts {
  prisma?: string;
  live?: string;
  /** A URL, or `-` to read it from stdin. */
  url?: string;
  /** Read the URL from this environment variable (true: DAYPASS_OWNER_URL). */
  urlEnv?: string | true;
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
  /** Materialized views whose stored rows are the owner's (core/matview.ts). */
  matviews: MatviewTaint[];
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
       t.relkind::text AS ref_kind, so.schema AS owner_schema, so.table AS owner_table, so.column AS owner_column
FROM pg_catalog.pg_depend d
JOIN pg_catalog.pg_rewrite rw ON rw.oid = d.objid
JOIN pg_catalog.pg_class v ON v.oid = rw.ev_class
JOIN pg_catalog.pg_namespace vn ON vn.oid = v.relnamespace
JOIN pg_catalog.pg_class t ON t.oid = d.refobjid
JOIN pg_catalog.pg_namespace rn ON rn.oid = t.relnamespace
LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid AND d.refobjsubid > 0
LEFT JOIN LATERAL (
  SELECT on2.nspname AS schema, oc.relname AS table, oa.attname AS column
    FROM pg_catalog.pg_depend od
    JOIN pg_catalog.pg_class oc ON oc.oid = od.refobjid JOIN pg_catalog.pg_namespace on2 ON on2.oid = oc.relnamespace
    JOIN pg_catalog.pg_attribute oa ON oa.attrelid = od.refobjid AND oa.attnum = od.refobjsubid
   WHERE t.relkind = 'S' AND od.classid = 'pg_catalog.pg_class'::regclass AND od.objid = t.oid
     AND od.refclassid = 'pg_catalog.pg_class'::regclass AND od.deptype IN ('a', 'i') AND od.refobjsubid > 0
   LIMIT 1) so ON true
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
  const mv = await run(MATVIEW_TAINT_SQL, MATVIEW_SQL_PARAMS);
  return {
    cols: c.rows.map((row) => ({ schema: row.schema, table: row.table, column: row.column, type: row.type })),
    deps: d.rows.map((row) => ({
      schema: row.schema, view: row.view, refSchema: row.ref_schema, refTable: row.ref_table, refColumn: row.ref_column ?? null, wholeRow: row.whole_row === true,
      refKind: row.ref_kind,
      ...(row.owner_column ? { seqOwner: formatHiddenEntry({ schema: row.owner_schema, table: row.owner_table, column: row.owner_column }) } : {}),
    })),
    generated: g.rows.map((row) => ({ schema: row.schema, table: row.table, column: row.column, fromColumn: row.from_column })),
    refs: rr.rows.map((row) => ({
      schema: row.schema, view: row.view, viewKind: row.view_kind, refType: row.ref_type, refSchema: row.ref_schema, refName: row.ref_name,
      ...(row.public_readable === null ? {} : { publicReadable: row.public_readable }),
    })),
    inherits: i.rows.map((row) => ({ schema: row.schema, table: row.table, parentSchema: row.parent_schema, parentTable: row.parent_table })),
    matviews: mv.rows.map((row) => ({ schema: row.schema, view: row.view, why: row.why, kind: row.kind })),
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
  const u = parsePostgresUrl(url);
  // Same rule as a target: verified TLS (RDS hosts pin the bundled CA); sslmode=disable only off RDS.
  const ssl = sslOptions({ host: u.host, ssl: u.sslDisabled ? false : undefined }, rdsCa()) ?? false;
  const client = new pg.Client({
    host: u.host,
    port: u.port ?? 5432,
    database: u.database,
    user: u.user,
    password: u.password,
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

const OWNER_URL_ENV = 'DAYPASS_OWNER_URL';

async function readStdin(): Promise<string> {
  let text = '';
  for await (const chunk of process.stdin) text += chunk;
  return text;
}

/**
 * The owner URL from `--url <url>`, `--url -` (first line of stdin) or `--url-env [var]`. A URL
 * typed on the command line is visible in the process list and shell history, so one carrying
 * a password gets a warning.
 */
async function ownerUrl(opts: SourceOpts): Promise<string> {
  if (opts.urlEnv !== undefined) {
    const name = opts.urlEnv === true ? OWNER_URL_ENV : opts.urlEnv;
    const v = process.env[name];
    if (!v) throw new Error(`${name} is not set`);
    return v.trim();
  }
  if (opts.url === '-') {
    const line = (await readStdin()).split(/\r?\n/).find((l) => l.trim());
    if (!line) throw new Error('--url -: no URL on stdin');
    return line.trim();
  }
  const url = opts.url!;
  let hasPassword = false;
  try {
    hasPassword = !!new URL(url.replace(/^postgresql:/, 'postgres:')).password;
  } catch {
    /* reported when it is parsed for real */
  }
  if (hasPassword) {
    console.error(
      `warning: the password in --url is visible to other local users (process list) and lands in shell history. ` +
        `Use --url - (URL on stdin) or --url-env (reads ${OWNER_URL_ENV}) instead.`,
    );
  }
  return url;
}

async function loadCatalog(opts: SourceOpts): Promise<Catalog> {
  const given = [opts.prisma, opts.live, opts.url, opts.urlEnv].filter((x) => x !== undefined).length;
  if (given !== 1) throw new Error('give exactly one of --prisma <schema.prisma>, --live <target>, --url <postgres url | ->, --url-env [var]');
  // A Prisma schema has no views, so there is nothing to follow.
  if (opts.prisma) return { cols: parsePrismaColumns(await fs.readFile(opts.prisma, 'utf8')), deps: [], inherits: [], generated: [], refs: [], matviews: [], schemas: ['public'] };
  if (opts.live) return liveCatalog(opts.live, opts.schemas);
  return urlCatalog(await ownerUrl(opts), opts.schemas);
}

function withSource(cmd: Command): Command {
  return cmd
    .option('--prisma <schema.prisma>', 'read columns from a Prisma schema')
    .option('--live <target>', 'read columns from a configured target (connects like the MCP server)')
    .option('--url <postgres url>', 'read columns from any Postgres URL; "-" reads the URL from stdin (keeps the password out of argv)')
    .option('--url-env [var]', `read columns from the Postgres URL in an environment variable (default ${OWNER_URL_ENV})`)
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
      const { cols: all, deps, inherits, generated, refs, matviews, schemas } = await loadCatalog(opts);
      const cols = suggestHidden(all, { deps, inherits, generated, refs, matviews, schemas: opts.prisma ? undefined : schemas });
      console.error(`daypass hidden suggest: ${cols.length} of ${all.length} columns flagged`);
      const lines = [
        `# Suggested by daypass hidden suggest on ${new Date().toISOString()}. Review this list, then:`,
        '#   daypass sql --hide-file <this file> | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1',
        ...cols,
      ];
      // A terminal gets escaped names (a quoted identifier can hold escape sequences); a file gets them as they are.
      process.stdout.write((process.stdout.isTTY ? lines.map(printable) : lines).join('\n') + '\n');
    },
  );

  withSource(
    hidden
      .command('check')
      .description('Verify a hidden-columns list against the schema; exit 1 when it has drifted')
      .requiredOption('--file <hidden-columns.txt>', 'the list to verify (lines starting with ! are reviewed, intentionally visible columns)'),
  ).action(async (opts: SourceOpts & { file: string }) => {
    // Names come from the database: a quoted identifier can hold escape sequences for the terminal.
    const say = (line: string) => console.log(printable(line));
    const { hidden: list, allow } = parseHiddenFile(await fs.readFile(opts.file, 'utf8'));
    const { cols, deps, inherits, generated, refs, matviews, schemas } = await loadCatalog(opts);
    const shape = { deps, inherits, generated, refs, matviews, schemas: opts.prisma ? undefined : schemas };
    const { missingFromSchema, sensitiveNotHidden, conflicts, childOnly, derived } = diffHidden(list, cols, allow, shape);
    const hiddenCount = new Set(canonicalEntries(list)).size;
    // Informational: the setup grants these views nothing, which is the point of hiding the column.
    const leaks = viewLeaks(list, deps, { schemas: shape.schemas, refs, matviews });
    if (leaks.length) {
      say(`Views the setup withholds (${leaks.length}):`);
      for (const l of leaks) {
        const what = (l.kind ? {
          foreign: `reads foreign table ${l.column}`,
          schema: `reads ${l.column}, outside --schemas`,
          function: `calls function ${l.column} (a materialized view stores what the owner could read)`,
          catalog: `reads ${l.column}, which the role cannot read itself`,
          matview: `${l.column} (a materialized view stores what the owner could read)`,
          rls: `${l.column} (a view reads its tables with its owner's rights; only a security_invoker view, PostgreSQL 15+, reads them as the caller)`,
          sequence: `reads ${l.column}, a sequence owned by a hidden column`,
        }[l.kind] : undefined) ?? `exposes hidden column ${l.column}`;
        say(`  view ${l.view} ${what}${l.via ? ` through view ${l.via}` : ''}`);
      }
    }
    if (!missingFromSchema.length && !sensitiveNotHidden.length && !conflicts.length && !childOnly.length && !derived.length) {
      say(`hidden list matches the schema (${hiddenCount} hidden, ${cols.length} columns scanned)`);
      return;
    }
    if (conflicts.length) {
      say(`Columns both hidden and !allowed - keep one line per column (${conflicts.length}):`);
      for (const c of conflicts) say(`  ${c}`);
    }
    if (derived.length) {
      say(`Generated from a hidden column - hide these too (${derived.length}):`);
      for (const d of derived) say(`  ${d.entry} (generated from ${d.from})`);
    }
    if (childOnly.length) {
      say(`Hidden on a partition/child only - the parent still returns it; list the parent column instead (${childOnly.length}):`);
      for (const c of childOnly) say(`  ${c.entry} -> list ${c.parent}`);
    }
    if (missingFromSchema.length) {
      say(`Listed (hidden or !allowed) but not in the schema (${missingFromSchema.length}):`);
      for (const c of missingFromSchema) {
        const s = parseHiddenEntry(c).schema;
        say(`  ${c}${schemas.includes(s) ? '' : `  (schema ${s} was not scanned: add --schemas ${[...schemas, s].join(',')})`}`);
      }
    }
    if (sensitiveNotHidden.length) {
      say(`Sensitive-looking but not hidden (${sensitiveNotHidden.length}):`);
      for (const c of sensitiveNotHidden) say(`  ${c}`);
    }
    process.exitCode = 1;
  });

  return hidden;
}
