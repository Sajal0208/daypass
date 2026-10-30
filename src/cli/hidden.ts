import { Command } from 'commander';
import { promises as fs } from 'node:fs';
import pg from 'pg';
import { diffHidden, parseHiddenFile, parsePrismaColumns, suggestHidden } from '../core/index.js';
import type { ColumnInfo } from '../core/index.js';
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

/** Every column of every ordinary/partitioned table in the given schemas, regardless of grants. */
const CATALOG_SQL = `
SELECT n.nspname AS schema, c.relname AS table, a.attname AS column, format_type(a.atttypid, a.atttypmod) AS type
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped AND n.nspname = ANY($1)
ORDER BY 1,2,3`;

function parseSchemas(s: string | undefined, fallback: string[]): string[] {
  const schemas = s === undefined ? fallback : s.split(',').map((x) => x.trim()).filter(Boolean);
  if (!schemas.length) throw new Error('--schemas must name at least one schema');
  if (schemas.some((x) => x !== 'public')) {
    console.error('warning: columns in other schemas are listed without the schema prefix; `daypass sql` applies them to `public` only');
  }
  return schemas;
}

async function catalogColumns(run: (sql: string, params: unknown[]) => Promise<pg.QueryResult>, schemas: string[]): Promise<ColumnInfo[]> {
  const r = await run(CATALOG_SQL, [schemas]);
  return r.rows.map((row) => ({ table: row.table, column: row.column, type: row.type }));
}

/** Same connection path as the MCP server: config target, IAM token or password, pinned/verified TLS. */
async function liveColumns(targetName: string, schemasOpt: string | undefined): Promise<ColumnInfo[]> {
  const cfg = await readConfig();
  const raw = cfg.targets[targetName];
  if (!raw) throw new Error(`Unknown target "${targetName}". Known: ${Object.keys(cfg.targets).join(', ')}`);
  const t = resolveTarget(targetName, raw);
  const schemas = parseSchemas(schemasOpt, t.schemas ?? ['public']);
  const pool = await getPool(targetName, t);
  try {
    return await catalogColumns((sql, params) => pool.query(sql, params), schemas);
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
async function urlColumns(url: string, schemasOpt: string | undefined): Promise<ColumnInfo[]> {
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
    return await catalogColumns((sql, params) => client.query(sql, params), schemas);
  } finally {
    await client.end().catch(() => {});
  }
}

async function loadColumns(opts: SourceOpts): Promise<ColumnInfo[]> {
  const given = [opts.prisma, opts.live, opts.url].filter((x) => x !== undefined).length;
  if (given !== 1) throw new Error('give exactly one of --prisma <schema.prisma>, --live <target>, --url <postgres url>');
  if (opts.prisma) return parsePrismaColumns(await fs.readFile(opts.prisma, 'utf8'));
  if (opts.live) return liveColumns(opts.live, opts.schemas);
  return urlColumns(opts.url!, opts.schemas);
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

  withSource(hidden.command('suggest').description('Print sensitive-looking columns as table.column (redirect to hidden-columns.txt)')).action(
    async (opts: SourceOpts) => {
      const all = await loadColumns(opts);
      const cols = suggestHidden(all);
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
    const cols = await loadColumns(opts);
    const { missingFromSchema, sensitiveNotHidden } = diffHidden(list, cols, allow);
    if (!missingFromSchema.length && !sensitiveNotHidden.length) {
      console.log(`hidden list matches the schema (${list.length} hidden, ${cols.length} columns scanned)`);
      return;
    }
    if (missingFromSchema.length) {
      console.log(`Listed (hidden or !allowed) but not in the schema (${missingFromSchema.length}):`);
      for (const c of missingFromSchema) console.log(`  ${c}`);
    }
    if (sensitiveNotHidden.length) {
      console.log(`Sensitive-looking but not hidden (${sensitiveNotHidden.length}):`);
      for (const c of sensitiveNotHidden) console.log(`  ${c}`);
    }
    process.exitCode = 1;
  });

  return hidden;
}
