import { lookup } from 'node:dns/promises';
import { connect } from 'node:net';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { fromIni } from '@aws-sdk/credential-providers';
import { isLeaseLive } from '../core/index.js';
import { promises as fs } from 'node:fs';
import { ancestorColumns, canonicalEntries, expandHidden, parseHiddenEntry, parseHiddenFile, viewLeaks, HIDDEN_RELKINDS } from '../core/hidden.js';
import { catalog, PIN_SEARCH_PATH } from './hidden.js';
import type pg from 'pg';
import { readConfig, readLease, resolveTarget, getPool, closePool, CONFIG_PATH } from '../mcp/index.js';

type Check = { name: string; ok: boolean; detail: string };

/** What sql/setup-role.sql puts in pg_roles.rolconfig. The role can change these for itself, so doctor compares. */
export const EXPECTED_ROLE_SETTINGS: Record<string, string> = {
  default_transaction_read_only: 'on',
  statement_timeout: '10s',
  idle_in_transaction_session_timeout: '30s',
  lock_timeout: '1s',
  temp_file_limit: '256MB',
};

const RELKINDS = HIDDEN_RELKINDS.map((k) => `'${k}'`).join(',');

async function tcp(host: string, port: number): Promise<string> {
  return new Promise((res) => {
    const s = connect({ host, port });
    const t = setTimeout(() => { s.destroy(); res('timeout after 5 s (firewall / security group?)'); }, 5000);
    s.once('connect', () => { clearTimeout(t); s.destroy(); res('open'); });
    s.once('error', (e) => { clearTimeout(t); res(e.message); });
  });
}

/** statement_timeout may be raised (e.g. for a read replica) up to this; 0 means no limit and is drift. */
const MAX_STATEMENT_TIMEOUT_MS = 5 * 60_000;

/** A Postgres duration setting in ms (`250ms`, `10s`, `1min`, `30000`), or null when unreadable. */
function durationMs(v: string): number | null {
  const m = /^(\d+(?:\.\d+)?)\s*(ms|s|min|h|d)?$/.exec(v.trim());
  if (!m) return null;
  const unit = { ms: 1, s: 1000, min: 60_000, h: 3_600_000, d: 86_400_000 }[(m[2] ?? 'ms') as 'ms'];
  return Number(m[1]) * unit;
}

function parseConfig(entries: string[] | null): [string, string][] {
  const out: [string, string][] = [];
  for (const kv of entries ?? []) {
    const i = kv.indexOf('=');
    if (i > 0) out.push([kv.slice(0, i), kv.slice(i + 1)]);
  }
  return out;
}

/**
 * Drift from what sql/setup-role.sql writes. `rolconfig` entries are `name=value`; a value with
 * `=` keeps everything after the first one. statement_timeout may be anything from 1ms to 5min;
 * the other four must be exact. `perDatabase` is the role's pg_db_role_setting entry for the
 * current database: it overrides rolconfig, the setup never writes one, so every entry is drift.
 */
export function roleSettingsDrift(rolconfig: string[] | null, perDatabase: string[] | null = null): string[] {
  const have = new Map(parseConfig(rolconfig));
  const out: string[] = [];
  for (const [k, want] of Object.entries(EXPECTED_ROLE_SETTINGS)) {
    const got = have.get(k);
    if (got === undefined) out.push(`${k} missing (want ${want})`);
    else if (k === 'statement_timeout') {
      const ms = durationMs(got);
      if (ms === null || ms < 1 || ms > MAX_STATEMENT_TIMEOUT_MS) out.push(`${k}=${got} (want 1ms to 5min, set up as ${want})`);
    } else if (got !== want) out.push(`${k}=${got} (want ${want})`);
  }
  for (const [k, v] of have) if (!(k in EXPECTED_ROLE_SETTINGS)) out.push(`${k}=${v} (not set by the setup)`);
  for (const [k, v] of parseConfig(perDatabase)) out.push(`${k}=${v} (in database, overrides the role default)`);
  return out;
}

/** What one setup run stored on the role (COMMENT ON ROLE), for one database. */
export interface Manifest {
  hidden: string[];
  allow: string[];
  schemas: string[];
  allowDefiner: boolean;
}

/** Reads the setup's manifest for `database` from the role comment; null when absent or unreadable. */
export function parseManifest(comment: string | null, database: string): Manifest | null {
  if (!comment) return null;
  try {
    const m = JSON.parse(comment)?.databases?.[database];
    if (!m || !Array.isArray(m.hidden)) return null;
    const strings = (x: unknown) => (Array.isArray(x) ? x.filter((v): v is string => typeof v === 'string') : []);
    return { hidden: strings(m.hidden), allow: strings(m.allow), schemas: strings(m.schemas), allowDefiner: m.allowDefiner === true };
  } catch {
    return null;
  }
}

/**
 * Does a function's argument list (pg_get_function_arguments) take SQL as text? An argument named
 * like query / sql / stmt / statement / command (alone or as a word part: edges_sql, p_query)
 * of a text type. Such a function runs whatever string it is handed, out of the guard's sight.
 */
export function runsSqlFromString(args: string): boolean {
  return args
    .split(/,\s*/)
    .some((a) => /^(?:(?:IN|INOUT|VARIADIC)\s+)?(?:\w+_)?(?:query|sql|stmt|statement|command)(?:_\w+)?\s+(?:text|character varying|varchar|name)\b/i.test(a.trim()));
}

const few = (xs: string[], n = 5) => `${xs.slice(0, n).join(', ')}${xs.length > n ? ', …' : ''}`;
/** Schemas a role setup never reads or writes. */
const USER_SCHEMA = `n.nspname not in ('pg_catalog', 'information_schema') and n.nspname !~ '^pg_(toast|temp)'`;

/** Runs one doctor check; a failure is that check's ✖ line, never a throw or a mislabelled "db login". */
async function check(push: (name: string, ok: boolean, detail: string) => void, name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (e: any) {
    push(name, false, `check failed: ${e?.message || e?.code || String(e)}`);
  }
}

/** Walks the whole chain for one target and reports each link. Never throws. */
export async function doctor(targetName?: string, opts: { hideFile?: string } = {}): Promise<Check[]> {
  const out: Check[] = [];
  const push = (name: string, ok: boolean, detail: string) => out.push({ name, ok, detail });

  const major = Number(process.versions.node.split('.')[0]);
  push('node >= 20', major >= 20, `v${process.versions.node}`);

  let cfg;
  try {
    cfg = await readConfig();
    push('config', true, `${CONFIG_PATH} (${Object.keys(cfg.targets).join(', ') || 'no targets'})`);
  } catch (e: any) {
    push('config', false, e.message);
    return out;
  }

  const lease = await readLease();
  const name = targetName ?? lease?.target ?? Object.keys(cfg.targets)[0];
  if (!name) return out;
  const raw = cfg.targets[name];
  if (!raw) {
    push('target', false, `"${name}" not in config`);
    return out;
  }

  let t;
  try {
    t = resolveTarget(name, raw);
    push('target', true, `${name}: ${t.user}@${t.host}:${t.port}/${t.database} via ${t.region ? 'RDS IAM' : 'password'}`);
  } catch (e: any) {
    push('target', false, e.message);
    return out;
  }

  try {
    const a = await lookup(t.host);
    push('dns', true, `${t.host} → ${a.address}`);
  } catch (e: any) {
    push('dns', false, e.message);
  }

  if (t.region) {
    try {
      const sts = new STSClient({ region: t.region, ...(t.awsProfile ? { credentials: fromIni({ profile: t.awsProfile }) } : {}) });
      const id = await sts.send(new GetCallerIdentityCommand({}));
      push('aws credentials', true, `${id.Arn}${t.awsProfile ? ` (profile ${t.awsProfile})` : ''}`);
    } catch (e: any) {
      push('aws credentials', false, e.message);
    }
  }

  const port = await tcp(t.host, t.port);
  push('tcp', port === 'open', `${t.host}:${t.port} ${port}`);

  const live = !!lease && isLeaseLive(lease) && lease.target === name;
  push('lease', live, live ? `${lease!.id} until ${lease!.expiresAt}` : `none open for "${name}" (daypass open ${name} --reason ...)`);

  if (live && port === 'open') {
    // One session for every check, with search_path pinned to pg_catalog and every catalog name
    // qualified (except the multi-argument unnest(...) in FROM, which is grammar and only exists
    // unqualified; the pinned search_path covers it): the role may have CREATE somewhere and its own search_path setting, and could
    // otherwise answer these queries with look-alike views, functions or operators.
    let client: pg.PoolClient;
    let version = 0;
    try {
      const pool = await getPool(name, t);
      client = await pool.connect();
      await client.query(PIN_SEARCH_PATH);
      const r = await client.query(
        "select current_user, pg_catalog.current_database() as db, pg_catalog.current_setting('default_transaction_read_only') as ro, pg_catalog.version(), pg_catalog.current_setting('server_version_num')::int as num",
      );
      const row = r.rows[0];
      version = row.num;
      push('db login', true, `as ${row.current_user}; read_only=${row.ro}; ${String(row.version).split(',')[0]}`);
      if (row.ro !== 'on') push('read-only', false, 'session is NOT read-only — check role settings');
    } catch (e: any) {
      push('db login', false, e.message || e.code || String(e));
      await closePool();
      return out;
    }
    const p = client;
    let rr: any = {};
    let manifest: Manifest | null = null;

    // F3/I3: the role-level defaults are the role's own to change (SET, ALTER ROLE ... RESET ALL,
    // ALTER ROLE ... IN DATABASE ... SET), so read what the catalog holds now and compare with
    // what the setup script wrote. A per-database entry overrides rolconfig and is not shown in it.
    await check(push, 'role settings', async () => {
      const role = await p.query(
        `select r.rolconfig, r.rolsuper, r.rolcreaterole, r.rolcreatedb,
                pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'TEMP') as temp,
                pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'CREATE') as dbcreate,
                pg_catalog.shobj_description(r.oid, 'pg_authid') as comment, pg_catalog.current_database() as db,
                (select s.setconfig from pg_catalog.pg_db_role_setting s
                  where s.setrole = r.oid and s.setdatabase = (select oid from pg_catalog.pg_database where datname = pg_catalog.current_database())) as perdb
           from pg_catalog.pg_roles r where r.rolname = current_user`,
      );
      rr = role.rows[0] ?? {};
      manifest = parseManifest(rr.comment ?? null, rr.db);
      const drift = roleSettingsDrift(rr.rolconfig ?? null, rr.perdb ?? null);
      push('role settings', drift.length === 0, drift.length ? `drifted: ${drift.join('; ')} — re-run daypass sql` : `${Object.keys(EXPECTED_ROLE_SETTINGS).length} role defaults as set up`);
    });
    const m = manifest as Manifest | null;
    const schemas = m?.schemas.length ? m.schemas : t.schemas ?? ['public'];

    // F4: the pool forces default_transaction_read_only=on, so a write probe through it proves
    // nothing about the role. Ask the catalog what the role could do once it turns that off, in
    // EVERY schema (grants to PUBLIC and by other roles count): write privileges on relations
    // (MAINTAIN on 17+), USAGE/UPDATE on sequences, CREATE on a schema or the database, owned
    // objects, membership in another role, and the role attributes.
    await check(push, 'write blocked', async () => {
      const privs = `INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER${version >= 170000 ? ', MAINTAIN' : ''}`;
      const w = await p.query(
        `select c.oid::regclass::text as rel
           from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace
          where ${USER_SCHEMA}
            and case when c.relkind = 'S' then pg_catalog.has_sequence_privilege(current_user, c.oid, 'USAGE, UPDATE')
                     when c.relkind in (${RELKINDS}) then pg_catalog.has_table_privilege(current_user, c.oid, $1)
                     else false end
          order by 1`,
        [privs],
      );
      const cs = await p.query(
        `select n.nspname from pg_catalog.pg_namespace n where ${USER_SCHEMA} and pg_catalog.has_schema_privilege(current_user, n.oid, 'CREATE') order by 1`,
      );
      const owned = await p.query(
        `select pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid) as obj from pg_catalog.pg_shdepend d
          where d.refclassid = 'pg_catalog.pg_authid'::regclass and d.deptype = 'o'
            and d.refobjid = (select oid from pg_catalog.pg_roles where rolname = current_user)
            and d.dbid in (0, (select oid from pg_catalog.pg_database where datname = pg_catalog.current_database()))
          order by 1`,
      );
      const member = await p.query(
        `select distinct r.rolname from pg_catalog.pg_auth_members m join pg_catalog.pg_roles r on r.oid = m.roleid
          where m.member = (select oid from pg_catalog.pg_roles where rolname = current_user) and r.rolname <> 'rds_iam' order by 1`,
      );
      const writable = w.rows.map((x) => x.rel as string);
      const creatable = cs.rows.map((x) => x.nspname as string);
      const objs = owned.rows.map((x) => x.obj as string);
      const roles = member.rows.map((x) => x.rolname as string);
      const attrs = [rr.rolsuper && 'SUPERUSER', rr.rolcreaterole && 'CREATEROLE', rr.rolcreatedb && 'CREATEDB'].filter(Boolean) as string[];
      const problems = [
        ...(attrs.length ? [`role has ${attrs.join(', ')}`] : []),
        ...(writable.length ? [`can write ${writable.length} relation(s)/sequence(s): ${few(writable)}`] : []),
        ...(creatable.length ? [`has CREATE on schema ${creatable.join(', ')} (daypass sql --revoke-public-create, or REVOKE CREATE ON SCHEMA ... FROM PUBLIC)`] : []),
        ...(rr.dbcreate ? ['has CREATE on the database (REVOKE CREATE ON DATABASE ... FROM PUBLIC)'] : []),
        ...(objs.length ? [`owns ${objs.length} object(s): ${few(objs)} (DROP OWNED BY as the owner)`] : []),
        ...(roles.length ? [`is a member of ${roles.join(', ')} (SET ROLE reaches their privileges)`] : []),
      ];
      push(
        'write blocked',
        problems.length === 0,
        problems.length
          ? `${problems.join('; ')} — role is not read-only!`
          : `no write privilege in any schema; no CREATE; owns nothing; no other roles; no SUPERUSER/CREATEROLE/CREATEDB; temp tables ${rr.temp ? 'allowed (PUBLIC has TEMP; daypass sql --revoke-public-temp)' : 'denied'}`,
      );
    });

    // Anything readable outside the schemas the setup granted: a PUBLIC grant elsewhere.
    await check(push, 'other schemas', async () => {
      const o = await p.query(
        `select c.oid::regclass::text as rel
           from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace
          where ${USER_SCHEMA} and not n.nspname = any($1) and c.relkind in (${RELKINDS}, 'S')
            and pg_catalog.has_schema_privilege(current_user, n.oid, 'USAGE')
            and case when c.relkind = 'S' then pg_catalog.has_sequence_privilege(current_user, c.oid, 'SELECT, USAGE, UPDATE')
                     else pg_catalog.has_any_column_privilege(current_user, c.oid, 'SELECT') end
          order by 1`,
        [schemas],
      );
      const rels = o.rows.map((x) => x.rel as string);
      push('other schemas', rels.length === 0, rels.length ? `can read ${rels.length} relation(s) outside ${schemas.join(', ')}: ${few(rels)}` : `nothing readable outside ${schemas.join(', ')}`);
    });

    // Hidden columns: the list the setup stored on the role, plus --hide-file. Fails when any
    // listed column (or its copy on a partition/child) is readable, or a view exposing one is.
    await check(push, 'hidden columns', async () => {
      let list = [...(m?.hidden ?? [])];
      if (opts.hideFile) list = [...list, ...parseHiddenFile(await fs.readFile(opts.hideFile, 'utf8')).hidden];
      list = canonicalEntries(list);
      if (!list.length) {
        push('hidden columns', false, 'no hidden list to check: nothing proves the hidden columns are hidden. Re-run daypass sql (it stores the list on the role), or pass --hide-file <list>');
        return;
      }
      const scan = [...new Set([...schemas, ...list.map((e) => parseHiddenEntry(e).schema)])];
      const cat = await catalog((sql, params) => p.query(sql, params), scan);
      const expanded = expandHidden(list, cat.inherits).map(parseHiddenEntry);
      // Upwards too: a table attached under a readable parent after the setup leaks through it.
      const up = ancestorColumns(expanded.map((e) => (e.schema === 'public' ? '' : `${e.schema}.`) + `"${e.table.replace(/"/g, '""')}"."${e.column.replace(/"/g, '""')}"`), cat.inherits);
      const upEntries = up.map((u) => ({ ...parseHiddenEntry(u.entry), child: u.child }));
      const r = await p.query(
        `select x.s, x.t, x.c, a.attnum is not null as present,
                coalesce(pg_catalog.has_column_privilege(current_user, c.oid, a.attnum, 'SELECT'), false) as readable
           from unnest($1::text[], $2::text[], $3::text[]) with ordinality as x(s, t, c, i)
           left join pg_catalog.pg_namespace n on n.nspname = x.s
           left join pg_catalog.pg_class c on c.relnamespace = n.oid and c.relname = x.t
           left join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attname = x.c and a.attnum > 0 and not a.attisdropped
          order by x.i`,
        [[...expanded, ...upEntries].map((e) => e.schema), [...expanded, ...upEntries].map((e) => e.table), [...expanded, ...upEntries].map((e) => e.column)],
      );
      const label = (x: any) => (x.s === 'public' ? `${x.t}.${x.c}` : `${x.s}.${x.t}.${x.c}`);
      const rows = r.rows.slice(0, expanded.length);
      const upRows = r.rows.slice(expanded.length).map((x, i) => ({ ...x, child: upEntries[i].child }));
      const readable = [
        ...rows.filter((x) => x.readable).map(label),
        ...upRows.filter((x) => x.readable).map((x) => `${label(x)} (parent of ${x.child})`),
      ];
      const missing = rows.filter((x) => !x.present).map(label);
      const leaks = viewLeaks(list, cat.deps, { schemas, refs: cat.refs });
      const views = leaks.map((l) => parseHiddenEntry(`${l.view}.x`));
      const v = await p.query(
        `select x.s, x.t from unnest($1::text[], $2::text[]) as x(s, t)
          where coalesce(pg_catalog.has_any_column_privilege(current_user, pg_catalog.to_regclass(pg_catalog.format('%I.%I', x.s, x.t)), 'SELECT'), false)`,
        [views.map((e) => e.schema), views.map((e) => e.table)],
      );
      const readableViews = v.rows.map((x) => (x.s === 'public' ? x.t : `${x.s}.${x.t}`));
      const problems = [
        ...(readable.length ? [`readable: ${few(readable)}`] : []),
        ...(readableViews.length ? [`readable views that expose one: ${few(readableViews)}`] : []),
      ];
      push(
        'hidden columns',
        problems.length === 0,
        problems.length
          ? `${problems.join('; ')} — re-run daypass sql`
          : `${list.length} listed (${expanded.length} with partitions/children) not readable; ${leaks.length} view(s) over them withheld` +
              (missing.length ? `; not in the database: ${few(missing)}` : ''),
      );
    });

    // SECURITY DEFINER functions the role may call, in ANY schema (a view calls a function without
    // the caller needing USAGE on its schema). A failure unless the setup acknowledged them.
    await check(push, 'definer functions', async () => {
      const d = await p.query(
        `select p.oid::regprocedure::text as fn
           from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
          where p.prosecdef and n.nspname not in ('pg_catalog', 'information_schema') and pg_catalog.has_function_privilege(current_user, p.oid, 'EXECUTE')
          order by 1`,
      );
      const fns = d.rows.map((x) => x.fn as string);
      const acked = m?.allowDefiner === true;
      push(
        'definer functions',
        fns.length === 0 || acked,
        fns.length
          ? `${acked ? 'acknowledged (--allow-definer-functions): ' : ''}can execute ${fns.length} SECURITY DEFINER function(s): ${few(fns)} — they run as their owner (REVOKE EXECUTE ... FROM PUBLIC)`
          : 'none executable',
      );
    });
    // Every function is EXECUTE-to-PUBLIC by default, so extension and app functions are callable by
    // the role; the guard cannot see what they do. A warning (SECURITY DEFINER ones fail above).
    await check(push, 'functions', async () => {
      const f = await p.query(
        `select p.oid::pg_catalog.regprocedure::text as fn, pg_catalog.pg_get_function_arguments(p.oid) as args
           from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
          where ${USER_SCHEMA} and p.prokind in ('f', 'p')
            and pg_catalog.has_function_privilege(current_user, p.oid, 'EXECUTE')
          order by 1`,
      );
      const all = f.rows as { fn: string; args: string }[];
      const sql = all.filter((x) => runsSqlFromString(x.args)).map((x) => x.fn.replace(/\(.*$/, `(${x.args})`));
      push(
        'functions',
        true,
        all.length
          ? `warning: can execute ${all.length} function(s) outside pg_catalog: ${few(all.map((x) => x.fn))}` +
              (sql.length ? `; runs SQL from a string: ${few(sql)}` : '') +
              ' — the guard cannot see what they do (REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA <s> FROM PUBLIC, then grant your app roles)'
          : 'none executable outside pg_catalog',
      );
    });
    p.release(true);
    await closePool();
  }
  return out;
}
