import { lookup } from 'node:dns/promises';
import { connect } from 'node:net';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { fromIni } from '@aws-sdk/credential-providers';
import { isLeaseLive } from '../core/index.js';
import type { Lease } from '../core/index.js';
import { promises as fs } from 'node:fs';
import { ancestorColumns, canonicalEntries, expandHidden, parseHiddenEntry, parseHiddenFile, viewLeaks, HIDDEN_RELKINDS } from '../core/hidden.js';
import { MATVIEW_LEAKS_SQL, MATVIEW_SQL_PARAMS, UNREADABLE_SOURCES_SQL, USER_SCHEMA } from '../core/matview.js';
import { printable } from './log.js';
import { catalog, PIN_SEARCH_PATH } from './hidden.js';
import type pg from 'pg';
import { readConfig, readLeases, readAuditDetailed, resolveTarget, getPool, closePool, CONFIG_PATH, AUDIT_PATH, DAYPASS_HOME } from '../mcp/index.js';
import { inspectStateFiles } from '../mcp/state.js';
import { rdsCa, sslOptions } from '../mcp/db.js';

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

/** The first `n` names, escaped (they come from the database). */
const few = (xs: string[], n = 5) => printable(`${xs.slice(0, n).join(', ')}${xs.length > n ? ', …' : ''}`);
export { MATVIEW_LEAKS_SQL, MATVIEW_SAFE_CATALOGS, MATVIEW_SAFE_FUNCTIONS } from '../core/matview.js';

/** rds_iam before PostgreSQL 16: what it holds, any of which SET ROLE rds_iam reaches. */
const RDS_IAM_HOLDINGS_SQL = `
select x from (
  select case when d.dbid in (0, (select oid from pg_catalog.pg_database where datname = pg_catalog.current_database()))
              then case d.deptype when 'o' then 'owns ' else 'is named in the privileges of ' end || pg_catalog.pg_describe_object(d.classid, d.objid, d.objsubid)
              else 'holds privileges or objects in database ' || (select pg_catalog.quote_ident(datname) from pg_catalog.pg_database where oid = d.dbid) end as x
    from pg_catalog.pg_shdepend d
   where d.refclassid = 'pg_catalog.pg_authid'::pg_catalog.regclass and d.refobjid = (select oid from pg_catalog.pg_roles where rolname = 'rds_iam')
  union all
  select 'is a member of ' || r.rolname from pg_catalog.pg_auth_members m join pg_catalog.pg_roles r on r.oid = m.roleid
   where m.member = (select oid from pg_catalog.pg_roles where rolname = 'rds_iam')
  union all
  select 'has attribute ' || a from pg_catalog.pg_roles r,
         unnest(array[case when r.rolsuper then 'SUPERUSER' end, case when r.rolreplication then 'REPLICATION' end,
                      case when r.rolbypassrls then 'BYPASSRLS' end, case when r.rolcreatedb then 'CREATEDB' end,
                      case when r.rolcreaterole then 'CREATEROLE' end]) a
   where r.rolname = 'rds_iam' and a is not null) q
order by 1`;

/** Grants on pg_catalog / information_schema objects to PUBLIC or the role beyond what a fresh cluster has (pg_init_privs). */
const CATALOG_GRANTS_SQL = `
select distinct x from (
  select pg_catalog.format('%s on %s.%I%s to %s', a.privilege_type, cn.nspname, c.relname,
           case when o.sub = 0 then '' else pg_catalog.format(' (%I)', (select attname from pg_catalog.pg_attribute where attrelid = c.oid and attnum = o.sub)) end,
           case when a.grantee = 0 then 'PUBLIC' else current_user end) as x
    from pg_catalog.pg_class c join pg_catalog.pg_namespace cn on cn.oid = c.relnamespace,
         lateral (select 0::int2 as sub, c.relacl as acl, pg_catalog.acldefault(case when c.relkind = 'S' then 's' else 'r' end::"char", c.relowner) as dflt
                  union all
                  select pa.attnum, pa.attacl, null::aclitem[] from pg_catalog.pg_attribute pa where pa.attrelid = c.oid and pa.attnum > 0 and pa.attacl is not null) o,
         pg_catalog.aclexplode(o.acl) a
   where cn.nspname in ('pg_catalog', 'information_schema')
     and a.grantee in (0, (select oid from pg_catalog.pg_roles where rolname = current_user))
     and not (cn.nspname = 'information_schema' and a.grantee = 0 and a.privilege_type = 'SELECT' and o.sub = 0)
     and not exists (select 1 from pg_catalog.aclexplode(coalesce((select i.initprivs from pg_catalog.pg_init_privs i
                                                                    where i.classoid = 'pg_catalog.pg_class'::pg_catalog.regclass and i.objoid = c.oid and i.objsubid = o.sub), o.dflt)) b
                      where b.grantee = a.grantee and b.privilege_type = a.privilege_type)
  union all
  select pg_catalog.format('%s on function %s to %s', a.privilege_type, p.oid::pg_catalog.regprocedure, case when a.grantee = 0 then 'PUBLIC' else current_user end)
    from pg_catalog.pg_proc p join pg_catalog.pg_namespace pn on pn.oid = p.pronamespace, pg_catalog.aclexplode(p.proacl) a
   where pn.nspname in ('pg_catalog', 'information_schema')
     and a.grantee in (0, (select oid from pg_catalog.pg_roles where rolname = current_user))
     and not exists (select 1 from pg_catalog.aclexplode(coalesce((select i.initprivs from pg_catalog.pg_init_privs i
                                                                    where i.classoid = 'pg_catalog.pg_proc'::pg_catalog.regclass and i.objoid = p.oid and i.objsubid = 0),
                                                                   pg_catalog.acldefault('f', p.proowner))) b
                      where b.grantee = a.grantee and b.privilege_type = a.privilege_type)) q
order by 1`;

const octal = (m: number) => m.toString(8).padStart(4, '0');

/**
 * ~/.daypass (DAYPASS_HOME) and its files, by the rules every read and write applies: a symlink,
 * a wrong file type or another owner fails (daypass refuses to use it). Bits for other users fail
 * when they can write (someone else may already have changed the file) and are a warning when
 * they can only read: daypass tightens its own files to 0700/0600 on the next use, but not
 * hidden-columns.txt. Windows: symlink and file-type checks only.
 */
export async function filesCheck(): Promise<{ ok: boolean; detail: string }> {
  const st = await inspectStateFiles();
  if (!st.length) return { ok: true, detail: `${DAYPASS_HOME} does not exist yet (daypass init)` };
  const refused = st.filter((f) => f.refused).map((f) => f.refused!);
  const loose = st.filter((f) => !f.refused && f.mode !== undefined && f.mode & 0o077);
  const writable = loose.filter((f) => f.mode! & 0o022);
  const label = (f: (typeof st)[number]) => `${f.path} ${octal(f.mode!)} (want ${octal(f.want)})`;
  const fix = (xs: typeof st) => xs.map((f) => `chmod ${octal(f.want).slice(1)} ${f.path}`).join('; ');
  const readable = loose.filter((f) => !(f.mode! & 0o022));
  if (refused.length || writable.length) {
    return {
      ok: false,
      detail: [
        ...refused,
        ...(writable.length ? [`writable by other users: ${writable.map(label).join(', ')} — check the contents, then ${fix(writable)}`] : []),
        ...(readable.length ? [`readable by other users: ${readable.map(label).join(', ')} (${fix(readable)})`] : []),
      ].join('; '),
    };
  }
  const names = st.slice(1).map((f) => f.path.slice(DAYPASS_HOME.length + 1));
  const what = `${DAYPASS_HOME}${names.length ? ` and ${names.join(', ')}` : ''}`;
  if (loose.length) return { ok: true, detail: `warning: readable by other users: ${loose.map(label).join(', ')} — daypass tightens its own files on next use (${fix(loose)})` };
  return { ok: true, detail: st[0].mode === undefined ? `${what}: no symlinks` : `${what}: yours, no symlinks, 0700/0600` };
}

/** How the pool will connect, or why it refuses to (ssl: false on an RDS / IAM target, an unreadable sslCa). */
function tlsCheck(t: Parameters<typeof sslOptions>[0]): { ok: boolean; detail: string } {
  try {
    const o = sslOptions(t, rdsCa());
    if (!o) return { ok: true, detail: 'off (ssl: false / sslmode=disable): for a local database only' };
    return { ok: true, detail: `verified against ${t.sslCa ? `sslCa ${t.sslCa}` : o.ca ? 'the bundled RDS CA' : 'the system CAs'}` };
  } catch (e: any) {
    const msg = e?.message || String(e);
    return { ok: false, detail: t.sslCa && e?.code ? `cannot read sslCa ${t.sslCa}: ${msg}` : msg };
  }
}

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
  // Details carry names from the database, the config and the lease: a quoted identifier can hold
  // escape sequences for the terminal, so every detail is escaped once, here.
  const push = (name: string, ok: boolean, detail: string) => out.push({ name, ok, detail: printable(detail) });

  const major = Number(process.versions.node.split('.')[0]);
  push('node >= 20', major >= 20, `v${process.versions.node}`);

  // Before anything reads them: the reads below tighten loose modes (with a warning on stderr).
  await check(push, 'files', async () => {
    const f = await filesCheck();
    push('files', f.ok, f.detail);
  });

  let cfg;
  try {
    cfg = await readConfig();
    push('config', true, `${CONFIG_PATH} (${Object.keys(cfg.targets).join(', ') || 'no targets'})`);
  } catch (e: any) {
    push('config', false, e.message);
    return out;
  }

  await check(push, 'audit log', async () => {
    const { events, corrupt } = await readAuditDetailed(0);
    push(
      'audit log',
      true,
      corrupt
        ? `warning: ${corrupt} unreadable line(s) in ${AUDIT_PATH} (a torn write, or edited by hand); ${events.length} event(s) readable`
        : `${events.length} event(s), all readable`,
    );
  });

  let leases: Lease[] = [];
  try {
    leases = await readLeases();
  } catch (e: any) {
    push('lease', false, e?.message || String(e));
  }
  const name = targetName ?? (leases.length === 1 ? leases[0].target : undefined) ?? Object.keys(cfg.targets)[0];
  const lease = leases.find((l) => l.target === name) ?? null;
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

  const tls = tlsCheck(t);
  push('tls', tls.ok, tls.detail);

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
  if (!out.some((c) => c.name === 'lease')) push('lease', live, live ? `${lease!.id} until ${lease!.expiresAt}` : `none open for "${name}" (daypass open ${name} --reason ...)`);

  if (live && port === 'open' && tls.ok) {
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
        `select r.rolconfig, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
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
                                                       or pg_catalog.has_any_column_privilege(current_user, c.oid, 'INSERT, UPDATE')
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
      const attrs = [rr.rolsuper && 'SUPERUSER', rr.rolreplication && 'REPLICATION', rr.rolbypassrls && 'BYPASSRLS', rr.rolcreaterole && 'CREATEROLE', rr.rolcreatedb && 'CREATEDB'].filter(Boolean) as string[];
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
          : `no write privilege in any schema; no CREATE; owns nothing; no other roles; no SUPERUSER/REPLICATION/BYPASSRLS/CREATEROLE/CREATEDB; temp tables ${rr.temp ? 'allowed (PUBLIC has TEMP; daypass sql --revoke-public-temp)' : 'denied'}`,
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

    // rds_iam (RDS only): IAM login needs the membership, never rds_iam's privileges. From PG 16
    // the grant must carry no SET / INHERIT / ADMIN; before 16 SET ROLE rds_iam always works, so
    // rds_iam itself must hold nothing.
    await check(push, 'rds_iam', async () => {
      const mem = await p.query(
        `select pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER') as member from pg_catalog.pg_roles r where r.rolname = 'rds_iam'`,
      );
      if (!mem.rows.length) return; // not RDS: nothing to report
      if (!mem.rows[0].member) {
        push('rds_iam', true, 'not a member (IAM login needs it on RDS)');
        return;
      }
      let problems: string[];
      if (version >= 160000) {
        const g = await p.query(
          `select pg_catalog.pg_get_userbyid(m.grantor) as grantor, m.set_option, m.inherit_option, m.admin_option
             from pg_catalog.pg_auth_members m
            where m.roleid = (select oid from pg_catalog.pg_roles where rolname = 'rds_iam')
              and m.member = (select oid from pg_catalog.pg_roles where rolname = current_user)
              and (m.set_option or m.inherit_option or m.admin_option)`,
        );
        problems = g.rows.map((x) => `granted by ${x.grantor} with ${[x.set_option && 'SET', x.inherit_option && 'INHERIT', x.admin_option && 'ADMIN'].filter(Boolean).join(', ')}`);
      } else {
        problems = (await p.query(RDS_IAM_HOLDINGS_SQL)).rows.map((x) => `rds_iam ${x.x}`);
      }
      push(
        'rds_iam',
        problems.length === 0,
        problems.length
          ? `${few(problems)} — the role can use what rds_iam holds (SET ROLE); re-run daypass sql${version >= 160000 ? ' (it grants rds_iam WITH INHERIT FALSE, SET FALSE)' : ', after revoking those from rds_iam'}`
          : version >= 160000 ? 'member WITH INHERIT FALSE, SET FALSE (login only)' : 'member; rds_iam holds nothing',
      );
    });

    // Foreign servers: USAGE (or a wrapper's USAGE, to create one) and a user mapping for the role
    // or PUBLIC let dblink / postgres_fdw log in with stored credentials, out of every grant's reach.
    await check(push, 'foreign servers', async () => {
      const f = await p.query(
        `select x from (
           select pg_catalog.format('USAGE on server %I', s.srvname) as x from pg_catalog.pg_foreign_server s
            where pg_catalog.has_server_privilege(current_user, s.oid, 'USAGE')
           union all
           select pg_catalog.format('USAGE on foreign-data wrapper %I', w.fdwname) from pg_catalog.pg_foreign_data_wrapper w
            where pg_catalog.has_foreign_data_wrapper_privilege(current_user, w.oid, 'USAGE')
           union all
           select pg_catalog.format('user mapping for %s on server %I', case when u.umuser = 0 then 'PUBLIC' else u.usename::text end, u.srvname)
             from pg_catalog.pg_user_mappings u where u.umuser in (0, (select oid from pg_catalog.pg_roles where rolname = current_user))) q
          order by 1`,
      );
      const xs = f.rows.map((x) => x.x as string);
      push('foreign servers', xs.length === 0, xs.length ? `${few(xs)} — REVOKE USAGE ON FOREIGN SERVER ... / DROP USER MAPPING as the owner` : 'no foreign server reachable');
    });

    // Default privileges for PUBLIC make every new table / sequence / schema readable at once,
    // before anyone reviews it (EXECUTE on functions and USAGE on types are Postgres' defaults).
    // Ones for the role itself are removed by the setup.
    await check(push, 'default privileges', async () => {
      const d = await p.query(
        `select distinct pg_catalog.format('%s on new %s%s for %s (set by %s)', a.privilege_type,
                  case d.defaclobjtype when 'r' then 'tables' when 'S' then 'sequences' when 'f' then 'functions' when 'T' then 'types' when 'n' then 'schemas' else d.defaclobjtype::text end,
                  case when d.defaclnamespace = 0 then '' else ' in schema ' || (select pg_catalog.quote_ident(nspname) from pg_catalog.pg_namespace where oid = d.defaclnamespace) end,
                  case when a.grantee = 0 then 'PUBLIC' else current_user end, pg_catalog.pg_get_userbyid(d.defaclrole)) as x
           from pg_catalog.pg_default_acl d, pg_catalog.aclexplode(d.defaclacl) a
          where (a.grantee = (select oid from pg_catalog.pg_roles where rolname = current_user))
             or (a.grantee = 0 and not (d.defaclobjtype = 'f' and a.privilege_type = 'EXECUTE') and not (d.defaclobjtype = 'T' and a.privilege_type = 'USAGE'))
          order by 1`,
      );
      const xs = d.rows.map((x) => x.x as string);
      push('default privileges', xs.length === 0, xs.length ? `${few(xs)} — as that owner: ALTER DEFAULT PRIVILEGES [IN SCHEMA s] REVOKE ALL ON TABLES FROM PUBLIC (or SEQUENCES / SCHEMAS)` : 'none for PUBLIC or the role');
    });

    // System catalogs as initdb left them (pg_init_privs): an extra grant to PUBLIC or the role
    // (SELECT on pg_statistic / pg_authid / pg_largeobject, EXECUTE on pg_read_file, ...).
    await check(push, 'catalog grants', async () => {
      const xs = (await p.query(CATALOG_GRANTS_SQL)).rows.map((x) => x.x as string);
      push('catalog grants', xs.length === 0, xs.length ? `beyond a fresh cluster's: ${few(xs)} — REVOKE them` : 'as a fresh cluster has them');
    });

    // Materialized views store what their OWNER saw at refresh: through a catalog that filters by
    // caller (pg_stats, pg_stat_activity, ...), a function (current_setting, query_to_xml, ...),
    // or row-level security, directly or through the views they read.
    let leaks: { rel: string; mv: string; why: string; kind: string }[] = [];
    await check(push, 'materialized views', async () => {
      leaks = (await p.query(MATVIEW_LEAKS_SQL, MATVIEW_SQL_PARAMS)).rows;
      const xs = leaks.filter((x) => x.kind === 'm').map((x) => (x.rel === x.mv ? `${x.rel} ${x.why}` : `${x.rel} (over materialized view ${x.mv}, which ${x.why})`));
      push('materialized views', xs.length === 0, xs.length ? `readable, stored as the owner: ${few(xs)} — REVOKE SELECT, then re-run daypass sql` : 'none readable stores what only the owner could see');
    });

    // A plain view reads its tables with its OWNER's rights (unless security_invoker, PG 15+):
    // row-level security filters for the owner (who, without FORCE ROW LEVEL SECURITY, sees every
    // row), and a relation the role cannot read at all (a sequence the setup withheld) is read anyway.
    await check(push, 'views as owner', async () => {
      const rls = leaks.filter((x) => x.kind === 'v').map((x) => (x.rel === x.mv ? `${x.rel} ${x.why}` : `${x.rel} (over view ${x.mv}, which ${x.why})`));
      const unreadable = (await p.query(UNREADABLE_SOURCES_SQL)).rows.map((x) => `${x.rel} reads ${x.ref}, which the role cannot read`);
      const xs = [...rls, ...unreadable];
      push(
        'views as owner',
        xs.length === 0,
        xs.length
          ? `readable views read as their owner: ${few(xs)} — REVOKE SELECT (or make the view security_invoker, PostgreSQL 15+), then re-run daypass sql`
          : 'no readable view reads row-level-security data or an unreadable relation with its owner\'s rights',
      );
    });

    // PUBLIC holds CONNECT on every new database: the role can log in to the others on this server,
    // where none of the checks above ran. A warning: say which (REVOKE CONNECT ... FROM PUBLIC).
    await check(push, 'other databases', async () => {
      const d = await p.query(
        `select d.datname from pg_catalog.pg_database d
          where d.datallowconn and d.datname <> pg_catalog.current_database()
            and pg_catalog.has_database_privilege(current_user, d.oid, 'CONNECT')
          order by 1`,
      );
      const dbs = d.rows.map((x) => x.datname as string);
      push(
        'other databases',
        true,
        dbs.length
          ? `warning: can connect to ${dbs.length} other database(s) on this server: ${few(dbs)} — nothing there was checked; as the owner: REVOKE CONNECT ON DATABASE <db> FROM PUBLIC (and grant your app roles)`
          : 'cannot connect to any other database on this server',
      );
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
