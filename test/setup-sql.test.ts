import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { renderSetupSql, HIDDEN_RELKINDS, DATA_READING_FUNCTIONS } from '../src/core/hidden.js';
import { MATVIEW_SAFE_CATALOGS, MATVIEW_SAFE_FUNCTIONS, MATVIEW_LEAKS_SQL } from '../src/cli/doctor.js';

/**
 * The SQL itself can only be proven against a real Postgres (scripts/ci-integration.sh does
 * that). This checks the shape of the template the same way `daypass sql` renders it:
 * one transaction, password set only on create, the three DO blocks still present.
 */
const TPL = readFileSync(resolve(__dirname, '..', 'sql', 'setup-role.sql'), 'utf8');
function render(role = 'daypass_ro', hidden: string[] = ['customers.secret'], extra: Partial<Parameters<typeof renderSetupSql>[1]> = {}): string {
  return renderSetupSql(TPL, { role, hidden, allow: [], schemas: ['public'], allowDefiner: false, revokeTemp: false, revokeCreate: false, ...extra });
}

/** Top-level statements: non-comment, non-blank, non-meta-command lines outside DO $$ ... $$ bodies. */
function statements(sql: string): string[] {
  const out: string[] = [];
  let inBody = false;
  for (const raw of sql.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('--') || line.startsWith('\\')) continue;
    if (!inBody && /^DO \$\$/.test(line)) { inBody = true; out.push(line); continue; }
    if (inBody) { if (/^END \$\$;/.test(line)) inBody = false; continue; }
    out.push(line);
  }
  return out;
}

describe('sql/setup-role.sql template', () => {
  const sql = render();
  const stmts = statements(sql);

  it('substitutes the role and the hidden list', () => {
    expect(sql).not.toMatch(/__[A-Z_]+__/);
    expect(sql).toContain(`'public|customers|secret'`);
    expect(render('other_ro')).toContain('"other_ro"');
  });

  it('runs as one transaction: first statement BEGIN;, last COMMIT;', () => {
    expect(stmts[0]).toBe('BEGIN;');
    expect(stmts[stmts.length - 1]).toBe('COMMIT;');
    expect(stmts.filter((s) => s === 'BEGIN;')).toHaveLength(1);
    expect(stmts.filter((s) => s === 'COMMIT;')).toHaveLength(1);
  });

  it('pins ON_ERROR_STOP on and ON_ERROR_ROLLBACK off before BEGIN, so a psqlrc cannot undo the transaction', () => {
    const at = (needle: string) => {
      const hits = [...sql.matchAll(new RegExp(`^${needle.replace(/\\/g, '\\\\')}$`, 'gm'))];
      expect(hits, needle).toHaveLength(1);
      return hits[0].index!;
    };
    const begin = at('BEGIN;');
    expect(at('\\set ON_ERROR_STOP on')).toBeLessThan(begin);
    expect(at('\\set ON_ERROR_ROLLBACK off')).toBeLessThan(begin);
  });

  it('sets PASSWORD NULL only when the role is created, never on a re-run', () => {
    const hits = [...sql.matchAll(/PASSWORD NULL/g)].map((m) => m.index!);
    expect(hits).toHaveLength(1);
    const createBranch = /IF NOT EXISTS \(SELECT 1 FROM pg_roles WHERE rolname = 'daypass_ro'\) THEN([\s\S]*?)END IF;/.exec(sql);
    expect(createBranch).not.toBeNull();
    const start = createBranch!.index;
    const end = start + createBranch![0].length;
    expect(hits[0]).toBeGreaterThan(start);
    expect(hits[0]).toBeLessThan(end);
    // The unconditional ALTER ROLE keeps the attribute lock-down but not the password reset.
    const alter = /^ALTER ROLE "daypass_ro" WITH [^\n]*$/m.exec(sql)?.[0];
    expect(alter).toMatch(/LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 5/);
    expect(alter).not.toMatch(/PASSWORD/);
  });

  it('keeps the DO blocks (create role, attributes, rds_iam grant, owned objects + membership, grants + hide + self-check, report, final check)', () => {
    expect(sql.match(/^DO \$\$/gm)).toHaveLength(7);
    expect(sql).toContain('self-check failed');
  });

  describe('review 2026-10-30: the role is only what the script grants', () => {
    /** The template minus its `--` comments, so prose about what the script no longer does cannot satisfy a check. */
    const code = sql.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');
    it('never grants ALL TABLES and sets no default privileges: new relations are invisible until a re-run', () => {
      expect(code).not.toMatch(/GRANT SELECT ON ALL TABLES/);
      // ALTER DEFAULT PRIVILEGES appears only to REVOKE (old installs), never to GRANT.
      const adp = code.split('\n').filter((l) => l.includes('ALTER DEFAULT PRIVILEGES'));
      expect(adp.length).toBeGreaterThan(0);
      for (const l of adp) expect(l).toMatch(/ALTER DEFAULT PRIVILEGES[^\n]*REVOKE ALL ON/);
      expect(code).not.toMatch(/ALTER DEFAULT PRIVILEGES[^\n]*GRANT/);
    });
    it('substitutes schemas, allow list, definer and temp flags', () => {
      const r = render('daypass_ro', ['analytics.events.user_email', '"Order-Items"."ship.address"'], {
        allow: ['customers.newcol'],
        schemas: ['public', 'analytics'],
        allowDefiner: true,
        revokeTemp: true,
      });
      expect(r).not.toMatch(/__[A-Z_]+__/);
      expect(r).toContain(`'analytics|events|user_email'`);
      expect(r).toContain(`'public|Order-Items|ship.address'`);
      expect(r).toContain(`'public|customers|newcol'`);
      expect(r).toMatch(/schemas\s+text\[\]\s*:=\s*ARRAY\['public','analytics'\]/);
      expect(r).toMatch(/allow_definer\s+boolean\s*:=\s*true/);
      expect(r).toMatch(/revoke_temp\s+boolean\s*:=\s*true/);
      expect(sql).toMatch(/allow_definer\s+boolean\s*:=\s*false/);
      expect(sql).toMatch(/revoke_temp\s+boolean\s*:=\s*false/);
      expect(sql).toMatch(/allow_in\s+text\[\]\s*:=\s*ARRAY\[\]::text\[\]/);
    });
    it('escapes single quotes in identifiers', () => {
      expect(render('daypass_ro', [`"it's".col`])).toContain(`'public|it''s|col'`);
    });
    it('uses pg_attribute (not information_schema.columns, which omits matviews) and the shared relkind set', () => {
      expect(code).not.toContain('information_schema.columns');
      expect(code).toContain(`relkind IN (${HIDDEN_RELKINDS.map((k) => `'${k}'`).join(',')})`);
    });
    it('expands hidden columns over pg_inherits and refuses a child that lacks the column', () => {
      expect(sql).toContain('pg_inherits');
      expect(sql).toMatch(/lacks column/);
    });
    it('withholds views that depend on a hidden column, found through pg_depend/pg_rewrite', () => {
      expect(sql).toContain('pg_rewrite');
      expect(sql).toContain('pg_depend');
      expect(sql).toMatch(/exposes hidden column/);
    });
    it('fails on executable SECURITY DEFINER functions unless acknowledged, naming both remedies', () => {
      expect(sql).toContain('prosecdef');
      expect(sql).toContain('REVOKE EXECUTE ON FUNCTION');
      expect(sql).toContain('--allow-definer-functions');
    });
    it('refuses a PUBLIC grant on a hidden table and names the fix', () => {
      expect(sql).toContain('aclexplode');
      expect(sql).toMatch(/REVOKE SELECT ON .* FROM PUBLIC/);
    });
    it('snapshots readable columns before revoking, so a column added to a hidden table since the last run stops the script', () => {
      const snap = sql.indexOf('prev_readable');
      const revoke = sql.indexOf("REVOKE ALL ON %s %s FROM %I");
      expect(snap).toBeGreaterThan(0);
      expect(snap).toBeLessThan(revoke);
      expect(sql).toMatch(/added since the last run/);
    });
    it('reports TEMP, the RDS password note and the role-settings caveat', () => {
      expect(code).toMatch(/has_database_privilege\((role_name|'daypass_ro'), current_database\(\), 'TEMP'\)/);
      expect(code).toMatch(/role_name\s+constant text := 'daypass_ro'/);
      expect(sql).toContain('rds.restrict_password_commands');
      expect(sql).toMatch(/REVOKE TEMP ON DATABASE %I FROM PUBLIC/);
    });
    it('self-checks that no readable relation depends on a hidden column', () => {
      expect(sql).toMatch(/has_any_column_privilege/);
    });
  });

  describe('review 2026-10-30 round 2', () => {
    const code = sql.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');
    /** The body of each DO $$ ... $$ block: exactly one opening and one closing $$ each. */
    const doBodies = (s: string) => [...s.matchAll(/^DO \$\$\n([\s\S]*?)^END \$\$;/gm)].map((m) => m[1]);

    it('I1: identifiers with $, $$, $\' or a placeholder name cannot break the template', () => {
      const nasty = [`t."a$'b"`, `t."p$$$$q"`, `t."x$&y"`, `t."__SCHEMAS__"`, `t."__ALLOW__"`, `t."back\\slash"`];
      const r = render('daypass_ro', nasty);
      // Every placeholder is replaced exactly where it stands, once.
      expect(r).toMatch(/schemas\s+text\[\]\s*:=\s*ARRAY\['public'\];/);
      expect(r).toMatch(/allow_in\s+text\[\]\s*:=\s*ARRAY\[\]::text\[\];/);
      expect(r).toContain(`'public|t|__SCHEMAS__'`);
      expect(r).toContain(`'public|t|__ALLOW__'`);
      // No `$` reaches a dollar-quoted body: such entries travel hex-encoded.
      const bodies = doBodies(r);
      expect(bodies).toHaveLength(7);
      for (const b of bodies) expect(b).not.toContain('$$');
      const hex = (s: string) => Buffer.from(s, 'utf8').toString('hex');
      for (const e of ["public|t|a$'b", 'public|t|p$$$$q', 'public|t|x$&y', 'public|t|back\\slash']) {
        expect(r).toContain(`convert_from(decode('${hex(e)}', 'hex'), 'UTF8')`);
      }
      // The rest of the template is unchanged by the nasty entries.
      expect(r.length - render('daypass_ro', []).length).toBeGreaterThan(0);
      expect(r.split('\n').filter((l) => l.startsWith('COMMIT;'))).toHaveLength(1);
    });
    it('I2: --revoke-public-create flows in and the report names CREATE', () => {
      expect(render('daypass_ro', [], { revokeCreate: true })).toMatch(/revoke_create\s+boolean\s*:=\s*true/);
      expect(sql).toMatch(/revoke_create\s+boolean\s*:=\s*false/);
      expect(code).toMatch(/REVOKE CREATE ON SCHEMA %I FROM PUBLIC/);
      expect(code).toMatch(/can create objects in schema\(s\)/);
    });
    it('C1: removes default privileges for the role and self-checks that none remain', () => {
      expect(code).toMatch(/ALTER DEFAULT PRIVILEGES FOR ROLE %I %s REVOKE ALL ON %s FROM %I/);
      expect(code).toMatch(/pg_default_acl/);
    });
    it('I4: revokes what the role holds in every schema, not only the listed ones', () => {
      expect(code).not.toMatch(/REVOKE ALL ON ALL TABLES IN SCHEMA/);
      expect(code).toMatch(/REVOKE ALL ON %s %s FROM %I/);
      expect(code).toMatch(/REVOKE ALL ON SCHEMA %I FROM %I/);
    });
    it('C3/M1/I5: taint follows ON SELECT rules only, whole-row Vars and unlisted schemas', () => {
      expect(code).toMatch(/rw\.ev_type = '1'/);
      expect(code).not.toMatch(/pg_rewrite rw ON rw\.oid = d\.objid\s+WHERE (?![\s\S]{0,200}ev_type)/);
      expect(code).toContain(":varattno 0 ");
      expect(code).toMatch(/which is not in --schemas/);
    });
    it('C2: refuses a hidden column on a child whose parent column is not hidden', () => {
      expect(code).toMatch(/is on a partition\/child of/);
    });
    it('C4: the SECURITY DEFINER check is not limited to --schemas', () => {
      const q = /FROM pg_proc p[\s\S]*?has_function_privilege\(role_name, p\.oid, 'EXECUTE'\)/.exec(code)?.[0];
      expect(q).toBeDefined();
      expect(q).not.toMatch(/ANY \(schemas\)/);
    });
    it('I3: resets per-database settings of the role', () => {
      expect(code).toMatch(/ALTER ROLE %I IN DATABASE %I RESET ALL/);
      expect(code).toMatch(/pg_db_role_setting/);
    });
    it('PG 16: checks ADMIN OPTION before altering an existing role, skips rds_iam when already a member, dedupes memberships', () => {
      expect(code).toMatch(/server_version_num[\s\S]{0,120}MEMBER WITH ADMIN OPTION/);
      expect(code).toMatch(/pg_has_role\('daypass_ro', 'rds_iam', 'MEMBER'\)/);
      expect(code).toMatch(/string_agg\(DISTINCT r\.rolname/);
    });
    it('M2: the hidden-column self-check points at other grantors', () => {
      expect(code).toMatch(/another role may have granted it/);
    });
  });

  describe('review 2026-10-30 round 3', () => {
    const code = sql.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');
    it('C1: pins search_path right after BEGIN, before any other statement', () => {
      const stmts = statements(sql);
      expect(stmts[0]).toBe('BEGIN;');
      expect(stmts[1]).toBe('SET LOCAL search_path = pg_catalog, pg_temp;');
    });
    it('C1: refuses a role that owns objects (pg_shdepend) before the grants block', () => {
      const owned = code.indexOf('owns objects in this database');
      expect(owned).toBeGreaterThan(0);
      expect(owned).toBeLessThan(code.indexOf('hidden_in     text[]'));
      expect(code).toMatch(/pg_shdepend/);
      expect(code).toMatch(/DROP OWNED BY/);
    });
    it('C3: membership in any role other than rds_iam is an error, not a notice', () => {
      expect(code).toMatch(/RAISE EXCEPTION 'role % is a member of %/);
      expect(code).not.toMatch(/RAISE NOTICE 'warning: % is a member/);
    });
    it('C2: refuses a generated column computed from a hidden column; reports catalog text', () => {
      expect(code).toMatch(/derived from a hidden column would be readable/);
      expect(code).toMatch(/catalog text: % mentions hidden column/);
    });
    it('C4/writes/large objects: self-checks beyond the role\'s own grants', () => {
      expect(code).toMatch(/can read relation\(s\) outside --schemas/);
      expect(code).toMatch(/has_table_privilege\(role_name, c\.oid, write_privs\)/);
      expect(code).toMatch(/'USAGE, UPDATE'/);
      expect(code).toMatch(/MAINTAIN/);
      expect(code).toMatch(/lo_compat_privileges/);
    });
    it('C5: foreign tables are listable, never granted, and taint views', () => {
      expect(code).toMatch(/reads foreign table/);
      expect(code).toMatch(/c\.relkind <> 'f'/);
    });
    it('doctor manifest: the run stores its hidden list on the role', () => {
      const r = render('daypass_ro', ['customers.secret'], { allow: ['customers.name'] });
      expect(r).toContain(`manifest_in   text    := '{"hidden":["customers.secret"],"allow":["customers.name"],"schemas":["public"],"allowDefiner":false}';`);
      expect(code).toMatch(/COMMENT ON ROLE %I IS %L/);
    });
    it('resets every role setting before writing the five', () => {
      expect(code).toMatch(/ALTER ROLE "daypass_ro" RESET ALL;\nALTER ROLE "daypass_ro" SET default_transaction_read_only = on;/);
    });
  });

  describe('review 2026-10-30 round 4', () => {
    const code = sql.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');
    it('1: matviews calling non-catalog or data-reading functions are withheld, with the same pattern as hidden.ts', () => {
      expect(code).toContain(`p.proname ~ '${DATA_READING_FUNCTIONS.source}'`);
      expect(code).toMatch(/:\(funcid\|opfuncid\|aggfnoid\|winfnoid\)/);
      expect(code).toMatch(/WITH RECURSIVE tree\(mv, rel, via\) AS \(\n\s+SELECT c\.oid, c\.oid, c\.oid FROM pg_class c\n\s+WHERE c\.relkind = 'm'/);
    });
    it('2: views over catalogs the role cannot read are withheld', () => {
      expect(code).toMatch(/:relid \(\[0-9\]\+\)/);
      expect(code).toMatch(/which the role cannot read itself/);
    });
    it('sequences owned by a hidden column are not granted; no bulk sequence grant', () => {
      expect(code).not.toMatch(/GRANT SELECT ON ALL SEQUENCES/);
      expect(code).toMatch(/GRANT SELECT ON SEQUENCE %s TO %I/);
    });
    it('repeats the owns-nothing / no-membership check as the last step before COMMIT', () => {
      const last = code.lastIndexOf('owns objects in this database');
      expect(last).toBeGreaterThan(code.indexOf('hidden columns verified'));
      expect(code.indexOf('COMMIT;')).toBeGreaterThan(last);
      expect(code.lastIndexOf('is a member of')).toBeGreaterThan(code.indexOf('hidden columns verified'));
    });
    it('CVE-2024-4317: refuses unpatched pg_stats_ext / pg_stats_ext_exprs', () => {
      expect(code).toMatch(/pg_get_viewdef\('pg_catalog\.pg_stats_ext'::regclass\) !~ 'pg_has_role'/);
      expect(code).toMatch(/pg_get_viewdef\('pg_catalog\.pg_stats_ext_exprs'::regclass\) !~ 'pg_has_role'/);
      expect(code).toMatch(/fix-CVE-2024-4317\.sql/);
    });
    it('warns before replacing a role comment Daypass did not write', () => {
      expect(code).toMatch(/replacing the comment on role/);
    });
  });

  it('reports functions the role can execute outside pg_catalog, with the REVOKE hint, and revokes nothing', () => {
    const code = sql.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');
    expect(code).toMatch(/can execute % function\(s\) outside pg_catalog/);
    expect(code).toMatch(/REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA <s> FROM PUBLIC/);
    expect(code).not.toMatch(/EXECUTE format\('REVOKE EXECUTE ON ALL FUNCTIONS/);
  });
});

describe('review 2026-11-01', () => {
  const code = render().split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');
  /** The grants block: from its DECLARE to the report block. */
  const grants = code.slice(code.indexOf('hidden_in     text[]'), code.indexOf('hidden columns verified'));
  /** The last DO block, run just before COMMIT. */
  const final = code.slice(code.lastIndexOf('DO $$'), code.indexOf('COMMIT;'));

  it('1: the write self-check sees column-level INSERT/UPDATE grants', () => {
    expect(grants).toMatch(/has_any_column_privilege\(role_name, c\.oid, 'INSERT, UPDATE'\)/);
  });
  it('2: removes SUPERUSER / REPLICATION / BYPASSRLS when set, before the role is altered, and verifies all five attributes last', () => {
    const attrs = code.indexOf("'NOREPLICATION'");
    expect(attrs).toBeGreaterThan(0);
    expect(attrs).toBeLessThan(code.indexOf('ALTER ROLE "daypass_ro" WITH LOGIN'));
    expect(code).toMatch(/'NOSUPERUSER'[\s\S]{0,200}'NOBYPASSRLS'/);
    expect(code).toMatch(/only a superuser can remove that/);
    for (const a of ['rolsuper', 'rolreplication', 'rolbypassrls', 'rolcreatedb', 'rolcreaterole']) expect(final).toContain(a);
  });
  it('3: rds_iam is login-only from PG 16 and must hold nothing before it', () => {
    expect(code).toMatch(/GRANT rds_iam TO "daypass_ro" WITH INHERIT FALSE, SET FALSE/);
    expect(final).toMatch(/m\.set_option OR m\.inherit_option OR m\.admin_option/);
    expect(final).toMatch(/pg_shdepend d WHERE d\.refclassid = 'pg_authid'::regclass AND d\.refobjid = iam_oid/);
    expect(final).toMatch(/m\.member = iam_oid/);
    expect(final).toMatch(/rds_iam must hold nothing/);
  });
  it('4/5: matviews: the whole view tree is walked for catalogs, RLS and non-trivial functions, with the lists doctor uses', () => {
    expect(grants).toMatch(/WITH RECURSIVE tree\(mv, rel, via\)/);
    expect(grants).toContain(`tc.relname IN (${MATVIEW_SAFE_CATALOGS.map((c) => `'${c}'`).join(',')})`);
    expect(grants).toContain(`p.proname !~ '${MATVIEW_SAFE_FUNCTIONS.source}'`);
    expect(grants).toContain(`p.proname ~ '${DATA_READING_FUNCTIONS.source}'`);
    expect(grants).toMatch(/p\.provolatile <> 'i'/);
    expect(grants).toMatch(/relrowsecurity/);
    expect(grants).toMatch(/:\(opno\|sortop\|eqop\)/);
    // doctor walks the same tree
    expect(MATVIEW_LEAKS_SQL).toMatch(/with recursive tree\(root, rel, via\)/);
    expect(MATVIEW_LEAKS_SQL).toMatch(/p\.provolatile <> 'i'/);
    expect(MATVIEW_LEAKS_SQL).toMatch(/relrowsecurity/);
  });
  it('round 2: views over RLS (unless security_invoker), sequences of hidden columns, and more matview function paths', () => {
    expect(grants).toContain(`OR (c.relkind = 'v' AND NOT coalesce((SELECT bool_or(o ~* '^security_invoker=(t|tr|tru|true|y|ye|yes|on|1)$') FROM unnest(c.reloptions) o), false))`);
    expect(grants).toMatch(/reads %s, which the role is not granted%s/);
    expect(grants).toMatch(/has_sequence_privilege\(role_name, t\.oid, 'SELECT'\)/);
    for (const s of [`':opnos [(]o ([0-9 ]+)[)]'`, `'[{]COERCEVIAIO '`, `':refcontainertype ([0-9]+)'`, `'[{]COERCETODOMAIN '`]) {
      expect(grants).toContain(s);
      expect(MATVIEW_LEAKS_SQL).toContain(s);
    }
    expect(grants).toMatch(/extension ones included/);
  });
  it('6: refuses foreign server / wrapper USAGE and user mappings for the role or PUBLIC', () => {
    expect(grants).toMatch(/has_server_privilege\(role_name, s\.oid, 'USAGE'\)/);
    expect(grants).toMatch(/has_foreign_data_wrapper_privilege\(role_name, w\.oid, 'USAGE'\)/);
    expect(grants).toMatch(/pg_user_mappings u WHERE u\.umuser IN \(0, role_oid\)/);
  });
  it('7: refuses default privileges for PUBLIC, except Postgres\' own function EXECUTE / type USAGE', () => {
    expect(grants).toMatch(/default privileges grant PUBLIC/);
    expect(grants).toMatch(/NOT \(d\.defaclobjtype = 'f' AND a\.privilege_type = 'EXECUTE'\)/);
  });
  it('8: compares system catalog privileges with pg_init_privs', () => {
    expect(grants).toMatch(/pg_init_privs/);
    expect(grants).toMatch(/beyond a fresh cluster/);
  });
});
