import { describe, it, expect } from 'vitest';
import { roleSettingsDrift, parseManifest, runsSqlFromString, EXPECTED_ROLE_SETTINGS } from '../src/cli/doctor.js';

/** What sql/setup-role.sql writes, as pg_roles.rolconfig shows it. */
const SETUP = Object.entries(EXPECTED_ROLE_SETTINGS).map(([k, v]) => `${k}=${v}`);
const replace = (k: string, v: string | null) => [...SETUP.filter((e) => !e.startsWith(`${k}=`)), ...(v === null ? [] : [`${k}=${v}`])];

describe('roleSettingsDrift (M5)', () => {
  it('no drift for exactly what the setup writes', () => {
    expect(roleSettingsDrift(SETUP)).toEqual([]);
  });
  it('reports a missing setting, and a null rolconfig as all five missing', () => {
    expect(roleSettingsDrift(replace('lock_timeout', null))).toEqual(['lock_timeout missing (want 1s)']);
    expect(roleSettingsDrift(null)).toHaveLength(5);
  });
  it('reports a changed exact setting', () => {
    expect(roleSettingsDrift(replace('default_transaction_read_only', 'off'))).toEqual(['default_transaction_read_only=off (want on)']);
    expect(roleSettingsDrift(replace('temp_file_limit', '-1'))).toEqual(['temp_file_limit=-1 (want 256MB)']);
  });
  it('keeps everything after the first "=" as the value', () => {
    expect(roleSettingsDrift([...SETUP, 'search_path=a=b'])).toEqual(['search_path=a=b (not set by the setup)']);
    expect(roleSettingsDrift(replace('lock_timeout', '1s=x'))).toEqual(['lock_timeout=1s=x (want 1s)']);
  });
  it('M4: statement_timeout may be raised for a replica, up to 5min; 0 (no limit) and more are drift', () => {
    for (const ok of ['10s', '60s', '1min', '300s', '5min', '250ms', '30000']) expect(roleSettingsDrift(replace('statement_timeout', ok)), ok).toEqual([]);
    for (const bad of ['0', '1h', '301s', '6min', 'forever']) {
      expect(roleSettingsDrift(replace('statement_timeout', bad)), bad).toEqual([`statement_timeout=${bad} (want 1ms to 5min, set up as 10s)`]);
    }
  });
  it('I3: per-database settings override the role ones and are always drift (the setup never writes any)', () => {
    expect(roleSettingsDrift(SETUP, ['default_transaction_read_only=off', 'statement_timeout=0'])).toEqual([
      'default_transaction_read_only=off (in database, overrides the role default)',
      'statement_timeout=0 (in database, overrides the role default)',
    ]);
  });
});

describe('review 2026-10-30 round 3', () => {
  it('flags role settings the setup did not write (the setup resets them)', () => {
    expect(roleSettingsDrift([...SETUP, 'search_path=public', 'role=app'])).toEqual([
      'search_path=public (not set by the setup)',
      'role=app (not set by the setup)',
    ]);
  });
  it('parseManifest reads the per-database list the setup stored on the role, and nothing else', () => {
    const c = JSON.stringify({ daypass: 1, databases: { db1: { hidden: ['customers.secret'], allow: ['customers.name'], schemas: ['public'], allowDefiner: true } } });
    expect(parseManifest(c, 'db1')).toEqual({ hidden: ['customers.secret'], allow: ['customers.name'], schemas: ['public'], allowDefiner: true });
    expect(parseManifest(c, 'other')).toBeNull();
    expect(parseManifest('a human comment', 'db1')).toBeNull();
    expect(parseManifest(null, 'db1')).toBeNull();
    expect(parseManifest(JSON.stringify({ databases: { db1: { hidden: 'x' } } }), 'db1')).toBeNull();
    expect(parseManifest(JSON.stringify({ databases: { db1: { hidden: ['a.b', 7] } } }), 'db1')).toEqual({ hidden: ['a.b'], allow: [], schemas: [], allowDefiner: false });
  });
});

describe('runsSqlFromString (functions the role can EXECUTE)', () => {
  it.each(['query text', 'edges_sql text', 'p_query text, n integer', 'id integer, stmt character varying', 'command text DEFAULT \'\'::text', 'IN sql_text text', 'statement text'])(
    'flags %s',
    (a) => expect(runsSqlFromString(a)).toBe(true),
  );
  it.each(['', 'id integer', 'name text', 'query integer', 'queryable boolean', 'note text, sqlstate_code integer'])('does not flag %s', (a) =>
    expect(runsSqlFromString(a)).toBe(false),
  );
});

