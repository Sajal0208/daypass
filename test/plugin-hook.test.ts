import { afterAll, describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide, hiddenFilePath, looksSensitive as hookLooksSensitive } from '../plugin/hooks/pii-guard.mjs';
import { looksSensitive as coreLooksSensitive } from '../src/core/hidden.js';

const PATH = '/home/me/.daypass/hidden-columns.txt';
const env = (extra: Record<string, string> = {}) => ({ DAYPASS_HIDDEN_FILE: PATH, ...extra });

describe('decide', () => {
  it('allows a query with no sensitive-looking identifier', () => {
    expect(decide('select id, name from users', 'users.email\n', env())).toEqual({ allow: true });
  });

  it('denies a sensitive identifier when there is no list file, naming the path', () => {
    const r = decide('select phone from users', null, env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('no hidden-columns list');
    expect(r.reason).toContain(PATH);
    expect(r.reason).toContain('daypass hidden suggest --live');
    expect(r.reason).toContain('https://github.com/Sajal0208/daypass/blob/main/docs/hidden-columns.md');
    expect(r.reason).toContain('Tell the user:');
  });

  it('denies with a distinct reason when the list exists but cannot be read', () => {
    const r = decide('select phone from users', { error: 'EISDIR' }, env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('cannot read hidden-columns list');
    expect(r.reason).toContain(PATH);
    expect(r.reason).toContain('EISDIR');
    expect(r.reason).not.toContain('no hidden-columns list');
  });

  it('ignores an unreadable list when no identifier looks sensitive', () => {
    expect(decide('select id, name from users', { error: 'EISDIR' }, env())).toEqual({ allow: true });
  });

  it('denies a sensitive identifier the list does not cover, naming it and the path', () => {
    const r = decide('select phone from users', 'users.email\n', env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('"phone"');
    expect(r.reason).toContain(PATH);
    expect(r.reason).toContain('"<table>.phone"');
    expect(r.reason).toContain('"!<table>.phone"');
    expect(r.reason).toContain('DAYPASS_PII_HOOK=off');
    expect(r.reason).toContain('Tell the user:');
    expect(r.reason).toContain('have the database owner re-run daypass sql --hide-file ' + PATH);
  });

  it('allows a sensitive identifier that the list hides', () => {
    expect(decide('select phone from users', 'users.phone\n', env())).toEqual({ allow: true });
  });

  it('allows a sensitive identifier on an allow (!) line', () => {
    expect(decide('select phone from users', '!users.phone  # reviewed\n', env())).toEqual({ allow: true });
  });

  it('matches list entries case-insensitively and strips comments', () => {
    expect(decide('select PHONE from users', '# header\nusers.Phone # c\n', env())).toEqual({ allow: true });
  });

  it('infers the table for a qualified identifier through a FROM alias', () => {
    const r = decide('select p.email_address from profiles p', 'users.email\n', env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('"profiles.email_address"');
    expect(r.reason).toContain('"!profiles.email_address"');
  });

  it('infers the table for a qualified identifier through a JOIN "as" alias', () => {
    const r = decide('select u.id from users u join profiles as pr on pr.user_id = u.id where pr.phone is null', '', env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('"profiles.phone"');
  });

  it('allows a safe-tail name such as email_verified', () => {
    expect(decide('select id from users where email_verified = true', '', env())).toEqual({ allow: true });
  });

  it('ignores sensitive words inside string literals and comments', () => {
    const sql = `select id from users where name = 'phone' -- phone\n and status = 'it''s email' /* secret */`;
    expect(decide(sql, '', env())).toEqual({ allow: true });
  });

  it('is disabled by DAYPASS_PII_HOOK=off, even without a list', () => {
    expect(decide('select phone, password_hash from users', null, env({ DAYPASS_PII_HOOK: 'off' }))).toEqual({ allow: true });
  });

  it('never flags SQL keywords such as count', () => {
    expect(decide('select count(*) from users', '', env())).toEqual({ allow: true });
  });

  it('inspects double-quoted identifiers', () => {
    const r = decide('select "phoneNumber" from "users"', '', env());
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toContain('"phoneNumber"');
  });

  it('falls back to ~/.daypass/hidden-columns.txt when DAYPASS_HIDDEN_FILE is unset', () => {
    const r = decide('select phone from users', null, {});
    expect(r.allow).toBe(false);
    if (r.allow) return;
    expect(r.reason).toMatch(/\.daypass\/hidden-columns\.txt/);
  });
});

const LIST = 'users.email\n!servers.address  # host IP\n';
const deny = (sql: string, list: string | null = LIST) => {
  const r = decide(sql, list, env());
  expect(r.allow, sql).toBe(false);
  return r.allow ? '' : r.reason;
};
const allow = (sql: string, list: string | null = LIST) => expect(decide(sql, list, env()), sql).toEqual({ allow: true });

describe('decide: SELECT * and whole-row references', () => {
  const STAR = 'SELECT * can return columns the hidden list does not cover; name the columns';
  it.each(['select * from users', 'select u.* from users u', 'select (u).* from users u', 'select row(u.*) from users u', 'SELECT DISTINCT * FROM users', 'select id from users where id in (select * from admins)', 'select * from (values (1)) v(x)'])(
    'blocks %s',
    (sql) => expect(deny(sql)).toContain(STAR),
  );
  it.each(['select count(*) from users', 'select 10 * count(*) from users', 'select price * qty from items', 'select price*qty, (a) * 2, f(x) * 3, 2 * 3 from items', 'select count(*) filter (where id > 1) from users'])(
    'allows %s (count(*) or multiplication)',
    (sql) => allow(sql),
  );
  it.each([
    'select to_jsonb(u) from users u',
    'select row_to_json(u) from users u',
    'select jsonb_agg(u) from users u',
    'select u::text from users u',
    'select (u).phone from users u',
    'select u from users u',
    'select users from users',
    'select x from users u, lateral (select u) x',
    'select u as whole from users u',
    'select 1 from users u where u is not null',
    'select array_agg(u order by u.id) from users u',
    'select u from public.users as u',
    'select "U" from "Users" "U"',
  ])('blocks the whole-row reference in %s', (sql) => {
    const reason = deny(sql);
    expect(reason).toMatch(/whole row|whole-row/i);
    expect(reason).toContain('Daypass PII guard:');
  });
  it.each([
    'select count(*) as users from users',
    'select count(*) users from users',
    'select u.id, u.name from users u join orders o on o.user_id = u.id where o.status = \'paid\'',
    'select g from generate_series(1, 3) g',
    'select s.id from (select id from users) s',
    'with recent as (select id from users where created_at > now()) select recent.id from recent',
    'with r as (select id from users) select r from r',
    'select extract(year from created_at), created_at from users',
    'select substring(name from 1 for 2), trim(both \'x\' from name), name from users',
    'select id from users u order by u.id desc limit 10',
    'select id from users where exists (select 1 from orders o where o.user_id = users.id)',
    'select o.id from orders o natural join items',
    'select v.x from (values (1)) v(x)',
  ])('allows %s', (sql) => allow(sql));
});

describe('decide: xml / SQL-from-string function family', () => {
  it.each([
    "select query_to_xml('select phone from users', true, false, '')",
    "select table_to_xml('users', true, false, '')",
    "select pg_catalog.query_to_xml_and_xmlschema('select 1', true, false, '')",
    "select query_to_xmlschema('select 1', true, false, '')",
    "select cursor_to_xml('c', 1, true, false, '')",
    "select cursor_to_xmlschema('c', true, false, '')",
    "select table_to_xml_and_xmlschema('users', true, false, '')",
    "select table_to_xmlschema('users', true, false, '')",
    "select p from xmltable('/row' passing query_to_xml('select phone from users', true, false, '') columns p text path 'phone') x",
    "select QUERY_TO_XML ('select 1', true, false, '')",
    'select "query_to_xml"(\'select 1\', true, false, \'\')',
  ])('blocks %s', (sql) => {
    const reason = deny(sql);
    expect(reason).toContain('executes SQL from a string / returns whole rows, which the guard cannot inspect');
    expect(reason).toMatch(/query_to_xml|table_to_xml|cursor_to_xml|xmltable|query_to_xmlschema|table_to_xmlschema/i);
  });
  it('blocks the family even with a list that covers every name', () => {
    deny("select query_to_xml('select 1', true, false, '')", 'users.phone\nusers.email\n');
  });
  it('does not flag a column that happens to be named like one of them', () => {
    allow('select xmltable from docs');
  });
});

describe('decide: tokenizer-backed literal and identifier handling', () => {
  it.each([
    "select E'\\'', phone from users -- '",
    "select $$'$$, phone from users where id = $$'$$",
    "select $q$'$q$, phone from users where id = $q$'$q$",
    'select id as "x\'y", phone from users where status = \'z\'',
    'select U&"ph\\006Fne" from users',
    'select U&"ph!006Fne" UESCAPE \'!\' from users',
    'select U&"ph\\+00006Fne" from users',
    'select "phone" from users',
    'select "PhoneNumber" from users',
    'select u."phone" from users u',
    "select e'x' , phone from users",
    'select id /* comment with \'quote */, phone from users',
    'select id, /* nested /* comment */ still comment */ phone from users',
    "select N'x', phone from users",
    "select B'1010', X'FF', phone from users",
    "select U&'\\0041', phone from users",
    'select id, phone from users where id = $1',
    'select 1e5, .5, 0x1F, phone from users',
  ])('still sees the sensitive identifier in %s', (sql) => expect(deny(sql)).toMatch(/"phone/i));
  it.each([
    "select id from users where name = 'phone' -- phone\n and status = 'it''s email' /* secret */",
    "select id from users where name = E'it\\'s phone' and x = 'y'",
    'select id from users where note = $$phone$$ and tag = $t$ssn$t$',
    'select id from users where name = E\'\\\\\' and status = \'phone\'',
    'select id /* a /* b phone */ c */ from users',
    "select id from users where x = U&'ph\\006Fne'",
    'select id from users -- phone',
    'select id from users /* unterminated phone',
    "select id from users where x = 'unterminated phone",
  ])('ignores literals and comments in %s', (sql) => allow(sql));
  it('decodes U& identifiers in the reason', () => {
    expect(deny('select U&"ph\\006Fne" from users')).toContain('"phone"');
  });
  it('reports a quoted mixed-case identifier as written', () => {
    expect(deny('select "PhoneNumber" from users')).toContain('"PhoneNumber"');
  });
});

describe('decide: regressions from the 2026-10-30 bypass review (each one leaked phone on PG 14)', () => {
  // C1: the name heuristic must see the name Postgres resolves, not the spelling.
  it.each(['select phonE from users', 'select pHONE from users', 'select u.Phone_Number from users u'])('blocks the mixed-case spelling %s', (sql) =>
    expect(deny(sql)).toMatch(/looks like personal or secret data/),
  );
  // I4: toSnake parity: non-alphanumerics in a quoted name split words, as in src/core/hidden.ts.
  it.each(['select "phone-number" from t', 'select "user email" from t', 'select "ship.address" from t'])('blocks the quoted name %s', (sql) =>
    expect(deny(sql)).toMatch(/looks like personal or secret data/),
  );
  // C2: whole-row references the FROM parser missed.
  it.each([
    'select to_jsonb(l) from users u, leads l', // (a) comma FROM list
    'select to_jsonb(l) from users u, public.leads as l where u.id = l.id',
    'select to_jsonb(l) from (leads l join users u on true)', // (b) parenthesised join
    'select to_jsonb(j) from (leads l join users u on true) j',
    'select to_jsonb(u) from leads u where exists (select 1 from generate_series(1,1) u)', // (c) inner scope must not downgrade
    'with leads as (select 1 x) select to_jsonb(leads) from public.leads', // (d) qualified name is never the CTE
    'select to_jsonb(leads) from leads window a as (), leads as ()', // (d) WINDOW names are not CTEs
    'select to_jsonb(leads) from leads where exists (with leads as (select 1) select 1 from leads)', // (d) CTE scope
    'select distinct on (l.id) l from leads l', // (e)
    'select l.to_jsonb from leads l', // (f) attribute notation
    'select l.row_to_json from leads l',
    'select l.json_agg from leads l',
    'select l.concat from leads l',
    'select l.record_out from leads l',
    'select to_jsonb(l) from leads * l', // inheritance star
  ])('blocks the whole-row reference in %s', (sql) => expect(deny(sql)).toMatch(/whole row/));
  // C3: a column alias list renames table columns by position.
  it.each(['select c from leads l(a, c)', 'select z from users u(a, b, z)', 'select z from users as u (a, b, z)', 'select b from (leads l join users u on true) j(a, b)'])(
    'blocks the column alias list in %s',
    (sql) => expect(deny(sql)).toContain('column alias list'),
  );
  // I1: TABLE x is SELECT * FROM x.
  it.each(['table users', 'TABLE leads', 'select 1 union table leads', 'with s as (table leads) select 1', 'explain table leads'])('blocks %s', (sql) =>
    expect(deny(sql)).toContain('TABLE'),
  );
  // I2: more SQL-from-string / whole-schema functions.
  it.each([
    "select ts_stat('select to_tsvector(phone) from leads')",
    "select ts_rewrite('a'::tsquery, 'select ''a''::tsquery, phone::tsquery from leads')",
    "select schema_to_xml('public', true, false, '')",
    "select schema_to_xmlschema('public', true, false, '')",
    "select schema_to_xml_and_xmlschema('public', true, false, '')",
    "select database_to_xml(true, false, '')",
    "select database_to_xmlschema(true, false, '')",
    "select database_to_xml_and_xmlschema(true, false, '')",
    "select * from dblink('dbname=x', 'select phone from leads') as t(p text)",
    "select dblink_exec('select 1')",
    "select * from crosstab('select 1, 2, phone from leads') as c(a int, b text)",
  ])('blocks %s', (sql) => expect(deny(sql)).toContain('cannot inspect'));
  // I3: a comment between U&"..." and UESCAPE is allowed by Postgres 13+.
  it.each([`select U&"!0070hone" /* c */ UESCAPE '!' from leads`, `select U&"!0070hone" --c\n UESCAPE '!' from leads`, `select U&"!0070hone"/*a*//*b*/uescape'!' from leads`])(
    'decodes UESCAPE after a comment in %s',
    (sql) => expect(deny(sql)).toContain('"phone"'),
  );
  // M1: '\'' reads differently with standard_conforming_strings off.
  it.each(["select 'a\\'' , phone from users --'", "select 'C:\\' from t", "select N'a\\'' , phone from users --'"])('blocks the backslash-quote string in %s', (sql) =>
    expect(deny(sql)).toContain('standard_conforming_strings'),
  );
  // M2: planner statistics hold sample values of readable columns.
  it.each(["select most_common_vals from pg_stats where attname = 'phone'", 'select stavalues1 from pg_catalog.pg_statistic', 'select 1 from pg_stats_ext'])(
    'blocks the statistics view in %s',
    (sql) => expect(deny(sql)).toContain('statistics'),
  );
  // Allow cases the fixes must keep.
  it.each([
    'select l.id, u.name from leads l, users u where l.id = u.id',
    'select l.id from (leads l join users u on true)',
    'select g.x from generate_series(1, 3) g(x)',
    'select v.x from (values (1)) v(x)',
    's.a from (select id as a from users) s(a)'.replace(/^/, 'select '),
    'select r.n from (select id from users) r(n)',
    'with s(a) as (select id from users) select s.a from s',
    'with leads as (select 1 x) select to_jsonb(leads) from leads',
    'select id from users where name is distinct from id::text',
    'select id from users where name is not distinct from id::text',
    'select distinct on (u.id) u.id, u.name from users u',
    "select 'it''s', E'a\\\\b', 'a\\\\b', '\\\\' from users",
    'select l.id from leads l order by l.id',
    'select x from users u, lateral (select u.id as x) s',
    'select "table" from t',
    'select table_name from information_schema.tables',
    "select attname from pg_attribute where attname = 'x'",
  ])('still allows %s', (sql) => allow(sql));
  it('runs in linear time on adversarial unbalanced input', () => {
    for (const sql of ['select ' + 'x,a('.repeat(100_000), 'select 1 ' + 'from('.repeat(100_000), 'with ' + 'a as (select 1), '.repeat(20_000) + 'b as (select 1) select 1']) {
      const t0 = Date.now();
      decide(sql, LIST, env());
      // Linear: ~0.2 s per 100k repeats on a laptop, up to ~1.8 s on a loaded CI runner.
      // Quadratic behaviour would take minutes here, so 5 s still catches it without flaking.
      expect(Date.now() - t0, sql.slice(0, 20)).toBeLessThan(5000);
    }
  });
});

describe('decide: regressions from the second bypass review (each one returned data on PG 14)', () => {
  const C63 = 'contact_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_email';
  it.each([
    'with leads as (select to_jsonb(u) as j from leads u) select j from leads', // 1: a CTE is not in scope in its own body
    'with a as (select to_jsonb(u) j from leads u), leads as (select 1) select j from a', // 2: nor in earlier siblings
    'with recursive leads as (select to_jsonb(u) j from leads u) select j from leads', // recursive self-reference: table-backed
    'select to_jsonb(by) from leads as by', // 3: unreserved keywords are valid aliases
    'select to_jsonb(explain) from leads explain',
    'select to_jsonb(values) from leads as values',
    'select to_jsonb("Ku") from leads Ku', // 4: Postgres folds only A-Z
    'select to_jsonb(u) from t2 g join t2 h on array[0,1] is not null join leads u on true', // 5: [ , ] inside ON
    'select 1 from t2 join leads u on array[0, u::text::int] is null', // 6: value leaks in the error text
    "select '' operator(pg_catalog.||) u from leads u", // 7: OPERATOR(...) is an operator, not an operand
    'select u.record_send from leads u', // 8: attribute notation, regenerated from pg_proc
    'select u.hash_record from leads u',
    'select u.jsonb_build_object from leads u',
    'select u.anyelement_out from leads u',
  ])('blocks %s', (sql) => expect(deny(sql)).toMatch(/whole row/));
  it('truncates identifiers to 63 bytes like Postgres before the name check (9)', () => {
    expect(C63).toHaveLength(63);
    expect(deny(`select ${C63.slice(0, -6)}_email_verified from c63`)).toMatch(/looks like personal or secret data/);
    expect(deny(`select "${C63}_verified" from c63`)).toMatch(/looks like personal or secret data/);
    allow(`select ${C63.slice(0, -6)}_email_verified from c63`, `c63.${C63}\n`);
  });
  it('keeps FROM scanning linear when FROM repeats', () => {
    const t0 = Date.now();
    decide('select 1 from t' + ' from t'.repeat(40_000), LIST, env());
    decide('select phone.phone' + '.phone'.repeat(40_000), 'users.phone\n', env());
    expect(Date.now() - t0).toBeLessThan(1500);
  });
  it('still sees a FROM item after "is distinct from" in a join condition', () => {
    expect(deny('select to_jsonb(x) from users u join leads l on u.id is distinct from l.id, leads x')).toMatch(/whole row/);
  });
  // false positives from real use
  it.each([
    "select count(*) from \"PhoneCall\" where status = 'done'",
    'select count(*) from email_events',
    'select count(*) from public.email_events e join phone_calls p on p.id = e.id',
    'select count(*) as emails_sent from events',
    'select count(*) emails_sent, sum(x) as "phoneCalls" from events',
    'select count(o.*) from orders o',
    'select cast(id as text) from users',
    'with phone_stats as (select 1 n) select n from phone_stats',
    'select count(*) from leads by',
  ])('allows %s', (sql) => allow(sql));
  it.each([
    'select id phone_alias, phone from users', // an implicit alias after a name is not skipped, and phone is still checked
    'select x at time zone phone from users',
    "select 1 from users where phone between 'a' and 'b'",
    'select distinct on (u.id) phone from users u',
    "select '' operator(pg_catalog.||) phone from users",
    'select count(distinct u.*) from users u',
    'select distinct on (id) * from leads', // found while fixing 7: ) of DISTINCT ON is not a value
  ])('still blocks %s', (sql) => deny(sql));
});

describe('decide: hidden list formats', () => {
  it('accepts schema.table.column entries', () => {
    allow('select email from analytics.events', 'analytics.events.email\n');
    allow('select e.email from analytics.events e', 'analytics.events.email\n');
    allow('select phone from users', 'public.users.phone\n');
  });
  it('accepts double-quoted identifiers with dots and dashes inside', () => {
    allow('select "ship.address" from "Order-Items"', '"Order-Items"."ship.address"\n');
    allow('select "Phone" from users', 'users."Phone"\n');
    allow('select phone from users', '!"public"."users"."phone"  # reviewed\n');
  });
  it('still treats # as a comment and a quoted entry with # inside as a name', () => {
    allow('select "a#b_phone" from t', 't."a#b_phone"\n');
    allow('select phone from users', 'users.phone # phone\n');
  });
  it('does not let a schema.table.column entry cover a different column', () => {
    deny('select phone from users', 'analytics.events.email\n');
  });
  it('keeps the safe tail: phone_id passes', () => allow('select phone_id from users', ''));
});

describe('decide: DAYPASS_PII_HOOK spellings', () => {
  it.each(['off', 'OFF', 'Off', 'false', 'False', '0'])('is off for %s', (v) => {
    expect(decide('select * from users', null, env({ DAYPASS_PII_HOOK: v }))).toEqual({ allow: true });
  });
  it.each(['on', '1', 'yes', '', 'offline'])('stays on for %s', (v) => {
    expect(decide('select phone from users', null, env({ DAYPASS_PII_HOOK: v })).allow).toBe(false);
  });
});

describe('hiddenFilePath', () => {
  it('honours DAYPASS_HIDDEN_FILE, then DAYPASS_HOME, then ~/.daypass', () => {
    expect(hiddenFilePath({ DAYPASS_HIDDEN_FILE: '/x/list.txt', DAYPASS_HOME: '/h' })).toBe('/x/list.txt');
    expect(hiddenFilePath({ DAYPASS_HOME: '/h' })).toBe('/h/hidden-columns.txt');
    expect(hiddenFilePath({})).toMatch(/\.daypass\/hidden-columns\.txt$/);
  });
});

describe('looksSensitive parity with src/core/hidden.ts', () => {
  const names = [
    'phone', 'phone_number', 'mobile', 'email', 'email_address', 'api_key', 'key_hash', 'secret', 'client_secret',
    'token', 'refresh_token', 'password', 'password_hash', 'transcript', 'address', 'street_address', 'ssn', 'iban',
    'card_number', 'encrypted_payload', 'date_of_birth', 'id', 'created_at', 'status',
    'email_verified', 'phone_country', 'tokens_used', 'keyboard_layout', 'name', 'amount', 'phoneNumber', 'apiKey',
    'emailVerified', 'APIKey', 'HTTPToken', 'national_id', 'user_id', 'invoice_number',
    // the account_id fix on main: foreign keys stay visible, the identifiers themselves stay hidden
    'account_id', 'bank_account_id', 'account_number', 'bank_account_number', 'tax_id',
    // 2026-10-30 heuristic extension: new WORDS, SPECIAL name forms, SAFE_KEY, STRONG tails, digit split in toSnake
    'emails', 'mail', 'cvv', 'aadhaar', 'pan_number', 'ip', 'ip_address', 'surname', 'username', 'gender',
    'race', 'religion', 'notes', 'body', 'payload', 'metadata', 'recording', 'lat', 'lng', 'latitude',
    'longitude', 'postal_code', 'zip', 'zipcode', 'caller', 'encrypted', 'health_score', 'first_name',
    'last_name', 'full_name', 'user_name', 'e_mail', 'user_agent', 'national_insurance',
    'national_insurance_number', 'device_id', 'stripe_customer_id', 'public_key', 'partition_key', 's3_key',
    'cache_key', 'idempotency_key', 'phone_country_code', 'card_brand', 'card_last_4', 'email_id',
    'secret_key_id', 'api_key_hash_type', 'token_type', 'Address1', 'addressLine2', 'firstName', 'ipAddress',
    'zip_code', 'national', 'raw', 'data', 'content',
    // quoted names with non-alphanumerics (toSnake turns them into underscores)
    'phone-number', 'ship.address', 'user email', 'Order-Items',
    // third review: run-together and plural names, and names that must stay unflagged
    'emailaddress', 'phonenumber', 'passwordhash', 'apikey', 'firstname', 'lastname', 'dateofbirth', 'secrets',
    'passwords', 'access_tokens', 'api_keys', 'addresses', 'apikeyid', 'useragent', 'address_id', 'tokencount',
    'cache_keys', 'publickey', 'keyboard', 'monkey', 'panel', 'pinned', 'statuses', 'lines', 'prompt_snapshot',
    'EMAILADDRESS', 'Api_Keys', 'emailAddresses',
  ];
  it('has 133 fixtures', () => expect(names).toHaveLength(133));
  it.each(names)('agrees on %s', (n) => expect(hookLooksSensitive(n)).toBe(coreLooksSensitive(n)));
});

describe('end to end (stdin -> exit code)', () => {
  const tmpDirs: string[] = [];
  const tmp = () => {
    const d = mkdtempSync(join(tmpdir(), 'daypass-hook-'));
    tmpDirs.push(d);
    return d;
  };
  afterAll(() => {
    for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
  });
  const runRaw = (stdin: string, extraEnv: Record<string, string>) =>
    spawnSync('node', ['plugin/hooks/pii-guard.mjs'], {
      input: stdin,
      // DAYPASS_PII_HOOK is cleared so a developer's own shell setting cannot turn the guard off here.
      env: { ...process.env, DAYPASS_PII_HOOK: '', ...extraEnv },
      encoding: 'utf8',
    });
  const run = (sql: string | undefined, extraEnv: Record<string, string>) =>
    runRaw(JSON.stringify({ tool_name: 'mcp__plugin_daypass_daypass__query', tool_input: sql === undefined ? {} : { sql } }), extraEnv);

  it('exits 2 with the reason on stderr when there is no list', () => {
    const r = run('select phone from users', { DAYPASS_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('no hidden-columns list');
    expect(r.stdout).toBe('');
  });

  it('exits 0 when the list covers the column', () => {
    const file = join(tmp(), 'hidden-columns.txt');
    writeFileSync(file, 'users.phone\n');
    const r = run('select phone from users', { DAYPASS_HIDDEN_FILE: file });
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });

  it('exits 2 with "cannot read" when the list path is a directory', () => {
    const r = run('select phone from users', { DAYPASS_HIDDEN_FILE: tmp() });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('cannot read hidden-columns list');
    expect(r.stderr).toContain('EISDIR');
    expect(r.stderr).not.toContain('no hidden-columns list');
  });

  it('exits 2 (blocks) with a reason when tool_input has no sql', () => {
    const r = run(undefined, { DAYPASS_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/^Daypass PII guard: .*"sql"/);
    expect(r.stdout).toBe('');
  });

  it('exits 2 when sql is not a string', () => {
    const r = runRaw(JSON.stringify({ tool_name: 'mcp__plugin_daypass_daypass__query', tool_input: { sql: 42 } }), { DAYPASS_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('"sql"');
  });

  it('exits 2 on stdin that is not JSON', () => {
    const r = runRaw('not json', { DAYPASS_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/^Daypass PII guard: .*JSON/);
  });

  it('exits 2 on empty stdin', () => {
    const r = runRaw('', { DAYPASS_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/^Daypass PII guard: /);
  });

  it('exits 2 when there is no tool_input object', () => {
    const r = runRaw(JSON.stringify({ tool_name: 'mcp__plugin_daypass_daypass__query' }), { DAYPASS_HIDDEN_FILE: '/nonexistent' });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('tool_input');
  });

  it('checks the explain tool the same way as query', () => {
    const file = join(tmp(), 'hidden-columns.txt');
    writeFileSync(file, 'users.email\n');
    const blocked = runRaw(JSON.stringify({ tool_name: 'mcp__daypass__explain', tool_input: { sql: 'select phone from users' } }), { DAYPASS_HIDDEN_FILE: file });
    expect(blocked.status).toBe(2);
    expect(blocked.stderr).toContain('"phone"');
    const ok = runRaw(JSON.stringify({ tool_name: 'mcp__daypass__explain', tool_input: { sql: 'select id from users' } }), { DAYPASS_HIDDEN_FILE: file });
    expect(ok.status).toBe(0);
  });

  it('reads the list from $DAYPASS_HOME/hidden-columns.txt when DAYPASS_HIDDEN_FILE is unset', () => {
    const home = tmp();
    writeFileSync(join(home, 'hidden-columns.txt'), 'users.phone\n');
    const env: Record<string, string> = { DAYPASS_HOME: home };
    const r = spawnSync('node', ['plugin/hooks/pii-guard.mjs'], {
      input: JSON.stringify({ tool_name: 'mcp__plugin_daypass_daypass__query', tool_input: { sql: 'select phone from users' } }),
      env: { ...process.env, DAYPASS_PII_HOOK: '', DAYPASS_HIDDEN_FILE: undefined, ...env } as NodeJS.ProcessEnv,
      encoding: 'utf8',
    });
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
  });

  it('is turned off by DAYPASS_PII_HOOK in any of its accepted spellings, for malformed input too', () => {
    for (const v of ['off', 'OFF', 'Off', 'false', 'FALSE', '0']) {
      const r = run('select phone from users', { DAYPASS_HIDDEN_FILE: '/nonexistent', DAYPASS_PII_HOOK: v });
      expect(r.status, `DAYPASS_PII_HOOK=${v}`).toBe(0);
      expect(runRaw('not json', { DAYPASS_HIDDEN_FILE: '/nonexistent', DAYPASS_PII_HOOK: v }).status).toBe(0);
    }
    for (const v of ['on', '1', 'yes', 'offline']) {
      expect(run('select phone from users', { DAYPASS_HIDDEN_FILE: '/nonexistent', DAYPASS_PII_HOOK: v }).status, `DAYPASS_PII_HOOK=${v}`).toBe(2);
    }
  });

  it('handles a 1 MB statement well inside the hook timeout', () => {
    const file = join(tmp(), 'hidden-columns.txt');
    writeFileSync(file, 'users.email\n');
    const sql = `select id from users where name = '${'x'.repeat(1_000_000)}' and status = 'phone'`;
    const t0 = Date.now();
    const r = run(sql, { DAYPASS_HIDDEN_FILE: file });
    const ms = Date.now() - t0;
    expect(r.status).toBe(0);
    expect(ms).toBeLessThan(3000);
    const sql2 = `select id from users where ${Array.from({ length: 40_000 }, (_, i) => `id <> ${i}`).join(' and ')} -- ${'y'.repeat(100_000)}`;
    const r2 = run(sql2, { DAYPASS_HIDDEN_FILE: file });
    expect(r2.status).toBe(0);
  });
});

describe('hooks.json', () => {
  const cfg = JSON.parse(readFileSync('plugin/hooks/hooks.json', 'utf8'));
  const entry = cfg.hooks.PreToolUse[0];
  it('fails closed and has a timeout', () => {
    expect(entry.hooks[0].onFailure).toBe('block');
    expect(entry.hooks[0].timeout).toBe(10);
  });
  it('matches query and explain, plugin-prefixed or hand-registered, and nothing else', () => {
    const re = new RegExp(entry.matcher);
    for (const n of ['mcp__plugin_daypass_daypass__query', 'mcp__daypass__query', 'mcp__plugin_daypass_daypass__explain', 'mcp__daypass__explain']) {
      expect(re.test(n), n).toBe(true);
    }
    for (const n of ['mcp__plugin_daypass_daypass__list_tables', 'mcp__daypass__describe_table', 'mcp__daypass__daypass_status', 'mcp__other__query', 'xmcp__daypass__query']) {
      expect(re.test(n), n).toBe(false);
    }
  });
});

describe('decide: regressions from the third review (each one returned data on PG 16/17)', () => {
  const blocked = (sql: string, list = 'users.ssn\n') => expect(decide(sql, list, env()).allow, sql).toBe(false);
  it('treats \\r as the end of a -- comment, like Postgres', () => {
    blocked('select id, --x\r email from users');
    blocked('select 1 --x\r, * from users');
    blocked('select 1 --x\r, u from users u');
  });
  it('decodes U&"..." with UESCAPE given as a dollar-quoted or E-string constant', () => {
    blocked('select U&"em!0061il" UESCAPE $$!$$ from users');
    blocked("select U&\"em!0061il\" UESCAPE E'!' from users");
    blocked("select U&\"em!0061il\" UESCAPE E'\\041' from users");
  });
});

describe('decide: whole rows after SQL/JSON keywords (third review)', () => {
  const blocked = (sql: string) => expect(decide(sql, 'users.ssn\n', env()).allow, sql).toBe(false);
  const allowed = (sql: string) => expect(decide(sql, 'users.ssn\n', env()), sql).toEqual({ allow: true });
  it('denies a FROM alias after VALUE, PASSING, KEY, BETWEEN or BY REF', () => {
    blocked("select json_object('k' value u) from users u");
    blocked("select json_object(key 'k' value u) from users u");
    blocked('select json_objectagg(u.id value u) from users u');
    blocked("select json_query('{}'::jsonb, '$a' passing u as a) from users u");
    blocked("select json_value('{}'::jsonb, '$a.x' passing u as a) from users u");
    blocked("select json_exists('{}'::jsonb, '$a' passing 1 as b, u as a) from users u");
    blocked("select json_exists('{}'::jsonb, '$a' passing u as a) from users u");
    blocked("select 1 from users u, json_table('{}'::jsonb, '$a' passing u as a columns (e text path '$a.x')) jt");
    blocked("select xmlexists('/x' passing by ref u) from users u");
    blocked('select 1 from users u where u between u and u');
    blocked('select json_array(u), json_arrayagg(u), json_scalar(u) from users u');
  });
  it('still reads a column named value as a column, with an alias after it', () => {
    allowed('select kv.value u from kv, users u');
    allowed('select value * 2 from kv');
    allowed("select json_object('k' value u.id) from users u");
  });
});

describe('decide: attribute notation (third review)', () => {
  const blocked = (sql: string) => expect(decide(sql, 'users.ssn\n', env()).allow, sql).toBe(false);
  it.each(['any_value', 'json_agg_strict', 'jsonb_agg_strict', 'ANY_VALUE'])('denies u.%s, which returns the whole row (PG 16+)', (f) => {
    blocked(`select u.${f} from users u`);
    blocked(`select (u).${f} from users u`);
  });
  it('denies SQL-from-string functions called in attribute notation', () => {
    blocked("select ('select email from users').ts_stat");
    blocked("select ('select 1').dblink");
    blocked("select (('select 1')).dblink_exec");
    blocked("select (3).f.ts_stat");
    blocked('select t.crosstab from t');
  });
});

describe('decide: table names used as qualifiers (third review)', () => {
  it('does not read a FROM table name before a dot as a column', () => {
    expect(decide('select api_keys.key_prefix, api_keys.id from api_keys', '', env())).toEqual({ allow: true });
    expect(decide('select emails.id from emails', '', env())).toEqual({ allow: true });
    expect(decide('select secrets.id from public.secrets', '', env())).toEqual({ allow: true });
  });
  it('still checks a composite column used as a qualifier, and the column after the dot', () => {
    expect(decide('select (addresses).city from users', '', env()).allow).toBe(false);
    expect(decide('select u.addresses.city from users u', '', env()).allow).toBe(false);
    expect(decide('select api_keys.secret from api_keys', '', env()).allow).toBe(false);
  });
  it('flags run-together and plural names', () => {
    for (const c of ['emailaddress', 'phonenumber', 'apikey', 'firstname', 'dateofbirth', 'passwords', 'access_tokens']) {
      expect(decide(`select ${c} from users`, 'users.ssn\n', env()).allow, c).toBe(false);
    }
  });
});

describe('decide: linear time on adversarial input (third review)', () => {
  const timed = (sql: string) => {
    const t0 = performance.now();
    decide(sql, '', env());
    return performance.now() - t0;
  };
  it('handles a long run of `distinct from` after one FROM', () => {
    expect(timed('select 1 from a ' + 'distinct from '.repeat(20000))).toBeLessThan(1500);
    expect(timed('select 1 from a where x is ' + 'distinct from x is '.repeat(20000) + 'null')).toBeLessThan(1500);
  });
  it('handles 1 MB of long run-together names', () => {
    const ids = Array.from({ length: 16000 }, (_, i) => 'idatcountnoof'.repeat(4) + 'x' + i);
    expect(timed(`select ${ids.join(',')} from t`)).toBeLessThan(3000);
  });
  it('still skips the FROM of `is distinct from` and reads the next real FROM', () => {
    expect(decide('select 1 from users u where 1 is distinct from 2 and u is not null', '', env()).allow).toBe(false);
    expect(decide('select (select 1 from users u where u.id is not distinct from 1) from users u', '', env())).toEqual({ allow: true });
  });
});
