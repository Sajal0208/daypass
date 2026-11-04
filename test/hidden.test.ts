import { describe, it, expect } from 'vitest';
import {
  looksSensitive, suggestHidden, parsePrismaColumns, parseHiddenList, parseHiddenFile, diffHidden,
  parseHiddenEntry, formatHiddenEntry, canonicalEntries, viewLeaks, expandHidden, HIDDEN_RELKINDS, ancestorColumns, DATA_READING_FUNCTIONS,
} from '../src/core/hidden.js';

describe('looksSensitive', () => {
  it.each([
    'phone', 'phone_number', 'mobile', 'email', 'email_address', 'api_key', 'key_hash', 'secret',
    'client_secret', 'token', 'refresh_token', 'password', 'password_hash', 'transcript', 'address',
    'street_address', 'ssn', 'iban', 'card_number', 'encrypted_payload', 'date_of_birth',
  ])('flags %s', (c) => expect(looksSensitive(c)).toBe(true));

  it.each(['id', 'created_at', 'status', 'email_verified', 'phone_country', 'tokens_used', 'keyboard_layout', 'name', 'amount'])(
    'does not flag %s',
    (c) => expect(looksSensitive(c)).toBe(false),
  );

  it.each(['phoneNumber', 'apiKey', 'passwordHash'])('flags camelCase %s', (c) => expect(looksSensitive(c)).toBe(true));
  it.each(['emailVerified', 'tokensUsed', 'createdAt'])('does not flag camelCase %s', (c) => expect(looksSensitive(c)).toBe(false));

  it.each(['APIKey', 'HTTPToken'])('splits all-caps runs: flags %s', (c) => expect(looksSensitive(c)).toBe(true));

  it.each(['national_id', 'tax_id', 'government_id', 'account_number', 'bank_account_number'])('flags %s (identifier that is itself PII)', (c) => expect(looksSensitive(c)).toBe(true));
  it.each(['user_id', 'license_type', 'account_id', 'bank_account_id'])('does not flag %s (safe tail wins for ordinary names and foreign keys)', (c) => expect(looksSensitive(c)).toBe(false));

  it.each(['passport_number', 'birthday', 'routing_number'])('flags %s (tuned words)', (c) => expect(looksSensitive(c)).toBe(true));
  it.each(['invoice_number', 'attempt_number', 'trackingNumber', 'key_prefix', 'token_expiry', 'salt_rounds', 'secret_version', 'email_domain'])(
    'does not flag %s (tuned safe tails)',
    (c) => expect(looksSensitive(c)).toBe(false),
  );
});

describe('looksSensitive: run-together and plural names (third review)', () => {
  it.each([
    'emailaddress', 'phonenumber', 'passwordhash', 'apikey', 'firstname', 'lastname', 'dateofbirth', 'secrets',
    'passwords', 'access_tokens', 'api_keys', 'addresses', 'EMAILADDRESS', 'apikeys', 'accesstoken', 'ipaddress',
    'creditcard', 'cardnumber', 'accountnumber', 'taxid', 'nationalid', 'apikeyid', 'useragent', 'phone_numbers',
    'email_addresses', 'refreshtokens', 'fullname', 'streetaddress',
  ])('flags %s', (c) => expect(looksSensitive(c)).toBe(true));
  it.each([
    // a foreign key to an addresses table is not an address
    'address_id', 'addressid', 'tokens_used', 'tokencount', 'emailverified', 'cache_keys', 'partition_keys',
    'publickey', 'keyboard', 'monkey', 'panel', 'company', 'pinned', 'spinner', 'tokenizer', 'zipper', 'status',
    'statuses', 'lines', 'prompt_snapshot', 'hostname', 'filename', 'lastlogin', 'firstseen',
  ])('does not flag %s', (c) => expect(looksSensitive(c)).toBe(false));
});

describe('parsePrismaColumns', () => {
  const schema = `
model User {
  id        String  @id
  email     String  @unique
  phoneNum  String? @map("phone_number")
  createdAt DateTime
  posts     Post[]
  author    Post    @relation(fields: [authorId], references: [id])
  authorId  Int
  @@map("users")
  @@index([email])
}
model Post {
  id   Int    @id
  body String
}`;
  it('maps models and fields through @@map/@map and returns scalar fields with their Prisma type', () => {
    expect(parsePrismaColumns(schema)).toEqual([
      { table: 'users', column: 'id', type: 'String' },
      { table: 'users', column: 'email', type: 'String' },
      { table: 'users', column: 'phone_number', type: 'String?' },
      { table: 'users', column: 'createdAt', type: 'DateTime' },
      { table: 'users', column: 'authorId', type: 'Int' },
      { table: 'Post', column: 'id', type: 'Int' },
      { table: 'Post', column: 'body', type: 'String' },
    ]);
  });
});

describe('suggestHidden', () => {
  it('returns sorted table.column for sensitive-looking columns only', () => {
    expect(
      suggestHidden([
        { table: 'users', column: 'email' },
        { table: 'users', column: 'id' },
        { table: 'api_keys', column: 'key_hash' },
        { table: 'users', column: 'phone_number' },
        { table: 'users', column: 'email' },
      ]),
    ).toEqual(['api_keys.key_hash', 'users.email', 'users.phone_number']);
  });
});

describe('parseHiddenList + diffHidden', () => {
  it('strips comments and blanks', () => {
    expect(parseHiddenList('# c\nusers.email\n\n users.phone # trailing\n')).toEqual(['users.email', 'users.phone']);
  });
  it('parseHiddenList drops ! allow lines so sql --hide-file never hides them', () => {
    expect(parseHiddenList('users.email\n!documents.s3_key\n')).toEqual(['users.email']);
  });
  it('parseHiddenFile splits hidden and ! allow lines', () => {
    expect(parseHiddenFile('# c\nusers.email\n!documents.s3_key # reviewed\n! users.phone\n')).toEqual({
      hidden: ['users.email'],
      allow: ['documents.s3_key', 'users.phone'],
    });
  });
  it('diffHidden drops allowed columns from sensitiveNotHidden and reports allowed entries missing from the schema', () => {
    const cols = [
      { table: 'users', column: 'email' },
      { table: 'users', column: 'phone' },
      { table: 'documents', column: 's3_key' },
    ];
    expect(diffHidden(['users.email'], cols, ['users.phone', 'documents.s3_key', 'documents.old_key'])).toEqual({
      missingFromSchema: ['documents.old_key'],
      sensitiveNotHidden: [],
      conflicts: [],
      childOnly: [],
      derived: [],
    });
  });
  it('reports hidden entries missing from the schema and sensitive columns not hidden', () => {
    const cols = [
      { table: 'users', column: 'email' },
      { table: 'users', column: 'phone' },
      { table: 'users', column: 'id' },
    ];
    expect(diffHidden(['users.email', 'users.gone'], cols)).toEqual({
      missingFromSchema: ['users.gone'],
      sensitiveNotHidden: ['users.phone'],
      conflicts: [],
      childOnly: [],
      derived: [],
    });
  });
});

describe('looksSensitive (review 2026-10-30 recall additions)', () => {
  it.each([
    'ip', 'last_login_ip', 'first_name', 'last_name', 'full_name', 'fullName', 'surname', 'username', 'user_name',
    'cvv', 'gender', 'race', 'religion', 'health_record', 'health_conditions', 'notes', 'body', 'payload', 'metadata',
    'transcript', 'recording_url', 'lat', 'lng', 'latitude', 'longitude', 'e_mail', 'mail', 'emails', 'postal_code',
    'zip', 'zipcode', 'aadhaar_number', 'pan_number', 'caller_number', 'user_agent', 'device_id', 'stripe_customer_id',
    'Address1', 'phone2', 'encrypted', 'secret_key_id', 'api_key_hash_type', 'email_id', 'national_insurance_number',
    'ship.address', 'ship-address', 'Ship Address',
  ])('flags %s', (c) => expect(looksSensitive(c)).toBe(true));

  it.each([
    'phone_country_code', 'card_last4', 'public_key', 'card_brand', 'partition_key', 'sort_key', 's3_key', 'cache_key',
    'idempotency_key', 'national_holiday', 'email_verified', 'token_count', 'address_count', 'user_id', 'license_type',
    'account_id', 'key_prefix', 'token_expiry', 'secret_version', 'email_domain',
  ])('does not flag %s', (c) => expect(looksSensitive(c)).toBe(false));
});

describe('parseHiddenEntry / formatHiddenEntry', () => {
  it('accepts table.column and defaults the schema to public', () => {
    expect(parseHiddenEntry('users.email')).toEqual({ schema: 'public', table: 'users', column: 'email' });
  });
  it('accepts schema.table.column', () => {
    expect(parseHiddenEntry('analytics.events.user_email')).toEqual({ schema: 'analytics', table: 'events', column: 'user_email' });
  });
  it('keeps the case of unquoted identifiers (Prisma camelCase)', () => {
    expect(parseHiddenEntry('AppUser.phoneNumber')).toEqual({ schema: 'public', table: 'AppUser', column: 'phoneNumber' });
  });
  it('accepts double-quoted identifiers with dots, dashes, spaces and uppercase', () => {
    expect(parseHiddenEntry('"Order-Items"."ship.address"')).toEqual({ schema: 'public', table: 'Order-Items', column: 'ship.address' });
    expect(parseHiddenEntry('"my schema"."order items".ship_to')).toEqual({ schema: 'my schema', table: 'order items', column: 'ship_to' });
    expect(parseHiddenEntry('"order-items".ship_address')).toEqual({ schema: 'public', table: 'order-items', column: 'ship_address' });
    expect(parseHiddenEntry('t."a""b"')).toEqual({ schema: 'public', table: 't', column: 'a"b' });
  });
  it.each(['users', 'a.b.c.d', 'users.', '.email', 'users..email', 'users.em ail', 'users."unterminated', 'users.""', 'a|b.c', '1users.email'])(
    'rejects %s with a clear error',
    (bad) => expect(() => parseHiddenEntry(bad)).toThrow(/bad hidden entry/),
  );
  it('formats the canonical form: schema prefix only outside public, quotes only when needed', () => {
    expect(formatHiddenEntry({ schema: 'public', table: 'users', column: 'email' })).toBe('users.email');
    expect(formatHiddenEntry({ schema: 'public', table: 'AppUser', column: 'phoneNumber' })).toBe('AppUser.phoneNumber');
    expect(formatHiddenEntry({ schema: 'analytics', table: 'events', column: 'user_email' })).toBe('analytics.events.user_email');
    expect(formatHiddenEntry({ schema: 'public', table: 'Order-Items', column: 'ship.address' })).toBe('"Order-Items"."ship.address"');
    expect(formatHiddenEntry({ schema: 'my schema', table: 't', column: 'a"b' })).toBe('"my schema".t."a""b"');
  });
  it('round-trips through parse', () => {
    for (const e of ['users.email', 'analytics.events.user_email', '"Order-Items"."ship.address"', '"my schema".t."a""b"']) {
      expect(formatHiddenEntry(parseHiddenEntry(e))).toBe(e);
    }
  });
  it('canonicalEntries dedupes equivalent spellings and sorts', () => {
    expect(canonicalEntries(['public.users.email', 'users.email', '"users"."email"', 'a.b'])).toEqual(['a.b', 'users.email']);
  });
  it('exports the one relkind set shared with the SQL', () => {
    expect(HIDDEN_RELKINDS).toEqual(['r', 'p', 'v', 'm', 'f']);
  });
});

describe('parseHiddenFile strictness', () => {
  it('rejects a bare ! line', () => {
    expect(() => parseHiddenFile('users.email\n!\n')).toThrow(/bare "!"/);
    expect(() => parseHiddenFile('! # just a comment\n')).toThrow(/bare "!"/);
  });
});

describe('suggestHidden canonical output', () => {
  it('quotes and schema-prefixes as needed, and dedupes', () => {
    expect(
      suggestHidden([
        { schema: 'public', table: 'order-items', column: 'ship_address' },
        { schema: 'analytics', table: 'events', column: 'user_email' },
        { schema: 'public', table: 'users', column: 'email' },
        { table: 'users', column: 'email' },
      ]),
    ).toEqual(['"order-items".ship_address', 'analytics.events.user_email', 'users.email']);
  });
});

describe('diffHidden with schemas, quoting and conflicts', () => {
  const cols = [
    { schema: 'public', table: 'order-items', column: 'ship_address' },
    { schema: 'analytics', table: 'events', column: 'user_email' },
    { schema: 'analytics', table: 'events', column: 'id' },
    { schema: 'public', table: 'users', column: 'email' },
  ];
  it('matches quoted and schema-prefixed entries against the catalog', () => {
    expect(diffHidden(['"order-items".ship_address', 'analytics.events.user_email', 'users.email'], cols)).toEqual({
      missingFromSchema: [],
      sensitiveNotHidden: [],
      conflicts: [],
      childOnly: [],
      derived: [],
    });
  });
  it('treats equivalent spellings as the same column', () => {
    expect(diffHidden(['public.users.email', '"analytics"."events"."user_email"', '"order-items"."ship_address"'], cols).missingFromSchema).toEqual([]);
  });
  it('reports a column that is both hidden and !allowed as a conflict', () => {
    const d = diffHidden(['users.email', '"order-items".ship_address', 'analytics.events.user_email'], cols, ['public.users.email']);
    expect(d.conflicts).toEqual(['users.email']);
  });
  it('dedupes before reporting', () => {
    const d = diffHidden(['users.email', 'users.email', 'public.users.email'], cols);
    expect(d.missingFromSchema).toEqual([]);
    expect(d.sensitiveNotHidden).toEqual(['"order-items".ship_address', 'analytics.events.user_email']);
  });
  it('throws on an unparseable entry', () => {
    expect(() => diffHidden(['users'], cols)).toThrow(/bad hidden entry/);
  });
});

describe('viewLeaks', () => {
  const dep = (view: string, ref: string, refColumn: string | null, viewSchema = 'public', refSchema = 'public') => ({
    schema: viewSchema, view, refSchema, refTable: ref, refColumn,
  });
  it('names a view that depends on a hidden column', () => {
    expect(viewLeaks(['customers.secret'], [dep('v_secret', 'customers', 'id'), dep('v_secret', 'customers', 'secret'), dep('v_names', 'customers', 'name')])).toEqual([
      { view: 'v_secret', column: 'customers.secret', via: null },
    ]);
  });
  it('ignores whole-relation dependencies (count(*) views) and the view\'s own rule', () => {
    expect(viewLeaks(['customers.secret'], [dep('v_count', 'customers', null), dep('v_count', 'v_count', null)])).toEqual([]);
  });
  it('follows nested views transitively, naming the tainted view it goes through', () => {
    const deps = [dep('v_secret', 'customers', 'secret'), dep('v_nested', 'v_secret', 'id'), dep('v_deep', 'v_nested', null)];
    expect(viewLeaks(['customers.secret'], deps)).toEqual([
      { view: 'v_secret', column: 'customers.secret', via: null },
      { view: 'v_nested', column: 'customers.secret', via: 'v_secret' },
      { view: 'v_deep', column: 'customers.secret', via: 'v_nested' },
    ]);
  });
  it('works across schemas with canonical names', () => {
    expect(viewLeaks(['analytics.events.user_email'], [dep('v', 'events', 'user_email', 'reports', 'analytics')])).toEqual([
      { view: 'reports.v', column: 'analytics.events.user_email', via: null },
    ]);
  });
});

describe('partitions, children and views in suggest/check', () => {
  const cols = [
    { schema: 'public', table: 'customers', column: 'id' },
    { schema: 'public', table: 'customers', column: 'secret' },
    { schema: 'public', table: 'measurements', column: 'secret' },
    { schema: 'public', table: 'measurements_a', column: 'secret' },
    { schema: 'public', table: 'measurements_a_1', column: 'secret' },
    { schema: 'public', table: 'customer_secrets', column: 'secret' },
    { schema: 'public', table: 'customer_nested', column: 'id' },
    { schema: 'public', table: 'stats_mv', column: 'full_name' },
  ];
  const inherits = [
    { schema: 'public', table: 'measurements_a', parentSchema: 'public', parentTable: 'measurements' },
    { schema: 'public', table: 'measurements_a_1', parentSchema: 'public', parentTable: 'measurements_a' },
  ];
  const deps = [
    { schema: 'public', view: 'customer_secrets', refSchema: 'public', refTable: 'customers', refColumn: 'secret' },
    { schema: 'public', view: 'customer_nested', refSchema: 'public', refTable: 'customer_secrets', refColumn: 'id' },
    { schema: 'public', view: 'stats_mv', refSchema: 'public', refTable: 'customers', refColumn: 'id' },
  ];
  it('expandHidden adds the same column on every partition/child, recursively', () => {
    expect(expandHidden(['measurements.secret'], inherits)).toEqual(['measurements.secret', 'measurements_a.secret', 'measurements_a_1.secret']);
    expect(expandHidden(['customers.secret'], inherits)).toEqual(['customers.secret']);
  });
  it('suggestHidden prints the minimal applicable list: parents only, no columns of views the list already taints', () => {
    expect(suggestHidden(cols, { inherits, deps })).toEqual(['customers.secret', 'measurements.secret', 'stats_mv.full_name']);
  });
  it('suggestHidden without catalog shape (Prisma) lists every flagged column', () => {
    expect(suggestHidden(cols)).toContain('measurements_a.secret');
    expect(suggestHidden(cols)).toContain('customer_secrets.secret');
  });
  it('diffHidden counts partition, child and tainted-view columns as covered', () => {
    expect(diffHidden(['customers.secret', 'measurements.secret', 'stats_mv.full_name'], cols, [], { inherits, deps })).toEqual({
      missingFromSchema: [],
      sensitiveNotHidden: [],
      conflicts: [],
      childOnly: [],
      derived: [],
    });
    expect(diffHidden(['customers.secret', 'stats_mv.full_name'], cols, [], { inherits, deps }).sensitiveNotHidden).toEqual(['measurements.secret']);
  });
});

describe('review 2026-10-30 round 2', () => {
  const dep = (view: string, ref: string, refColumn: string | null, wholeRow = false) => ({
    schema: 'public', view, refSchema: 'public', refTable: ref, refColumn, wholeRow,
  });
  it('C3: a whole-row reference to a relation with a hidden column taints the view; count(*) does not', () => {
    const deps = [dep('v_whole', 'customers', null, true), dep('v_count', 'customers', null, false), dep('v_whole_other', 'orders', null, true)];
    expect(viewLeaks(['customers.secret'], deps)).toEqual([{ view: 'v_whole', column: 'customers.secret', via: null }]);
  });
  it('C2: diffHidden reports a hidden child column whose parent column is not hidden', () => {
    const cols = [
      { table: 'parent2', column: 'id' }, { table: 'parent2', column: 'secret' },
      { table: 'child2', column: 'id' }, { table: 'child2', column: 'secret' },
      { table: 'child3', column: 'local_only' },
    ];
    const inherits = [
      { schema: 'public', table: 'child2', parentSchema: 'public', parentTable: 'parent2' },
      { schema: 'public', table: 'child3', parentSchema: 'public', parentTable: 'parent2' },
    ];
    expect(diffHidden(['child2.secret'], cols, [], { inherits }).childOnly).toEqual([{ entry: 'child2.secret', parent: 'parent2.secret' }]);
    // Hiding the parent covers the child; a column that exists only on the child is fine.
    expect(diffHidden(['parent2.secret', 'child2.secret'], cols, [], { inherits }).childOnly).toEqual([]);
    expect(diffHidden(['parent2.secret', 'child3.local_only'], cols, [], { inherits }).childOnly).toEqual([]);
  });
  it('M9: # inside a double-quoted identifier is not a comment', () => {
    expect(parseHiddenFile('"a#b".c # real comment\n!"x#y".z\n')).toEqual({ hidden: ['"a#b".c'], allow: ['"x#y".z'] });
  });
  it('M12: suggestHidden follows every parent of a multiply-inherited child', () => {
    const cols = [
      { table: 'p1', column: 'id' }, { table: 'p2', column: 'secret' }, { table: 'kid', column: 'secret' },
    ];
    const inherits = [
      { schema: 'public', table: 'kid', parentSchema: 'public', parentTable: 'p2' },
      { schema: 'public', table: 'kid', parentSchema: 'public', parentTable: 'p1' },
    ];
    expect(suggestHidden(cols, { inherits })).toEqual(['p2.secret']);
    expect(suggestHidden(cols, { inherits: [...inherits].reverse() })).toEqual(['p2.secret']);
  });
});

describe('review 2026-10-30 round 3', () => {
  const generated = [{ schema: 'public', table: 'derived_t', column: 'hint', fromColumn: 'secret' }];
  const cols = [
    { table: 'derived_t', column: 'id' }, { table: 'derived_t', column: 'secret' }, { table: 'derived_t', column: 'hint' },
  ];
  it('C2: suggestHidden adds a generated column computed from a flagged one', () => {
    expect(suggestHidden(cols, { generated })).toEqual(['derived_t.hint', 'derived_t.secret']);
    expect(suggestHidden(cols)).toEqual(['derived_t.secret']);
  });
  it('C2: diffHidden reports a generated column computed from a hidden one until it is listed', () => {
    expect(diffHidden(['derived_t.secret'], cols, [], { generated }).derived).toEqual([{ entry: 'derived_t.hint', from: 'derived_t.secret' }]);
    expect(diffHidden(['derived_t.secret', 'derived_t.hint'], cols, [], { generated }).derived).toEqual([]);
    expect(diffHidden([], cols, [], { generated }).derived).toEqual([]);
  });
  const dep = (view: string, refTable: string, extra: Record<string, unknown> = {}) => ({
    schema: 'public', view, refSchema: 'public', refTable, refColumn: 'id', ...extra,
  });
  it('C5: a view over a foreign table is withheld, transitively', () => {
    expect(viewLeaks([], [dep('ext_view', 'ext_events', { refKind: 'f' }), dep('ext_view2', 'ext_view')])).toEqual([
      { view: 'ext_view', column: 'ext_events', via: null, kind: 'foreign' },
      { view: 'ext_view2', column: 'ext_events', via: 'ext_view', kind: 'foreign' },
    ]);
  });
  it('I5 mirror: with schemas given, a view over a relation in an unlisted schema is withheld; system schemas are fine', () => {
    const deps = [dep('ev', 'events', { refSchema: 'analytics' }), dep('cat', 'pg_class', { refSchema: 'pg_catalog' })];
    expect(viewLeaks([], deps, { schemas: ['public'] })).toEqual([{ view: 'ev', column: 'analytics.events', via: null, kind: 'schema' }]);
    expect(viewLeaks([], deps)).toEqual([]);
  });
});

describe('review 2026-10-30 round 4', () => {
  const ref = (view: string, viewKind: string, refType: 'function' | 'relation', refSchema: string, refName: string, publicReadable?: boolean) => ({
    schema: 'public', view, viewKind, refType, refSchema, refName, ...(publicReadable === undefined ? {} : { publicReadable }),
  });
  it('1: a matview calling a non-catalog or data-reading function is withheld; plain views and plain built-ins are fine', () => {
    const refs = [
      ref('mv_fn', 'm', 'function', 'public', 'secret_of'),
      ref('mv_xml', 'm', 'function', 'pg_catalog', 'query_to_xml'),
      ref('mv_plain', 'm', 'function', 'pg_catalog', 'upper'),
      ref('v_fn', 'v', 'function', 'public', 'secret_of'),
    ];
    expect(viewLeaks([], [], { refs })).toEqual([
      { view: 'mv_fn', column: 'public.secret_of', via: null, kind: 'function' },
      { view: 'mv_xml', column: 'pg_catalog.query_to_xml', via: null, kind: 'function' },
    ]);
  });
  it('1: the data-reading pattern', () => {
    for (const f of ['query_to_xml', 'query_to_xml_and_xmlschema', 'table_to_xmlschema', 'cursor_to_xml', 'ts_stat', 'lo_get', 'pg_read_file', 'pg_ls_dir', 'current_setting', 'dblink_exec', 'crosstab3']) {
      expect(DATA_READING_FUNCTIONS.test(f), f).toBe(true);
    }
    for (const f of ['upper', 'length', 'lower', 'ts_headline', 'to_jsonb', 'now', 'current_settings_x']) expect(DATA_READING_FUNCTIONS.test(f), f).toBe(false);
  });
  it('2: a view over a catalog PUBLIC cannot read is withheld; over a readable one it is fine', () => {
    const refs = [ref('v_auth', 'v', 'relation', 'pg_catalog', 'pg_authid', false), ref('v_roles', 'v', 'relation', 'pg_catalog', 'pg_roles', true)];
    expect(viewLeaks([], [], { refs })).toEqual([{ view: 'v_auth', column: 'pg_catalog.pg_authid', via: null, kind: 'catalog' }]);
  });
  it('4: ancestorColumns lists the same column on every ancestor', () => {
    const inherits = [
      { schema: 'public', table: 'customers', parentSchema: 'public', parentTable: 'parent_p' },
      { schema: 'public', table: 'parent_p', parentSchema: 'public', parentTable: 'grand_p' },
    ];
    expect(ancestorColumns(['customers.secret', 'other.x'], inherits)).toEqual([
      { entry: 'grand_p.secret', child: 'customers' },
      { entry: 'parent_p.secret', child: 'customers' },
    ]);
  });
});

