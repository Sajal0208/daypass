import { describe, it, expect } from 'vitest';
import { looksSensitive, suggestHidden, parsePrismaColumns, parseHiddenList, parseHiddenFile, diffHidden } from '../src/core/hidden.js';

describe('looksSensitive', () => {
  it.each([
    'phone', 'phone_number', 'mobile', 'email', 'email_address', 'api_key', 'key_hash', 'secret',
    'client_secret', 'token', 'refresh_token', 'password', 'password_hash', 'transcript', 'address',
    'street_address', 'ssn', 'iban', 'card_number', 'encrypted_payload', 'prompt_snapshot', 'date_of_birth',
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
    });
  });
});
