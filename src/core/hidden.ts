/**
 * Pure helpers behind `peephole hidden suggest|check`: a name heuristic for personal or
 * secret columns, a Prisma schema reader, and the hidden-list diff. No I/O here.
 */

export interface ColumnInfo {
  table: string;
  column: string;
  type?: string;
}

/** Words that mark a column as personal or secret data. Matched on snake_case / camelCase parts. */
const WORDS = new Set([
  'phone', 'mobile', 'email', 'token', 'secret', 'key', 'transcript', 'password', 'passwd',
  'address', 'ssn', 'iban', 'card', 'dob', 'birth', 'birthday', 'birthdate', 'salt', 'otp', 'pin',
  'passport', 'license', 'licence', 'routing', 'national',
]);
/** Prefix/exact-name cases; `lines` and `prompt_snapshot` are free-text transcript/log columns from the first deployment. */
const SPECIAL = /^encrypted_|^prompt_snapshot$|^(lines|credentials)$/;
/** Identifiers that are themselves PII, even though they end in a normally-safe tail. */
const ALWAYS = /^(national|tax|government)_(id|number)$|^(bank_)?account_number$/;
/** Suffixes that make a sensitive-looking name safe (users.email_verified is a boolean, api_keys.key_prefix is public). */
const SAFE_TAIL =
  /_(verified|confirmed|count|used|at|id|type|status|enabled|required|country|layout|limit|prefix|version|expiry|expires|expiration|rounds|domain)$/;

/** snake_case for both snake_case and camelCase input: phoneNumber -> phone_number, APIKey -> api_key. */
function toSnake(name: string): string {
  return name
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase();
}

export function looksSensitive(column: string): boolean {
  const name = toSnake(column);
  if (ALWAYS.test(name)) return true;
  if (SAFE_TAIL.test(name)) return false;
  if (SPECIAL.test(name)) return true;
  return name.split('_').some((part) => WORDS.has(part));
}

/** Sorted, unique `table.column` for every column that looks sensitive. */
export function suggestHidden(cols: ColumnInfo[]): string[] {
  const out = new Set<string>();
  for (const c of cols) if (looksSensitive(c.column)) out.add(`${c.table}.${c.column}`);
  return [...out].sort();
}

/**
 * Every scalar field of every model, as `table.column` with its Prisma type. Honours
 * `@@map` (table) and `@map` (column). Relation fields (lists, or a type that is another
 * model) are skipped; `@@...` block attributes are not fields.
 */
export function parsePrismaColumns(schema: string): ColumnInfo[] {
  const blocks = [...schema.matchAll(/^model (\w+) \{([\s\S]*?)^\}/gm)];
  const models = new Set(blocks.map((b) => b[1]));
  const out: ColumnInfo[] = [];
  for (const [, model, body] of blocks) {
    const table = /@@map\("([^"]+)"\)/.exec(body)?.[1] ?? model;
    for (const line of body.split('\n')) {
      const f = /^\s+(\w+)\s+([\w\[\]?]+)(.*)$/.exec(line);
      if (!f) continue;
      const [, field, type, rest] = f;
      if (type.endsWith('[]') || models.has(type.replace(/\?$/, ''))) continue;
      const column = /@map\("([^"]+)"\)/.exec(rest)?.[1] ?? field;
      out.push({ table, column, type });
    }
  }
  return out;
}

/**
 * The hidden-columns file: one `table.column` per line, `#` starts a comment, blank lines are
 * ignored. A line starting with `!` names a column that was reviewed and is intentionally
 * visible (an allow-list entry); `hidden check` stops flagging it.
 */
export function parseHiddenFile(text: string): { hidden: string[]; allow: string[] } {
  const hidden: string[] = [];
  const allow: string[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) continue;
    if (line.startsWith('!')) allow.push(line.slice(1).trim());
    else hidden.push(line);
  }
  return { hidden, allow };
}

/** Only the columns to hide; `!` allow lines are not hidden, so `sql --hide-file` ignores them. */
export function parseHiddenList(text: string): string[] {
  return parseHiddenFile(text).hidden;
}

export function diffHidden(
  hidden: string[],
  cols: ColumnInfo[],
  allow: string[] = [],
): { missingFromSchema: string[]; sensitiveNotHidden: string[] } {
  const known = new Set(cols.map((c) => `${c.table}.${c.column}`));
  const listed = new Set([...hidden, ...allow]);
  return {
    missingFromSchema: [...listed].filter((h) => !known.has(h)).sort(),
    sensitiveNotHidden: suggestHidden(cols).filter((c) => !listed.has(c)),
  };
}
