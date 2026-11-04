/**
 * Pure helpers behind `daypass hidden suggest|check` and `daypass sql`: a name heuristic for
 * personal or secret columns, a Prisma schema reader, the hidden-list entry parser and the
 * hidden-list diff. No I/O here.
 */

export interface ColumnInfo {
  /** Defaults to `public` when absent (Prisma schemas carry no schema). */
  schema?: string;
  table: string;
  column: string;
  type?: string;
}

/** One parsed hidden-list (or `!` allow-list) entry. */
export interface HiddenEntry {
  schema: string;
  table: string;
  column: string;
}

/**
 * One view → relation edge from pg_depend/pg_rewrite (ON SELECT rules only). `refColumn` is null
 * for a whole-relation dependency. That alone exposes no column (`select count(*) from t`), unless
 * `wholeRow` says the rule also holds a whole-row reference (`select t from t`, `row_to_json(t)`),
 * which returns every column.
 */
export interface RelDep {
  schema: string;
  view: string;
  refSchema: string;
  refTable: string;
  refColumn: string | null;
  /** The view's rule contains a whole-row Var (sql/setup-role.sql: `ev_action::text ~ ':varattno 0 '`). */
  wholeRow?: boolean;
  /** pg_class.relkind of the referenced relation ('f' = foreign table, never granted). */
  refKind?: string;
  /**
   * refKind 'S' only: the column that owns the sequence (serial / identity), as a hidden-list
   * entry. The setup withholds a sequence owned by a hidden column, and every view reading it.
   */
  seqOwner?: string;
}

/**
 * A function or relation a view's stored rule names (read from pg_rewrite.ev_action, because
 * built-in functions and catalogs are pinned and pg_depend does not record them).
 */
export interface RuleRef {
  schema: string;
  view: string;
  /** 'v' view, 'm' materialized view. */
  viewKind: string;
  refType: 'function' | 'relation';
  refSchema: string;
  refName: string;
  /** relation only: can PUBLIC (and so the role) read it with table-level SELECT? */
  publicReadable?: boolean;
}

/**
 * Built-in functions that read data by name or from the server (a query string, a table name, a
 * large object, a file, other sessions' queries, settings). A materialized view calling one, or
 * any function outside pg_catalog, stored what the OWNER could read. sql/setup-role.sql carries
 * the same pattern (test/setup-sql.test.ts guards that).
 */
export const DATA_READING_FUNCTIONS =
  /^((query|cursor|table|schema|database)_to_xml|ts_(stat|rewrite)$|lo_|pg_read_|pg_ls_|pg_stat_file$|pg_stat_get_activity$|current_setting$|dblink|crosstab|xpath_table$)/;

/** A generated column and the column it is computed from (pg_depend; via pg_attrdef from PG 16). */
export interface GeneratedDep {
  schema: string;
  table: string;
  column: string;
  fromColumn: string;
}

/** One pg_inherits edge: a partition or inheritance child and its parent. */
export interface RelParent {
  schema: string;
  table: string;
  parentSchema: string;
  parentTable: string;
}

/**
 * A materialized view whose stored rows are what its OWNER could read at refresh (a row of
 * MATVIEW_TAINT_SQL in core/matview.ts, rule (e) of sql/setup-role.sql). `why` names the first
 * reason found in its view tree.
 */
export interface MatviewTaint {
  schema: string;
  view: string;
  why: string;
  /** 'm' (default): a materialized view. 'v': a plain view that reads a row-level-security table with its owner's rights. */
  kind?: string;
}

/** What a live catalog adds to the column list; a Prisma schema has neither. */
export interface CatalogShape {
  inherits?: RelParent[];
  deps?: RelDep[];
  generated?: GeneratedDep[];
  refs?: RuleRef[];
  matviews?: MatviewTaint[];
  /** The schemas the role may read (--schemas). A view over a relation outside them is withheld. */
  schemas?: string[];
}

/**
 * The relation kinds a hidden-list entry may name, and that `hidden suggest|check` scan: ordinary
 * tables, partitioned tables, views, materialized views and foreign tables. sql/setup-role.sql uses
 * the same set for its existence check (test/setup-sql.test.ts guards that they agree). Foreign
 * tables are never granted.
 */
export const HIDDEN_RELKINDS = ['r', 'p', 'v', 'm', 'f'] as const;

// The name heuristic below (WORDS, SPECIAL, ALWAYS, SAFE_KEY, SAFE_TAIL, STRONG, GLUE, toSnake,
// singular, splitGlued, looksSensitive) is mirrored verbatim in plugin/hooks/pii-guard.mjs, which runs dependency-free
// and cannot import this module. Change both files together: the parity test in
// test/plugin-hook.test.ts guards drift.

/** Words that mark a column as personal or secret data. Matched on snake_case / camelCase parts. */
const WORDS = new Set([
  'phone', 'mobile', 'email', 'emails', 'mail', 'token', 'secret', 'key', 'transcript', 'password', 'passwd',
  'address', 'ssn', 'iban', 'card', 'cvv', 'dob', 'birth', 'birthday', 'birthdate', 'salt', 'otp', 'pin',
  'passport', 'license', 'licence', 'routing', 'aadhaar', 'pan', 'ip', 'surname', 'username', 'gender', 'race',
  'religion', 'notes', 'body', 'payload', 'metadata', 'recording', 'lat', 'lng', 'latitude', 'longitude',
  'postal', 'zip', 'zipcode', 'caller', 'encrypted',
]);
/** Prefix/exact-name cases. */
const SPECIAL =
  /^encrypted_|^health_|^credentials$|^(first|last|full|middle|given|family|user)_name$|^e_mail$|^user_agent$/;
/** Identifiers that are themselves PII, even though they end in a normally-safe tail. */
const ALWAYS = /^(national|tax|government)_(id|number)$|^(bank_)?account_number$|^national_insurance(_number)?$|^device_id$|^stripe_customer_id$/;
/** `key` names that are not credentials: public keys, storage and cache keys, partition keys. */
const SAFE_KEY = /^(public|partition|sort|s_?3|cache|idempotency|primary|shard|lookup|config|object|storage|bucket|redis)_key$/;
/** Suffixes that make a sensitive-looking name safe (users.email_verified is a boolean, api_keys.key_prefix is public). */
const SAFE_TAIL =
  /_(verified|confirmed|count|used|at|id|type|status|enabled|required|country|country_code|brand|layout|limit|prefix|version|expiry|expires|expiration|rounds|domain|last_\d+)$/;
/** Words that beat an `_id` / `_type` tail: email_id, secret_key_id and api_key_hash_type are still sensitive. */
const STRONG = new Set(['email', 'secret', 'key', 'token', 'password']);
/**
 * Words a run-together part is split into (`emailaddress` -> email_address, `dateofbirth` ->
 * date_of_birth, `apikeyid` -> api_key_id): WORDS, the safe tails, and the words that pair with
 * them in common names. A part is split only when it is made entirely of these, so `keyboard`,
 * `panel` and `pinned` stay whole.
 */
const GLUE = new Set([
  ...WORDS,
  'api', 'access', 'refresh', 'auth', 'session', 'private', 'client', 'first', 'last', 'full', 'middle', 'given',
  'family', 'user', 'agent', 'date', 'of', 'number', 'num', 'no', 'hash', 'digest', 'name', 'street', 'home',
  'billing', 'shipping', 'national', 'tax', 'government', 'account', 'bank', 'credit', 'device', 'code',
  'verified', 'confirmed', 'count', 'used', 'at', 'id', 'type', 'status', 'enabled', 'required', 'country',
  'brand', 'layout', 'limit', 'prefix', 'version', 'expiry', 'expires', 'expiration', 'rounds', 'domain',
]);
/** Longest GLUE word plus a plural `es`: bounds the split to linear time. */
const GLUE_MAX = Math.max(...[...GLUE].map((w) => w.length)) + 2;

/**
 * snake_case for snake_case, camelCase and quoted names: phoneNumber -> phone_number,
 * APIKey -> api_key, Address1 -> address_1, "ship.address" -> ship_address.
 */
function toSnake(name: string): string {
  return name
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Za-z])([0-9])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .toLowerCase();
}

/** The singular of a plural sensitive word (`secrets` -> secret, `addresses` -> address); anything else as it is. */
function singular(w: string): string {
  if (WORDS.has(w)) return w;
  if (w.endsWith('es') && WORDS.has(w.slice(0, -2))) return w.slice(0, -2);
  if (w.endsWith('s') && WORDS.has(w.slice(0, -1))) return w.slice(0, -1);
  return w;
}

/** A run-together part as two or more GLUE words (longest first), or null when it is not one. */
function splitGlued(p: string): string[] | null {
  if (p.length < 4 || p.length > 64) return null;
  const best: (string[] | null)[] = new Array(p.length + 1).fill(null);
  best[p.length] = [];
  for (let i = p.length - 1; i >= 0; i--) {
    for (let j = Math.min(p.length, i + GLUE_MAX); j > i; j--) {
      const rest = best[j];
      const w = singular(p.slice(i, j));
      if (rest !== null && GLUE.has(w)) {
        best[i] = [w, ...rest];
        break;
      }
    }
  }
  return best[0] !== null && best[0].length >= 2 ? best[0] : null;
}

export function looksSensitive(column: string): boolean {
  const parts = toSnake(column)
    .split('_')
    .flatMap((p) => (WORDS.has(singular(p)) ? [singular(p)] : splitGlued(p) ?? [p]));
  const name = parts.join('_');
  if (ALWAYS.test(name)) return true;
  if (SAFE_KEY.test(name)) return false;
  if (SAFE_TAIL.test(name) && !(/_(id|type)$/.test(name) && parts.some((p) => STRONG.has(p)))) return false;
  if (SPECIAL.test(name)) return true;
  return parts.some((part) => WORDS.has(part));
}

const PLAIN_IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** One identifier of a hidden-list entry: quoted only when it is not a plain identifier. Unquoted case is kept. */
function quoteIdent(s: string): string {
  return PLAIN_IDENT.test(s) ? s : `"${s.replace(/"/g, '""')}"`;
}

/** Canonical spelling: `table.column`, with the schema prefixed when it is not `public`. */
export function formatHiddenEntry(e: HiddenEntry): string {
  const base = `${quoteIdent(e.table)}.${quoteIdent(e.column)}`;
  return e.schema === 'public' ? base : `${quoteIdent(e.schema)}.${base}`;
}

/**
 * Parses `table.column`, `schema.table.column`, or the same with double-quoted identifiers
 * (`"Order-Items"."ship.address"`, `""` for an embedded quote). Unquoted identifiers keep their
 * case (Prisma's `AppUser.phoneNumber`), unlike SQL. The schema defaults to `public`. `|` is
 * refused because the generated SQL carries entries as `schema|table|column`.
 */
export function parseHiddenEntry(entry: string): HiddenEntry {
  const bad = (why: string): never => {
    throw new Error(`bad hidden entry "${entry}": ${why} (want table.column or schema.table.column; double-quote an identifier with dots, dashes, spaces or an unusual character)`);
  };
  const parts: string[] = [];
  let i = 0;
  const s = entry.trim();
  while (i <= s.length) {
    if (s[i] === '"') {
      let j = i + 1;
      let out = '';
      for (;;) {
        if (j >= s.length) return bad('unterminated double quote');
        if (s[j] === '"') {
          if (s[j + 1] === '"') { out += '"'; j += 2; continue; }
          j++;
          break;
        }
        out += s[j++];
      }
      if (!out) return bad('empty quoted identifier');
      parts.push(out);
      i = j;
    } else {
      let j = i;
      while (j < s.length && s[j] !== '.') j++;
      const raw = s.slice(i, j);
      if (!PLAIN_IDENT.test(raw)) return bad(raw ? `"${raw}" is not a plain identifier` : 'empty identifier');
      parts.push(raw);
      i = j;
    }
    if (i === s.length) break;
    if (s[i] !== '.') return bad(`unexpected "${s[i]}"`);
    i++;
    if (i === s.length) return bad('trailing dot');
  }
  if (parts.length < 2 || parts.length > 3) return bad(`${parts.length} part(s)`);
  if (parts.some((p) => p.includes('|'))) return bad('"|" is not allowed in an identifier');
  const [schema, table, column] = parts.length === 2 ? ['public', ...parts] : parts;
  return { schema, table, column };
}

/** Canonical, deduped, sorted spellings of a list of entries. Throws on the first unparseable one. */
export function canonicalEntries(entries: string[]): string[] {
  return [...new Set(entries.map((e) => formatHiddenEntry(parseHiddenEntry(e))))].sort();
}

function canonicalColumn(c: ColumnInfo): string {
  return formatHiddenEntry({ schema: c.schema ?? 'public', table: c.table, column: c.column });
}

function relName(schema: string, table: string): string {
  return schema === 'public' ? quoteIdent(table) : `${quoteIdent(schema)}.${quoteIdent(table)}`;
}

/** child relName -> its parents (multiple inheritance gives several). */
function parentMap(inherits: RelParent[]): Map<string, { schema: string; table: string }[]> {
  const m = new Map<string, { schema: string; table: string }[]>();
  for (const i of inherits) {
    const k = relName(i.schema, i.table);
    m.set(k, [...(m.get(k) ?? []), { schema: i.parentSchema, table: i.parentTable }]);
  }
  return m;
}

/** Every ancestor of a relation over pg_inherits, nearest first, each once. */
function ancestors(parents: Map<string, { schema: string; table: string }[]>, schema: string, table: string): { schema: string; table: string }[] {
  const out: { schema: string; table: string }[] = [];
  const seen = new Set<string>([relName(schema, table)]);
  const queue = [...(parents.get(relName(schema, table)) ?? [])];
  while (queue.length) {
    const p = queue.shift()!;
    const k = relName(p.schema, p.table);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(p);
    queue.push(...(parents.get(k) ?? []));
  }
  return out;
}

/**
 * The same-named column on every ancestor of each entry: a table attached under a readable
 * parent (ALTER TABLE ... INHERIT) leaks its hidden column through the parent. `daypass doctor`
 * checks each of these that exists.
 */
export function ancestorColumns(entries: string[], inherits: RelParent[] = []): { entry: string; child: string }[] {
  const parents = parentMap(inherits);
  const out = new Map<string, string>();
  for (const k of canonicalEntries(entries)) {
    const e = parseHiddenEntry(k);
    for (const p of ancestors(parents, e.schema, e.table)) {
      const pk = formatHiddenEntry({ ...p, column: e.column });
      if (!out.has(pk)) out.set(pk, relName(e.schema, e.table));
    }
  }
  return [...out.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([entry, child]) => ({ entry, child }));
}

/**
 * The hidden set as the setup applies it: every entry plus the same column on each partition
 * and inheritance child, recursively (sql/setup-role.sql walks pg_inherits the same way).
 */
export function expandHidden(hidden: string[], inherits: RelParent[] = []): string[] {
  const out = new Set(canonicalEntries(hidden));
  const children = new Map<string, HiddenEntry[]>();
  for (const i of inherits) {
    const k = relName(i.parentSchema, i.parentTable);
    children.set(k, [...(children.get(k) ?? []), { schema: i.schema, table: i.table, column: '' }]);
  }
  const queue = hidden.map(parseHiddenEntry);
  while (queue.length) {
    const e = queue.shift()!;
    for (const child of children.get(relName(e.schema, e.table)) ?? []) {
      const c = { schema: child.schema, table: child.table, column: e.column };
      const k = formatHiddenEntry(c);
      if (!out.has(k)) {
        out.add(k);
        queue.push(c);
      }
    }
  }
  return [...out].sort();
}

/**
 * Sorted, unique canonical entries for every column that looks sensitive. With a live catalog's
 * shape the list is the minimal one the setup accepts: a partition or child column is dropped
 * when an ancestor's is listed, and a view column is dropped when the view already depends on a
 * listed column (the setup withholds such a view entirely and refuses to list its columns).
 */
export function suggestHidden(cols: ColumnInfo[], shape: CatalogShape = {}): string[] {
  const flagged = new Set<string>();
  for (const c of cols) if (looksSensitive(c.column)) flagged.add(canonicalColumn(c));
  // A generated column computed from a flagged one carries its value: the setup requires it listed too.
  for (const g of shape.generated ?? []) {
    if (flagged.has(formatHiddenEntry({ schema: g.schema, table: g.table, column: g.fromColumn }))) {
      flagged.add(formatHiddenEntry({ schema: g.schema, table: g.table, column: g.column }));
    }
  }
  const parents = parentMap(shape.inherits ?? []);
  const coveredByAncestor = (e: HiddenEntry): boolean =>
    ancestors(parents, e.schema, e.table).some((p) => flagged.has(formatHiddenEntry({ ...p, column: e.column })));
  const tainted = new Set(viewLeaks([...flagged], shape.deps ?? [], { schemas: shape.schemas, refs: shape.refs, matviews: shape.matviews }).map((l) => l.view));
  return [...flagged]
    .filter((k) => {
      const e = parseHiddenEntry(k);
      return !coveredByAncestor(e) && !tainted.has(relName(e.schema, e.table));
    })
    .sort();
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

/** Drops a `#` comment; a `#` inside a double-quoted identifier is part of the name (same as plugin/hooks/pii-guard.mjs). */
function stripComment(line: string): string {
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') inQuote = !inQuote;
    else if (line[i] === '#' && !inQuote) return line.slice(0, i);
  }
  return line;
}

/**
 * The hidden-columns file: one entry per line, `#` starts a comment, blank lines are ignored. A
 * line starting with `!` names a column that was reviewed and is intentionally visible (an
 * allow-list entry); `hidden check` stops flagging it and `daypass sql` passes it to the setup
 * as a known-visible column. A bare `!` is an error. Entries are returned as written; use
 * parseHiddenEntry to interpret them.
 */
export function parseHiddenFile(text: string): { hidden: string[]; allow: string[] } {
  const hidden: string[] = [];
  const allow: string[] = [];
  text.split('\n').forEach((raw, idx) => {
    const line = stripComment(raw).trim();
    if (!line) return;
    if (line.startsWith('!')) {
      const rest = line.slice(1).trim();
      if (!rest) throw new Error(`hidden list line ${idx + 1}: bare "!" - an allow line needs a column, e.g. !documents.s3_key`);
      allow.push(rest);
    } else hidden.push(line);
  });
  return { hidden, allow };
}

/** Only the columns to hide; `!` allow lines are not hidden. */
export function parseHiddenList(text: string): string[] {
  return parseHiddenFile(text).hidden;
}

/**
 * Compares the list with the catalog. `sensitiveNotHidden` treats as covered: listed columns, `!`
 * allowed columns, the same column on partitions/children of a listed table, and every column of a
 * view that depends on a listed column (the setup grants such a view nothing). `childOnly` names
 * hidden columns of a partition/child whose ancestor has the same column unhidden: querying the
 * parent would still return them, so the setup refuses such a list.
 */
export function diffHidden(
  hidden: string[],
  cols: ColumnInfo[],
  allow: string[] = [],
  shape: CatalogShape = {},
): {
  missingFromSchema: string[];
  sensitiveNotHidden: string[];
  conflicts: string[];
  childOnly: { entry: string; parent: string }[];
  derived: { entry: string; from: string }[];
} {
  const known = new Set(cols.map(canonicalColumn));
  const h = new Set(canonicalEntries(hidden));
  const a = new Set(canonicalEntries(allow));
  const listed = new Set([...h, ...a]);
  const expanded = new Set(expandHidden(hidden, shape.inherits));
  const covered = new Set([...expanded, ...a]);
  const tainted = new Set(viewLeaks(hidden, shape.deps ?? [], { schemas: shape.schemas, refs: shape.refs, matviews: shape.matviews }).map((l) => l.view));
  const parents = parentMap(shape.inherits ?? []);
  // Generated columns computed from a hidden column: the setup refuses the list until they are hidden too.
  const derived: { entry: string; from: string }[] = [];
  for (const g of shape.generated ?? []) {
    const from = formatHiddenEntry({ schema: g.schema, table: g.table, column: g.fromColumn });
    const entry = formatHiddenEntry({ schema: g.schema, table: g.table, column: g.column });
    if (expanded.has(from) && !expanded.has(entry)) derived.push({ entry, from });
  }
  derived.sort((x, y) => (x.entry < y.entry ? -1 : x.entry > y.entry ? 1 : 0));
  const childOnly: { entry: string; parent: string }[] = [];
  for (const k of [...expanded].sort()) {
    const e = parseHiddenEntry(k);
    for (const p of ancestors(parents, e.schema, e.table)) {
      const pk = formatHiddenEntry({ ...p, column: e.column });
      if (known.has(pk) && !expanded.has(pk)) childOnly.push({ entry: k, parent: pk });
    }
  }
  return {
    childOnly,
    derived,
    missingFromSchema: [...listed].filter((x) => !known.has(x)).sort(),
    sensitiveNotHidden: suggestHidden(cols, shape).filter((c) => {
      const e = parseHiddenEntry(c);
      return !covered.has(c) && !tainted.has(relName(e.schema, e.table));
    }),
    conflicts: [...h].filter((x) => a.has(x)).sort(),
  };
}

/**
 * Views (and materialized views) that would expose a hidden column: a view whose rewrite rule
 * depends on a hidden (table, column), and transitively any view that depends on such a view at
 * all (pg_depend does not say which output column carries the taint, so the whole view counts).
 * Mirrors the taint query in sql/setup-role.sql; `via` names the tainted view an indirect leak
 * goes through.
 */
/**
 * Why a view is withheld when it is not a hidden column: see viewLeaks. 'matview': a materialized
 * view stored what its owner could read (`column` is the reason, from MATVIEW_TAINT_SQL). 'rls': a
 * plain view reads a row-level-security table with its owner's rights (same source). 'sequence': it
 * reads a sequence owned by a hidden column (`column` is the sequence).
 */
export type LeakKind = 'foreign' | 'schema' | 'function' | 'catalog' | 'matview' | 'rls' | 'sequence';

export function viewLeaks(
  hidden: string[],
  deps: RelDep[],
  opts: { schemas?: string[]; refs?: RuleRef[]; matviews?: MatviewTaint[] } = {},
): { view: string; column: string; via: string | null; kind?: LeakKind }[] {
  const hiddenSet = new Set(canonicalEntries(hidden));
  // relName -> first hidden column on it, for whole-row references.
  const hiddenRel = new Map<string, string>();
  for (const k of [...hiddenSet].sort()) {
    const e = parseHiddenEntry(k);
    if (!hiddenRel.has(relName(e.schema, e.table))) hiddenRel.set(relName(e.schema, e.table), k);
  }
  const tainted = new Map<string, { column: string; via: string | null; kind?: LeakKind }>();
  const edges = deps.filter((d) => !(d.schema === d.refSchema && d.view === d.refTable));
  const system = (s: string) => s === 'pg_catalog' || s === 'information_schema' || /^pg_(toast|temp)/.test(s);
  for (const d of edges) {
    if (d.refColumn === null) continue;
    const col = formatHiddenEntry({ schema: d.refSchema, table: d.refTable, column: d.refColumn });
    const v = relName(d.schema, d.view);
    if (hiddenSet.has(col) && !tainted.has(v)) tainted.set(v, { column: col, via: null });
  }
  for (const d of edges) {
    const col = d.refColumn === null && d.wholeRow ? hiddenRel.get(relName(d.refSchema, d.refTable)) : undefined;
    const v = relName(d.schema, d.view);
    if (col && !tainted.has(v)) tainted.set(v, { column: col, via: null });
  }
  // Foreign tables are never granted, and a relation outside --schemas is not the role's to read.
  for (const d of edges) {
    const v = relName(d.schema, d.view);
    const ref = relName(d.refSchema, d.refTable);
    if (tainted.has(v)) continue;
    if (d.refKind === 'f') tainted.set(v, { column: ref, via: null, kind: 'foreign' });
    else if (d.refKind === 'S' && d.seqOwner && hiddenSet.has(canonicalEntries([d.seqOwner])[0])) {
      tainted.set(v, { column: ref, via: null, kind: 'sequence' });
    }
    else if (opts.schemas && !system(d.refSchema) && !opts.schemas.includes(d.refSchema)) tainted.set(v, { column: ref, via: null, kind: 'schema' });
  }
  // A matview calling a non-catalog or data-reading function; a view over a catalog PUBLIC cannot read.
  for (const r of opts.refs ?? []) {
    const v = relName(r.schema, r.view);
    if (tainted.has(v)) continue;
    if (r.refType === 'function' && r.viewKind === 'm' && (r.refSchema !== 'pg_catalog' || DATA_READING_FUNCTIONS.test(r.refName))) {
      tainted.set(v, { column: `${r.refSchema}.${r.refName}`, via: null, kind: 'function' });
    } else if (r.refType === 'relation' && system(r.refSchema) && r.publicReadable === false) {
      tainted.set(v, { column: `${r.refSchema}.${r.refName}`, via: null, kind: 'catalog' });
    }
  }
  // A matview whose whole tree (views it reads, recursively) reached a caller-filtered catalog, a
  // table with row-level security or a function that ran as the owner: the catalog query decides.
  for (const m of opts.matviews ?? []) {
    const v = relName(m.schema, m.view);
    if (!tainted.has(v)) tainted.set(v, { column: m.why, via: null, kind: m.kind === 'v' ? 'rls' : 'matview' });
  }
  for (let changed = true; changed; ) {
    changed = false;
    for (const d of edges) {
      const v = relName(d.schema, d.view);
      const ref = relName(d.refSchema, d.refTable);
      const t = tainted.get(ref);
      if (t && !tainted.has(v)) {
        tainted.set(v, { column: t.column, via: ref, ...(t.kind ? { kind: t.kind } : {}) });
        changed = true;
      }
    }
  }
  return [...tainted.entries()].map(([view, t]) => ({ view, column: t.column, via: t.via, ...(t.kind ? { kind: t.kind } : {}) }));
}

export interface SetupSqlOptions {
  /** Validated by the caller: ^[a-z_][a-z0-9_]*$ */
  role: string;
  /** Hidden-list entries as written; parsed, deduped and checked against `schemas` here. */
  hidden: string[];
  /** `!` allow-list entries as written. */
  allow: string[];
  /** Schemas the role may read. Each must be a plain identifier. */
  schemas: string[];
  /** Acknowledge executable SECURITY DEFINER functions instead of failing the self-check. */
  allowDefiner: boolean;
  /** Emit REVOKE TEMP ON DATABASE ... FROM PUBLIC. */
  revokeTemp: boolean;
  /** Emit REVOKE CREATE ON SCHEMA <each listed schema> FROM PUBLIC. */
  revokeCreate: boolean;
}

/**
 * A text value for the template, which lands inside `DO $$ ... $$` bodies: a `$` there could end
 * the dollar quote (and a backslash or control character is unreadable at best), so such values
 * travel hex-encoded; everything else stays a readable '...' literal for the owner to review.
 */
const sqlText = (s: string) =>
  /[$\\\u0000-\u001f\u007f]/.test(s)
    ? `convert_from(decode('${Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, '0')).join('')}', 'hex'), 'UTF8')`
    : `'${s.replace(/'/g, "''")}'`;
const sqlTextArray = (xs: string[], indent = '    ') =>
  xs.length ? `ARRAY[\n${indent}${xs.map(sqlText).join(`,\n${indent}`)}\n  ]` : 'ARRAY[]::text[]';

/**
 * Fills sql/setup-role.sql. Entries travel as `schema|table|column` text (the SQL splits on `|`
 * and quotes with %I); the hidden and allow lists are deduped, must not overlap, and must live
 * in one of `schemas`. Throws with the entry named on any violation.
 */
export function renderSetupSql(template: string, o: SetupSqlOptions): string {
  if (!o.schemas.length) throw new Error('--schemas must name at least one schema');
  for (const s of o.schemas) if (!PLAIN_IDENT.test(s)) throw new Error(`bad schema name "${s}" (want a plain identifier)`);
  const parse = (xs: string[]) => {
    const seen = new Map<string, HiddenEntry>();
    for (const x of xs) {
      const e = parseHiddenEntry(x);
      seen.set(formatHiddenEntry(e), e);
    }
    return [...seen.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  };
  const hidden = parse(o.hidden);
  const allow = parse(o.allow);
  const allowKeys = new Set(allow.map(([k]) => k));
  const conflicts = hidden.filter(([k]) => allowKeys.has(k)).map(([k]) => k);
  if (conflicts.length) throw new Error(`column(s) both hidden and !allowed: ${conflicts.join(', ')} - keep one line per column`);
  for (const [k, e] of [...hidden, ...allow]) {
    if (!o.schemas.includes(e.schema)) {
      throw new Error(`entry ${k} is in schema "${e.schema}", which is not in --schemas (${o.schemas.join(',')}); add it: --schemas ${[...o.schemas, e.schema].join(',')}`);
    }
  }
  if (!/^[a-z_][a-z0-9_]*$/.test(o.role)) throw new Error('role must match ^[a-z_][a-z0-9_]*$');
  const triple = ([, e]: [string, HiddenEntry]) => `${e.schema}|${e.table}|${e.column}`;
  const values: Record<string, string> = {
    ROLE: o.role,
    HIDDEN: sqlTextArray(hidden.map(triple)),
    ALLOW: sqlTextArray(allow.map(triple)),
    SCHEMAS: `ARRAY[${o.schemas.map(sqlText).join(',')}]`,
    ALLOW_DEFINER: String(o.allowDefiner),
    REVOKE_TEMP: String(o.revokeTemp),
    REVOKE_CREATE: String(o.revokeCreate),
    // What `daypass doctor` checks later; stored on the role by the setup (COMMENT ON ROLE).
    MANIFEST: sqlText(
      JSON.stringify({ hidden: hidden.map(([k]) => k), allow: allow.map(([k]) => k), schemas: o.schemas, allowDefiner: o.allowDefiner }),
    ),
  };
  // One pass with a function: inserted values are never rescanned for placeholders, and `$&`,
  // `$'` or `$$` in a value stay literal (a replacement STRING would interpret them).
  return template.replace(/__([A-Z_]+?)__/g, (m, k: string) => {
    if (!(k in values)) throw new Error(`unknown placeholder ${m} in sql/setup-role.sql`);
    return values[k];
  });
}
