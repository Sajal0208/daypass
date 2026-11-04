#!/usr/bin/env node
/**
 * PreToolUse hook for the Daypass `query` and `explain` tools: a second fence on the client, in
 * front of the column grants that Postgres enforces. It reads the tool call from stdin, tokenizes
 * the SQL the way Postgres does (quoting, dollar quoting, escapes, nested comments), and blocks
 * (exit 2, reason on stderr) when
 *
 *   - a `'...'` literal ends elsewhere when standard_conforming_strings is off (`'a\'' ...`),
 *   - a function that runs SQL from a string or returns whole rows, tables or schemas is called
 *     (`query_to_xml`, `schema_to_xml`, `ts_stat`, `dblink`, ...), or planner statistics
 *     (`pg_stats`, `pg_statistic`) are read,
 *   - a statement contains `*` or `alias.*` that is not `count(*)`, a `TABLE x` command, or a
 *     column alias list on a table (`from users u(a, b, c)` renames columns by position),
 *   - a FROM table or its alias is used as a whole row (`to_jsonb(u)`, `(u).x`, `u::text`,
 *     `select u`, attribute notation `u.to_jsonb`), or
 *   - an identifier looks like personal or secret data (as written, or as Postgres folds and
 *     truncates it; table/CTE names and output aliases are not column reads and are skipped) and
 *     the hidden-columns list says nothing about it, hidden or allowed. A column the list hides
 *     is let through (the role cannot read it anyway); one on a `!` allow line was reviewed.
 *
 * The hook fails closed: unparsable stdin, a tool input without a string `sql`, or any thrown
 * error exits 2 with a reason, and hooks.json sets `onFailure: block` for a crash or a timeout.
 *
 * Dependency-free on purpose: it runs on every query, from a plugin directory, with no install.
 * The name heuristic (WORDS, SPECIAL, ALWAYS, SAFE_KEY, SAFE_TAIL, STRONG, GLUE, toSnake, singular,
 * splitGlued, looksSensitive) is a verbatim copy of src/core/hidden.ts, which cannot be imported from here. Change both files together:
 * the parity test in test/plugin-hook.test.ts guards against drift.
 */
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

// --- name heuristic: mirrors src/core/hidden.ts; test/plugin-hook.test.ts guards drift -----
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
function toSnake(name) {
  return name
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Za-z])([0-9])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .toLowerCase();
}

/** The singular of a plural sensitive word (`secrets` -> secret, `addresses` -> address); anything else as it is. */
function singular(w) {
  if (WORDS.has(w)) return w;
  if (w.endsWith('es') && WORDS.has(w.slice(0, -2))) return w.slice(0, -2);
  if (w.endsWith('s') && WORDS.has(w.slice(0, -1))) return w.slice(0, -1);
  return w;
}

/** A run-together part as two or more GLUE words (longest first), or null when it is not one. */
function splitGlued(p) {
  if (p.length < 4 || p.length > 64) return null;
  const best = new Array(p.length + 1).fill(null);
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

export function looksSensitive(column) {
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
// -----------------------------------------------------------------------------------------

/**
 * Postgres reserved words (plus the type/function-reserved ones): never a column name when
 * unquoted, so they are skipped by the name heuristic and do not count as operands.
 */
const KEYWORDS = new Set([
  'all', 'analyse', 'analyze', 'and', 'any', 'array', 'as', 'asc', 'asymmetric', 'authorization', 'binary',
  'both', 'case', 'cast', 'check', 'collate', 'collation', 'column', 'concurrently', 'constraint', 'create',
  'cross', 'current_catalog', 'current_date', 'current_role', 'current_schema', 'current_time',
  'current_timestamp', 'current_user', 'default', 'deferrable', 'desc', 'distinct', 'do', 'else', 'end',
  'except', 'false', 'fetch', 'for', 'foreign', 'freeze', 'from', 'full', 'grant', 'group', 'having', 'ilike',
  'in', 'initially', 'inner', 'intersect', 'into', 'is', 'isnull', 'join', 'lateral', 'leading', 'left', 'like',
  'limit', 'localtime', 'localtimestamp', 'natural', 'not', 'notnull', 'null', 'offset', 'on', 'only', 'or',
  'order', 'outer', 'overlaps', 'placing', 'primary', 'references', 'returning', 'right', 'select',
  'session_user', 'similar', 'some', 'symmetric', 'table', 'tablesample', 'then', 'to', 'trailing', 'true',
  'union', 'unique', 'user', 'using', 'variadic', 'verbose', 'when', 'where', 'window', 'with',
  // not reserved, but they end or start clauses and are never table aliases
  'explain', 'values', 'by',
]);
/** Keywords that stand for a value, so a bare name right after them is a column alias, not a whole-row use. */
const OPERAND_KEYWORDS = new Set([
  'end', 'null', 'true', 'false', 'current_date', 'current_time', 'current_timestamp', 'localtime',
  'localtimestamp', 'current_user', 'session_user', 'user', 'current_role', 'current_catalog', 'current_schema',
]);
/**
 * Unreserved keywords that take an expression right after them: `json_object('k' VALUE u)`,
 * `KEY 'k' VALUE u`, `json_query(x, '$a' PASSING u AS a)`, `PASSING BY REF u`, `x BETWEEN u AND y`.
 * A FROM alias after one of these is a whole row, not a column alias of the word before it.
 */
const VALUE_INTRO = new Set(['value', 'passing', 'key', 'between', 'ref']);
/**
 * Words that are never a table alias: Postgres's reserved and type/function-name keywords
 * (pg_get_keywords() catcode R and T on PG 14). Unreserved words such as `by`, `values` and
 * `explain` are valid aliases (`from leads as by`), so they are not in here.
 */
const NOT_ALIAS = new Set([...KEYWORDS].filter((w) => !['explain', 'values', 'by'].includes(w)));
/** `from` inside these function calls is a keyword argument, not a FROM clause. */
const FROM_IN_ARGS = new Set(['extract', 'substring', 'trim', 'overlay', 'position']);
/**
 * Functions that execute SQL given as a string, or return whole rows, tables or schemas the guard
 * cannot inspect. Core Postgres first; then the dblink, tablefunc and xml2 extensions, which are
 * blocked by name in case a database has them installed.
 */
const UNINSPECTABLE = new Set([
  'query_to_xml', 'query_to_xml_and_xmlschema', 'query_to_xmlschema', 'cursor_to_xml', 'cursor_to_xmlschema',
  'table_to_xml', 'table_to_xml_and_xmlschema', 'table_to_xmlschema', 'xmltable',
  'schema_to_xml', 'schema_to_xmlschema', 'schema_to_xml_and_xmlschema',
  'database_to_xml', 'database_to_xmlschema', 'database_to_xml_and_xmlschema',
  'ts_stat', 'ts_rewrite',
  'dblink', 'dblink_exec', 'dblink_open', 'dblink_fetch', 'dblink_send_query', 'dblink_get_result',
  'crosstab', 'crosstab2', 'crosstab3', 'crosstab4', 'connectby', 'xpath_table',
]);
/**
 * Functions that take a whole row and can be called in attribute notation: Postgres reads
 * `l.to_jsonb` as `to_jsonb(l)` when `l` has no column of that name. Regenerated on PG 16 and 17
 * (a superset of 14 and 15: any_value, json_agg_strict and jsonb_agg_strict are new in 16) by
 * running `select p.<name> from probe p` for every name from
 *
 *   select distinct p.proname from pg_proc p
 *   where p.pronargs >= 1 and p.pronargs - p.pronargdefaults <= 1
 *     and (select t.typtype in ('p', 'c') from pg_type t where t.oid = p.proargtypes[0]);
 *
 * and keeping the ones whose result contains the row's values; plus hstore (extension), and the
 * *_out / json_build_object / hash_record names of the first PG 14 list. Left out because they
 * return no values and are common column names: count, num_nulls, num_nonnulls, pg_typeof,
 * pg_column_size, pg_column_compression, pg_column_toast_chunk_id (and rank, mode, lead, lag and
 * the other aggregates and window functions that error without OVER / WITHIN GROUP).
 */
const WHOLE_ROW_ATTR = new Set([
  'to_json', 'to_jsonb', 'row_to_json', 'json_build_array', 'jsonb_build_array', 'json_build_object',
  'jsonb_build_object', 'json_agg', 'jsonb_agg', 'json_agg_strict', 'jsonb_agg_strict', 'array_agg', 'any_value',
  'concat', 'quote_literal', 'quote_nullable', 'record_out', 'record_send', 'hash_record', 'any_out',
  'anyelement_out', 'anynonarray_out', 'anycompatible_out', 'anycompatiblenonarray_out', 'hstore',
]);
/** Planner statistics: sample values (most_common_vals, histogram_bounds) of every readable column. */
const STATS = new Set(['pg_stats', 'pg_statistic', 'pg_stats_ext', 'pg_stats_ext_exprs', 'pg_statistic_ext_data']);
/** Words that end a FROM list. */
const FROM_END = new Set([
  'where', 'group', 'having', 'window', 'order', 'limit', 'offset', 'fetch', 'for', 'union', 'intersect',
  'except', 'returning', 'into', 'select',
]);
/** First words of a subquery inside parentheses (anything else in FROM parentheses is a join). */
const SUBQUERY_START = new Set(['select', 'values', 'with', 'table']);

export function hiddenFilePath(env) {
  return env.DAYPASS_HIDDEN_FILE ?? join(env.DAYPASS_HOME ?? join(homedir(), '.daypass'), 'hidden-columns.txt');
}

export function hookDisabled(env) {
  const v = (env.DAYPASS_PII_HOOK ?? '').trim().toLowerCase();
  return v === 'off' || v === 'false' || v === '0';
}

// --- tokenizer ---------------------------------------------------------------------------
// Follows src/backend/parser/scan.l (Postgres 17). Where versions differ it takes the reading
// that makes the guard see more: `\v` is whitespace (17+; a syntax error before), numbers follow
// the 16+ forms (14/15 read `0x1F` as `0` plus the alias `x1F`, which is never a column read).
// test/plugin-scanner-parity.test.ts compares token boundaries with libpg-query's scanner.

const isDigit = (c) => c >= 48 && c <= 57;
const isIdentStart = (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c >= 128;
const isIdentPart = (c) => isIdentStart(c) || isDigit(c) || c === 36;
/** scan.l `space`: [ \t\n\r\f\v] */
const isSpace = (c) => c === 32 || (c >= 9 && c <= 13);
/** scan.l `horiz_space`: [ \t\f\v] */
const isHorizSpace = (c) => c === 32 || c === 9 || c === 11 || c === 12;
/** scan.l `newline`: [\n\r] */
const isNewline = (c) => c === 10 || c === 13;
const NUMBER = /0[xX](?:_?[0-9A-Fa-f])+|0[oO](?:_?[0-7])+|0[bB](?:_?[01])+|(?:[0-9](?:_?[0-9])*(?:\.(?:[0-9](?:_?[0-9])*)?)?|\.[0-9](?:_?[0-9])*)(?:[eE][+-]?[0-9](?:_?[0-9])*)?/y;
const DOLLAR_TAG = /\$(?:[A-Za-z_\u0080-￿][A-Za-z0-9_\u0080-￿]*)?\$/y;
const NEWLINE = /[\n\r]/g;

/** Index of the `\n` / `\r` that ends a `--` comment starting at `i` (scan.l: non_newline is [^\n\r]). */
function lineCommentEnd(sql, i) {
  NEWLINE.lastIndex = i;
  return NEWLINE.exec(sql) ? NEWLINE.lastIndex - 1 : sql.length;
}

/** Index of the next character that is not whitespace or inside a comment. */
function skipSpace(sql, i) {
  const n = sql.length;
  for (;;) {
    while (i < n && isSpace(sql.charCodeAt(i))) i++;
    if (sql[i] === '-' && sql[i + 1] === '-') {
      i = lineCommentEnd(sql, i);
    } else if (sql[i] === '/' && sql[i + 1] === '*') {
      i = skipBlockComment(sql, i);
    } else return i;
  }
}

/** Index just past a nested `/* ... *\/` comment starting at `i`. Unterminated: end of input. */
function skipBlockComment(sql, i) {
  const n = sql.length;
  let depth = 1;
  i += 2;
  while (i < n && depth > 0) {
    if (sql[i] === '/' && sql[i + 1] === '*') { depth++; i += 2; }
    else if (sql[i] === '*' && sql[i + 1] === '/') { depth--; i += 2; }
    else i++;
  }
  return i;
}

/**
 * scan.l `quotecontinue`: after a string constant ends at `i`, whitespace that holds a newline
 * (`--` comments allowed, block comments not) and another `'` continue the same constant
 * (`'a'\n'b'` is 'ab'). Returns the index of that `'`, or -1.
 */
function continuation(sql, i) {
  const n = sql.length;
  while (i < n) {
    if (isHorizSpace(sql.charCodeAt(i))) i++;
    else if (sql[i] === '-' && sql[i + 1] === '-') i = lineCommentEnd(sql, i);
    else break;
  }
  if (!isNewline(sql.charCodeAt(i))) return -1;
  i++;
  for (;;) {
    if (isSpace(sql.charCodeAt(i))) { i++; continue; }
    if (sql[i] === '-' && sql[i + 1] === '-') {
      const e = lineCommentEnd(sql, i);
      if (e < n) { i = e + 1; continue; }
    }
    break;
  }
  return sql[i] === "'" ? i : -1;
}

/** Index just past the closing `q`, treating `qq` as an escaped quote. Unterminated: end of input. */
function readQuoted(sql, start, q) {
  let i = start + 1;
  for (;;) {
    const j = sql.indexOf(q, i);
    if (j < 0) return sql.length;
    if (sql[j + 1] === q) { i = j + 2; continue; }
    return j + 1;
  }
}

/** `E'...'`: backslash escapes anything (including `'` and `\`), `''` is still a quote. */
function readEscapeString(sql, start) {
  let i = start + 1;
  const n = sql.length;
  while (i < n) {
    const c = sql[i];
    if (c === '\\') { i += 2; continue; }
    if (c === "'") {
      if (sql[i + 1] === "'") { i += 2; continue; }
      return i + 1;
    }
    i++;
  }
  return n;
}

/** Index just past the `'` that ends a `B'...'` / `X'...'` body (no `''` doubling there). */
function readBitString(sql, start) {
  const j = sql.indexOf("'", start + 1);
  return j < 0 ? sql.length : j + 1;
}

const E_ESCAPE = /\\(?:([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|([\s\S]))|''/g;
const E_CHARS = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
/** Body of an `E'...'` segment with its escapes decoded. */
function decodeEscapeBody(body) {
  return body.replace(E_ESCAPE, (m, oct, hex, u4, u8, other) => {
    if (m === "''") return "'";
    if (oct !== undefined) return String.fromCharCode(parseInt(oct, 8) & 0xff);
    if (hex !== undefined) return String.fromCharCode(parseInt(hex, 16));
    if (u4 !== undefined || u8 !== undefined) return String.fromCodePoint(Math.min(parseInt(u4 ?? u8, 16), 0x10ffff));
    return E_CHARS[other] ?? other;
  });
}

/**
 * A quoted string constant starting with its opening `'` at `q`, in one of the modes of scan.l:
 * 'std' ('...', N'...'), 'esc' (E'...'), 'bit' (B'...', X'...'), 'uni' (U&'...'), followed
 * through quote continuations. `ambiguous`: some 'std' segment ends elsewhere when
 * standard_conforming_strings is off. `value`: the decoded text (std and esc only).
 */
function readStringConstant(sql, q, mode) {
  let ambiguous = false;
  let value = '';
  for (;;) {
    let end;
    if (mode === 'esc') {
      end = readEscapeString(sql, q);
      value += decodeEscapeBody(sql.slice(q + 1, end - 1));
    } else if (mode === 'bit') {
      end = readBitString(sql, q);
    } else {
      end = readQuoted(sql, q, "'");
      if (mode === 'std' && readEscapeString(sql, q) !== end) ambiguous = true;
      value += sql.slice(q + 1, end - 1).replace(/''/g, "'");
    }
    const next = continuation(sql, end);
    if (next < 0) return { end, ambiguous, value };
    q = next;
  }
}

/**
 * The string constant that may follow `UESCAPE`: '...', E'...' or a dollar-quoted body (any
 * SCONST, as gram.y's base_yylex reads it). Null when there is none at `i`.
 */
function readEscapeConstant(sql, i) {
  const ch = sql[i];
  if (ch === "'") return readStringConstant(sql, i, 'std');
  if ((ch === 'E' || ch === 'e') && sql[i + 1] === "'") return readStringConstant(sql, i + 1, 'esc');
  if (ch === '$') {
    DOLLAR_TAG.lastIndex = i;
    const m = DOLLAR_TAG.exec(sql);
    if (!m) return null;
    const close = sql.indexOf(m[0], i + m[0].length);
    if (close < 0) return { end: sql.length, ambiguous: false, value: '' };
    return { end: close + m[0].length, ambiguous: false, value: sql.slice(i + m[0].length, close) };
  }
  return null;
}

/** check_uescapechar: one ASCII character that is not a hex digit, `+`, a quote or whitespace. */
const validUescape = (s) => s.length === 1 && s.charCodeAt(0) < 128 && !/[0-9A-Fa-f+'"\s]/.test(s);

/** The string mode for each one-letter prefix of `X'...'`. */
const PREFIX_MODE = { E: 'esc', e: 'esc', B: 'bit', b: 'bit', X: 'bit', x: 'bit', N: 'std', n: 'std' };

/** Postgres folds unquoted names by lower-casing A-Z only (U+212A KELVIN SIGN stays as it is). */
export function asciiLower(s) {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

/** NAMEDATALEN - 1: Postgres truncates longer identifiers, at a character boundary, before resolving them. */
const MAX_IDENT_BYTES = 63;
export function truncateIdent(s) {
  if (s.length <= 15 || Buffer.byteLength(s, 'utf8') <= MAX_IDENT_BYTES) return s;
  let out = '';
  let bytes = 0;
  for (const ch of s) {
    const b = Buffer.byteLength(ch, 'utf8');
    if (bytes + b > MAX_IDENT_BYTES) break;
    out += ch;
    bytes += b;
  }
  return out;
}

/** Body of a `"..."` identifier with `""` collapsed. */
function unquoteIdent(raw) {
  return raw.slice(1, -1).replace(/""/g, '"');
}

/** `U&"..."` body: `\XXXX`, `\+XXXXXX` and `\\` with the given escape character. */
function decodeUnicodeIdent(body, esc) {
  const e = esc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`${e}${e}|${e}\\+([0-9A-Fa-f]{6})|${e}([0-9A-Fa-f]{4})`, 'g');
  return body.replace(re, (m, six, four) => {
    if (six !== undefined) return String.fromCodePoint(parseInt(six, 16));
    if (four !== undefined) return String.fromCharCode(parseInt(four, 16));
    return esc;
  });
}

/**
 * Splits SQL into tokens. Strings and comments carry no content (`value: ''`): the guard never
 * looks inside a literal. Identifiers carry the decoded name, `quoted`, and `fold` (the name
 * Postgres resolves: lower-cased when unquoted, as written when quoted).
 *
 * @param {string} sql
 * @returns {Array<{type: 'ident'|'string'|'number'|'param'|'punct'|'op', value: string, quoted?: boolean, fold?: string, ambiguous?: boolean, start: number, end: number}>}
 */
export function tokenize(sql) {
  const toks = [];
  const n = sql.length;
  let i = 0;
  const push = (type, value, start, end, extra) => toks.push({ type, value, start, end, ...extra });
  const ident = (raw, quoted, start, end) => {
    const value = truncateIdent(raw);
    push('ident', value, start, end, { quoted, fold: quoted ? value : asciiLower(value) });
  };
  while (i < n) {
    const c = sql.charCodeAt(i);
    const ch = sql[i];
    if (isSpace(c)) { i++; continue; }
    if (ch === '-' && sql[i + 1] === '-') {
      i = lineCommentEnd(sql, i);
      continue;
    }
    if (ch === '/' && sql[i + 1] === '*') {
      i = skipBlockComment(sql, i);
      continue;
    }
    if (ch === "'") {
      // With standard_conforming_strings off, Postgres reads a backslash in '...' as an escape,
      // so the literal can end somewhere else and hide (or expose) the text after it.
      const s = readStringConstant(sql, i, 'std');
      push('string', '', i, s.end, s.ambiguous ? { ambiguous: true } : undefined);
      i = s.end;
      continue;
    }
    const prefixed = sql[i + 1] === "'" ? PREFIX_MODE[ch] : undefined;
    if (prefixed !== undefined) {
      // E'...', B'...', X'...', and N'...' (a plain string with a national-character tag: the same backslash ambiguity)
      const s = readStringConstant(sql, i + 1, prefixed);
      push('string', '', i, s.end, s.ambiguous ? { ambiguous: true } : undefined);
      i = s.end;
      continue;
    }
    if ((ch === 'U' || ch === 'u') && sql[i + 1] === '&' && (sql[i + 2] === "'" || sql[i + 2] === '"')) {
      if (sql[i + 2] === "'") {
        const s = readStringConstant(sql, i + 2, 'uni');
        push('string', '', i, s.end);
        i = s.end;
        continue;
      }
      const close = readQuoted(sql, i + 2, '"');
      let esc = '\\';
      let end = close;
      let ambiguous = false;
      // `UESCAPE <string constant>` may follow after whitespace and comments (Postgres 13+ reads
      // it as the next tokens): '!', E'\041', $$!$$ and continued strings all count.
      const kw = skipSpace(sql, close);
      let kwEnd = kw;
      while (kwEnd < n && isIdentPart(sql.charCodeAt(kwEnd))) kwEnd++;
      if (kwEnd - kw === 7 && sql.slice(kw, kwEnd).toLowerCase() === 'uescape' && isIdentStart(sql.charCodeAt(kw))) {
        const s = readEscapeConstant(sql, skipSpace(sql, kwEnd));
        if (s !== null) {
          // an invalid escape character is an error in Postgres; keep the default then
          if (validUescape(s.value)) esc = s.value;
          end = s.end;
          ambiguous = s.ambiguous;
        }
      }
      ident(decodeUnicodeIdent(unquoteIdent(sql.slice(i + 2, close)), esc), true, i, end);
      if (ambiguous) toks[toks.length - 1].ambiguous = true;
      i = end;
      continue;
    }
    if (ch === '"') {
      const end = readQuoted(sql, i, '"');
      ident(unquoteIdent(sql.slice(i, end)), true, i, end);
      i = end;
      continue;
    }
    if (ch === '$') {
      DOLLAR_TAG.lastIndex = i;
      const m = DOLLAR_TAG.exec(sql);
      if (m) {
        const tag = m[0];
        const close = sql.indexOf(tag, i + tag.length);
        const end = close < 0 ? n : close + tag.length;
        push('string', '', i, end);
        i = end;
        continue;
      }
      if (isDigit(sql.charCodeAt(i + 1))) {
        // scan.l `param`: \$ followed by digits
        let j = i + 1;
        while (j < n && isDigit(sql.charCodeAt(j))) j++;
        push('param', sql.slice(i, j), i, j);
        i = j;
        continue;
      }
      push('op', '$', i, i + 1);
      i++;
      continue;
    }
    if (ch === '.' && sql[i + 1] === '.') {
      // scan.l `dot_dot`: `..2` is `..` and then 2, not `.` and .2
      push('punct', '.', i, i + 1);
      push('punct', '.', i + 1, i + 2);
      i += 2;
      continue;
    }
    if (isDigit(c) || (ch === '.' && isDigit(sql.charCodeAt(i + 1)))) {
      NUMBER.lastIndex = i;
      let num = NUMBER.exec(sql)[0];
      // scan.l `decimalfail`: `1..` is the integer 1 and then `..`
      if (num.endsWith('.') && sql[i + num.length] === '.') num = num.slice(0, -1);
      push('number', num, i, i + num.length);
      i += num.length;
      continue;
    }
    if (isIdentStart(c)) {
      let j = i + 1;
      while (j < n && isIdentPart(sql.charCodeAt(j))) j++;
      ident(sql.slice(i, j), false, i, j);
      i = j;
      continue;
    }
    if (ch === ':' && sql[i + 1] === ':') {
      push('op', '::', i, i + 2);
      i += 2;
      continue;
    }
    if ('(),.;[]'.includes(ch)) {
      push('punct', ch, i, i + 1);
      i++;
      continue;
    }
    push('op', ch, i, i + 1);
    i++;
  }
  return toks;
}

// --- hidden list -------------------------------------------------------------------------

/** `#` starts a comment unless it is inside a double-quoted identifier. */
function stripListComment(line) {
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '"') inQuote = !inQuote;
    else if (line[i] === '#' && !inQuote) return line.slice(0, i);
  }
  return line;
}

/** `[schema.]table.column`, each part bare or `"..."` with `""` escapes. Returns the decoded parts. */
function parseEntry(entry) {
  const parts = [];
  let i = 0;
  while (i < entry.length) {
    if (entry[i] === '"') {
      const end = readQuoted(entry, i, '"');
      parts.push(unquoteIdent(entry.slice(i, end)));
      i = end;
    } else {
      let j = entry.indexOf('.', i);
      if (j < 0) j = entry.length;
      parts.push(entry.slice(i, j).trim());
      i = j;
    }
    if (entry[i] === '.') i++;
  }
  return parts.filter((p) => p !== '').map(truncateIdent);
}

/** Same line grammar as `parseHiddenFile` in src/core/hidden.ts, with quoted and schema-qualified entries. */
export function parseHiddenFile(text) {
  const hidden = [];
  const allow = [];
  for (const raw of text.split('\n')) {
    const line = stripListComment(raw).trim();
    if (!line) continue;
    if (line.startsWith('!')) allow.push(parseEntry(line.slice(1).trim()));
    else hidden.push(parseEntry(line));
  }
  return { hidden, allow };
}

function coverage(text) {
  const { hidden, allow } = parseHiddenFile(text);
  const columns = new Set();
  const full = new Set();
  for (const parts of [...hidden, ...allow]) {
    if (!parts.length) continue;
    columns.add(asciiLower(parts[parts.length - 1]));
    full.add(asciiLower(parts.join('.')));
  }
  return { columns, full };
}

// --- analysis ----------------------------------------------------------------------------

const isKeyword = (t, word) => t !== undefined && t.type === 'ident' && !t.quoted && (word === undefined ? KEYWORDS.has(t.fold) : t.fold === word);
const isPunct = (t, ch) => t !== undefined && t.type === 'punct' && t.value === ch;
/** A token that ends a value: a bare name right after it is a column alias, not a whole-row reference. */
function isOperand(t) {
  if (t === undefined) return false;
  if (t.type === 'number' || t.type === 'string' || t.type === 'param') return true;
  if (t.type === 'punct') return t.value === ')' || t.value === ']';
  if (t.type === 'ident') return t.quoted || !KEYWORDS.has(t.fold) || OPERAND_KEYWORDS.has(t.fold);
  return false;
}

/**
 * Matching parentheses and brackets in one pass: `match[i]` is the partner of a `(` `)` `[` `]`
 * at `i` (an unclosed opener matches the last token), `parent[i]` the innermost `(` around
 * token `i` (-1 at top level).
 */
function parens(toks) {
  const match = new Int32Array(toks.length).fill(-1);
  const parent = new Int32Array(toks.length).fill(-1);
  const stack = [];
  const brackets = [];
  for (let k = 0; k < toks.length; k++) {
    parent[k] = stack.length ? stack[stack.length - 1] : -1;
    if (isPunct(toks[k], '(')) stack.push(k);
    else if (isPunct(toks[k], '[')) brackets.push(k);
    else if (isPunct(toks[k], ')') && stack.length) {
      const o = stack.pop();
      match[o] = k;
      match[k] = o;
    } else if (isPunct(toks[k], ']') && brackets.length) {
      const o = brackets.pop();
      match[o] = k;
      match[k] = o;
    }
  }
  for (const o of [...stack, ...brackets]) match[o] = toks.length - 1;
  return { match, parent };
}

/**
 * Whether the token at `i` ends a value, so a bare name after it is a column alias. A `)` does
 * not when it closes `OPERATOR(...)` (an operator) or `DISTINCT ON (...)` (the select list
 * starts after it).
 */
function endsValue(toks, match, i) {
  const t = toks[i];
  if (!isOperand(t)) return false;
  if (isPunct(t, ')') && match[i] >= 0) {
    const o = match[i];
    if (toks[o - 1]?.type === 'ident' && !toks[o - 1].quoted && toks[o - 1].fold === 'operator') return false;
    if (isKeyword(toks[o - 1], 'on') && isKeyword(toks[o - 2], 'distinct')) return false;
  }
  return true;
}

/** Deeper FROM nesting than this is treated as table-backed without looking further. */
const MAX_FROM_DEPTH = 64;

/**
 * Every FROM / JOIN item, CTE names and their scope. `aliases` maps a folded name to its item:
 * `table` is the table's name as written and `backed` says whether a whole-row reference to it
 * could expose table columns (false for CTEs, subqueries and set-returning functions, whose own
 * select lists are checked on their own). A name is never downgraded from backed to not backed,
 * whatever scope the second declaration is in. `declared` holds the token indexes of the
 * declarations; `renamed` lists table-backed items with a column alias list, `t(a, b)`.
 */
function fromItems(toks, match, parent) {
  const aliases = new Map();
  const declared = new Set();
  const names = new Set(); // table and CTE name tokens: not column reads
  const renamed = [];
  const close = (o) => (match[o] >= 0 ? match[o] : toks.length - 1);
  const scopeEnd = (k) => (parent[k] >= 0 ? close(parent[k]) : toks.length);
  const register = (fold, item) => {
    const had = aliases.get(fold);
    if (had === undefined || !had.backed) aliases.set(fold, item);
  };

  // CTE names: `with [recursive] name [(cols)] as [not] [materialized] (...) [, name ...]`.
  // A CTE is visible from its WITH to the end of the enclosing parentheses.
  const ctes = new Map();
  for (let k = 0; k < toks.length; k++) {
    if (!isKeyword(toks[k], 'with')) continue;
    let j = k + 1;
    if (isKeyword(toks[j], 'recursive')) j++;
    const end = scopeEnd(k);
    for (;;) {
      const nm = toks[j];
      if (nm === undefined || nm.type !== 'ident' || (!nm.quoted && KEYWORDS.has(nm.fold))) break;
      let p = j + 1;
      if (isPunct(toks[p], '(')) p = close(p) + 1;
      if (!isKeyword(toks[p], 'as')) break;
      p++;
      if (isKeyword(toks[p], 'not')) p++;
      if (isKeyword(toks[p], 'materialized')) p++;
      if (!isPunct(toks[p], '(')) break;
      // visible after its own body (later siblings and the main query), not inside it or in
      // earlier siblings; a WITH RECURSIVE self-reference is therefore treated as the table
      const body = close(p);
      if (!ctes.has(nm.fold)) ctes.set(nm.fold, []);
      ctes.get(nm.fold).push([body, end]);
      declared.add(j);
      names.add(j);
      register(nm.fold, { table: nm.value, backed: false });
      p = body + 1;
      if (!isPunct(toks[p], ',')) break; // SEARCH / CYCLE: later names are treated as tables (safe)
      j = p + 1;
    }
  }
  const isCte = (fold, k) => {
    const ranges = ctes.get(fold) ?? [];
    return ranges.length <= 64 && ranges.some(([s, e]) => k > s && k <= e); // many same-named CTEs: a table (safe)
  };

  /** One FROM item at `j`: returns the index after it and its alias, or null when there is none. */
  function item(j, end, depth) {
    while (isKeyword(toks[j], 'only') || isKeyword(toks[j], 'lateral')) j++;
    const t = toks[j];
    if (t === undefined || j >= end) return null;
    let entry;
    if (isPunct(t, '(')) {
      const c = close(j);
      const first = toks[j + 1];
      if (first !== undefined && first.type === 'ident' && !first.quoted && SUBQUERY_START.has(first.fold)) {
        entry = { table: null, backed: false };
      } else if (depth >= MAX_FROM_DEPTH) {
        entry = { table: '(join)', backed: true };
      } else {
        // `(a x join b y)`: a parenthesised join, parsed as its own FROM list
        const inner = fromList(j + 1, c, depth + 1);
        entry = { table: inner.table ?? '(join)', backed: inner.backed };
      }
      j = c + 1;
    } else if (t.type === 'ident' && !(!t.quoted && KEYWORDS.has(t.fold))) {
      const parts = [j];
      j++;
      while (isPunct(toks[j], '.') && toks[j + 1]?.type === 'ident') { parts.push(j + 1); j += 2; }
      if (isPunct(toks[j], '(')) {
        // set-returning function: `from generate_series(1, 3) g`
        j = close(j) + 1;
        if (isKeyword(toks[j], 'with') && toks[j + 1]?.fold === 'ordinality') j += 2;
        entry = { table: null, backed: false };
      } else {
        const name = toks[parts[parts.length - 1]];
        // a schema-qualified name is always a table, never a CTE
        const backed = parts.length > 1 || !isCte(name.fold, parts[0]);
        entry = { table: name.value, backed };
        for (const p of parts) { declared.add(p); names.add(p); }
        register(name.fold, entry);
        if (toks[j]?.type === 'op' && toks[j].value === '*') j++; // `from leads *` (inheritance)
      }
    } else {
      return null;
    }
    if (isKeyword(toks[j], 'as')) j++;
    const alias = toks[j];
    if (alias !== undefined && j < end && alias.type === 'ident' && !(!alias.quoted && NOT_ALIAS.has(alias.fold))) {
      declared.add(j);
      register(alias.fold, entry);
      j++;
    }
    if (isPunct(toks[j], '(') && j < end) {
      // `alias(a, b)` renames columns by position; `as (a int)` is a function's column definition list
      if (entry.backed) renamed.push({ alias: alias?.value ?? entry.table, table: entry.table });
      j = close(j) + 1;
    }
    return { next: j, entry };
  }

  /** A comma- and JOIN-separated list of items from `j` up to `end` or a clause keyword. */
  function fromList(j, end, depth) {
    let backed = false;
    let table = null;
    for (;;) {
      const r = item(j, end, depth);
      if (r !== null) {
        backed ||= r.entry.backed;
        table ??= r.entry.backed ? r.entry.table : null;
        j = r.next;
      }
      // An item it cannot read is skipped, not the end of the list: scan on to the next `,` / JOIN.
      let more = false;
      while (j < end && j < toks.length) {
        const t = toks[j];
        if (isPunct(t, '(') || isPunct(t, '[')) { j = close(j) + 1; continue; }
        if (isPunct(t, ',') || isKeyword(t, 'join')) { j++; more = true; break; }
        if (isPunct(t, ';') || isPunct(t, ')') || (isKeyword(t) && FROM_END.has(t.fold))) break;
        // the next FROM starts its own list (keeps this linear); `is [not] distinct from` does not
        if (isKeyword(t, 'from') && !isKeyword(toks[j - 1], 'distinct')) break;
        j++; // join type words, ON / USING conditions, TABLESAMPLE ...
      }
      if (!more) break;
    }
    return { backed, table };
  }

  for (let k = 0; k < toks.length; k++) {
    if (!isKeyword(toks[k], 'from')) continue;
    const p = parent[k];
    if (p >= 1 && toks[p - 1].type === 'ident' && FROM_IN_ARGS.has(toks[p - 1].fold)) continue; // `extract(year from x)`
    // `is [not] distinct from` (DISTINCT right before FROM is nothing else in Postgres's grammar). The
    // same test as the one fromList scans past, so a FROM list never runs over a FROM that also
    // starts its own list: that would scan `from a distinct from distinct from ...` quadratically.
    if (isKeyword(toks[k - 1], 'distinct')) continue;
    fromList(k + 1, scopeEnd(k), 0);
  }
  return { aliases, declared, names, renamed };
}

/**
 * A name that labels an output column rather than reading one: right after AS (`count(*) as
 * emails_sent`, also the type in `cast(x as t)`), or an implicit alias right after a literal or
 * a closing paren/bracket and right before `,` / FROM / `)` / the end (`count(*) emails_sent,`).
 * A name after another name (`id phone`, `at time zone phone`) is not skipped: it may be a
 * column read, so it is checked.
 */
function isOutputAlias(toks, match, k) {
  const next = toks[k + 1];
  if (isPunct(next, '.') || isPunct(next, '(')) return false;
  if (isKeyword(toks[k - 1], 'as')) return true;
  const prev = toks[k - 1];
  const literalOrClose = prev !== undefined && (prev.type === 'number' || prev.type === 'string' || prev.type === 'param' || isPunct(prev, ')') || isPunct(prev, ']'));
  if (!literalOrClose || !endsValue(toks, match, k - 1)) return false;
  return next === undefined || isPunct(next, ',') || isPunct(next, ')') || isPunct(next, ';') || isKeyword(next, 'from');
}

const HIDDEN_DOCS = 'https://github.com/Sajal0208/daypass/blob/main/docs/hidden-columns.md';
const PREFIX = 'Daypass PII guard: ';

/**
 * Deny reasons for a list problem are relayed to the human by the model ("Tell the user: ...");
 * structural reasons (`SELECT *`, whole rows, SQL-from-string functions) tell the model how to
 * rewrite the statement. None is phrased as an instruction that widens access.
 *
 * @param {string} sql
 * @param {string | null | { error: string }} hiddenFile  contents of the list; null when the
 *   file does not exist (ENOENT); `{ error }` with the error code when it exists but cannot be read
 * @param {Record<string, string | undefined>} env
 * @returns {{ allow: true } | { allow: false, reason: string }}
 */
export function decide(sql, hiddenFile, env) {
  if (hookDisabled(env)) return { allow: true };
  const path = hiddenFilePath(env);
  const toks = tokenize(sql);
  const { match, parent } = parens(toks);
  const { aliases, declared, names, renamed } = fromItems(toks, match, parent);
  const deny = (reason) => ({ allow: false, reason: PREFIX + reason });

  // 0. A '...' literal that ends elsewhere when standard_conforming_strings is off.
  if (toks.some((t) => t.ambiguous)) {
    return deny(
      "a '...' literal contains a backslash before a quote, which Postgres reads differently when " +
        "standard_conforming_strings is off, so the guard cannot tell where it ends. Double the quote ('') or use E'...'.",
    );
  }
  // 1. Functions that run SQL from a string or return whole rows.
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    // `f(...)`, or attribute notation `('select ...').ts_stat` / `t.dblink`, which Postgres reads as f(x)
    if (t.type === 'ident' && UNINSPECTABLE.has(t.value.toLowerCase()) && (isPunct(toks[k + 1], '(') || isPunct(toks[k - 1], '.'))) {
      return deny(
        `${t.value}() executes SQL from a string / returns whole rows, which the guard cannot inspect. ` +
          'Use a plain SELECT that names its columns instead.',
      );
    }
  }
  // 1b. Planner statistics views hold sample values of every readable column.
  for (const t of toks) {
    if (t.type === 'ident' && STATS.has(t.fold)) {
      return deny(
        `${t.value} holds planner statistics with sample values (most_common_vals, histogram_bounds) of readable columns, which the guard ` +
          'cannot check against the hidden list; query the table itself with named columns.',
      );
    }
  }
  // 2. `*` / `alias.*` targets other than count(*), and `TABLE x`.
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (isKeyword(t, 'table')) {
      return deny('TABLE x returns every column, like SELECT *; name the columns in a SELECT instead.');
    }
    if (t.type !== 'op' || t.value !== '*') continue;
    const prev = toks[k - 1];
    if (endsValue(toks, match, k - 1)) continue; // multiplication, or `from leads *` (inheritance)
    if (isPunct(prev, '(') && toks[k - 2]?.type === 'ident' && toks[k - 2].fold === 'count' && isPunct(toks[k + 1], ')')) continue;
    // count(o.*) is a row count
    if (isPunct(prev, '.') && toks[k - 2]?.type === 'ident' && isPunct(toks[k - 3], '(') && toks[k - 4]?.type === 'ident' && toks[k - 4].fold === 'count' && isPunct(toks[k + 1], ')')) continue;
    return deny(
      'SELECT * can return columns the hidden list does not cover; name the columns ' +
        '(describe_table lists the ones this role may read; count(*) is fine).',
    );
  }
  // 2b. Column alias lists on a table rename its columns by position, hiding their names.
  if (renamed.length) {
    const { alias, table } = renamed[0];
    return deny(
      `the column alias list on ${alias} renames the columns of ${table} by position, which hides their names ` +
        `from the guard; select the columns by name and alias each one (col AS name).`,
    );
  }
  // 3. Whole-row references to a FROM table or its alias.
  const wholeRow = (t, item) =>
    deny(
      `"${t.value}" is used as a whole row of ${item.table}, which can return columns the hidden list does not cover; ` +
        `name the columns (${t.value}.column). If "${t.value}" is a column of the same name, qualify it as <alias>.${t.value}.`,
    );
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (t.type !== 'ident' || declared.has(k)) continue;
    const item = aliases.get(t.fold);
    if (item === undefined || !item.backed) continue;
    const prev = toks[k - 1];
    const next = toks[k + 1];
    // `l.to_jsonb` is attribute notation for to_jsonb(l)
    const attr = toks[k + 2];
    if (isPunct(next, '.') && attr?.type === 'ident' && WHOLE_ROW_ATTR.has(attr.fold) && !isPunct(toks[k + 3], '(')) {
      return wholeRow(t, item);
    }
    if (isPunct(prev, '.') || isPunct(next, '.')) continue; // qualifier or qualified name
    if (isKeyword(prev, 'as')) continue; // `count(*) as users`
    // `kv.value u` is a column and its alias; a bare `value u` is the SQL/JSON keyword and a whole row
    const intro = prev?.type === 'ident' && !prev.quoted && VALUE_INTRO.has(prev.fold) && !isPunct(toks[k - 2], '.');
    if (!intro && endsValue(toks, match, k - 1)) continue; // `count(*) users`: an implicit column alias
    return wholeRow(t, item);
  }
  // 4. Every identifier against the name heuristic and the list.
  let cover = null;
  for (let k = 0; k < toks.length; k++) {
    const t = toks[k];
    if (t.type !== 'ident') continue;
    if (!t.quoted && KEYWORDS.has(t.fold)) continue;
    if (names.has(k)) continue; // a table or CTE name in FROM / WITH, not a column
    // `api_keys.key_prefix`: a FROM table or alias as the qualifier of a column (Postgres resolves
    // `a.b` to a relation first); the column after the dot is checked on its own
    if (isPunct(toks[k + 1], '.') && !isPunct(toks[k - 1], '.') && aliases.has(t.fold)) continue;
    if (isOutputAlias(toks, match, k)) continue;
    // the spelling (camelCase splits into words) and, unquoted, the name Postgres resolves (phonE -> phone)
    if (!looksSensitive(t.value) && (t.quoted || !looksSensitive(t.fold))) continue;
    if (hiddenFile === null) {
      return deny(
        `no hidden-columns list at ${path}. Tell the user: generate one with ` +
          `daypass hidden suggest --live <target> > ${path} (${HIDDEN_DOCS}), or set DAYPASS_PII_HOOK=off for this session.`,
      );
    }
    if (typeof hiddenFile !== 'string') {
      return deny(
        `cannot read hidden-columns list at ${path}: ${hiddenFile.error}. ` +
          `Tell the user: fix or remove that file, or set DAYPASS_PII_HOOK=off for this session.`,
      );
    }
    cover ??= coverage(hiddenFile);
    if (cover.columns.has(asciiLower(t.value))) continue;
    // qualified `a.b.c`: also accept an exact schema.table.column entry
    const chain = [t.value];
    // at most catalog.schema.table.column, so a long a.b.c... chain stays linear
    for (let j = k - 1; chain.length < 4 && isPunct(toks[j], '.') && toks[j - 1]?.type === 'ident'; j -= 2) chain.unshift(toks[j - 1].value);
    if (chain.length > 1 && cover.full.has(asciiLower(chain.join('.')))) continue;
    const qualifier = chain.length > 1 ? toks[k - 2] : undefined;
    const table = qualifier ? aliases.get(qualifier.fold)?.table ?? qualifier.value : '<table>';
    return deny(
      `"${t.value}" looks like personal or secret data and is not in the hidden-columns list (${path}). ` +
        `Tell the user: if it must stay visible, add "!${table}.${t.value}" after review, or set DAYPASS_PII_HOOK=off for this session; ` +
        `otherwise add "${table}.${t.value}" and have the database owner re-run ` +
        `daypass sql --hide-file ${path} | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1.`,
    );
  }
  return { allow: true };
}

/**
 * Exit codes follow the Claude Code hook contract: 0 = no decision (the call goes ahead),
 * 2 = block with the reason on stderr. The hook fails closed: stdin that is not the JSON of a
 * tool call with a string `sql`, and any error while deciding, exit 2 with a reason, and
 * hooks.json adds `onFailure: block` for a crash or a timeout the script cannot catch itself.
 * DAYPASS_PII_HOOK=off (also `false`/`0`, any case) is the one way to let everything through.
 */
function block(reason) {
  process.stderr.write(PREFIX + reason + '\n');
  process.exit(2);
}

function main() {
  if (hookDisabled(process.env)) return;
  let input;
  try {
    input = JSON.parse(readFileSync(0, 'utf8'));
  } catch (err) {
    block(`stdin is not the JSON of a tool call (${err?.message ?? err}); the query was not checked and is blocked.`);
  }
  const toolInput = input?.tool_input;
  if (toolInput === null || typeof toolInput !== 'object') {
    block('the tool call has no tool_input object; the query was not checked and is blocked.');
  }
  if (typeof toolInput.sql !== 'string') {
    block('the tool input has no string "sql" field; the query was not checked and is blocked.');
  }
  let hiddenFile;
  try {
    hiddenFile = readFileSync(hiddenFilePath(process.env), 'utf8');
  } catch (err) {
    hiddenFile = err?.code === 'ENOENT' ? null : { error: err?.code ?? String(err) };
  }
  const verdict = decide(toolInput.sql, hiddenFile, process.env);
  if (!verdict.allow) {
    process.stderr.write(verdict.reason + '\n');
    process.exit(2);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (err) {
    block(`internal error (${err?.stack ?? err}); the query was not checked and is blocked.`);
  }
}
