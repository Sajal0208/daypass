#!/usr/bin/env node
/**
 * PreToolUse hook for the Peephole `query` tool: a second fence on the client, in front of the
 * column grants that Postgres enforces. It reads the tool call from stdin, pulls every identifier
 * out of the SQL, and blocks (exit 2, reason on stderr) when one looks like personal or secret
 * data and the hidden-columns list says nothing about it, hidden or allowed. A column the list
 * hides is let through (the role cannot read it anyway); one on a `!` allow line was reviewed.
 *
 * Dependency-free on purpose: it runs on every query, from a plugin directory, with no install.
 * The name heuristic (WORDS, SPECIAL, ALWAYS, SAFE_TAIL, toSnake, looksSensitive) is a verbatim
 * copy of src/core/hidden.ts, which cannot be imported from here. Change both files together:
 * the parity test in test/plugin-hook.test.ts guards against drift.
 */
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

// --- name heuristic: mirrors src/core/hidden.ts; test/plugin-hook.test.ts guards drift -----
const WORDS = new Set([
  'phone', 'mobile', 'email', 'token', 'secret', 'key', 'transcript', 'password', 'passwd',
  'address', 'ssn', 'iban', 'card', 'dob', 'birth', 'birthday', 'birthdate', 'salt', 'otp', 'pin',
  'passport', 'license', 'licence', 'routing', 'national',
]);
const SPECIAL = /^encrypted_|^prompt_snapshot$|^(lines|credentials)$/;
const ALWAYS = /^(national|tax|government)_(id|number)$|^(bank_)?account_number$/;
const SAFE_TAIL =
  /_(verified|confirmed|count|used|at|id|type|status|enabled|required|country|layout|limit|prefix|version|expiry|expires|expiration|rounds|domain)$/;

function toSnake(name) {
  return name
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase();
}

export function looksSensitive(column) {
  const name = toSnake(column);
  if (ALWAYS.test(name)) return true;
  if (SAFE_TAIL.test(name)) return false;
  if (SPECIAL.test(name)) return true;
  return name.split('_').some((part) => WORDS.has(part));
}
// -----------------------------------------------------------------------------------------

const KEYWORDS = new Set([
  'select', 'from', 'where', 'join', 'on', 'and', 'or', 'not', 'as', 'limit', 'order', 'by', 'group',
  'having', 'left', 'right', 'inner', 'outer', 'count', 'sum', 'avg', 'min', 'max', 'distinct', 'case',
  'when', 'then', 'else', 'end', 'null', 'true', 'false', 'is', 'in', 'like', 'ilike', 'between', 'asc',
  'desc', 'union', 'all', 'with', 'exists', 'cast', 'interval', 'date', 'now', 'coalesce', 'nullif',
  'explain', 'offset',
]);
/** Words that can follow a table name in FROM/JOIN and are therefore never its alias. */
const NOT_ALIAS = new Set([
  'on', 'where', 'join', 'left', 'right', 'inner', 'outer', 'cross', 'full', 'natural', 'group',
  'order', 'limit', 'union', 'having', 'using', 'lateral', 'offset', 'as',
]);

export function hiddenFilePath(env) {
  return env.PEEPHOLE_HIDDEN_FILE ?? join(homedir(), '.peephole', 'hidden-columns.txt');
}

/** Same format as `parseHiddenFile` in src/core/hidden.ts. */
function parseHiddenFile(text) {
  const hidden = [];
  const allow = [];
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*/, '').trim();
    if (!line) continue;
    if (line.startsWith('!')) allow.push(line.slice(1).trim());
    else hidden.push(line);
  }
  return { hidden, allow };
}

/** String literals (with '' escapes), -- comments and block comments become spaces. */
function stripLiteralsAndComments(sql) {
  return sql.replace(/'(?:[^']|'')*'|--[^\n]*|\/\*[\s\S]*?\*\//g, ' ');
}

/** alias -> table and table -> table for every `FROM x [AS] y` / `JOIN x [AS] y`. */
function tableAliases(text) {
  const map = new Map();
  const re = /\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(?:\s+as)?(?:\s+([A-Za-z_][A-Za-z0-9_]*))?/gi;
  for (const m of text.matchAll(re)) {
    const table = m[1].split('.').pop();
    map.set(table.toLowerCase(), table);
    if (m[2] && !NOT_ALIAS.has(m[2].toLowerCase())) map.set(m[2].toLowerCase(), table);
  }
  return map;
}

/** Every identifier with the qualifier that precedes it (`p.email` -> { name: 'email', qualifier: 'p' }). */
function identifiers(text) {
  const out = [];
  const re = /(?<![A-Za-z0-9_.])[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/g;
  for (const m of text.matchAll(re)) {
    const parts = m[0].split('.');
    out.push({ name: parts[parts.length - 1], qualifier: parts.length > 1 ? parts[parts.length - 2] : null });
  }
  return out;
}

const HIDDEN_DOCS = 'https://github.com/Sajal0208/peephole/blob/main/docs/hidden-columns.md';

/**
 * Deny reasons are relayed to the human by the model ("Tell the user: ..."); they are never
 * phrased as an instruction to the model itself.
 *
 * @param {string} sql
 * @param {string | null | { error: string }} hiddenFile  contents of the list; null when the
 *   file does not exist (ENOENT); `{ error }` with the error code when it exists but cannot be read
 * @param {Record<string, string | undefined>} env
 * @returns {{ allow: true } | { allow: false, reason: string }}
 */
export function decide(sql, hiddenFile, env) {
  if (env.PEEPHOLE_PII_HOOK === 'off') return { allow: true };
  const path = hiddenFilePath(env);
  const text = stripLiteralsAndComments(sql).replace(/"/g, '');
  const aliases = tableAliases(text);
  for (const { name, qualifier } of identifiers(text)) {
    if (KEYWORDS.has(name.toLowerCase()) || !looksSensitive(name)) continue;
    if (hiddenFile === null) {
      return {
        allow: false,
        reason:
          `Peephole PII guard: no hidden-columns list at ${path}. Tell the user: generate one with ` +
          `peephole hidden suggest --live <target> > ${path} (${HIDDEN_DOCS}), or set PEEPHOLE_PII_HOOK=off for this session.`,
      };
    }
    if (typeof hiddenFile !== 'string') {
      return {
        allow: false,
        reason:
          `Peephole PII guard: cannot read hidden-columns list at ${path}: ${hiddenFile.error}. ` +
          `Tell the user: fix or remove that file, or set PEEPHOLE_PII_HOOK=off for this session.`,
      };
    }
    const { hidden, allow } = parseHiddenFile(hiddenFile);
    const covered = new Set([...hidden, ...allow].map((e) => e.split('.').pop().toLowerCase()));
    if (covered.has(name.toLowerCase())) continue;
    const table = qualifier ? aliases.get(qualifier.toLowerCase()) ?? qualifier : '<table>';
    return {
      allow: false,
      reason:
        `Peephole PII guard: "${name}" looks like personal or secret data and is not in the hidden-columns list (${path}). ` +
        `Tell the user: if it must stay visible, add "!${table}.${name}" after review, or set PEEPHOLE_PII_HOOK=off for this session; ` +
        `otherwise add "${table}.${name}" and have the database owner re-run ` +
        `peephole sql --hide-file ${path} | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1.`,
    };
  }
  return { allow: true };
}

/**
 * Exit codes follow the Claude Code hook contract: 0 = no decision (the call goes ahead),
 * 2 = block with the reason on stderr, anything else = non-blocking error whose first stderr
 * line shows in the transcript. Unparsable stdin is not a tool call we understand, so it is
 * let through silently; a tool input with no `sql` is let through with a visible note, so a
 * renamed argument does not turn the guard off unnoticed.
 */
function main() {
  let input;
  try {
    input = JSON.parse(readFileSync(0, 'utf8'));
  } catch {
    return;
  }
  const toolInput = input?.tool_input;
  if (toolInput === null || typeof toolInput !== 'object') return;
  if (typeof toolInput.sql !== 'string') {
    process.stderr.write('Peephole PII guard: no "sql" in tool input, not checked\n');
    process.exit(1);
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
