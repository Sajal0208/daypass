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

/**
 * @param {string} sql
 * @param {string | null} hiddenFileText  contents of the list, or null when the file is missing
 * @param {Record<string, string | undefined>} env
 * @returns {{ allow: true } | { allow: false, reason: string }}
 */
export function decide(sql, hiddenFileText, env) {
  if (env.PEEPHOLE_PII_HOOK === 'off') return { allow: true };
  const path = hiddenFilePath(env);
  const text = stripLiteralsAndComments(sql).replace(/"/g, '');
  const aliases = tableAliases(text);
  for (const { name, qualifier } of identifiers(text)) {
    if (KEYWORDS.has(name.toLowerCase()) || !looksSensitive(name)) continue;
    if (hiddenFileText === null) {
      return {
        allow: false,
        reason:
          `Peephole PII guard: no hidden-columns list at ${path}. Generate one with ` +
          `"peephole hidden suggest --live <target> > ${path}" (see docs/hidden-columns.md) or set PEEPHOLE_PII_HOOK=off.`,
      };
    }
    const { hidden, allow } = parseHiddenFile(hiddenFileText);
    const covered = new Set([...hidden, ...allow].map((e) => e.split('.').pop().toLowerCase()));
    if (covered.has(name.toLowerCase())) continue;
    const table = qualifier ? aliases.get(qualifier.toLowerCase()) ?? qualifier : '<table>';
    return {
      allow: false,
      reason:
        `Peephole PII guard: "${name}" looks like personal or secret data and is not in your hidden-columns list (${path}). ` +
        `If it must stay visible, add "!${table}.${name}" to the list after review, or set PEEPHOLE_PII_HOOK=off for this session; ` +
        `otherwise add "${table}.${name}" and re-run "peephole sql --hide-file ${path} | psql -X "$OWNER_URL" -v ON_ERROR_STOP=1".`,
    };
  }
  return { allow: true };
}

function main() {
  let input;
  try {
    input = JSON.parse(readFileSync(0, 'utf8'));
  } catch {
    return; // not a tool call we understand; never block on our own failure
  }
  const sql = input?.tool_input?.sql;
  if (typeof sql !== 'string') return;
  let text = null;
  try {
    text = readFileSync(hiddenFilePath(process.env), 'utf8');
  } catch {
    text = null;
  }
  const verdict = decide(sql, text, process.env);
  if (!verdict.allow) {
    process.stderr.write(verdict.reason + '\n');
    process.exit(2);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
