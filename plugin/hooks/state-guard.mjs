#!/usr/bin/env node
/**
 * PreToolUse hook for Bash, Monitor and the file tools: keeps the agent away from Daypass's own state.
 * ~/.daypass (or $DAYPASS_HOME) holds config.json (target URLs, which can carry passwords),
 * lease.json (the lease the MCP server trusts), audit.jsonl and hidden-columns.txt (whose
 * `!table.column` lines let the PII guard pass a column). Only the human changes these. It blocks
 *
 *   - Bash (or Monitor, which runs a command in the same shell) that starts the MCP server (`daypass mcp`, which would skip the PII guard) or opens a
 *     lease (`daypass open`); `status`, `log`, `doctor`, `close`, `hidden`, `sql` stay allowed,
 *   - Bash that names the state directory, except the daypass CLI reading the hidden list
 *     (`daypass hidden check --file ~/.daypass/hidden-columns.txt`) with no output redirect,
 *   - Write / Edit / MultiEdit / NotebookEdit of any path in the state directory or of
 *     $DAYPASS_HIDDEN_FILE (symlinks resolved),
 *   - Read of config.json or lease.json there, and Grep / Glob whose path, `glob` or `pattern` can
 *     reach the directory.
 *
 * Paths are compared case-insensitively everywhere (macOS and Windows file systems usually are).
 *
 * It matches command text, so it is a fence against mistakes and prompt-injected instructions,
 * not a security boundary. Before matching it folds case, drops quotes and backslashes, expands
 * `{a,b}`, looks through common wrappers (sudo, env, timeout, nice, nohup, xargs, sh/bash/zsh -c,
 * npx/pnpm dlx/bunx, `$(which daypass)` ...) and treats a glob that can match `.daypass` as naming
 * it. It is still not a shell parser: variables, `eval`, scripts and other indirection get past
 * it. The boundaries are the database role and the lease, which a human opens. Claude Code cannot tell a
 * `!` command the user typed from one the agent ran if it sends both through this hook; the
 * deny message says to run the command in the user's own terminal.
 *
 * Fails closed like pii-guard.mjs: unparsable stdin or a Bash call without a string command
 * exits 2, and hooks.json sets `onFailure: block`.
 */
import { readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const PREFIX = 'Daypass state guard: ';
const FENCE =
  ' This hook is a fence against mistakes, not a wall: it matches command text. If the user meant to do this, ' +
  'they run it in their own terminal.';
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
const SECRET_FILES = new Set(['config.json', 'lease.json']);
/** Commands that run the next word as the program. */
const WRAPPERS = new Set([
  'npx', 'bunx', 'pnpx', 'sudo', 'doas', 'env', 'exec', 'time', 'nohup', 'command', 'builtin', 'nice', 'ionice', 'timeout',
  'stdbuf', 'xargs', 'watch', 'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish',
  // shell words that put a command after them
  '{', '!', 'if', 'then', 'else', 'elif', 'do', 'while', 'until',
]);
/** Package runners whose next word is a sub-command before the program: `npm exec`, `pnpm dlx`, `bun x`. */
const RUNNERS = new Set(['npm', 'pnpm', 'yarn', 'bun']);
/** Per wrapper, the options that take the next word as their value (`sudo -u me`, `npx -p daypass`). */
const VALUE_OPTS = {
  sudo: ['-u', '-g', '-p', '-C', '-D', '-h', '-r', '-t', '-T', '-U', '-a', '-c', '--user', '--group', '--prompt', '--close-from', '--chdir', '--host', '--role', '--type', '--command-timeout', '--other-user', '--login-class', '--auth-type'],
  doas: ['-u', '-C'],
  env: ['-u', '-C', '-P', '--unset', '--chdir'],
  exec: ['-a'],
  nice: ['-n', '--adjustment'],
  ionice: ['-c', '-n', '-p', '--class', '--classdata', '--pid'],
  timeout: ['-s', '-k', '--signal', '--kill-after'],
  stdbuf: ['-i', '-o', '-e', '--input', '--output', '--error'],
  xargs: ['-n', '-I', '-L', '-P', '-s', '-d', '-E', '-a', '--max-args', '--replace', '--max-lines', '--max-procs', '--max-chars', '--delimiter', '--eof', '--arg-file'],
  watch: ['-n', '-d', '--interval'],
  time: ['-f', '-o', '--format', '--output'],
  sh: ['-o', '-O'], bash: ['-o', '-O'], zsh: ['-o'], dash: ['-o'], ksh: ['-o'],
  npx: ['-p', '--package'], bunx: ['-p', '--package'], pnpx: ['-p', '--package'],
  npm: ['-p', '--package', '-w', '--workspace'], pnpm: ['-p', '--package', '-C', '--dir', '--filter'], yarn: ['-p', '--package'], bun: ['-p', '--package'],
};
const BLOCKED_SUBCOMMANDS = new Set(['mcp', 'open']);
const STATE_REF = /\.daypass(?![A-Za-z0-9_-])|\bDAYPASS_HOME\b/i;
// No braces, commas or glob characters in the path form: `{~/.daypass/config.json,~/.daypass/hidden-columns.txt}`
// must not be scrubbed as one hidden-list reference.
const HIDDEN_REF = /\$\{DAYPASS_HIDDEN_FILE(?::-[^}]*)?\}|\$DAYPASS_HIDDEN_FILE\b|[^\s;&|<>(){},*?[\]]*\.daypass\/hidden-columns\.txt/gi;
/** An output redirect or tee, after `2>&1` and `> /dev/null` are taken out. */
const WRITES = /\d?>&\d|>\s*\/dev\/null/g;
const REDIRECT = />|\btee\b/;
const BRACE = /(?<!\$)\{([^{}]*,[^{}]*)\}/;
const GLOB_CHARS = /[*?[]/;

const homeOf = (env) => env.HOME || homedir();
/** Case folded: the state directory is matched case-insensitively. */
const fold = (p) => p.toLowerCase();
/** The state directory as configured and as it resolves through symlinks (/var -> /private/var on macOS), case folded. */
function stateDirs(env) {
  const dirs = [env.DAYPASS_HOME, join(homeOf(env), '.daypass')].filter(Boolean).map((d) => resolve(d));
  for (const d of [...dirs]) {
    try {
      dirs.push(realpathSync(d));
    } catch {
      // not there (yet): the configured path is all there is
    }
  }
  return dirs.map(fold);
}

/**
 * Command text as the shell would mostly see it, for matching: no quotes, no backslash escapes, and `$(which daypass)` / `` `command -v daypass` `` replaced by the name.
 */
function normalize(command) {
  return command
    .replace(/\\(.)/gs, '$1')
    .replace(/['"]/g, '')
    .replace(/\$\(\s*(?:which|command\s+-v|type\s+-p|whence\s+-p)\s+([^)]*)\)|`\s*(?:which|command\s+-v|type\s+-p|whence\s+-p)\s+([^`]*)`/gi, (_m, a, b) => ` ${a ?? b} `);
}

/** `a{b,c}d` -> `abd acd` (one word; at most 256 results, the rest stay unexpanded). */
function expandBraces(word) {
  const out = [];
  const queue = [word];
  while (queue.length && out.length + queue.length < 256) {
    const w = queue.shift();
    const m = BRACE.exec(w);
    if (!m) {
      out.push(w);
      continue;
    }
    for (const alt of m[1].split(',')) queue.push(w.slice(0, m.index) + alt + w.slice(m.index + m[0].length));
  }
  return [...out, ...queue];
}

/** A shell glob for one path component as an anchored, case-insensitive regex. */
function globRegex(component) {
  let re = '';
  for (let i = 0; i < component.length; i++) {
    const c = component[i];
    if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '[' && component.indexOf(']', i + 2) > 0) {
      const end = component.indexOf(']', i + 2);
      const body = component.slice(i + 1, end).replace(/^!/, '^').replace(/\\/g, '\\\\');
      re += `[${body}]`;
      i = end;
    } else re += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  try {
    return new RegExp(`^${re}$`, 'i');
  } catch {
    return /^\.daypass$/i; // an odd bracket: assume the worst
  }
}

/** True if this path component, a glob, can match `.daypass` (`.d*pass`, `.day?ass`, `.[d]aypass`). */
const globHitsState = (component) => GLOB_CHARS.test(component) && globRegex(component).test('.daypass');

/**
 * A glob in the command that can match `.daypass`. Shell globs only match a leading dot spelled
 * out, so `*` never counts; the catch-all dotfile globs (`.*`, `.[!.]*`, `.??*`) are let through
 * so `du -sh ~/.*` still runs: they say nothing about Daypass.
 */
function bashGlobHitsState(text) {
  for (const token of text.split(/[\s;&|()<>`=:]+/)) {
    for (const c of token.split('/')) {
      if (!c.startsWith('.') || !globHitsState(c)) continue;
      if (/^[.*?]+$/.test(c.replace(/\[[^\]]*\]/g, ''))) continue;
      return true;
    }
  }
  return false;
}

function deny(reason) {
  return { allow: false, reason: PREFIX + reason + FENCE };
}

/**
 * `daypass <sub>` at the program position of one (normalized) shell segment, or null. `?` when
 * the sub-command cannot be read (`xargs daypass`, `daypass $SUB`).
 */
function daypassSubcommand(segment) {
  const words = segment.trim().split(/\s+/).filter(Boolean);
  let i = 0;
  let viaXargs = false;
  for (;;) {
    while (i < words.length && /^[a-z_][a-z0-9_]*=/i.test(words[i])) i++; // FOO=1 cmd
    const w = words[i];
    if (w === undefined) return null;
    const prog = fold(w.split('/').pop());
    if (RUNNERS.has(prog) && ['exec', 'x', 'dlx'].includes(fold(words[i + 1] ?? ''))) i += 2;
    else if (WRAPPERS.has(prog)) i++;
    else break;
    if (prog === 'xargs') viaXargs = true;
    const takesValue = VALUE_OPTS[prog] ?? [];
    while (i < words.length && words[i].startsWith('-')) {
      const o = words[i++];
      if (o === '--') break;
      if (takesValue.includes(o)) i++;
    }
    if (prog === 'timeout' && /^\d/.test(words[i] ?? '')) i++; // the duration
  }
  if (!/(^|\/)daypass(@\S*)?$/i.test(words[i])) return null;
  i++;
  while (i < words.length && words[i].startsWith('-')) i++;
  const sub = fold(words[i] ?? '');
  if ((sub === '' && viaXargs) || (sub !== '' && !/^[a-z][a-z0-9-]*$/.test(sub))) return '?';
  return sub;
}

function decideBash(command, env) {
  const text = normalize(command);
  const segments = text.split(/\|\||&&|\$\(|[;&|\n()`]/);
  for (const seg of segments) {
    const sub = daypassSubcommand(seg);
    if (sub !== null && (BLOCKED_SUBCOMMANDS.has(sub) || sub === '?')) {
      return deny(
        sub === 'mcp'
          ? '`daypass mcp` from Bash starts a second MCP server outside the PII guard; use the daypass MCP tools instead.'
          : sub === 'open'
            ? 'opening a lease is the user\'s decision and is recorded under their name; print the `daypass open` line for the user to run.'
            : 'the daypass sub-command here comes from a variable or from xargs, so it cannot be checked; spell it out.',
      );
    }
  }
  const custom = [env.DAYPASS_HOME, env.DAYPASS_HIDDEN_FILE].filter(Boolean).map(fold);
  const expanded = fold(text).replace(/\S+/g, (w) => expandBraces(w).join(' '));
  let scrubbed = expanded.replace(HIDDEN_REF, ' ');
  if (env.DAYPASS_HIDDEN_FILE) scrubbed = scrubbed.split(fold(env.DAYPASS_HIDDEN_FILE)).join(' ');
  const touchesState =
    STATE_REF.test(scrubbed) || (env.DAYPASS_HOME && scrubbed.includes(fold(env.DAYPASS_HOME))) || bashGlobHitsState(scrubbed);
  if (touchesState) {
    return deny(
      'Bash may not read or change Daypass\'s state directory (~/.daypass: config.json can hold passwords, lease.json and ' +
        'audit.jsonl are the lease and its record, hidden-columns.txt is the list the PII guard trusts). Use `daypass status` / ' +
        '`daypass log`; propose hidden-list lines as text for the user to add.',
    );
  }
  if (scrubbed !== expanded || custom.some((c) => fold(text).includes(c))) {
    // only the daypass CLI may name the hidden list, and nothing may write to it
    const hiddenSegs = segments.filter((s) => s.replace(HIDDEN_REF, ' ') !== s || (env.DAYPASS_HIDDEN_FILE && fold(s).includes(fold(env.DAYPASS_HIDDEN_FILE))));
    const onlyCli = hiddenSegs.every((s) => daypassSubcommand(s) !== null);
    if (!onlyCli || REDIRECT.test(text.replace(WRITES, ' '))) {
      return deny(
        'the hidden-columns list is the human\'s to edit: an `!table.column` line lets the PII guard pass that column. ' +
          'Propose the lines as text; the user adds them. The daypass CLI may read the list (`daypass hidden check --file ...`).',
      );
    }
  }
  return { allow: true };
}

/** Absolute, normalised path, with a leading `~` expanded and symlinks resolved where they exist. */
function paths(p, cwd, env) {
  let abs = p === '~' ? homeOf(env) : p.startsWith('~/') ? join(homeOf(env), p.slice(2)) : p;
  abs = isAbsolute(abs) ? resolve(abs) : resolve(cwd, abs);
  const out = [abs];
  try {
    out.push(realpathSync(abs));
  } catch {
    try {
      out.push(join(realpathSync(dirname(abs)), basename(abs)));
    } catch {
      // neither exists: the plain path is all there is
    }
  }
  return out;
}

function inState(p, env) {
  const q = fold(p);
  return stateDirs(env).some((d) => q === d || q.startsWith(d + sep)) || q.split(sep).includes('.daypass');
}

/** True if `p` is the state directory or one of its ancestors, so a recursive search from it can reach the state. */
function aboveState(p, env) {
  const q = fold(p);
  const base = q.endsWith(sep) ? q : q + sep;
  return stateDirs(env).some((d) => d === q || d.startsWith(base));
}

/** True if a Grep `glob` or Glob `pattern`, searched from `root`, can reach the state directory. */
function patternHitsState(pattern, root, cwd, env) {
  for (const alt of expandBraces(pattern)) {
    const parts = alt.split('/');
    const firstGlob = parts.findIndex((c) => GLOB_CHARS.test(c));
    const literal = (firstGlob < 0 ? parts : parts.slice(0, firstGlob)).join('/');
    const rest = firstGlob < 0 ? [] : parts.slice(firstGlob);
    const from = isAbsolute(alt) || alt === '~' || alt.startsWith('~/') ? literal || sep : join(root, literal);
    const bases = paths(from, cwd, env);
    if (bases.some((p) => inState(p, env))) return true;
    if (rest.some((c) => fold(c) === '.daypass')) return true;
    if (rest.some(globHitsState) && bases.some((p) => aboveState(p, env))) return true;
  }
  return false;
}

function decideFile(tool, input, cwd, env) {
  const search = tool === 'Grep' || tool === 'Glob';
  const target = tool === 'NotebookEdit' ? input.notebook_path : search ? input.path ?? cwd : input.file_path;
  if (typeof target !== 'string') return { allow: true }; // the tool itself rejects a call without a path
  const all = paths(target, cwd, env);
  const state = all.some((p) => inState(p, env));
  if (WRITE_TOOLS.has(tool)) {
    const hidden = env.DAYPASS_HIDDEN_FILE ? paths(env.DAYPASS_HIDDEN_FILE, cwd, env).map(fold) : [];
    if (state || all.some((p) => hidden.includes(fold(p)))) {
      return deny(
        `${tool} may not change Daypass's state (${target}): the lease, the audit log, the targets and the hidden-columns list are the user's. ` +
          'Propose the change as text; the user makes it.',
      );
    }
  } else if (search) {
    const pattern = tool === 'Glob' ? input.pattern : input.glob;
    if (state || (typeof pattern === 'string' && patternHitsState(pattern, target, cwd, env))) {
      return deny(`${tool} may not search Daypass's state directory (${target}${typeof pattern === 'string' ? `, ${pattern}` : ''}): config.json can hold database passwords and lease.json is the lease. Use \`daypass status\`.`);
    }
  } else if (state && all.some((p) => SECRET_FILES.has(fold(basename(p))))) {
    return deny(`${tool} may not read ${target}: config.json can hold database passwords and lease.json is the lease. Use \`daypass status\`.`);
  }
  return { allow: true };
}

/**
 * @param {{ tool_name?: string, tool_input?: any, cwd?: string }} input  the PreToolUse payload
 * @param {Record<string, string | undefined>} env
 * @returns {{ allow: true } | { allow: false, reason: string }}
 */
export function decideTool(input, env) {
  const tool = input?.tool_name;
  const toolInput = input?.tool_input;
  const cwd = typeof input?.cwd === 'string' ? input.cwd : process.cwd();
  // Monitor runs its command in the same shell as Bash, so it gets the same check.
  if (tool === 'Bash' || tool === 'Monitor') {
    if (typeof toolInput?.command !== 'string') return { allow: false, reason: PREFIX + `the ${tool} call has no string "command"; it was not checked and is blocked.` };
    return decideBash(toolInput.command, env);
  }
  if (toolInput === null || typeof toolInput !== 'object') return { allow: true };
  return decideFile(tool, toolInput, cwd, env);
}

function main() {
  let input;
  try {
    input = JSON.parse(readFileSync(0, 'utf8'));
  } catch (err) {
    process.stderr.write(`${PREFIX}stdin is not the JSON of a tool call (${err?.message ?? err}); the call was not checked and is blocked.\n`);
    process.exit(2);
  }
  const verdict = decideTool(input, process.env);
  if (!verdict.allow) {
    process.stderr.write(verdict.reason + '\n');
    process.exit(2);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (err) {
    process.stderr.write(`${PREFIX}internal error (${err?.stack ?? err}); the call was not checked and is blocked.\n`);
    process.exit(2);
  }
}
