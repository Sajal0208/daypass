import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decideTool } from '../plugin/hooks/state-guard.mjs';

const HOME = '/home/me';
const env = { HOME };
const bash = (command: string) => decideTool({ tool_name: 'Bash', tool_input: { command }, cwd: '/work' }, env);
const blocked = (command: string) => expect(bash(command).allow, command).toBe(false);
const allowed = (command: string) => expect(bash(command), command).toEqual({ allow: true });

describe('state guard: Bash', () => {
  it('blocks starting the MCP server or opening a lease from Bash', () => {
    for (const c of ['daypass mcp', 'npx daypass mcp', 'npx -y daypass@latest mcp', '/usr/local/bin/daypass mcp < /dev/null', 'echo hi && daypass open prod --ttl 8h --reason x', '(daypass open prod -r x)', 'X=1 daypass mcp', '"daypass" mcp']) {
      blocked(c);
    }
    const r = bash('daypass open prod -r x');
    expect(r.allow).toBe(false);
    if (!r.allow) expect(r.reason).toMatch(/fence against mistakes, not a wall/);
  });
  it('allows the read-only daypass commands', () => {
    for (const c of ['daypass status', 'daypass log -n 20', 'daypass doctor prod', 'daypass close', 'daypass hidden suggest --prisma prisma/schema.prisma', 'daypass sql --hide-file hidden-columns.txt', 'git log --oneline', 'grep -rn "daypass mcp" docs/']) {
      allowed(c);
    }
  });
  it('blocks reading or writing the state files directly', () => {
    for (const c of [
      'cat ~/.daypass/config.json', 'cat $HOME/.daypass/lease.json', 'cat "${HOME}/.daypass/config.json"',
      'cat /home/me/.daypass/config.json', 'echo {} > ~/.daypass/lease.json', 'tail -n 5 ~/.daypass/audit.jsonl',
      'cd ~/.daypass && ls', 'cat $DAYPASS_HOME/config.json', 'cat "${DAYPASS_HOME}/lease.json"', 'ls ~/.daypass',
      "echo '!users.email' >> ~/.daypass/hidden-columns.txt", 'daypass hidden suggest --live prod > ~/.daypass/hidden-columns.txt',
      'cp list.txt ~/.daypass/hidden-columns.txt', 'tee -a "$DAYPASS_HIDDEN_FILE" < x', 'sed -i s/a/b/ ~/.daypass/hidden-columns.txt',
      'cat ~/.daypass/hidden-columns.txt',
    ]) {
      blocked(c);
    }
  });
  it('allows the daypass CLI to read the hidden list', () => {
    allowed('daypass hidden check --file "${DAYPASS_HIDDEN_FILE:-$HOME/.daypass/hidden-columns.txt}" --live "prod"');
    allowed('daypass hidden check --file ~/.daypass/hidden-columns.txt --live prod 2>&1');
    allowed('daypass doctor prod --hide-file ~/.daypass/hidden-columns.txt');
  });
  it('blocks (fails closed) when tool_input has no string command', () => {
    expect(decideTool({ tool_name: 'Bash', tool_input: {} }, env).allow).toBe(false);
  });
});

describe('state guard: Bash, spelled differently', () => {
  it('matches the program and the state directory case-insensitively', () => {
    for (const c of ['cat ~/.DAYPASS/config.json', 'cat $HOME/.DayPass/lease.json', 'DAYPASS mcp', 'Daypass open prod -r x', 'cat $daypass_home/config.json']) blocked(c);
  });
  it('strips quotes and backslashes before matching', () => {
    for (const c of ['da\\ypass mcp', "d'ay'pass mcp", 'daypass "mcp"', "cat ~/'.day'pass/config.json", 'cat ~/.day\\pass/config.json', 'cat ~/".daypass"/lease.json']) blocked(c);
  });
  it('sees through the common wrappers and their options', () => {
    for (const c of [
      '$(which daypass) mcp', '`which daypass` mcp', '$(command -v daypass) mcp',
      'sh -c "daypass mcp"', "bash -lc 'daypass open prod -r x'", 'zsh -c "cd /tmp; daypass mcp"', '/bin/sh -c daypass\\ mcp',
      'timeout 60 daypass mcp', 'timeout -s KILL 60s daypass mcp', 'timeout --signal=KILL 60 daypass mcp',
      'nice daypass mcp', 'nice -n 10 daypass mcp', 'nohup daypass mcp &', 'ionice -c 3 daypass mcp', 'stdbuf -o L daypass mcp',
      'echo mcp | xargs daypass', 'xargs -n 1 daypass < subs.txt', 'xargs -I {} daypass {} prod',
      'npx -p daypass daypass mcp', 'npx --package daypass daypass mcp', 'npx --package=daypass@1 daypass mcp', 'npx -c "daypass mcp"',
      'pnpm dlx daypass mcp', 'bunx daypass mcp', 'bun x daypass mcp', 'npm exec -- daypass mcp',
      'sudo -u me daypass mcp', 'sudo -E -u me -- daypass mcp', 'sudo --user=me daypass open prod -r x', 'doas -u me daypass mcp',
      'env -u FOO BAR=1 daypass mcp', 'command daypass mcp', 'exec -a x daypass mcp', 'time -p daypass mcp',
      'if daypass mcp; then :; fi', '{ daypass mcp; }', '! daypass mcp', 'daypass $SUB prod',
    ]) {
      blocked(c);
    }
  });
  it('treats a glob or brace that can reach the state directory as naming it', () => {
    for (const c of [
      'cat ~/.d*pass/config.json', 'tar c -C ~ .d?ypass | tar x -C /tmp/x', 'cat ~/.[d]aypass/config.json', 'cat ~/.daypa*/lease.json',
      'cat ~/.DAY*/lease.json', 'cat ~/.{daypass,x}/config.json', 'cat ~/.{day,x}pass/config.json',
      'daypass hidden check --file {~/.daypass/config.json,~/.daypass/hidden-columns.txt}',
      'daypass hidden check --file ~/.daypass/{config.json,hidden-columns.txt}',
    ]) {
      blocked(c);
    }
  });
  it('still lets ordinary commands through', () => {
    for (const c of [
      'git status', 'npm test', 'npm run build && node dist/cli/main.js status', 'grep -rn daypass src/', 'grep -rni "DAYPASS MCP" docs/',
      'ls ~/.daypass-backup', 'echo $DAYPASS_HOME_URL', 'ls -la ~/.config/*', 'du -sh ~/.*', 'ls -d .[!.]*', 'cat ~/.bashrc',
      'find . -name "*.ts" | xargs grep -l daypass', 'timeout 60 npm test', 'sh -c "npm test"', 'sudo -u me ls /tmp',
      'npx -p typescript tsc --noEmit', 'xargs daypass status < /dev/null', 'command -v daypass', 'which daypass',
      'echo {a,b}.txt', 'git commit -m "docs: say how daypass open works"', 'daypass hidden check --file ~/.daypass/hidden-columns.txt',
    ]) {
      allowed(c);
    }
  });
});

describe('state guard: file tools', () => {
  const file = (tool_name: string, tool_input: Record<string, unknown>, e: Record<string, string> = env) => decideTool({ tool_name, tool_input, cwd: '/work' }, e);
  it('blocks Write, Edit, MultiEdit and NotebookEdit under the state directory', () => {
    for (const [tool, input] of [
      ['Write', { file_path: '/home/me/.daypass/lease.json', content: '{}' }],
      ['Edit', { file_path: '~/.daypass/hidden-columns.txt', old_string: 'a', new_string: 'b' }],
      ['MultiEdit', { file_path: '/home/me/.daypass/config.json', edits: [] }],
      ['NotebookEdit', { notebook_path: '/home/me/.daypass/x.ipynb', new_source: '' }],
      ['Write', { file_path: '/home/me/.daypass/../.daypass/new.txt', content: '' }],
      ['Write', { file_path: '/other/home/.daypass/lease.json', content: '' }],
    ] as const) {
      expect(file(tool, input).allow, `${tool} ${JSON.stringify(input)}`).toBe(false);
    }
    expect(file('Write', { file_path: '/custom/state/lease.json', content: '' }, { HOME, DAYPASS_HOME: '/custom/state' }).allow).toBe(false);
    expect(file('Write', { file_path: '/elsewhere/list.txt', content: '' }, { HOME, DAYPASS_HIDDEN_FILE: '/elsewhere/list.txt' }).allow).toBe(false);
  });
  it('blocks reading config.json and lease.json, and searching the state directory', () => {
    expect(file('Read', { file_path: '/home/me/.daypass/config.json' }).allow).toBe(false);
    expect(file('Read', { file_path: '~/.daypass/lease.json' }).allow).toBe(false);
    expect(file('Grep', { pattern: 'url', path: '/home/me/.daypass' }).allow).toBe(false);
    expect(file('Glob', { pattern: '*', path: '~/.daypass' }).allow).toBe(false);
  });
  it('allows reading the hidden list and the audit log, and anything outside the state directory', () => {
    expect(file('Read', { file_path: '/home/me/.daypass/hidden-columns.txt' })).toEqual({ allow: true });
    expect(file('Read', { file_path: '/home/me/.daypass/audit.jsonl' })).toEqual({ allow: true });
    expect(file('Write', { file_path: '/work/src/a.ts', content: '' })).toEqual({ allow: true });
    expect(file('Write', { file_path: 'notes/.daypass-plan.md', content: '' })).toEqual({ allow: true });
    expect(file('Grep', { pattern: 'x' })).toEqual({ allow: true });
  });
  it('compares state paths case-insensitively (macOS and Windows file systems)', () => {
    expect(file('Read', { file_path: '/home/me/.DAYPASS/config.json' }).allow).toBe(false);
    expect(file('Write', { file_path: '/home/me/.DayPass/lease.json', content: '{}' }).allow).toBe(false);
    expect(file('Write', { file_path: '/Custom/STATE/lease.json', content: '' }, { HOME, DAYPASS_HOME: '/custom/state' }).allow).toBe(false);
    expect(file('Read', { file_path: '/custom/state/Config.JSON' }, { HOME, DAYPASS_HOME: '/custom/state' }).allow).toBe(false);
    expect(file('Write', { file_path: '/Elsewhere/List.txt', content: '' }, { HOME, DAYPASS_HIDDEN_FILE: '/elsewhere/list.txt' }).allow).toBe(false);
  });
  it('checks the Grep glob and the Glob pattern, not only the path', () => {
    for (const [tool, input] of [
      ['Grep', { pattern: 'password', path: HOME, glob: '.daypass/*' }],
      ['Grep', { pattern: 'password', path: HOME, glob: '**/.DAYPASS/**' }],
      ['Grep', { pattern: 'password', path: HOME, glob: '.{daypass,x}/*' }],
      ['Glob', { pattern: '.daypass/*', path: HOME }],
      ['Glob', { pattern: '.d*/*.json', path: HOME }],
      ['Glob', { pattern: '.*/config.json', path: HOME }],
      ['Glob', { pattern: '**/.daypass/*' }],
      ['Glob', { pattern: '/home/me/.daypass/*' }],
      ['Glob', { pattern: '/home/me/.d?ypass/*', path: '/work' }],
      ['Glob', { pattern: '../home/me/.daypass/*', path: '/work' }],
      ['Glob', { pattern: '~/.daypass/*' }],
      ['Glob', { pattern: 'me/.d*/*', path: '/home' }],
    ] as const) {
      expect(file(tool, input).allow, `${tool} ${JSON.stringify(input)}`).toBe(false);
    }
    for (const [tool, input] of [
      ['Glob', { pattern: '**/*.ts' }],
      ['Glob', { pattern: '.*', path: '/work' }],
      ['Glob', { pattern: '*.md', path: HOME }],
      ['Glob', { pattern: '.config/**/*.json', path: HOME }],
      ['Grep', { pattern: 'x', glob: '*.{ts,tsx}' }],
      ['Grep', { pattern: 'x', path: HOME, glob: '*.json' }],
    ] as const) {
      expect(file(tool, input), `${tool} ${JSON.stringify(input)}`).toEqual({ allow: true });
    }
  });
  it('follows a symlink into the state directory', () => {
    const d = mkdtempSync(join(tmpdir(), 'daypass-state-'));
    try {
      const state = join(d, 'state');
      mkdirSync(state);
      writeFileSync(join(state, 'lease.json'), '{}');
      symlinkSync(join(state, 'lease.json'), join(d, 'link.json'));
      expect(file('Write', { file_path: join(d, 'link.json'), content: '' }, { HOME, DAYPASS_HOME: state }).allow).toBe(false);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});

describe('state guard: Monitor', () => {
  // Monitor runs a shell command like Bash does (the same command string, each stdout line an event).
  const monitor = (command: unknown) => decideTool({ tool_name: 'Monitor', tool_input: { command }, cwd: '/work' }, env);
  it('checks the Monitor command like a Bash command', () => {
    for (const c of ['cat ~/.daypass/config.json', 'daypass mcp', 'daypass open prod -r x', 'tail -f $HOME/.daypass/audit.jsonl']) {
      expect(monitor(c).allow, c).toBe(false);
    }
    expect(monitor('tail -f app.log')).toEqual({ allow: true });
  });
  it('blocks a Monitor call without a string command', () => {
    expect(monitor(undefined).allow).toBe(false);
    expect(monitor(42).allow).toBe(false);
  });
});

describe('state guard: end to end and hooks.json', () => {
  const run = (stdin: string) => spawnSync('node', ['plugin/hooks/state-guard.mjs'], { input: stdin, encoding: 'utf8', env: { ...process.env, HOME } });
  it('exits 2 with the reason on stderr, 0 otherwise', () => {
    const r = run(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'daypass mcp' } }));
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/^Daypass state guard: /);
    expect(run(JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' } })).status).toBe(0);
    expect(run('not json').status).toBe(2);
  });
  it('is registered for Bash and the file tools, failing closed', () => {
    const cfg = JSON.parse(readFileSync('plugin/hooks/hooks.json', 'utf8'));
    const entry = cfg.hooks.PreToolUse.find((e: any) => e.hooks[0].args[0].endsWith('state-guard.mjs'));
    expect(entry.hooks[0].onFailure).toBe('block');
    const re = new RegExp(entry.matcher);
    for (const n of ['Bash', 'Monitor', 'Read', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'Grep', 'Glob']) expect(re.test(n), n).toBe(true);
    for (const n of ['WebFetch', 'mcp__daypass__query', 'BashOutput']) expect(re.test(n), n).toBe(false);
  });
});
