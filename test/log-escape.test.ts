import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { formatLog, printable } from '../src/cli/log.js';
import type { AuditEvent } from '../src/core/audit.js';

const CLI = join(resolve(__dirname, '..'), 'dist', 'cli', 'main.js');
// C0, DEL, C1: none of these may reach the terminal raw.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
const ESC = '\x1b';
const evil = `${ESC}[2K${ESC}[1A\r\b\x07\x00\x7f\x9b31m\nline2`;

describe('printable', () => {
  it('escapes C0, DEL and C1 characters to a visible \\xNN form', () => {
    expect(printable(`a${ESC}[2Kb`)).toBe('a\\x1b[2Kb');
    expect(printable('a\nb\rc\td')).toBe('a\\x0ab\\x0dc\\x09d');
    expect(printable('\x7f\x9b\x85')).toBe('\\x7f\\x9b\\x85');
    expect(printable('plain é 漢 😀')).toBe('plain é 漢 😀');
  });
  it('escapes bidi overrides and line separators', () => {
    expect(printable('a‮b c⁦')).toBe('a\\u202eb\\u2028c\\u2066');
  });
  it('escapes invisible format characters (Unicode category Cf) and other invisibles', () => {
    // LRM, RLM, ALM, ZWSP, ZWNJ, ZWJ, word joiner, BOM, soft hyphen
    expect(printable('a\u200e\u200f\u061c\u200b\u200c\u200d\u2060\ufeff\u00adb')).toBe(
      'a\\u200e\\u200f\\u061c\\u200b\\u200c\\u200d\\u2060\\ufeff\\xadb',
    );
    // tag characters, a Hangul filler, a variation selector from the supplement, a lone surrogate
    expect(printable('x\u{e0041}\u{e007f}y')).toBe('x\\u{e0041}\\u{e007f}y');
    expect(printable('x\u3164\u{e0100}y')).toBe('x\\u3164\\u{e0100}y');
    expect(printable('lone \ud800 surrogate')).toBe('lone \\ud800 surrogate');
    expect(printable('\u2764\ufe0f ok')).toBe('\u2764\ufe0f ok');
  });
});

describe('formatLog never prints control characters', () => {
  const base: AuditEvent = { at: 'T1', who: `me${evil}`, leaseId: 'l', target: `t${evil}`, reason: `r${evil}`, tool: `query${evil}`, sql: `select '${evil}'`, allowed: true };
  it.each<[string, Partial<AuditEvent>]>([
    ['error', { error: `boom${evil}`, ms: 1 }],
    ['blockedReason', { allowed: false, blockedReason: `no${evil}` }],
    ['server line', { tool: 'server', sql: null, error: `crash${evil}` }],
    ['unfinished start', { phase: 'start', callId: 'c1' }],
    ['at', { at: `T${evil}` }],
  ])('%s', (_name, extra) => {
    const rows = formatLog([{ ...base, ...extra }]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).not.toMatch(CONTROL);
    expect(rows[0]).toContain('\\x1b[2K');
  });
});

describe('daypass status / log (CLI) never print control characters', () => {
  const run = async (home: string, ...args: string[]) =>
    promisify(execFile)('node', [CLI, ...args], { env: { ...process.env, DAYPASS_HOME: home } });

  it('status escapes the lease fields', async () => {
    const home = mkdtempSync(join(tmpdir(), 'daypass-esc-'));
    try {
      const lease = { id: `x${evil}`, target: `t${evil}`, reason: `r${evil}`, who: `w${evil}`, openedAt: '', expiresAt: new Date(Date.now() + 3600e3).toISOString() };
      writeFileSync(join(home, 'lease.json'), JSON.stringify(lease), { mode: 0o600 });
      const r = await run(home, 'status');
      expect(r.stdout.trimEnd()).not.toMatch(CONTROL);
      expect(r.stdout).toContain('\\x1b[2K');
      writeFileSync(join(home, 'lease.json'), JSON.stringify({ ...lease, expiresAt: `2000-01-01T00:00:00Z${evil}` }), { mode: 0o600 });
      const r2 = await run(home, 'status');
      expect(r2.stdout.trimEnd()).not.toMatch(CONTROL);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('log escapes the audit fields', async () => {
    const home = mkdtempSync(join(tmpdir(), 'daypass-esc-'));
    try {
      const line: AuditEvent = { at: 'T1', who: 'me', leaseId: 'l', target: 't', reason: 'r', tool: 'query', sql: `select '${evil}'`, allowed: true, error: `e${evil}` };
      writeFileSync(join(home, 'audit.jsonl'), JSON.stringify(line) + '\n', { mode: 0o600 });
      const r = await run(home, 'log');
      expect(r.stdout.trimEnd()).not.toMatch(CONTROL);
      expect(r.stdout).toContain('\\x1b[2K');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
