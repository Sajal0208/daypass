import { describe, it, expect } from 'vitest';
import { formatLog } from '../src/cli/log.js';
import type { AuditEvent } from '../src/core/audit.js';

const base = { who: 'me@host', leaseId: 'abcd1234', target: 'prod', reason: 'r', tool: 'query', sql: 'select 1', allowed: true } as const;
const ev = (at: string, extra: Partial<AuditEvent> = {}): AuditEvent => ({ ...base, at, ...extra });

describe('formatLog (daypass log)', () => {
  it('renders an old unphased line exactly as before', () => {
    expect(formatLog([ev('T1', { rows: 3, ms: 12 })])).toEqual(['T1 ok   me@host prod query 3r 12ms  select 1']);
    expect(formatLog([ev('T1', { allowed: false, blockedReason: 'Only SELECT' })])).toEqual(['T1 BLK  me@host prod query -r -ms  select 1  <- Only SELECT']);
    expect(formatLog([ev('T1', { error: 'boom', ms: 5 })])).toEqual(['T1 ERR  me@host prod query -r 5ms  select 1  <- boom']);
  });

  it('pairs start and end by callId into one row, at the start line, with the end line\'s result', () => {
    const rows = formatLog([
      ev('T1', { phase: 'start', callId: 'c1' }),
      ev('T2', { phase: 'start', callId: 'c2', sql: 'select 2' }),
      ev('T3', { phase: 'end', callId: 'c1', rows: 7, ms: 40 }),
      ev('T4', { phase: 'end', callId: 'c2', error: 'timeout', ms: 10000, sql: 'select 2' }),
    ]);
    expect(rows).toEqual([
      'T1 ok   me@host prod query 7r 40ms  select 1',
      'T2 ERR  me@host prod query -r 10000ms  select 2  <- timeout',
    ]);
  });

  it('shows a start with no end as unfinished, never as ok', () => {
    const rows = formatLog([ev('T1', { phase: 'start', callId: 'c9' })]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatch(/^T1 RUN  me@host prod query -r -ms  select 1  <- unfinished/);
    expect(rows[0]).not.toMatch(/ ok /);
  });

  it('shows an end whose start fell outside the window on its own', () => {
    expect(formatLog([ev('T3', { phase: 'end', callId: 'c1', rows: 1, ms: 2 })])).toEqual(['T3 ok   me@host prod query 1r 2ms  select 1']);
  });

  it('shows server lines distinctly', () => {
    expect(formatLog([ev('T5', { tool: 'server', sql: null, error: 'uncaught: EPIPE' })])).toEqual(['T5 SRV  me@host prod server  <- uncaught: EPIPE']);
    expect(formatLog([ev('T6', { tool: 'server', sql: null, target: '' })])).toEqual(['T6 SRV  me@host - server']);
  });

  it('keeps the last n rows after pairing', () => {
    const events = [
      ev('T1', { phase: 'start', callId: 'a' }), ev('T2', { phase: 'end', callId: 'a', rows: 1, ms: 1 }),
      ev('T3', { phase: 'start', callId: 'b' }), ev('T4', { phase: 'end', callId: 'b', rows: 2, ms: 2 }),
    ];
    expect(formatLog(events, 1)).toEqual(['T3 ok   me@host prod query 2r 2ms  select 1']);
  });
});

describe('daypass log (CLI)', () => {
  it('pairs start/end lines from the audit file', async () => {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join, resolve } = await import('node:path');
    const home = mkdtempSync(join(tmpdir(), 'daypass-log-'));
    try {
      const lines = [
        ev('T1', { phase: 'start', callId: 'c1' }),
        ev('T2', { phase: 'end', callId: 'c1', rows: 4, ms: 9 }),
        ev('T3', { phase: 'start', callId: 'c2', sql: 'select 2' }),
      ];
      writeFileSync(join(home, 'audit.jsonl'), lines.map((l) => JSON.stringify(l)).join('\n') + '\n');
      const cli = join(resolve(__dirname, '..'), 'dist', 'cli', 'main.js');
      const r = await promisify(execFile)('node', [cli, 'log', '-n', '5'], { env: { ...process.env, DAYPASS_HOME: home } });
      expect(r.stdout.trim().split('\n')).toEqual([
        'T1 ok   me@host prod query 4r 9ms  select 1',
        expect.stringMatching(/^T3 RUN  me@host prod query -r -ms  select 2  <- unfinished/),
      ]);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
