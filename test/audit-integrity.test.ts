import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { formatAudit } from '../src/core/audit.js';
import type { AuditEvent } from '../src/core/audit.js';

const ROOT = resolve(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli', 'main.js');
const home = mkdtempSync(join(tmpdir(), 'daypass-audit-'));
process.env.DAYPASS_HOME = home;
const AUDIT = join(home, 'audit.jsonl');
let state: typeof import('../src/mcp/state.js');

beforeAll(async () => {
  state = await import('../src/mcp/state.js');
});
afterAll(() => rmSync(home, { recursive: true, force: true }));

const ev = (extra: Partial<AuditEvent> = {}): AuditEvent => ({
  at: new Date().toISOString(), who: 'me', leaseId: 'l1', target: 't', reason: 'r', tool: 'query', sql: 'select 1', allowed: true, ...extra,
});

describe('formatAudit keeps every line well under 64 KiB', () => {
  it('caps a 256 KiB statement and records the full statement hash', () => {
    const sql = 'select ' + '\x01'.repeat(256 * 1024 - 7); // control chars: 6 bytes each once JSON-escaped
    const line = formatAudit(ev({ sql }));
    expect(line.endsWith('\n')).toBe(true);
    expect(Buffer.byteLength(line)).toBeLessThan(40 * 1024);
    const back = JSON.parse(line);
    expect(back.sqlSha256).toBe(createHash('sha256').update(sql, 'utf8').digest('hex'));
    expect(back.sql.startsWith('select \x01')).toBe(true);
    expect(back.sql).toMatch(/\[\+\d+ chars/);
  });
  it('leaves a short statement alone and adds no hash', () => {
    const back = JSON.parse(formatAudit(ev()));
    expect(back.sql).toBe('select 1');
    expect(back.sqlSha256).toBeUndefined();
  });
  it('caps every string field, even with all of them huge at once', () => {
    const big = '"\\\x02é😀'.repeat(200_000);
    const line = formatAudit(ev({ sql: big, who: big, target: big, reason: big, tool: big, blockedReason: big, error: big, leaseId: big, callId: big, at: big }));
    expect(Buffer.byteLength(line)).toBeLessThan(48 * 1024);
    const back = JSON.parse(line);
    for (const k of ['who', 'target', 'reason', 'tool', 'blockedReason', 'error', 'leaseId', 'callId', 'at', 'sql']) {
      expect(back[k], k).toMatch(/\[\+\d+ chars/);
      expect(back[k]).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/); // no split surrogate pair
    }
  });
});

describe('appendAudit / readAudit', () => {
  it('starts a new line when the file does not end with a newline', async () => {
    writeFileSync(AUDIT, '{"partial":', { mode: 0o600 });
    await state.appendAudit(ev({ sql: 'select 2' }));
    const lines = readFileSync(AUDIT, 'utf8').split('\n');
    expect(lines[0]).toBe('{"partial":');
    expect(JSON.parse(lines[1]).sql).toBe('select 2');
  });
  it('skips unparseable lines and counts them', async () => {
    writeFileSync(AUDIT, '', { mode: 0o600 });
    await state.appendAudit(ev({ sql: 'select 1' }));
    appendFileSync(AUDIT, 'garbage\n42\n\n');
    await state.appendAudit(ev({ sql: 'select 3' }));
    const r = await state.readAuditDetailed(10);
    expect(r.corrupt).toBe(2);
    expect(r.events.map((e) => e.sql)).toEqual(['select 1', 'select 3']);
    expect((await state.readAudit(10)).map((e) => e.sql)).toEqual(['select 1', 'select 3']);
  });
  it('daypass log warns about unreadable lines and still prints the rest', async () => {
    const r = await promisify(execFile)('node', [CLI, 'log'], { env: { ...process.env, DAYPASS_HOME: home } });
    expect(r.stdout).toMatch(/select 1/);
    expect(r.stdout).toMatch(/select 3/);
    expect(r.stderr).toMatch(/2 unreadable line/);
  });
  it('concurrent writers from several processes never interleave lines', async () => {
    writeFileSync(AUDIT, '', { mode: 0o600 });
    const script = `
      const { appendAudit } = await import(${JSON.stringify(join(ROOT, 'dist', 'mcp', 'state.js'))});
      const id = process.argv[1];
      await Promise.all(Array.from({ length: 40 }, (_, i) => appendAudit({ at: 'x', who: id, leaseId: null, target: 't', reason: null, tool: 'query', sql: id.repeat(200_000), allowed: true, callId: String(i) })));
    `;
    await Promise.all(['a', 'b', 'c', 'd'].map((id) => promisify(execFile)('node', ['--input-type=module', '-e', script, id], { env: { ...process.env, DAYPASS_HOME: home } })));
    const r = await state.readAuditDetailed(1000);
    expect(r.corrupt).toBe(0);
    expect(r.events).toHaveLength(160);
  }, 60_000);
});
