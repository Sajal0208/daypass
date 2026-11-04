// Lease file races, corrupt leases, and security-group revoke/sweep against a local fake EC2.
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { startFakeEc2, fakeAwsEnv, type FakeEc2 } from './helpers/fake-ec2.js';

const CLI = join(resolve(__dirname, '..'), 'dist', 'cli', 'main.js');
const home = mkdtempSync(join(tmpdir(), 'daypass-net-'));
process.env.DAYPASS_HOME = home;
let fake: FakeEc2;
let env: Record<string, string>;
let state: typeof import('../src/mcp/state.js');
let sg: typeof import('../src/mcp/sg.js');
let client: Client;

const LEASE = join(home, 'lease.json');
const past = '2000-01-01T00:00:00.000Z';
const future = () => new Date(Date.now() + 3600e3).toISOString();
const lease = (extra: Record<string, unknown> = {}) => ({ id: 'aaaa1111', target: 'prod', reason: 'r', who: 'me', openedAt: past, expiresAt: future(), ...extra });
const put = (l: object | string) => writeFileSync(LEASE, typeof l === 'string' ? l : JSON.stringify(l), { mode: 0o600 });
const config = (prod: Record<string, unknown>) =>
  writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: { prod: { host: 'db.invalid', database: 'd', user: 'u', ...prod }, dev: { url: 'postgres://u:p@db.invalid/d?sslmode=disable' } } }), { mode: 0o600 });
const cli = async (...args: string[]) => {
  try {
    const r = await promisify(execFile)('node', [CLI, ...args], { env: { ...process.env, ...env, DAYPASS_HOME: home } });
    return { code: 0, ...r };
  } catch (e: any) {
    return { code: e.code as number, stdout: e.stdout as string, stderr: e.stderr as string };
  }
};
const call = async (name: string, args: Record<string, unknown> = {}) => {
  const r: any = await client.callTool({ name, arguments: args });
  return { ok: !r.isError, text: r.content[0].text as string };
};

beforeAll(async () => {
  fake = await startFakeEc2();
  env = fakeAwsEnv(fake, home);
  Object.assign(process.env, env);
  delete process.env.AWS_PROFILE;
  state = await import('../src/mcp/state.js');
  sg = await import('../src/mcp/sg.js');
  const { buildServer } = await import('../src/mcp/server.js');
  const server = buildServer();
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  client = new Client({ name: 'net-test', version: '0' });
  await client.connect(ct);
});
afterAll(async () => {
  await client?.close();
  await fake?.close();
  rmSync(home, { recursive: true, force: true });
});
beforeEach(() => {
  fake.rules.length = 0;
  fake.calls.length = 0;
  fake.revokeDelayMs = 0;
});

describe('writeLease', () => {
  it('ifId: writes only while the lease on disk still has that id', async () => {
    put(lease({ id: 'newer000' }));
    expect(await state.writeLease(lease({ id: 'aaaa1111', reason: 'stale cleanup' }), { ifId: 'aaaa1111' })).toBe(false);
    expect(JSON.parse(readFileSync(LEASE, 'utf8')).id).toBe('newer000');
    expect(await state.writeLease(lease({ id: 'newer000', reason: 'ok' }), { ifId: 'newer000' })).toBe(true);
    expect(JSON.parse(readFileSync(LEASE, 'utf8')).reason).toBe('ok');
  });
  it('leaves no temp files behind', async () => {
    await state.writeLease(lease());
    expect(readFileSync(LEASE, 'utf8')).toContain('aaaa1111');
    const { readdirSync } = await import('node:fs');
    expect(readdirSync(home).filter((f) => f.endsWith('.tmp'))).toEqual([]);
  });
});

describe('expired-lease cleanup in the server never overwrites a newer lease', () => {
  it('a lease opened while the old rule is being revoked survives', async () => {
    config({ region: 'us-east-1', securityGroupId: 'sg-1' });
    fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: `daypass:aaaa1111 until ${past}` });
    put(lease({ expiresAt: past, sgRuleId: 'sgr-old', sgRegion: 'us-east-1', sgGroupId: 'sg-1' }));
    fake.revokeDelayMs = 800;
    const pending = call('query', { sql: 'select 1' });
    await new Promise((r) => setTimeout(r, 300));
    put(lease({ id: 'bbbb2222', target: 'dev', reason: 'new work' }));
    const r = await pending;
    expect(r.ok).toBe(false);
    expect(JSON.parse(readFileSync(LEASE, 'utf8'))).toMatchObject({ id: 'bbbb2222', reason: 'new work' });
    expect(fake.rules).toEqual([]);
  });
  it('without a race, the revoked rule id is dropped from the expired lease', async () => {
    config({ region: 'us-east-1', securityGroupId: 'sg-1' });
    fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: `daypass:aaaa1111 until ${past}` });
    put(lease({ expiresAt: past, sgRuleId: 'sgr-old', sgRegion: 'us-east-1', sgGroupId: 'sg-1' }));
    await call('query', { sql: 'select 1' });
    const now = JSON.parse(readFileSync(LEASE, 'utf8'));
    expect(now.id).toBe('aaaa1111');
    expect(now.sgRuleId).toBeUndefined();
  });
});

describe('expired-lease cleanup never holds up a call for long', () => {
  it('a slow AWS answer is left to finish in the background', async () => {
    const server = await import('../src/mcp/server.js');
    server.setNetworkReleaseWaitForTests(300);
    try {
      config({ region: 'us-east-1', securityGroupId: 'sg-1' });
      fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: `daypass:aaaa1111 until ${past}` });
      put(lease({ expiresAt: past, sgRuleId: 'sgr-old', sgRegion: 'us-east-1', sgGroupId: 'sg-1' }));
      fake.revokeDelayMs = 3000;
      const t0 = Date.now();
      const q = await call('query', { sql: 'select 1' });
      expect(q.text).toMatch(/expired/);
      expect(Date.now() - t0).toBeLessThan(2500);
    } finally {
      server.setNetworkReleaseWaitForTests(undefined);
      await new Promise((r) => setTimeout(r, 3200)); // let the background revoke finish before the next test
    }
  }, 15_000);
});

describe('a corrupt lease.json', () => {
  it.each(['{"id": "x", "tar', '[]', '{"id": 5}'])('MCP tools say so clearly: %s', async (bad) => {
    put(bad);
    for (const tool of ['query', 'daypass_status', 'list_tables']) {
      const r = await call(tool, tool === 'query' ? { sql: 'select 1' } : {});
      expect(r.ok, tool).toBe(false);
      expect(r.text).toMatch(/lease file .* is corrupt.*daypass close/);
    }
  });
  it('daypass status explains it and exits 1; daypass close removes it', async () => {
    put('{"id": "x", "tar');
    const s = await cli('status');
    expect(s.code).toBe(1);
    expect(s.stderr).toMatch(/corrupt.*daypass close/);
    const c = await cli('close');
    expect(c.code).toBe(0);
    expect(c.stdout + c.stderr).toMatch(/corrupt lease file/i);
    expect(existsSync(LEASE)).toBe(false);
  });
});

describe('revoking a lease rule uses what the lease recorded', () => {
  it('revokes in the recorded group even after the config changed', async () => {
    fake.rules.push({ id: 'sgr-1', groupId: 'sg-old', description: `daypass:aaaa1111 until ${past}` });
    const r = await sg.revokeLeaseRule(lease({ sgRuleId: 'sgr-1', sgRegion: 'us-east-1', sgGroupId: 'sg-old' }) as any, { region: 'us-west-2', securityGroupId: 'sg-new' });
    expect(r).toEqual({ revoked: true });
    expect(fake.calls.at(-1)).toMatchObject({ Action: 'RevokeSecurityGroupIngress', GroupId: 'sg-old', 'SecurityGroupRuleId.1': 'sgr-1' });
    expect(fake.rules).toEqual([]);
  });
  it('a rule already gone from the recorded group counts as revoked', async () => {
    const r = await sg.revokeLeaseRule(lease({ sgRuleId: 'sgr-gone', sgRegion: 'us-east-1', sgGroupId: 'sg-old' }) as any, undefined);
    expect(r).toEqual({ revoked: true });
  });
  it('an older lease falls back to the config, and a not-found rule there is a warning, not success', async () => {
    const r = await sg.revokeLeaseRule(lease({ sgRuleId: 'sgr-1' }) as any, { region: 'us-east-1', securityGroupId: 'sg-new' });
    expect(r.revoked).toBe(false);
    expect(r.warning).toMatch(/sgr-1.*not found.*sg-new/);
  });
  it('refuses to revoke a rule that daypass did not create for this lease', async () => {
    for (const description of ['office VPN', 'daypass:bbbb2222 until 2000-01-01T00:00:00.000Z', 'daypass:aaaa1111 until soon']) {
      fake.rules.length = 0;
      fake.rules.push({ id: 'sgr-1', groupId: 'sg-old', description });
      const r = await sg.revokeLeaseRule(lease({ sgRuleId: 'sgr-1', sgRegion: 'us-east-1', sgGroupId: 'sg-old' }) as any, undefined);
      expect(r.revoked, description).toBe(false);
      expect(r.warning).toMatch(/sgr-1.*NOT revoked/);
      expect(fake.rules).toHaveLength(1);
      expect(fake.calls.some((c) => c.Action === 'RevokeSecurityGroupIngress')).toBe(false);
    }
  });
  it('refuses the config fallback too when the rule is not this lease\'s', async () => {
    fake.rules.push({ id: 'sgr-1', groupId: 'sg-new', description: 'office VPN' });
    const r = await sg.revokeLeaseRule(lease({ sgRuleId: 'sgr-1' }) as any, { region: 'us-east-1', securityGroupId: 'sg-new' });
    expect(r.revoked).toBe(false);
    expect(fake.rules).toHaveLength(1);
  });
  it('refuses a malformed recorded region, group or rule id without calling AWS', async () => {
    for (const bad of [{ sgRegion: 'evil.example.com/x' }, { sgGroupId: 'sg-1 x' }, { sgRuleId: '../sgr-1' }, { id: 'not-hex!' }]) {
      fake.calls.length = 0;
      const r = await sg.revokeLeaseRule(lease({ sgRuleId: 'sgr-1', sgRegion: 'us-east-1', sgGroupId: 'sg-old', ...bad }) as any, undefined);
      expect(r.revoked, JSON.stringify(bad)).toBe(false);
      expect(r.warning).toMatch(/NOT revoked/);
      expect(fake.calls).toEqual([]);
    }
  });
  it('daypass close leaves a rule that is not this lease\'s alone and says so', async () => {
    config({ region: 'us-east-1', securityGroupId: 'sg-old' });
    fake.rules.push({ id: 'sgr-1', groupId: 'sg-old', description: 'office VPN' });
    put(lease({ sgRuleId: 'sgr-1', sgRegion: 'us-east-1', sgGroupId: 'sg-old' }));
    const c = await cli('close');
    expect(c.code, c.stderr).toBe(0);
    expect(c.stderr).toMatch(/sgr-1.*NOT revoked/);
    expect(fake.rules).toHaveLength(1);
    expect(existsSync(LEASE)).toBe(false);
  });
  it('no region/group anywhere: a warning', async () => {
    const r = await sg.revokeLeaseRule(lease({ sgRuleId: 'sgr-1' }) as any, {});
    expect(r.revoked).toBe(false);
    expect(r.warning).toMatch(/NOT revoked/);
  });
  it('daypass close revokes in the recorded group, not the current config', async () => {
    config({ region: 'us-east-1', securityGroupId: 'sg-new' });
    fake.rules.push({ id: 'sgr-1', groupId: 'sg-old', description: `daypass:aaaa1111 until ${past}` });
    put(lease({ sgRuleId: 'sgr-1', sgRegion: 'us-east-1', sgGroupId: 'sg-old' }));
    const c = await cli('close');
    expect(c.code, c.stderr).toBe(0);
    expect(c.stdout).toMatch(/Removed security-group rule sgr-1/);
    expect(fake.rules).toEqual([]);
    expect(existsSync(LEASE)).toBe(false);
  });
  it('daypass close on an older lease whose rule is not in the configured group warns', async () => {
    config({ region: 'us-east-1', securityGroupId: 'sg-new' });
    put(lease({ sgRuleId: 'sgr-1' }));
    const c = await cli('close');
    expect(c.code).toBe(0);
    expect(c.stderr).toMatch(/sgr-1.*not found/);
  });
});

describe('daypass open', () => {
  it('exits non-zero when a lease is already open, and leaves it alone', async () => {
    config({});
    put(lease({ id: 'live0000', target: 'dev' }));
    const r = await cli('open', 'dev', '-r', 'again', '--no-network');
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/already open.*daypass close/);
    expect(JSON.parse(readFileSync(LEASE, 'utf8')).id).toBe('live0000');
  });
});

describe('sweep only removes rules daypass made', () => {
  it('matches the exact daypass:<8 hex> until <ISO> shape', async () => {
    const mk = (id: string, description: string, egress = false) => fake.rules.push({ id, groupId: 'sg-1', description, egress });
    mk('sgr-expired', `daypass:abcd1234 until ${past}`);
    mk('sgr-expired-nofrac', 'daypass:abcd1234 until 2000-01-01T00:00:00Z');
    mk('sgr-live', `daypass:abcd1234 until 2999-01-01T00:00:00.000Z`);
    mk('sgr-note', 'daypass: office VPN');
    mk('sgr-garbage', 'daypass:abcd1234 until soon');
    mk('sgr-suffix', `daypass:abcd1234 until ${past} (bastion)`);
    mk('sgr-upper', `daypass:ABCD1234 until ${past}`);
    mk('sgr-long', `daypass:abcd12345 until ${past}`);
    mk('sgr-egress', `daypass:abcd1234 until ${past}`, true);
    const removed = await sg.sweepExpired({ region: 'us-east-1', groupId: 'sg-1' });
    expect(removed.sort()).toEqual(['sgr-expired', 'sgr-expired-nofrac']);
    expect(fake.rules.map((r) => r.id).sort()).toEqual(['sgr-egress', 'sgr-garbage', 'sgr-live', 'sgr-long', 'sgr-note', 'sgr-suffix', 'sgr-upper']);
  });
});
