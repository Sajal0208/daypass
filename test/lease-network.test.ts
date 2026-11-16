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
const cli = (...args: string[]) => cliWith({}, ...args);
const cliWith = async (extra: Record<string, string>, ...args: string[]) => {
  try {
    const r = await promisify(execFile)('node', [CLI, ...args], { env: { ...process.env, ...env, DAYPASS_HOME: home, ...extra } });
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
  fake.authorizeDelayMs = 0;
  fake.failStatus = undefined;
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
  it('two targets: an expired lease on prod gives up its rule; the live dev lease is untouched', async () => {
    config({ region: 'us-east-1', securityGroupId: 'sg-1' });
    fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: `daypass:aaaa1111 until ${past}` });
    put({ version: 2, leases: [
      lease({ expiresAt: past, sgRuleId: 'sgr-old', sgRegion: 'us-east-1', sgGroupId: 'sg-1' }),
      lease({ id: 'bbbb2222', target: 'dev' }),
    ] });
    await call('query', { sql: 'select 1', target: 'dev' });
    expect(fake.rules).toEqual([]);
    const now = JSON.parse(readFileSync(LEASE, 'utf8'));
    expect(now.version).toBe(2);
    expect(now.leases.find((l: any) => l.target === 'prod').sgRuleId).toBeUndefined();
    expect(now.leases.find((l: any) => l.target === 'dev').id).toBe('bbbb2222');
  });
});

describe('several leases, no database', () => {
  const two = () => put({ version: 2, leases: [lease({ target: 'prod' }), lease({ id: 'bbbb2222', target: 'dev' })] });
  it('a tool with no target refuses and names both', async () => {
    config({}); two();
    const r = await call('query', { sql: 'select 1' });
    expect(r.ok).toBe(false);
    expect(r.text).toMatch(/2 leases are open \(prod, dev\)/);
  });
  it('a target with no lease says which are open', async () => {
    config({}); two();
    const r = await call('list_tables', { target: 'nope' });
    expect(r.text).toMatch(/No lease on "nope".*Open: prod, dev/);
  });
  it('daypass_status lists every lease and ends with the target hint', async () => {
    two();
    const r = await call('daypass_status');
    expect(r.text).toMatch(/Lease aaaa1111 on "prod"/);
    expect(r.text).toMatch(/Lease bbbb2222 on "dev"/);
    expect(r.text).toMatch(/Pass target: "prod" or "dev"/);
  });
  it('daypass_status with one expired lease keeps the 0.2.0 text', async () => {
    put(lease({ expiresAt: past }));
    expect((await call('daypass_status')).text).toBe(`Expired at ${past}`);
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
    expect(r.stderr).toMatch(/already open on "dev".*daypass close dev/);
    expect(JSON.parse(readFileSync(LEASE, 'utf8')).id).toBe('live0000');
  });

  it('two targets: both open, status lists both, close <t> closes one, close closes all', async () => {
    config({});
    writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: {
      a: { url: 'postgres://u:p@db.invalid/a?sslmode=disable' },
      b: { url: 'postgres://u:p@db.invalid/b?sslmode=disable' },
    } }), { mode: 0o600 });
    rmSync(LEASE, { force: true });
    expect((await cli('open', 'a', '-r', 'x', '--no-network')).code).toBe(0);
    expect((await cli('open', 'b', '-r', 'y', '--no-network')).code).toBe(0);
    const s = await cli('status');
    expect(s.stdout).toMatch(/on "a"/);
    expect(s.stdout).toMatch(/on "b"/);
    const c1 = await cli('close', 'b');
    expect(c1.stdout).toMatch(/closed/);
    expect(JSON.parse(readFileSync(LEASE, 'utf8')).target).toBe('a');   // back to the 0.2.0 shape
    expect((await cli('close', 'b')).stdout).toMatch(/No lease on "b"/);
    expect((await cli('open', 'b', '-r', 'y', '--no-network')).code).toBe(0);
    const c2 = await cli('close');
    expect(c2.stdout.match(/closed/g)).toHaveLength(2);
    expect(existsSync(LEASE)).toBe(false);
  }, 20_000); // five CLI spawns; the node 20 CI runner took over 5 s twice

  it('refuses a second target behind the same security group and port, before touching AWS', async () => {
    writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: {
      prod: { host: 'db.invalid', database: 'd', user: 'u', region: 'us-east-1', securityGroupId: 'sg-1' },
      prod2: { host: 'db.invalid', database: 'd2', user: 'u', region: 'us-east-1', securityGroupId: 'sg-1' },
    } }), { mode: 0o600 });
    put(lease({ sgRuleId: 'sgr-a', sgRegion: 'us-east-1', sgGroupId: 'sg-1', sgPort: 5432 }));
    fake.calls.length = 0;
    const r = await cli('open', 'prod2', '-r', 'x');
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/same security-group rule as the live lease on "prod"/);
    expect(fake.calls.filter((c) => c.Action === 'AuthorizeSecurityGroupIngress')).toEqual([]);
    expect(JSON.parse(readFileSync(LEASE, 'utf8')).target).toBe('prod');
  });

  it('sweep <target> with a corrupt lease file: sweeps AWS, then says the file is corrupt and exits 1', async () => {
    config({ region: 'us-east-1', securityGroupId: 'sg-1' });
    fake.rules.push({ id: 'sgr-x', groupId: 'sg-1', description: `daypass:abcd1234 until ${past}` });
    put('{nope');
    const r = await cli('sweep', 'prod');
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/Removed 1 expired rule/);
    expect(r.stderr).toMatch(/corrupt.*daypass close/);
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

describe('review fixes (PR #29): close, open and sweep with several leases', () => {
  const STUB_IP = join(resolve(__dirname), 'helpers', 'stub-ip.mjs');
  const twoTargets = () =>
    writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: {
      prod: { host: 'db.invalid', database: 'd', user: 'u', region: 'us-east-1', securityGroupId: 'sg-1' },
      dev: { url: 'postgres://u:p@db.invalid/d?sslmode=disable' },
    } }), { mode: 0o600 });

  it('close with no target: AWS failing on one lease still closes the others, and exits 1', async () => {
    twoTargets();
    put({ version: 2, leases: [
      lease({ sgRuleId: 'sgr-a', sgRegion: 'us-east-1', sgGroupId: 'sg-1' }),
      lease({ id: 'bbbb2222', target: 'dev' }),
    ] });
    const r = await cliWith({ AWS_ENDPOINT_URL_EC2: 'http://127.0.0.1:1' }, 'close');
    expect(r.code).toBe(1);
    expect(r.stdout).toMatch(/Lease bbbb2222 closed/);
    expect(r.stderr).toMatch(/aaaa1111 on "prod" was NOT closed/);
    const left = JSON.parse(readFileSync(LEASE, 'utf8'));
    expect(left.target).toBe('prod');
  });

  it('open: a close while the rule is being created wins; the new rule is revoked', async () => {
    twoTargets();
    rmSync(LEASE, { force: true });
    fake.authorizeDelayMs = 1500;
    const opening = cliWith({ NODE_OPTIONS: `--import=${STUB_IP}` }, 'open', 'prod', '-r', 'x');
    for (let i = 0; i < 100 && !(existsSync(LEASE) && readFileSync(LEASE, 'utf8').includes('sgGroupId')); i++) await new Promise((r) => setTimeout(r, 20));
    expect((await cli('close', 'prod')).code).toBe(0);
    const r = await opening;
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/closed while daypass open was running/);
    expect(fake.rules).toEqual([]);
    expect(existsSync(LEASE)).toBe(false);
  });

  it('open refuses a target whose rule an expired, unrevoked lease still holds', async () => {
    writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: {
      prod: { host: 'db.invalid', database: 'd', user: 'u', region: 'us-east-1', securityGroupId: 'sg-1' },
      prod2: { host: 'db.invalid', database: 'd2', user: 'u', region: 'us-east-1', securityGroupId: 'sg-1' },
    } }), { mode: 0o600 });
    put(lease({ expiresAt: past, sgRuleId: 'sgr-a', sgRegion: 'us-east-1', sgGroupId: 'sg-1', sgPort: 5432 }));
    fake.calls.length = 0;
    const r = await cli('open', 'prod2', '-r', 'x');
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/expired lease on "prod" still holds that rule.*daypass close prod/);
    expect(fake.calls.filter((c) => c.Action === 'AuthorizeSecurityGroupIngress')).toEqual([]);
  });

  it('sweep keeps an expired lease whose rule is in another group than the one it swept', async () => {
    twoTargets();
    put(lease({ expiresAt: past, sgRuleId: 'sgr-z', sgRegion: 'us-east-1', sgGroupId: 'sg-old' }));
    const r = await cli('sweep', 'prod');
    expect(r.code).toBe(0);
    expect(JSON.parse(readFileSync(LEASE, 'utf8')).id).toBe('aaaa1111');
    expect(r.stderr).toMatch(/sg-old.*daypass close prod/);
  });

  it('close on an older lease whose target left the config does not point at sweep', async () => {
    twoTargets();
    put(lease({ target: 'gone', sgRuleId: 'sgr-q' }));
    const r = await cli('close', 'gone');
    expect(r.stderr).toMatch(/not in the config/);
    expect(r.stderr).not.toMatch(/Run: daypass sweep gone/);
  });

  it('close with no target on a corrupt file says every lease was removed and live rules stay until they expire', async () => {
    put('{nope');
    const r = await cli('close');
    expect(r.stderr).toMatch(/every lease/);
    expect(r.stderr).toMatch(/until they expire/);
    expect(existsSync(LEASE)).toBe(false);
  });

  it('close <target> on a corrupt file refuses, keeps the file, and points at bare daypass close', async () => {
    put('{nope');
    const r = await cli('close', 'prod');
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/corrupt.*Run: daypass close/);
    expect(r.stderr).not.toMatch(/every lease/);
    expect(readFileSync(LEASE, 'utf8')).toBe('{nope');
  });
});

describe('review fixes (PR #29): the MCP server with several leases', () => {
  // An expired lease whose rule cannot be revoked (someone else's description, or AWS failing)
  // must not cost two AWS calls on every tool call made on the other, live lease.
  const expiredAndLive = () => {
    config({ region: 'us-east-1', securityGroupId: 'sg-1' });
    put({ version: 2, leases: [
      lease({ expiresAt: past, sgRuleId: 'sgr-old', sgRegion: 'us-east-1', sgGroupId: 'sg-1' }),
      lease({ id: 'bbbb2222', target: 'dev' }),
    ] });
  };
  const awsCalls = () => fake.calls.filter((c) => c.Action === 'DescribeSecurityGroupRules' || c.Action === 'RevokeSecurityGroupIngress').length;

  it('a revoke that found another rule in its place is not retried on every tool call', async () => {
    const server = await import('../src/mcp/server.js');
    server.resetNetworkReleaseForTests();
    expiredAndLive();
    fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: 'not ours' });
    for (let i = 0; i < 5; i++) await call('list_tables', { target: 'dev' });
    await new Promise((r) => setTimeout(r, 100));
    expect(awsCalls()).toBe(1);
    expect(fake.rules).toHaveLength(1);
  });

  it('a revoke that failed at AWS is not retried on every tool call', async () => {
    const server = await import('../src/mcp/server.js');
    server.resetNetworkReleaseForTests();
    expiredAndLive();
    fake.failStatus = 403;
    for (let i = 0; i < 5; i++) await call('list_tables', { target: 'dev' });
    await new Promise((r) => setTimeout(r, 100));
    expect(awsCalls()).toBe(1);
  });

  it('concurrent tool calls share one revoke of the same expired lease', async () => {
    const server = await import('../src/mcp/server.js');
    server.resetNetworkReleaseForTests();
    expiredAndLive();
    fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: `daypass:aaaa1111 until ${past}` });
    fake.revokeDelayMs = 200;
    await Promise.all([1, 2, 3, 4].map(() => call('list_tables', { target: 'dev' })));
    await new Promise((r) => setTimeout(r, 400));
    expect(fake.rules).toEqual([]);
    expect(fake.calls.filter((c) => c.Action === 'RevokeSecurityGroupIngress')).toHaveLength(1);
  });

  it('after the retry window a failed revoke is tried again', async () => {
    const server = await import('../src/mcp/server.js');
    server.resetNetworkReleaseForTests(50);
    try {
      expiredAndLive();
      fake.failStatus = 403;
      await call('list_tables', { target: 'dev' });
      await new Promise((r) => setTimeout(r, 100));
      expect(awsCalls()).toBe(1);
      fake.failStatus = undefined;
      fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: `daypass:aaaa1111 until ${past}` });
      await call('list_tables', { target: 'dev' });
      await new Promise((r) => setTimeout(r, 100));
      expect(fake.rules).toEqual([]);
    } finally {
      server.resetNetworkReleaseForTests();
    }
  });

  it('a call on a live target does not wait for the revoke of another, expired lease', async () => {
    const server = await import('../src/mcp/server.js');
    server.setNetworkReleaseWaitForTests(2000);
    try {
      config({ region: 'us-east-1', securityGroupId: 'sg-1' });
      fake.rules.push({ id: 'sgr-old', groupId: 'sg-1', description: `daypass:aaaa1111 until ${past}` });
      put({ version: 2, leases: [
        lease({ expiresAt: past, sgRuleId: 'sgr-old', sgRegion: 'us-east-1', sgGroupId: 'sg-1' }),
        lease({ id: 'bbbb2222', target: 'dev' }),
      ] });
      fake.revokeDelayMs = 1500;
      const t0 = Date.now();
      await call('list_tables', { target: 'dev' });
      expect(Date.now() - t0).toBeLessThan(1200);
      await new Promise((r) => setTimeout(r, 1800)); // the revoke still finishes in the background
      expect(fake.rules).toEqual([]);
    } finally {
      server.setNetworkReleaseWaitForTests(undefined);
    }
  }, 15_000);

  it('a server audit line names the only live lease when an expired one is also on disk', async () => {
    const { buildServer, auditLifecycle } = await import('../src/mcp/server.js');
    put({ version: 2, leases: [lease({ id: 'live1111', target: 'dev' }), lease({ id: 'old22222', expiresAt: past })] });
    const s = buildServer();
    auditLifecycle(s);
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await s.connect(st);
    const c = new Client({ name: 'audit-test', version: '0' });
    await c.connect(ct);
    await c.close();
    let last: any;
    for (let i = 0; i < 50; i++) {
      const lines = existsSync(join(home, 'audit.jsonl')) ? readFileSync(join(home, 'audit.jsonl'), 'utf8').trim().split('\n') : [];
      last = lines.length ? JSON.parse(lines[lines.length - 1]) : null;
      if (last?.tool === 'server') break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(last).toMatchObject({ tool: 'server', leaseId: 'live1111', target: 'dev' });
  });
});
