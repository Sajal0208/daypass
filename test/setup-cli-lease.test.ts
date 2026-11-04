import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { userInfo, hostname, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { ensureBuilt } from './setup-build.js';

/** `daypass open/close` against a temp DAYPASS_HOME. No database or AWS call succeeds here; that is the point. */
const ROOT = resolve(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli', 'main.js');
const dirs: string[] = [];
let home: string;
const run = async (env: Record<string, string>, ...args: string[]) => {
  try {
    const r = await promisify(execFile)('node', [CLI, ...args], { cwd: ROOT, env: { ...process.env, DAYPASS_HOME: home, ...env } });
    return { code: 0, ...r };
  } catch (e: any) {
    return { code: e.code as number, stdout: e.stdout as string, stderr: e.stderr as string };
  }
};
const lease = () => JSON.parse(readFileSync(join(home, 'lease.json'), 'utf8'));

beforeAll(() => ensureBuilt(), 60_000);
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'daypass-lease-'));
  dirs.push(home);
});
afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

describe('daypass open/close (review 2026-10-30)', () => {
  it('who() uses the OS account name, not the spoofable USER variable, and appends @hostname', async () => {
    writeFileSync(join(home, 'config.json'), JSON.stringify({ targets: { t: { url: 'postgres://u:p@db.example.invalid:5432/db' } } }));
    const r = await run({ USER: 'spoofed-root' }, 'open', 't', '--no-network', '--reason', 'test', '--ttl', '5m');
    expect(r.code).toBe(0);
    expect(lease().who).toBe(`${userInfo().username}@${hostname()}`);
    expect(lease().who).not.toContain('spoofed');
  });

  it('writes lease.json before the security-group call, so a failed allowIp never orphans a rule the lease does not know', async () => {
    // A local stand-in for AWS: STS answers GetCallerIdentity (so who() succeeds), EC2 refuses the rule.
    const hits: string[] = [];
    const aws: Server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        hits.push(body.includes('Action=GetCallerIdentity') ? 'sts' : 'ec2');
        if (body.includes('Action=GetCallerIdentity')) {
          res.writeHead(200, { 'content-type': 'text/xml' });
          res.end(
            '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>' +
              '<Arn>arn:aws:iam::123456789012:user/test</Arn><UserId>AIDATEST</UserId><Account>123456789012</Account>' +
              '</GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>',
          );
        } else {
          res.writeHead(400, { 'content-type': 'text/xml' });
          res.end('<Response><Errors><Error><Code>InvalidGroup.NotFound</Code><Message>no such group</Message></Error></Errors><RequestID>r</RequestID></Response>');
        }
      });
    });
    await new Promise<void>((ok) => aws.listen(0, '127.0.0.1', ok));
    const url = `http://127.0.0.1:${(aws.address() as { port: number }).port}`;
    try {
      writeFileSync(
        join(home, 'config.json'),
        JSON.stringify({
          targets: { prod: { host: 'db.example.invalid', database: 'db', user: 'daypass_ro', region: 'us-east-1', securityGroupId: 'sg-00000000000000000' } },
        }),
      );
      const r = await run(
        {
          AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE', AWS_SECRET_ACCESS_KEY: 'test', AWS_CONFIG_FILE: '/nonexistent',
          AWS_SHARED_CREDENTIALS_FILE: '/nonexistent', AWS_EC2_METADATA_DISABLED: 'true', AWS_ENDPOINT_URL_STS: url, AWS_ENDPOINT_URL_EC2: url,
        },
        'open', 'prod', '--reason', 'test', '--ttl', '5m',
      );
      expect(r.code).toBe(1);
      expect(hits).toContain('sts');
      expect(existsSync(join(home, 'lease.json'))).toBe(true);
      const l = lease();
      expect(l.target).toBe('prod');
      expect(l.who).toBe('arn:aws:iam::123456789012:user/test');
      expect(l.sgRuleId).toBeUndefined();
      // M6: the failed open says how to clear the lease it left behind.
      expect(r.stderr).toContain('Run: daypass close');
    } finally {
      await new Promise<void>((ok) => aws.close(() => ok()));
    }
  });

  it('close warns when the config is unreadable and the lease still holds a security-group rule', async () => {
    writeFileSync(
      join(home, 'lease.json'),
      JSON.stringify({ id: 'abcd1234', target: 'prod', reason: 'x', who: 'me@host', openedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(), ip: '203.0.113.7', sgRuleId: 'sgr-00000000000000000' }),
    );
    const r = await run({}, 'close');
    expect(r.code).toBe(0);
    const out = r.stdout + r.stderr;
    expect(out).toMatch(/NOT revoked/);
    expect(out).toContain('sgr-00000000000000000');
    expect(out).toContain('daypass sweep prod');
    expect(existsSync(join(home, 'lease.json'))).toBe(false);
  });
});
