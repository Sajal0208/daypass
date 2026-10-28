#!/usr/bin/env node
import { Command } from 'commander';
import { randomBytes } from 'node:crypto';
import { userInfo, hostname } from 'node:os';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { fromIni } from '@aws-sdk/credential-providers';
import { promises as fs } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseTtl, isLeaseLive } from '../core/index.js';
import type { Lease } from '../core/index.js';
import {
  readConfig,
  readLease,
  writeLease,
  clearLease,
  readAudit,
  resolveTarget,
  serveStdio,
  CONFIG_PATH,
  PEEPHOLE_HOME,
  allowIp,
  revokeRule,
  sweepExpired,
  myPublicIp,
} from '../mcp/index.js';
import type { TargetConfig } from '../mcp/index.js';
import { doctor } from './doctor.js';

const require = createRequire(import.meta.url);
const { version } = require('../../package.json') as { version: string };
const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const program = new Command()
  .name('peephole')
  .description('Temporary, read-only, audited database access for AI coding agents')
  .version(version);

/**
 * Identity written to the lease and every audit line. For IAM targets it is the AWS caller
 * ARN (not spoofable from the shell); other targets fall back to user@host.
 */
async function who(t: TargetConfig): Promise<string> {
  if (t.region) {
    const sts = new STSClient({ region: t.region, ...(t.awsProfile ? { credentials: fromIni({ profile: t.awsProfile }) } : {}) });
    const id = await sts.send(new GetCallerIdentityCommand({}));
    if (!id.Arn) throw new Error('AWS did not return a caller identity');
    return id.Arn;
  }
  return `${process.env.USER ?? userInfo().username}@${hostname()}`;
}

async function releaseNetwork(lease: Lease, t: TargetConfig | undefined) {
  if (lease.sgRuleId && t?.region && t.securityGroupId) {
    await revokeRule({ region: t.region, profile: t.awsProfile, groupId: t.securityGroupId, ruleId: lease.sgRuleId });
    console.log(`Removed security-group rule ${lease.sgRuleId}`);
  }
}

program
  .command('init')
  .description(`Write a starter config to ${CONFIG_PATH}`)
  .action(async () => {
    await fs.mkdir(PEEPHOLE_HOME, { recursive: true, mode: 0o700 });
    try {
      await fs.access(CONFIG_PATH);
      console.log(`Config already exists: ${CONFIG_PATH}`);
      return;
    } catch {}
    const example = {
      $comment: 'One entry per database. Give either "url" (any Postgres) or host/database/user + "region" (AWS RDS, IAM auth, no password).',
      targets: {
        local: { url: 'postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' },
        prod: {
          host: 'my-db.abc123.eu-central-1.rds.amazonaws.com',
          port: 5432,
          database: 'mydb',
          user: 'peephole_ro',
          region: 'eu-central-1',
          awsProfile: 'default',
          securityGroupId: 'sg-0123456789abcdef0',
          schemas: ['public'],
          maxRows: 500,
        },
      },
    };
    await fs.writeFile(CONFIG_PATH, JSON.stringify(example, null, 2), { mode: 0o600 });
    console.log(`Wrote ${CONFIG_PATH}\nNext: edit it, run the role setup (peephole sql | psql ...), then: peephole open prod --reason "..."`);
  });

program
  .command('sql')
  .description('Print the one-time role setup SQL (pipe into psql as the DB owner)')
  .option('--role <name>', 'name of the read-only role', 'peephole_ro')
  .option('--hide <cols...>', 'columns to hide, as table.column', [])
  .option('--hide-file <path>', 'file with one table.column per line (# comments ok)')
  .action(async (opts: { role: string; hide: string[]; hideFile?: string }) => {
    if (!/^[a-z_][a-z0-9_]*$/.test(opts.role)) throw new Error('role must match ^[a-z_][a-z0-9_]*$');
    const fromFile = opts.hideFile
      ? (await fs.readFile(opts.hideFile, 'utf8')).split('\n').map((l) => l.replace(/#.*/, '').trim()).filter(Boolean)
      : [];
    const cols = [...new Set([...fromFile, ...opts.hide])].sort();
    for (const c of cols) if (!/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/.test(c)) throw new Error(`bad column "${c}" (want table.column)`);
    const hidden = cols.length ? `ARRAY[\n    ${cols.map((c) => `'${c}'`).join(',\n    ')}\n  ]` : 'ARRAY[]::text[]';
    const sql = await fs.readFile(join(PKG_ROOT, 'sql', 'setup-role.sql'), 'utf8');
    process.stdout.write(sql.replace(/__ROLE__/g, opts.role).replace('__HIDDEN__', hidden));
  });

program
  .command('open <target>')
  .description('Open a time-boxed read-only lease')
  .requiredOption('-r, --reason <text>', 'why you need access (goes in the audit log)')
  .option('-t, --ttl <duration>', 'how long, e.g. 30m, 2h (max 8h)', '60m')
  .option('--no-network', 'skip the security-group rule')
  .action(async (targetName: string, opts: { reason: string; ttl: string; network: boolean }) => {
    const cfg = await readConfig();
    const raw = cfg.targets[targetName];
    if (!raw) throw new Error(`Unknown target "${targetName}". Known: ${Object.keys(cfg.targets).join(', ')}`);
    const t = resolveTarget(targetName, raw);

    const existing = await readLease();
    if (existing && isLeaseLive(existing)) {
      console.log(`A lease is already open (${existing.id} on ${existing.target}, until ${existing.expiresAt}). Run: peephole close`);
      return;
    }
    if (existing) await releaseNetwork(existing, cfg.targets[existing.target]).catch((e) => console.warn(`cleanup: ${e.message}`));

    const ttlMs = parseTtl(opts.ttl);
    const lease: Lease = {
      id: randomBytes(4).toString('hex'),
      target: targetName,
      reason: opts.reason,
      who: await who(t),
      openedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + ttlMs).toISOString(),
    };

    if (opts.network && t.region && t.securityGroupId) {
      lease.ip = await myPublicIp();
      lease.sgRuleId = await allowIp({
        region: t.region,
        profile: t.awsProfile,
        groupId: t.securityGroupId,
        port: t.port,
        ip: lease.ip,
        leaseId: lease.id,
        expiresAt: lease.expiresAt,
      });
      console.log(`Allowed ${lease.ip} on ${t.securityGroupId} (rule ${lease.sgRuleId})`);
    }

    await writeLease(lease);
    console.log(`Lease ${lease.id} open on "${targetName}" until ${lease.expiresAt} (${opts.ttl}). Reason: ${lease.reason}`);
    console.log('Your AI session can now use the peephole MCP tools. Close early with: peephole close');
  });

program
  .command('status')
  .description('Show the current lease')
  .action(async () => {
    const l = await readLease();
    if (!l) return console.log('No lease.');
    const left = Math.round((Date.parse(l.expiresAt) - Date.now()) / 60_000);
    console.log(
      isLeaseLive(l)
        ? `Lease ${l.id} on "${l.target}" by ${l.who}: ${left} min left. Reason: ${l.reason}`
        : `Lease ${l.id} on "${l.target}" expired at ${l.expiresAt}. Run: peephole close`,
    );
  });

program
  .command('close')
  .description('End the lease now and remove the network rule')
  .action(async () => {
    const l = await readLease();
    if (!l) return console.log('No lease.');
    const cfg = await readConfig().catch(() => ({ targets: {} as Record<string, TargetConfig> }));
    await releaseNetwork(l, cfg.targets[l.target]);
    await clearLease();
    console.log(`Lease ${l.id} closed.`);
  });

program
  .command('sweep <target>')
  .description('Remove expired peephole:* rules from the target security group (run from cron)')
  .action(async (targetName: string) => {
    const cfg = await readConfig();
    const t = cfg.targets[targetName];
    if (!t?.region || !t.securityGroupId) throw new Error('Target has no region/securityGroupId');
    const removed = await sweepExpired({ region: t.region, profile: t.awsProfile, groupId: t.securityGroupId });
    console.log(removed.length ? `Removed ${removed.length} expired rule(s): ${removed.join(', ')}` : 'Nothing to sweep.');
    const l = await readLease();
    if (l && !isLeaseLive(l)) {
      await clearLease();
      console.log(`Cleared expired local lease ${l.id}.`);
    }
  });

program
  .command('log')
  .description('Show recent audit entries')
  .option('-n, --last <n>', 'how many', '30')
  .action(async (opts: { last: string }) => {
    for (const e of await readAudit(Number(opts.last))) {
      const flag = e.allowed ? (e.error ? 'ERR ' : 'ok  ') : 'BLK ';
      const sql = (e.sql ?? '').replace(/\s+/g, ' ').slice(0, 120);
      console.log(
        `${e.at} ${flag} ${e.who} ${e.target} ${e.tool} ${e.rows ?? '-'}r ${e.ms ?? '-'}ms  ${sql}` +
          `${e.blockedReason ? `  <- ${e.blockedReason}` : ''}${e.error ? `  <- ${e.error}` : ''}`,
      );
    }
  });

program
  .command('doctor [target]')
  .description('Check config, DNS, AWS credentials, network, lease and read-only enforcement')
  .action(async (target?: string) => {
    const checks = await doctor(target);
    for (const c of checks) console.log(`${c.ok ? '✔' : '✖'} ${c.name.padEnd(16)} ${c.detail}`);
    if (checks.some((c) => !c.ok)) process.exit(1);
  });

program
  .command('mcp')
  .description('Run the MCP server on stdio (used by: claude mcp add peephole -- peephole mcp)')
  .action(async () => {
    await serveStdio();
  });

program.parseAsync(process.argv).catch((e) => {
  console.error(e?.message ?? e);
  process.exit(1);
});
