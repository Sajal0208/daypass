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
import { parseHiddenFile, renderSetupSql } from '../core/hidden.js';
import {
  readConfig,
  readLease,
  writeLease,
  clearLease,
  readAuditDetailed,
  writeConfigIfMissing,
  LeaseCorruptError,
  resolveTarget,
  serveStdio,
  CONFIG_PATH,
  allowIp,
  revokeLeaseRule,
  sweepExpired,
  myPublicIp,
} from '../mcp/index.js';
import type { TargetConfig } from '../mcp/index.js';
import { doctor } from './doctor.js';
import { hiddenCommand } from './hidden.js';
import { formatLog, printable as p } from './log.js';

const require = createRequire(import.meta.url);
const { version } = require('../../package.json') as { version: string };
const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const program = new Command()
  .name('daypass')
  .description('Temporary, read-only, audited database access for AI coding agents')
  .version(version);

/**
 * Identity written to the lease and every audit line. For IAM targets it is the AWS caller
 * ARN (not spoofable from the shell); other targets fall back to the OS account name (from the
 * process credentials, not the spoofable USER variable) @ hostname.
 */
async function who(t: TargetConfig): Promise<string> {
  if (t.region) {
    const sts = new STSClient({ region: t.region, ...(t.awsProfile ? { credentials: fromIni({ profile: t.awsProfile }) } : {}) });
    const id = await sts.send(new GetCallerIdentityCommand({}));
    if (!id.Arn) throw new Error('AWS did not return a caller identity');
    return id.Arn;
  }
  return `${osUser()}@${hostname()}`;
}

/** userInfo() throws when the UID has no passwd entry (some containers); fall back to the numeric UID. */
function osUser(): string {
  try {
    return userInfo().username;
  } catch {
    return `uid:${process.getuid?.() ?? 'unknown'}`;
  }
}

async function releaseNetwork(lease: Lease, t: TargetConfig | undefined) {
  const r = await revokeLeaseRule(lease, t);
  if (r.revoked) console.log(`Removed security-group rule ${p(lease.sgRuleId)}`);
  if (r.warning) console.warn(`warning: ${p(r.warning)}`);
}

program
  .command('init')
  .description(`Write a starter config to ${CONFIG_PATH}`)
  .action(async () => {
    const example = {
      $comment: 'One entry per database. Give either "url" (any Postgres) or host/database/user + "region" (AWS RDS, IAM auth, no password).',
      targets: {
        local: { url: 'postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' },
        prod: {
          host: 'my-db.abc123.us-east-1.rds.amazonaws.com',
          port: 5432,
          database: 'mydb',
          user: 'daypass_ro',
          region: 'us-east-1',
          awsProfile: 'default',
          securityGroupId: 'sg-xxxxxxxxxxxxxxxxx',
          schemas: ['public'],
          maxRows: 500,
        },
      },
    };
    if (!(await writeConfigIfMissing(JSON.stringify(example, null, 2)))) {
      console.log(`Config already exists: ${CONFIG_PATH}`);
      return;
    }
    console.log(`Wrote ${CONFIG_PATH}\nNext: edit it, run the role setup (daypass sql | psql ...), then: daypass open prod --reason "..."`);
  });

program
  .command('sql')
  .description('Print the one-time role setup SQL (pipe into psql as the DB owner)')
  .option('--role <name>', 'name of the read-only role', 'daypass_ro')
  .option('--hide <cols...>', 'columns to hide: table.column, schema.table.column, or "quoted"."identifiers"', [])
  .option('--hide-file <path>', 'file with one entry per line (# comments ok; !table.column marks a reviewed, visible column)')
  .option('--schemas <list>', 'comma-separated schemas the role may read', 'public')
  .option('--allow-definer-functions', 'acknowledge SECURITY DEFINER functions the role can execute instead of failing the self-check', false)
  .option('--revoke-public-temp', 'also REVOKE TEMP ON DATABASE ... FROM PUBLIC (app roles may need temp tables, so off by default)', false)
  .option('--revoke-public-create', 'also REVOKE CREATE ON SCHEMA <each listed schema> FROM PUBLIC (PostgreSQL 14 and older grant it on public)', false)
  .action(async (opts: { role: string; hide: string[]; hideFile?: string; schemas: string; allowDefinerFunctions: boolean; revokePublicTemp: boolean; revokePublicCreate: boolean }) => {
    if (!/^[a-z_][a-z0-9_]*$/.test(opts.role)) throw new Error('role must match ^[a-z_][a-z0-9_]*$');
    const fromFile = opts.hideFile ? parseHiddenFile(await fs.readFile(opts.hideFile, 'utf8')) : { hidden: [], allow: [] };
    const schemas = opts.schemas.split(',').map((x) => x.trim()).filter(Boolean);
    const sql = await fs.readFile(join(PKG_ROOT, 'sql', 'setup-role.sql'), 'utf8');
    process.stdout.write(
      renderSetupSql(sql, {
        role: opts.role,
        hidden: [...fromFile.hidden, ...opts.hide],
        allow: fromFile.allow,
        schemas,
        allowDefiner: opts.allowDefinerFunctions,
        revokeTemp: opts.revokePublicTemp,
        revokeCreate: opts.revokePublicCreate,
      }),
    );
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
      throw new Error(`A lease is already open (${p(existing.id)} on ${p(existing.target)}, until ${p(existing.expiresAt)}). Run: daypass close`);
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

    // The lease is on disk before the security-group call: a failed call leaves a lease that
    // `close` knows about. One window remains: a crash after AWS created the rule but before the
    // rule id is written. That rule is tagged daypass:<lease id> with the expiry, and
    // `daypass sweep <target>` removes it once the lease has expired.
    await writeLease(lease);
    if (opts.network && t.region && t.securityGroupId) {
      try {
        lease.ip = await myPublicIp();
        // Recorded before the rule exists, so close/cleanup revoke it in this group even if the config changes.
        lease.sgRegion = t.region;
        lease.sgGroupId = t.securityGroupId;
        if (t.awsProfile) lease.sgProfile = t.awsProfile;
        await writeLease(lease);
        lease.sgRuleId = await allowIp({
          region: t.region,
          profile: t.awsProfile,
          groupId: t.securityGroupId,
          port: t.port,
          ip: lease.ip,
          leaseId: lease.id,
          expiresAt: lease.expiresAt,
        });
      } catch (e: any) {
        console.error(`Lease ${lease.id} was recorded, but opening the network failed. Run: daypass close (then retry daypass open)`);
        throw e;
      }
      await writeLease(lease);
      console.log(`Allowed ${lease.ip} on ${t.securityGroupId} (rule ${lease.sgRuleId})`);
    }

    console.log(`Lease ${lease.id} open on "${targetName}" until ${lease.expiresAt} (${opts.ttl}). Reason: ${lease.reason}`);
    console.log('Your AI session can now use the daypass MCP tools. Close early with: daypass close');
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
        ? `Lease ${p(l.id)} on "${p(l.target)}" by ${p(l.who)}: ${left} min left. Reason: ${p(l.reason)}`
        : `Lease ${p(l.id)} on "${p(l.target)}" expired at ${p(l.expiresAt)}. Run: daypass close`,
    );
  });

program
  .command('close')
  .description('End the lease now and remove the network rule')
  .action(async () => {
    let l: Lease | null;
    try {
      l = await readLease();
    } catch (e: any) {
      if (!(e instanceof LeaseCorruptError)) throw e;
      await clearLease();
      console.warn('Removed the corrupt lease file. If it held a security-group rule, run: daypass sweep <target>');
      return;
    }
    if (!l) return console.log('No lease.');
    // The lease records where its rule lives; older leases fall back to the config.
    const recorded = !!(l.sgRegion && l.sgGroupId);
    let cfg: { targets: Record<string, TargetConfig> } | undefined;
    if (l.sgRuleId && !recorded) {
      try {
        cfg = await readConfig();
      } catch (e: any) {
        console.warn(
          `warning: cannot read the config (${p(e.message)}); security-group rule ${p(l.sgRuleId)} was NOT revoked. ` +
            `Restore the config and run: daypass sweep ${p(l.target)}`,
        );
      }
    }
    if (l.sgRuleId && (recorded || cfg)) await releaseNetwork(l, cfg?.targets[l.target]);
    await clearLease();
    console.log(`Lease ${p(l.id)} closed.`);
  });

program
  .command('sweep <target>')
  .description('Remove expired daypass:* rules from the target security group (run from cron)')
  .action(async (targetName: string) => {
    const cfg = await readConfig();
    const t = cfg.targets[targetName];
    if (!t?.region || !t.securityGroupId) throw new Error('Target has no region/securityGroupId');
    const removed = await sweepExpired({ region: t.region, profile: t.awsProfile, groupId: t.securityGroupId });
    console.log(removed.length ? `Removed ${removed.length} expired rule(s): ${removed.join(', ')}` : 'Nothing to sweep.');
    const l = await readLease();
    if (l && !isLeaseLive(l)) {
      await clearLease();
      console.log(`Cleared expired local lease ${p(l.id)}.`);
    }
  });

program
  .command('log')
  .description('Show recent audit entries')
  .option('-n, --last <n>', 'how many', '30')
  .action(async (opts: { last: string }) => {
    // Up to two lines per call (start + end): read twice as many, pair them, keep the last n rows.
    if (!/^\d+$/.test(opts.last) || Number(opts.last) < 1) throw new Error(`-n must be a positive integer (got "${opts.last}")`);
    const n = Number(opts.last);
    const { events, corrupt } = await readAuditDetailed(n * 2);
    if (corrupt) console.error(`warning: ${corrupt} unreadable line(s) in the audit log were skipped`);
    for (const line of formatLog(events, n)) console.log(line);
  });

program
  .command('doctor [target]')
  .description('Check config, DNS, AWS credentials, network, lease, read-only enforcement and the hidden columns')
  .option('--hide-file <path>', 'also check this hidden-columns list (the setup stores the list it applied on the role)')
  .action(async (target: string | undefined, opts: { hideFile?: string }) => {
    const checks = await doctor(target, { hideFile: opts.hideFile });
    for (const c of checks) console.log(`${c.ok ? '✔' : '✖'} ${c.name.padEnd(16)} ${c.detail}`);
    if (checks.some((c) => !c.ok)) process.exit(1);
  });

program.addCommand(hiddenCommand());

program
  .command('mcp')
  .description('Run the MCP server on stdio (used by: claude mcp add daypass -- daypass mcp)')
  .action(async () => {
    await serveStdio();
  });

program.parseAsync(process.argv).catch((e) => {
  console.error(e?.message ?? e);
  process.exit(1);
});
