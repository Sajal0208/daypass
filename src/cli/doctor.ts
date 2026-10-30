import { lookup } from 'node:dns/promises';
import { connect } from 'node:net';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { fromIni } from '@aws-sdk/credential-providers';
import { isLeaseLive } from '../core/index.js';
import { readConfig, readLease, resolveTarget, getPool, closePool, CONFIG_PATH } from '../mcp/index.js';

type Check = { name: string; ok: boolean; detail: string };

async function tcp(host: string, port: number): Promise<string> {
  return new Promise((res) => {
    const s = connect({ host, port });
    const t = setTimeout(() => { s.destroy(); res('timeout after 5 s (firewall / security group?)'); }, 5000);
    s.once('connect', () => { clearTimeout(t); s.destroy(); res('open'); });
    s.once('error', (e) => { clearTimeout(t); res(e.message); });
  });
}

/** Walks the whole chain for one target and reports each link. Never throws. */
export async function doctor(targetName?: string): Promise<Check[]> {
  const out: Check[] = [];
  const push = (name: string, ok: boolean, detail: string) => out.push({ name, ok, detail });

  const major = Number(process.versions.node.split('.')[0]);
  push('node >= 20', major >= 20, `v${process.versions.node}`);

  let cfg;
  try {
    cfg = await readConfig();
    push('config', true, `${CONFIG_PATH} (${Object.keys(cfg.targets).join(', ') || 'no targets'})`);
  } catch (e: any) {
    push('config', false, e.message);
    return out;
  }

  const lease = await readLease();
  const name = targetName ?? lease?.target ?? Object.keys(cfg.targets)[0];
  if (!name) return out;
  const raw = cfg.targets[name];
  if (!raw) {
    push('target', false, `"${name}" not in config`);
    return out;
  }

  let t;
  try {
    t = resolveTarget(name, raw);
    push('target', true, `${name}: ${t.user}@${t.host}:${t.port}/${t.database} via ${t.region ? 'RDS IAM' : 'password'}`);
  } catch (e: any) {
    push('target', false, e.message);
    return out;
  }

  try {
    const a = await lookup(t.host);
    push('dns', true, `${t.host} → ${a.address}`);
  } catch (e: any) {
    push('dns', false, e.message);
  }

  if (t.region) {
    try {
      const sts = new STSClient({ region: t.region, ...(t.awsProfile ? { credentials: fromIni({ profile: t.awsProfile }) } : {}) });
      const id = await sts.send(new GetCallerIdentityCommand({}));
      push('aws credentials', true, `${id.Arn}${t.awsProfile ? ` (profile ${t.awsProfile})` : ''}`);
    } catch (e: any) {
      push('aws credentials', false, e.message);
    }
  }

  const port = await tcp(t.host, t.port);
  push('tcp', port === 'open', `${t.host}:${t.port} ${port}`);

  const live = !!lease && isLeaseLive(lease) && lease.target === name;
  push('lease', live, live ? `${lease!.id} until ${lease!.expiresAt}` : `none open for "${name}" (daypass open ${name} --reason ...)`);

  if (live && port === 'open') {
    try {
      const pool = await getPool(name, t);
      const r = await pool.query('select current_user, current_setting(\'default_transaction_read_only\') as ro, version()');
      const row = r.rows[0];
      push('db login', true, `as ${row.current_user}; read_only=${row.ro}; ${String(row.version).split(',')[0]}`);
      if (row.ro !== 'on') push('read-only', false, 'session is NOT read-only — check role settings');
      try {
        await pool.query('create temp table daypass_doctor_probe(x int)');
        push('write blocked', false, 'CREATE TEMP TABLE succeeded — role is not read-only!');
      } catch {
        push('write blocked', true, 'write attempt rejected, as it should be');
      }
    } catch (e: any) {
      push('db login', false, e.message || e.code || String(e));
    } finally {
      await closePool();
    }
  }
  return out;
}
