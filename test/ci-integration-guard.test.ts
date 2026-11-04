import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

/** scripts/ci-integration.sh drops schemas and tables: it must refuse anything but a local database. No database is contacted here. */
const SCRIPT = resolve(__dirname, '..', 'scripts', 'ci-integration.sh');
const run = (env: Record<string, string | undefined>) => {
  const e: Record<string, string> = {};
  for (const [k, v] of Object.entries({ ...process.env, OWNER_URL: undefined, DAYPASS_CI_OWNER_URL: undefined, DAYPASS_CI_ALLOW_REMOTE: undefined, ...env })) {
    if (v !== undefined) e[k] = v;
  }
  return spawnSync('bash', [SCRIPT], { env: e, encoding: 'utf8', timeout: 20_000 });
};

describe('scripts/ci-integration.sh host guard (review 2026-11-01)', () => {
  it('ignores OWNER_URL (the name the setup docs export for a real database)', () => {
    const r = run({ OWNER_URL: 'postgres://u:p@localhost:1/x' });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/DAYPASS_CI_OWNER_URL/);
  });
  it.each([
    'postgres://u:p@db.example.com:5432/app',
    'postgresql://u:p@app.db.example.net/app',
    'postgres://u:p@localhost/app?host=db.example.com',
    'postgres://u:p@127.0.0.1/app?hostaddr=192.0.2.1',
    'postgres://u:p@localhost.example.com/app',
    'not a url',
  ])('refuses %s', (url) => {
    const r = run({ DAYPASS_CI_OWNER_URL: url });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/refusing to run|not a URL/);
  });
  it('passes the guard for localhost / 127.0.0.1 / ::1, and for a remote host only with DAYPASS_CI_ALLOW_REMOTE=1', () => {
    // Past the guard the script tries to connect: port 1 fails fast, and the error is psql's, not the guard's.
    for (const url of ['postgres://u:p@localhost:1/x', 'postgres://u:p@127.0.0.1:1/x', 'postgres://u:p@[::1]:1/x']) {
      const r = run({ DAYPASS_CI_OWNER_URL: url });
      expect(r.stderr, url).not.toMatch(/refusing to run/);
    }
    const r = run({ DAYPASS_CI_OWNER_URL: 'postgres://u:p@remote.invalid:1/x?connect_timeout=1', DAYPASS_CI_ALLOW_REMOTE: '1' });
    expect(r.stderr).not.toMatch(/refusing to run/);
  });
});
