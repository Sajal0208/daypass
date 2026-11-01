import { describe, it, expect } from 'vitest';
import { sslOptions } from '../src/mcp/db.js';

const PEM = '-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n';
const rds = 'my-db.abc123.eu-central-1.rds.amazonaws.com';

describe('sslOptions', () => {
  it('turns TLS off only when ssl === false', () => {
    expect(sslOptions({ host: rds, ssl: false }, PEM)).toBeUndefined();
  });
  it('pins the bundled RDS CA when region is set', () => {
    expect(sslOptions({ host: 'anything', region: 'eu-central-1' }, PEM)).toEqual({ rejectUnauthorized: true, ca: PEM });
  });
  it('pins the bundled RDS CA for an RDS host even without region (url/password target)', () => {
    expect(sslOptions({ host: rds, password: 'x' }, PEM)).toEqual({ rejectUnauthorized: true, ca: PEM });
  });
  it('is case-insensitive on the RDS host', () => {
    expect(sslOptions({ host: rds.toUpperCase() }, PEM)).toEqual({ rejectUnauthorized: true, ca: PEM });
  });
  it('uses system CAs for a non-RDS host', () => {
    expect(sslOptions({ host: 'db.example.com', password: 'x' }, PEM)).toEqual({ rejectUnauthorized: true });
  });
  it('falls back to system CAs when the bundle is not shipped', () => {
    expect(sslOptions({ host: rds }, undefined)).toEqual({ rejectUnauthorized: true });
  });
  it('never downgrades verification', () => {
    for (const t of [{ host: rds }, { host: 'x', region: 'r' }, { host: 'db.example.com' }]) {
      expect(sslOptions(t, PEM)?.rejectUnauthorized).toBe(true);
    }
  });
});
