import { describe, it, expect } from 'vitest';
import { resolveTarget } from '../src/mcp/state.js';

describe('resolveTarget', () => {
  it('parses a url', () => {
    const t = resolveTarget('x', { url: 'postgres://u:p%40ss@db.example.com:5433/app?sslmode=disable' });
    expect(t).toMatchObject({ host: 'db.example.com', port: 5433, database: 'app', user: 'u', password: 'p@ss', ssl: false });
  });
  it('accepts postgresql:// too', () => {
    expect(resolveTarget('x', { url: 'postgresql://u:p@h/db' })).toMatchObject({ host: 'h', port: 5432, database: 'db' });
  });
  it('explicit fields override url', () => {
    const t = resolveTarget('x', { url: 'postgres://u:p@h/db', user: 'other' });
    expect(t.user).toBe('other');
  });
  it('rds target needs no password', () => {
    expect(resolveTarget('p', { host: 'h', database: 'd', user: 'u', region: 'eu-central-1' }).port).toBe(5432);
  });
  it('rejects missing host', () => {
    expect(() => resolveTarget('p', { database: 'd', user: 'u', password: 'x' })).toThrow(/missing "host"/);
  });
  it('rejects no auth', () => {
    expect(() => resolveTarget('p', { host: 'h', database: 'd', user: 'u' })).toThrow(/region.*or a password/);
  });
});
