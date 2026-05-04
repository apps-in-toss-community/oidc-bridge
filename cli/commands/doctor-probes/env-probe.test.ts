import { describe, expect, it } from 'vitest';
import { runEnvProbe } from './env-probe.js';

const okSqliteEnv = {
  STORAGE: 'sqlite',
  SQLITE_PATH: '/tmp/bridge.db',
  OIDC_ISSUER: 'https://oidc-bridge.aitc.dev',
  OIDC_ACTIVE_KID: 'k1',
  OIDC_SIGNING_KEY_K1_PEM: 'PEM',
  MASTER_KEY_PROVIDER: 'file',
  MASTER_KEY_DIR: '/var/lib/bridge/keys',
};

describe('runEnvProbe', () => {
  it('green when all required envs are present and well-formed (sqlite)', () => {
    const r = runEnvProbe(okSqliteEnv);
    expect(r.state).toBe('green');
  });

  it('green when STORAGE=pg and DATABASE_URL is set', () => {
    const r = runEnvProbe({
      ...okSqliteEnv,
      STORAGE: 'pg',
      SQLITE_PATH: undefined,
      DATABASE_URL: 'postgres://localhost/x',
    });
    expect(r.state).toBe('green');
  });

  it('red when OIDC_ISSUER is missing', () => {
    const env: Record<string, string | undefined> = { ...okSqliteEnv };
    env.OIDC_ISSUER = undefined;
    const r = runEnvProbe(env);
    expect(r.state).toBe('red');
    expect(r.detail).toContain('OIDC_ISSUER');
  });

  it('red when OIDC_ACTIVE_KID is missing', () => {
    const env: Record<string, string | undefined> = { ...okSqliteEnv };
    env.OIDC_ACTIVE_KID = undefined;
    const r = runEnvProbe(env);
    expect(r.state).toBe('red');
  });

  it('red when STORAGE=sqlite but SQLITE_PATH absent (yellow degrades to red)', () => {
    const env: Record<string, string | undefined> = { ...okSqliteEnv };
    env.SQLITE_PATH = undefined;
    const r = runEnvProbe(env);
    // Server defaults SQLITE_PATH to ./data/oidc-bridge.sqlite, so this is yellow.
    expect(r.state).toBe('yellow');
    expect(r.detail).toContain('SQLITE_PATH');
  });

  it('red when STORAGE=pg but DATABASE_URL absent', () => {
    const env: Record<string, string | undefined> = {
      ...okSqliteEnv,
      STORAGE: 'pg',
      SQLITE_PATH: undefined,
    };
    const r = runEnvProbe(env);
    expect(r.state).toBe('red');
    expect(r.detail).toContain('DATABASE_URL');
  });

  it('red when MASTER_KEY_PROVIDER=file but MASTER_KEY_DIR absent', () => {
    const env: Record<string, string | undefined> = { ...okSqliteEnv };
    env.MASTER_KEY_DIR = undefined;
    const r = runEnvProbe(env);
    expect(r.state).toBe('red');
    expect(r.detail).toContain('MASTER_KEY_DIR');
  });

  it('red when MASTER_KEY_PROVIDER is unknown', () => {
    const r = runEnvProbe({ ...okSqliteEnv, MASTER_KEY_PROVIDER: 'wat' });
    expect(r.state).toBe('red');
  });

  it('yellow when OIDC_ISSUER has trailing slash', () => {
    const r = runEnvProbe({ ...okSqliteEnv, OIDC_ISSUER: 'https://x/' });
    expect(r.state).toBe('yellow');
    expect(r.detail).toContain('trailing slash');
  });

  it('red when active-kid signing key PEM env is missing', () => {
    const env: Record<string, string | undefined> = { ...okSqliteEnv };
    env.OIDC_SIGNING_KEY_K1_PEM = undefined;
    const r = runEnvProbe(env);
    expect(r.state).toBe('red');
    expect(r.detail).toContain('OIDC_SIGNING_KEY_K1_PEM');
  });

  it('green when STORAGE is unset (defaults to sqlite per server.ts) and SQLITE_PATH set', () => {
    const env: Record<string, string | undefined> = { ...okSqliteEnv };
    env.STORAGE = undefined;
    const r = runEnvProbe(env);
    expect(r.state).toBe('green');
  });
});
