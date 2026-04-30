import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from './config.js';

describe('loadConfig', () => {
  const originalEnv = { ...process.env };
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('parses fs-store config from env', () => {
    process.env = {
      ...originalEnv,
      OIDC_ISSUER: 'https://oidc-bridge.aitc.dev',
      OIDC_SIGNING_KEY: '-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----',
      OIDC_MASTER_KEY: Buffer.alloc(32, 1).toString('base64'),
      ADMIN_TOKEN: 'admin-token-secret',
      TENANT_STORE: 'fs',
      BRIDGE_DATA_DIR: '/var/lib/oidc-bridge',
    };
    const cfg = loadConfig();
    expect(cfg.issuer).toBe('https://oidc-bridge.aitc.dev');
    expect(cfg.masterKey).toHaveLength(32);
    expect(cfg.tenantStore).toEqual({ kind: 'fs', dataDir: '/var/lib/oidc-bridge' });
    expect(cfg.tossApiBase).toBe('https://apps-in-toss-api.toss.im');
  });

  it('throws when OIDC_ISSUER is missing', () => {
    process.env = { ...originalEnv };
    delete process.env.OIDC_ISSUER;
    expect(() => loadConfig()).toThrow(/OIDC_ISSUER/);
  });

  it('throws when OIDC_MASTER_KEY is not 32 bytes after base64 decode', () => {
    process.env = {
      ...originalEnv,
      OIDC_ISSUER: 'https://x',
      OIDC_SIGNING_KEY: 'pem',
      OIDC_MASTER_KEY: Buffer.alloc(16).toString('base64'),
      ADMIN_TOKEN: 'a',
      TENANT_STORE: 'fs',
      BRIDGE_DATA_DIR: '/tmp',
    };
    expect(() => loadConfig()).toThrow(/OIDC_MASTER_KEY.*32 bytes/);
  });

  it('parses gcpsm-store config', () => {
    process.env = {
      ...originalEnv,
      OIDC_ISSUER: 'https://x',
      OIDC_SIGNING_KEY: 'pem',
      OIDC_MASTER_KEY: Buffer.alloc(32).toString('base64'),
      ADMIN_TOKEN: 'a',
      TENANT_STORE: 'gcpsm',
      GCP_PROJECT_ID: 'my-project',
    };
    const cfg = loadConfig();
    expect(cfg.tenantStore).toEqual({ kind: 'gcpsm', projectId: 'my-project' });
  });

  it('rejects unknown TENANT_STORE values', () => {
    process.env = {
      ...originalEnv,
      OIDC_ISSUER: 'https://x',
      OIDC_SIGNING_KEY: 'pem',
      OIDC_MASTER_KEY: Buffer.alloc(32).toString('base64'),
      ADMIN_TOKEN: 'a',
      TENANT_STORE: 'redis',
    };
    expect(() => loadConfig()).toThrow(/TENANT_STORE/);
  });
});
