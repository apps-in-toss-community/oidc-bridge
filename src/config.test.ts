import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadOidcConfig, loadTossConfig } from './config.js';

describe('loadOidcConfig', () => {
  const orig = { ...process.env };
  beforeEach(() => {
    for (const k of Object.keys(process.env)) {
      if (k.startsWith('OIDC_') || k === 'ID_TOKEN_TTL_SECONDS') delete process.env[k];
    }
  });
  afterEach(() => {
    process.env = { ...orig };
  });

  it('reads issuer + active kid + signing key PEMs', () => {
    process.env.OIDC_ISSUER = 'https://oidc-bridge.aitc.dev';
    process.env.OIDC_ACTIVE_KID = 'k1';
    process.env.OIDC_SIGNING_KEY_K1_PEM =
      '-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n';
    const cfg = loadOidcConfig(process.env);
    expect(cfg.issuer).toBe('https://oidc-bridge.aitc.dev');
    expect(cfg.activeKid).toBe('k1');
    expect(cfg.signingKeys).toEqual([
      { kid: 'k1', pem: '-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n' },
    ]);
    expect(cfg.idTokenTtlSeconds).toBe(3600);
    expect(cfg.defaultScope).toBe('openid profile user_key');
  });

  it('throws when active kid has no PEM', () => {
    process.env.OIDC_ISSUER = 'https://x';
    process.env.OIDC_ACTIVE_KID = 'missing';
    expect(() => loadOidcConfig(process.env)).toThrow(/OIDC_SIGNING_KEY_MISSING_PEM/);
  });

  it('rejects trailing slash in issuer', () => {
    process.env.OIDC_ISSUER = 'https://x/';
    process.env.OIDC_ACTIVE_KID = 'k1';
    process.env.OIDC_SIGNING_KEY_K1_PEM = 'pem';
    expect(() => loadOidcConfig(process.env)).toThrow(/trailing slash/);
  });
});

describe('loadTossConfig', () => {
  const orig = { ...process.env };
  beforeEach(() => {
    delete process.env.TOSS_API_BASE;
  });
  afterEach(() => {
    process.env = { ...orig };
  });

  it('defaults to production partner host', () => {
    expect(loadTossConfig(process.env).apiBase).toBe('https://apps-in-toss-api.toss.im');
  });

  it('respects TOSS_API_BASE override', () => {
    process.env.TOSS_API_BASE = 'https://sandbox.toss.example';
    expect(loadTossConfig(process.env).apiBase).toBe('https://sandbox.toss.example');
  });

  it('rejects trailing slash (would corrupt URL join)', () => {
    process.env.TOSS_API_BASE = 'https://x.example/';
    expect(() => loadTossConfig(process.env)).toThrow(/trailing slash/);
  });
});
