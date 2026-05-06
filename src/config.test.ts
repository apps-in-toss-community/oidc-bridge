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

describe('loadBridgeFlags', () => {
  it('enableSessionLogin is false when env var unset', async () => {
    const { loadBridgeFlags } = await import('./config.js');
    expect(loadBridgeFlags({}).enableSessionLogin).toBe(false);
  });

  it('enableSessionLogin is false for any value other than "1"', async () => {
    const { loadBridgeFlags } = await import('./config.js');
    expect(loadBridgeFlags({ BRIDGE_ENABLE_SESSION_LOGIN: '0' }).enableSessionLogin).toBe(false);
    expect(loadBridgeFlags({ BRIDGE_ENABLE_SESSION_LOGIN: 'true' }).enableSessionLogin).toBe(false);
    expect(loadBridgeFlags({ BRIDGE_ENABLE_SESSION_LOGIN: '' }).enableSessionLogin).toBe(false);
  });

  it('enableSessionLogin is true only when env var is exactly "1"', async () => {
    const { loadBridgeFlags } = await import('./config.js');
    expect(loadBridgeFlags({ BRIDGE_ENABLE_SESSION_LOGIN: '1' }).enableSessionLogin).toBe(true);
  });
});

describe('loadObservabilityConfig', () => {
  it('defaults version + buildSha to dev when env unset', async () => {
    const { loadObservabilityConfig } = await import('./config.js');
    const c = loadObservabilityConfig({});
    expect(c.version).toBe('0.0.0-dev');
    expect(c.buildSha).toBe('dev');
    expect(c.ipHashSalt).toMatch(/^[0-9a-f]{32}$/);
  });

  it('honors BRIDGE_VERSION + BRIDGE_BUILD_SHA + IP_HASH_SALT when set', async () => {
    const { loadObservabilityConfig } = await import('./config.js');
    const c = loadObservabilityConfig({
      BRIDGE_VERSION: '1.2.3',
      BRIDGE_BUILD_SHA: 'abcdef0',
      IP_HASH_SALT: 'fixed-salt',
    });
    expect(c.version).toBe('1.2.3');
    expect(c.buildSha).toBe('abcdef0');
    expect(c.ipHashSalt).toBe('fixed-salt');
  });
});

describe('loadRateLimitConfig', () => {
  it('defaults: enabled=true, ipPerMin=60, appPerMin=600', async () => {
    const { loadRateLimitConfig } = await import('./config.js');
    expect(loadRateLimitConfig({})).toEqual({ enabled: true, ipPerMin: 60, appPerMin: 600 });
  });

  it('RATE_LIMIT_ENABLED=false disables; any other value keeps it enabled', async () => {
    const { loadRateLimitConfig } = await import('./config.js');
    expect(loadRateLimitConfig({ RATE_LIMIT_ENABLED: 'false' }).enabled).toBe(false);
    expect(loadRateLimitConfig({ RATE_LIMIT_ENABLED: '0' }).enabled).toBe(true);
    expect(loadRateLimitConfig({ RATE_LIMIT_ENABLED: 'true' }).enabled).toBe(true);
  });

  it('honors numeric overrides', async () => {
    const { loadRateLimitConfig } = await import('./config.js');
    expect(
      loadRateLimitConfig({ RATE_LIMIT_IP_PER_MIN: '120', RATE_LIMIT_APP_PER_MIN: '1200' }),
    ).toEqual({ enabled: true, ipPerMin: 120, appPerMin: 1200 });
  });

  it('rejects non-positive limits', async () => {
    const { loadRateLimitConfig } = await import('./config.js');
    expect(() => loadRateLimitConfig({ RATE_LIMIT_IP_PER_MIN: '0' })).toThrow(/positive/);
    expect(() => loadRateLimitConfig({ RATE_LIMIT_APP_PER_MIN: '-1' })).toThrow(/positive/);
    expect(() => loadRateLimitConfig({ RATE_LIMIT_IP_PER_MIN: 'not-a-number' })).toThrow(
      /positive/,
    );
  });
});
