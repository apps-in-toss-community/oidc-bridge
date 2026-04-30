import { describe, expect, it } from 'vitest';
import { mapToIdTokenClaims } from './claim-mapping.js';

describe('mapToIdTokenClaims', () => {
  it('maps userKey to sub (string-cast) and preserves numeric in toss:userKey', () => {
    const out = mapToIdTokenClaims({
      issuer: 'https://oidc-bridge.aitc.dev',
      audience: 'tnt_x',
      now: 1_700_000_000,
      tossAccessTokenExp: 1_700_003_600,
      loginMe: { userKey: 4200000000001, scope: 'user_key', agreedTerms: ['T1'] },
      requestedScopes: ['openid', 'user_key'],
    });
    expect(out.sub).toBe('4200000000001');
    expect(out['toss:userKey']).toBe(4200000000001);
    expect(out['toss:agreedTerms']).toEqual(['T1']);
    expect(out['toss:tossAccessTokenExpiresAt']).toBe(1_700_003_600);
    expect(out.iss).toBe('https://oidc-bridge.aitc.dev');
    expect(out.aud).toBe('tnt_x');
    expect(out.iat).toBe(1_700_000_000);
    expect(out.exp).toBe(1_700_003_600);
    expect(out.scope).toBe('openid user_key');
    expect(out.provider).toBe('toss');
  });

  it('honors `openid` even though Toss does not have it', () => {
    const out = mapToIdTokenClaims({
      issuer: 'https://x',
      audience: 'tnt_y',
      now: 1_700_000_000,
      tossAccessTokenExp: 1_700_003_600,
      loginMe: { userKey: 1, scope: 'user_key', agreedTerms: [] },
      requestedScopes: ['openid'],
    });
    expect(out.scope).toContain('openid');
  });

  it('caps id_token TTL at 1 hour even if Toss exp is further out', () => {
    const out = mapToIdTokenClaims({
      issuer: 'https://x',
      audience: 'tnt_y',
      now: 1_700_000_000,
      tossAccessTokenExp: 1_700_000_000 + 7200,
      loginMe: { userKey: 1, scope: 'user_key', agreedTerms: [] },
      requestedScopes: ['openid'],
    });
    expect(out.exp).toBe(1_700_000_000 + 3600);
  });
});
