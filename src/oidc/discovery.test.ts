import { describe, expect, it } from 'vitest';
import { buildDiscovery } from './discovery.js';

describe('buildDiscovery', () => {
  it('produces the spec-locked shape', () => {
    const doc = buildDiscovery({ issuer: 'https://oidc-bridge.aitc.dev' });
    expect(doc).toEqual({
      issuer: 'https://oidc-bridge.aitc.dev',
      jwks_uri: 'https://oidc-bridge.aitc.dev/.well-known/jwks.json',
      token_endpoint: 'https://oidc-bridge.aitc.dev/oidc/token',
      userinfo_endpoint: 'https://oidc-bridge.aitc.dev/oidc/userinfo',
      revocation_endpoint: 'https://oidc-bridge.aitc.dev/oidc/revoke',
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      id_token_signing_alg_values_supported: ['RS256'],
      subject_types_supported: ['public'],
      scopes_supported: ['openid', 'profile', 'user_key'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'exp',
        'iat',
        'nbf',
        'provider',
        'scope',
        'toss:userKey',
        'toss:agreedTerms',
        'toss:tossAccessTokenExpiresAt',
      ],
      code_challenge_methods_supported: ['S256'],
    });
  });

  it('does not include authorization_endpoint or response_types_supported', () => {
    const doc = buildDiscovery({ issuer: 'https://x' }) as unknown as Record<string, unknown>;
    expect(doc.authorization_endpoint).toBeUndefined();
    expect(doc.response_types_supported).toBeUndefined();
  });
});
