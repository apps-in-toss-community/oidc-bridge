import type { Hono } from 'hono';
import type { Config } from '../config.js';

export function mountDiscovery(app: Hono, config: Config): void {
  app.get('/.well-known/openid-configuration', (c) => {
    const i = config.issuer;
    return c.json({
      issuer: i,
      jwks_uri: `${i}/.well-known/jwks.json`,
      token_endpoint: `${i}/oidc/token`,
      userinfo_endpoint: `${i}/oidc/userinfo`,
      revocation_endpoint: `${i}/oidc/revoke`,
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      scopes_supported: [
        'openid',
        'profile',
        'user_key',
        'user_name',
        'user_phone',
        'user_birthday',
        'user_gender',
        'user_nationality',
        'user_ci',
      ],
      subject_types_supported: ['public'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'iat',
        'exp',
        'nbf',
        'provider',
        'scope',
        'toss:userKey',
        'toss:agreedTerms',
        'toss:tossAccessTokenExpiresAt',
      ],
    });
  });
}
