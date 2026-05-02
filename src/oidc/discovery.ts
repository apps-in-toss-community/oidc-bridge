export interface DiscoveryDoc {
  issuer: string;
  jwks_uri: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  revocation_endpoint: string;
  grant_types_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  id_token_signing_alg_values_supported: string[];
  subject_types_supported: string[];
  scopes_supported: string[];
  claims_supported: string[];
  code_challenge_methods_supported: string[];
}

export function buildDiscovery(opts: { issuer: string }): DiscoveryDoc {
  const i = opts.issuer;
  return {
    issuer: i,
    jwks_uri: `${i}/.well-known/jwks.json`,
    token_endpoint: `${i}/oidc/token`,
    userinfo_endpoint: `${i}/oidc/userinfo`,
    revocation_endpoint: `${i}/oidc/revoke`,
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
  };
}
