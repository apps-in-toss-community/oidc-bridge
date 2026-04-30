import type { LoginMeSuccess } from '../toss/types.js';
import type { IdTokenClaims } from './id-token.js';

const ID_TOKEN_TTL = 3600;

export function mapToIdTokenClaims(args: {
  issuer: string;
  audience: string;
  now: number;
  tossAccessTokenExp: number;
  loginMe: LoginMeSuccess;
  requestedScopes: string[];
}): IdTokenClaims {
  const exp = Math.min(args.now + ID_TOKEN_TTL, args.tossAccessTokenExp);
  const tossScopes = args.loginMe.scope.split(/\s+/).filter(Boolean);
  // openid is prepended so it sorts first in the scope string per OIDC convention.
  const merged = new Set<string>();
  if (args.requestedScopes.includes('openid')) merged.add('openid');
  for (const s of tossScopes) merged.add(s);
  return {
    sub: String(args.loginMe.userKey),
    iss: args.issuer,
    aud: args.audience,
    iat: args.now,
    exp,
    nbf: args.now,
    provider: 'toss',
    scope: Array.from(merged).join(' '),
    'toss:userKey': args.loginMe.userKey,
    'toss:agreedTerms': args.loginMe.agreedTerms,
    'toss:tossAccessTokenExpiresAt': args.tossAccessTokenExp,
  };
}
