import { SignJWT } from 'jose';
import type { SigningKeyRegistry } from './signing-keys.js';

export interface TossClaimsForIdToken {
  userKey: number;
  scope: string[];
  agreedTerms: string[];
  tossAtExp: number;
}

export interface MintInput {
  issuer: string;
  ttlSeconds: number;
  registry: SigningKeyRegistry;
  app: { clientId: string };
  tossClaims: TossClaimsForIdToken;
  now: number;
}

export async function mintIdToken(input: MintInput): Promise<string> {
  const exp = input.now + input.ttlSeconds;
  return await new SignJWT({
    provider: 'toss',
    scope: input.tossClaims.scope.join(' '),
    'toss:userKey': input.tossClaims.userKey,
    'toss:agreedTerms': input.tossClaims.agreedTerms,
    'toss:tossAccessTokenExpiresAt': input.tossClaims.tossAtExp,
  })
    .setProtectedHeader({ alg: 'RS256', kid: input.registry.activeKid })
    .setIssuer(input.issuer)
    .setAudience(input.app.clientId)
    .setSubject(String(input.tossClaims.userKey))
    .setIssuedAt(input.now)
    .setNotBefore(input.now)
    .setExpirationTime(exp)
    .sign(input.registry.activeSigner);
}
