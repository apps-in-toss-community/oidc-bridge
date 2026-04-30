import { calculateJwkThumbprint, exportJWK, importPKCS8, type JWK, SignJWT } from 'jose';

export interface IdTokenClaims {
  sub: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  nbf?: number;
  provider: 'toss';
  scope: string;
  'toss:userKey'?: number;
  'toss:agreedTerms'?: string[];
  'toss:tossAccessTokenExpiresAt'?: number;
}

let cachedKid: string | undefined;

export async function computeKid(signingKeyPem: string): Promise<string> {
  if (cachedKid) return cachedKid;
  const key = await importPKCS8(signingKeyPem, 'RS256');
  const jwk = await exportJWK(key);
  cachedKid = await calculateJwkThumbprint(jwk, 'sha256');
  return cachedKid;
}

export async function signIdToken(args: {
  claims: IdTokenClaims;
  signingKeyPem: string;
}): Promise<string> {
  const key = await importPKCS8(args.signingKeyPem, 'RS256');
  const kid = await computeKid(args.signingKeyPem);
  const { iss, aud, iat, exp, nbf, sub, ...rest } = args.claims;
  let jwt = new SignJWT({ ...rest })
    .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
    .setIssuer(iss)
    .setAudience(aud)
    .setSubject(sub)
    .setIssuedAt(iat)
    .setExpirationTime(exp);
  if (nbf !== undefined) jwt = jwt.setNotBefore(nbf);
  return jwt.sign(key);
}

export async function exportJwks(signingKeyPem: string): Promise<{ keys: JWK[] }> {
  const key = await importPKCS8(signingKeyPem, 'RS256');
  const full = await exportJWK(key);
  const kid = await computeKid(signingKeyPem);
  // importPKCS8 with 'RS256' always yields an RSA key, so n and e are always present.
  if (!full.n || !full.e) throw new Error('expected RSA JWK with n and e');
  const pub: JWK = { kty: full.kty, n: full.n, e: full.e, alg: 'RS256', use: 'sig', kid };
  return { keys: [pub] };
}
