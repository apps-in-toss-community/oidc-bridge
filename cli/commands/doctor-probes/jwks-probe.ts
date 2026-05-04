import { createPublicKey } from 'node:crypto';
import { importPKCS8, jwtVerify, SignJWT } from 'jose';
import type { ProbeItem } from '../../output.js';

export interface JwksProbeOpts {
  activeKid: string;
  /** kid → PEM (PKCS#8). */
  signingKeys: Record<string, string>;
}

export async function runJwksProbe(opts: JwksProbeOpts): Promise<ProbeItem> {
  const pem = opts.signingKeys[opts.activeKid];
  const totalKeys = Object.keys(opts.signingKeys).length;
  if (!pem) {
    return {
      name: 'jwks',
      state: 'red',
      detail: `active kid "${opts.activeKid}" missing from signingKeys`,
    };
  }
  let priv: Awaited<ReturnType<typeof importPKCS8>>;
  try {
    priv = await importPKCS8(pem, 'RS256');
  } catch (err) {
    return { name: 'jwks', state: 'red', detail: `PEM parse failed: ${(err as Error).message}` };
  }
  // Derive public from PKCS#8 PEM via node:crypto, then re-import in jose form.
  let pub: Awaited<ReturnType<typeof importPKCS8>>;
  try {
    const pubPem = createPublicKey(pem).export({ type: 'spki', format: 'pem' }).toString();
    const { importSPKI } = await import('jose');
    pub = await importSPKI(pubPem, 'RS256');
  } catch (err) {
    return {
      name: 'jwks',
      state: 'red',
      detail: `failed to derive public key: ${(err as Error).message}`,
    };
  }
  try {
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: opts.activeKid })
      .setIssuedAt()
      .setExpirationTime('1m')
      .sign(priv);
    await jwtVerify(jwt, pub);
    return {
      name: 'jwks',
      state: 'green',
      detail: `kid=${opts.activeKid} sign+verify ok (${totalKeys} keys loaded)`,
    };
  } catch (err) {
    return {
      name: 'jwks',
      state: 'red',
      detail: `sign/verify roundtrip failed: ${(err as Error).message}`,
    };
  }
}
