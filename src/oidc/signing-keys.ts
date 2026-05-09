import type { JWK, KeyLike } from 'jose';

export interface SigningKeyEntry {
  kid: string;
  pem: string;
}

export interface SigningKeyRegistry {
  activeKid: string;
  activeSigner: KeyLike;
  jwks(): { keys: JWK[] };
}

function pemToDer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----/g, '').replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export async function createSigningKeyRegistry(opts: {
  activeKid: string;
  signingKeys: SigningKeyEntry[];
}): Promise<SigningKeyRegistry> {
  if (!opts.signingKeys.some((s) => s.kid === opts.activeKid)) {
    throw new Error(`activeKid "${opts.activeKid}" not in signingKeys`);
  }
  const loaded: { kid: string; key: CryptoKey }[] = [];
  for (const s of opts.signingKeys) {
    const key = await crypto.subtle.importKey(
      'pkcs8',
      pemToDer(s.pem),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['sign'],
    );
    loaded.push({ kid: s.kid, key });
  }
  const active = loaded.find((l) => l.kid === opts.activeKid)!;
  const jwksKeys: JWK[] = await Promise.all(
    loaded.map(async ({ kid, key }) => {
      const jwk = (await crypto.subtle.exportKey('jwk', key)) as JWK;
      return { kid, alg: 'RS256', use: 'sig', kty: jwk.kty, n: jwk.n, e: jwk.e } as JWK;
    }),
  );
  return {
    activeKid: opts.activeKid,
    activeSigner: active.key,
    jwks: () => ({ keys: jwksKeys }),
  };
}
