import { exportJWK, importPKCS8, type JWK, type KeyLike } from 'jose';

export interface SigningKeyEntry {
  kid: string;
  pem: string;
}

export interface SigningKeyRegistry {
  activeKid: string;
  activeSigner: KeyLike;
  jwks(): { keys: JWK[] };
}

export async function createSigningKeyRegistry(opts: {
  activeKid: string;
  signingKeys: SigningKeyEntry[];
}): Promise<SigningKeyRegistry> {
  if (!opts.signingKeys.some((s) => s.kid === opts.activeKid)) {
    throw new Error(`activeKid "${opts.activeKid}" not in signingKeys`);
  }
  const loaded: { kid: string; key: KeyLike }[] = [];
  for (const s of opts.signingKeys) {
    const key = await importPKCS8(s.pem, 'RS256');
    loaded.push({ kid: s.kid, key });
  }
  const active = loaded.find((l) => l.kid === opts.activeKid)!;
  const jwksKeys: JWK[] = await Promise.all(
    loaded.map(async ({ kid, key }) => {
      const jwk = await exportJWK(key);
      return { kid, alg: 'RS256', use: 'sig', kty: jwk.kty, n: jwk.n, e: jwk.e } as JWK;
    }),
  );
  return {
    activeKid: opts.activeKid,
    activeSigner: active.key,
    jwks: () => ({ keys: jwksKeys }),
  };
}
