export interface SigningKeyEntry {
  kid: string;
  pem: string;
}

export interface OidcConfig {
  issuer: string;
  activeKid: string;
  signingKeys: SigningKeyEntry[];
  idTokenTtlSeconds: number;
  defaultScope: string;
}

export function loadOidcConfig(env: NodeJS.ProcessEnv = process.env): OidcConfig {
  const issuer = req(env, 'OIDC_ISSUER');
  if (issuer.endsWith('/')) {
    throw new Error('OIDC_ISSUER must not have a trailing slash');
  }
  const activeKid = req(env, 'OIDC_ACTIVE_KID');
  const signingKeys: SigningKeyEntry[] = [];
  const prefix = 'OIDC_SIGNING_KEY_';
  const suffix = '_PEM';
  for (const [k, v] of Object.entries(env)) {
    if (!k.startsWith(prefix) || !k.endsWith(suffix) || !v) continue;
    const kid = k.slice(prefix.length, -suffix.length).toLowerCase();
    signingKeys.push({ kid, pem: v });
  }
  const hasActive = signingKeys.some((s) => s.kid === activeKid.toLowerCase());
  if (!hasActive) {
    throw new Error(
      `OIDC_SIGNING_KEY_MISSING_PEM: no OIDC_SIGNING_KEY_${activeKid.toUpperCase()}_PEM env`,
    );
  }
  const ttl = env.ID_TOKEN_TTL_SECONDS ? Number.parseInt(env.ID_TOKEN_TTL_SECONDS, 10) : 3600;
  if (!Number.isFinite(ttl) || ttl <= 0)
    throw new Error('ID_TOKEN_TTL_SECONDS must be positive integer');
  const defaultScope = env.OIDC_DEFAULT_SCOPE ?? 'openid profile user_key';
  return {
    issuer,
    activeKid: activeKid.toLowerCase(),
    signingKeys,
    idTokenTtlSeconds: ttl,
    defaultScope,
  };
}

function req(env: NodeJS.ProcessEnv, k: string): string {
  const v = env[k];
  if (!v) throw new Error(`${k} required`);
  return v;
}

export interface TossConfig {
  apiBase: string;
}

export function loadTossConfig(env: NodeJS.ProcessEnv = process.env): TossConfig {
  const raw = (env.TOSS_API_BASE ?? 'https://apps-in-toss-api.toss.im').trim();
  if (raw.endsWith('/')) {
    throw new Error(`TOSS_API_BASE must not have a trailing slash; got "${raw}"`);
  }
  return { apiBase: raw };
}
