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

export interface BridgeFlags {
  enableSessionLogin: boolean;
}

export function loadBridgeFlags(env: NodeJS.ProcessEnv = process.env): BridgeFlags {
  return {
    enableSessionLogin: env.BRIDGE_ENABLE_SESSION_LOGIN === '1',
  };
}

export interface ObservabilityConfig {
  ipHashSalt: string;
  buildSha: string;
  version: string;
}

export interface RateLimitConfig {
  enabled: boolean;
  ipPerMin: number;
  appPerMin: number;
}

export function loadObservabilityConfig(env: NodeJS.ProcessEnv = process.env): ObservabilityConfig {
  // ipHashSalt defaults to a per-process random — restart rotates the hash
  // mapping (acceptable for an analytics aid, not a long-term identifier).
  const fallbackSalt = randomHex(16);
  return {
    ipHashSalt: env.IP_HASH_SALT ?? fallbackSalt,
    buildSha: env.BRIDGE_BUILD_SHA ?? 'dev',
    version: env.BRIDGE_VERSION ?? '0.0.0-dev',
  };
}

export function loadRateLimitConfig(env: NodeJS.ProcessEnv = process.env): RateLimitConfig {
  const ipPerMin = Number(env.RATE_LIMIT_IP_PER_MIN ?? 60);
  const appPerMin = Number(env.RATE_LIMIT_APP_PER_MIN ?? 600);
  if (!Number.isFinite(ipPerMin) || ipPerMin <= 0) {
    throw new Error('RATE_LIMIT_IP_PER_MIN must be a positive number');
  }
  if (!Number.isFinite(appPerMin) || appPerMin <= 0) {
    throw new Error('RATE_LIMIT_APP_PER_MIN must be a positive number');
  }
  return {
    enabled: env.RATE_LIMIT_ENABLED !== 'false',
    ipPerMin,
    appPerMin,
  };
}

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  let out = '';
  for (const b of arr) out += b.toString(16).padStart(2, '0');
  return out;
}
