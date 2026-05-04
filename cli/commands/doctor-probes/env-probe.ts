import type { ProbeItem } from '../../output.js';

const VALID_PROVIDERS = new Set(['env', 'file', 'gcpsm']);
const VALID_STORAGE = new Set(['sqlite', 'pg']);

export function runEnvProbe(env: Record<string, string | undefined>): ProbeItem {
  const errors: string[] = [];
  const warnings: string[] = [];

  // OIDC core.
  const issuer = env.OIDC_ISSUER;
  if (!issuer) errors.push('OIDC_ISSUER is missing');
  else if (issuer.endsWith('/')) warnings.push('OIDC_ISSUER has trailing slash');

  const activeKid = env.OIDC_ACTIVE_KID;
  if (!activeKid) {
    errors.push('OIDC_ACTIVE_KID is missing');
  } else {
    const pemEnv = `OIDC_SIGNING_KEY_${activeKid.toUpperCase()}_PEM`;
    if (!env[pemEnv]) {
      errors.push(`${pemEnv} is missing (active kid has no PEM)`);
    }
  }

  // Storage. STORAGE defaults to sqlite per server.ts.
  const storageRaw = (env.STORAGE ?? 'sqlite').toLowerCase();
  if (!VALID_STORAGE.has(storageRaw)) {
    errors.push(`STORAGE must be one of ${[...VALID_STORAGE].join('|')} (got "${env.STORAGE}")`);
  } else if (storageRaw === 'sqlite') {
    if (!env.SQLITE_PATH) {
      warnings.push('SQLITE_PATH is unset (server will default to ./data/oidc-bridge.sqlite)');
    }
  } else if (storageRaw === 'pg') {
    if (!env.DATABASE_URL) {
      errors.push('STORAGE=pg requires DATABASE_URL');
    }
  }

  // Master keys.
  const provider = env.MASTER_KEY_PROVIDER;
  if (!provider) {
    errors.push('MASTER_KEY_PROVIDER is missing');
  } else if (!VALID_PROVIDERS.has(provider)) {
    errors.push(
      `MASTER_KEY_PROVIDER must be one of ${[...VALID_PROVIDERS].join('|')} (got "${provider}")`,
    );
  } else if (provider === 'file' && !env.MASTER_KEY_DIR) {
    errors.push('MASTER_KEY_PROVIDER=file requires MASTER_KEY_DIR');
  }

  if (errors.length > 0) {
    return { name: 'env', state: 'red', detail: errors.join('; ') };
  }
  if (warnings.length > 0) {
    return { name: 'env', state: 'yellow', detail: warnings.join('; ') };
  }
  return { name: 'env', state: 'green', detail: 'all required envs present and well-formed' };
}
