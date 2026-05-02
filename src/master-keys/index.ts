import { withTtlCache } from './cache.js';
import { createEnvMasterKeyProvider } from './env-provider.js';
import { createFileMasterKeyProvider } from './file-provider.js';
import type { MasterKeyProvider } from './provider.js';

export { deriveSealingKey } from './hkdf.js';
export type { MasterKeyProvider } from './provider.js';

export interface CreateMasterKeyProviderOptions {
  /** Override env-var lookup for tests; defaults to process.env. */
  env?: NodeJS.ProcessEnv;
  ttlMs?: number;
}

export function createMasterKeyProvider(
  opts: CreateMasterKeyProviderOptions = {},
): MasterKeyProvider {
  const env = opts.env ?? process.env;
  const kind = (env.MASTER_KEY_PROVIDER ?? 'env').toLowerCase();

  let inner: MasterKeyProvider;
  if (kind === 'env') {
    inner = createEnvMasterKeyProvider();
  } else if (kind === 'file') {
    const dir = env.MASTER_KEY_DIR;
    if (!dir) {
      throw new Error('createMasterKeyProvider(file): MASTER_KEY_DIR env required');
    }
    inner = createFileMasterKeyProvider({ dir });
  } else {
    throw new Error(`createMasterKeyProvider: unknown MASTER_KEY_PROVIDER=${kind}`);
  }

  const cacheOpts = opts.ttlMs !== undefined ? { ttlMs: opts.ttlMs } : {};
  return withTtlCache(inner, cacheOpts);
}
