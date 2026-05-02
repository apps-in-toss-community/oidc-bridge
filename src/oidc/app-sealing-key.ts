import { deriveSealingKey, type MasterKeyProvider } from '../master-keys/index.js';

export type AppSealingKeyResolver = (input: {
  appId: string;
  sealingKeyVersion: number;
}) => Promise<Buffer>;

export function createAppSealingKeyResolver(opts: {
  provider: MasterKeyProvider;
}): AppSealingKeyResolver {
  return async ({ appId, sealingKeyVersion }) => {
    const masterKey = await opts.provider.getKeyBytes(sealingKeyVersion);
    return deriveSealingKey({ masterKey, appId });
  };
}
