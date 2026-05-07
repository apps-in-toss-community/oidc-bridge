import { Pool } from 'undici';
import type { MtlsClient, MtlsClientFactory, MtlsMaterial } from '../core/mtls.js';

export interface CreateNodeMtlsFactoryDeps {
  apiBase: string;
  getMtlsMaterial: (appId: string) => Promise<MtlsMaterial | null>;
  /** Override for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export function createNodeMtlsFactory(deps: CreateNodeMtlsFactoryDeps): MtlsClientFactory {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const cache = new Map<string, MtlsClient>();
  return {
    async forApp(appId: string): Promise<MtlsClient> {
      const hit = cache.get(appId);
      if (hit) return hit;
      const mtls = await deps.getMtlsMaterial(appId);
      if (!mtls) throw new Error(`MtlsClient(node): no mtls material for app=${appId}`);
      const dispatcher = new Pool(deps.apiBase, {
        connect: { cert: mtls.certPem, key: mtls.keyPem },
      });
      const client: MtlsClient = {
        async request(url, init) {
          return fetchImpl(url, {
            ...init,
            ...({ dispatcher } as Record<string, unknown>),
          } as RequestInit);
        },
      };
      cache.set(appId, client);
      return client;
    },
  };
}
