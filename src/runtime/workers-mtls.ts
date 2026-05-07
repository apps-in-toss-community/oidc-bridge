import type { MtlsClientFactory } from '../core/mtls.js';

/**
 * Stub MtlsClientFactory for the Workers entry point (Phase 09c).
 *
 * Phase 12c will replace this with a real Cloudflare Workers mTLS binding
 * implementation (env.TOSS_MTLS.fetch(url, init)). Until then the Workers
 * entry compiles and serves all no-mTLS routes (`/healthz`, JWKS, discovery,
 * admin, etc.) but `/oidc/token` returns 501 NOT_IMPLEMENTED.
 */
export function createWorkersStubMtlsFactory(): MtlsClientFactory {
  return {
    async forApp(_appId: string) {
      const err = new Error('mtls_not_implemented_workers_phase_09c');
      (err as Error & { code?: string }).code = 'NOT_IMPLEMENTED';
      throw err;
    },
  };
}
