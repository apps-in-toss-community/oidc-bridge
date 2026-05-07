/// <reference types="@cloudflare/workers-types" />

import { generateKeyPairSync } from 'node:crypto';
import { Miniflare } from 'miniflare';
import { describe, expect, it } from 'vitest';
import { runD1Migrations } from '../storage/d1.js';
import workerHandler, { type WorkersEnv } from './workers.js';

/** Generate a fresh RSA PKCS8 PEM for test use. */
function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

/** Build the minimum env required by config loaders. */
async function buildTestEnv(): Promise<Record<string, unknown>> {
  const pem = genPem();
  const mf = new Miniflare({
    modules: true,
    script: 'export default { fetch() { return new Response("ok"); } };',
    d1Databases: { DB: 'workers-smoke-db' },
    d1Persist: false,
  });
  const db = await mf.getD1Database('DB');
  await runD1Migrations(db);

  return {
    _mf: mf,
    DB: db,
    OIDC_ISSUER: 'https://workers-smoke.example',
    OIDC_ACTIVE_KID: 'k1',
    OIDC_SIGNING_KEY_K1_PEM: pem,
    MASTER_KEY_V1_HEX: '00'.repeat(32),
    // Keep rate-limit off so the single-test request isn't blocked
    RATE_LIMIT_ENABLED: 'false',
  };
}

describe('runtime/workers (smoke)', () => {
  it('serves GET /healthz with 200 from Workers entry', async () => {
    const env = await buildTestEnv();
    const mf = env._mf as Miniflare;

    try {
      const res = await workerHandler.fetch(
        new Request('https://workers-smoke.example/healthz'),
        env as WorkersEnv,
        {} as ExecutionContext,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(body.status).toBe('ok');
    } finally {
      await mf.dispose();
    }
  });

  it('returns 501 for POST /oidc/token (mTLS gap — Phase 12c)', async () => {
    const env = await buildTestEnv();
    const mf = env._mf as Miniflare;

    try {
      const res = await workerHandler.fetch(
        new Request('https://workers-smoke.example/oidc/token', {
          method: 'POST',
          body: JSON.stringify({ grant_type: 'authorization_code', code: 'xxx' }),
          headers: { 'content-type': 'application/json' },
        }),
        env as WorkersEnv,
        {} as ExecutionContext,
      );
      expect(res.status).toBe(501);
      const body = (await res.json()) as Record<string, unknown>;
      expect(body.error).toBe('temporarily_unavailable');
    } finally {
      await mf.dispose();
    }
  });
});
