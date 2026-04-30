import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';
import type { Config } from './config.js';
import { createFsStore } from './tenants/fs-store.js';

const signingKeyPem = readFileSync('src/__fixtures__/test-signing.key.pem', 'utf8');

async function smokeApp() {
  const dataDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-test-'));
  const store = await createFsStore(dataDir);
  const config: Config = {
    issuer: 'https://x',
    signingKeyPem,
    masterKey: Buffer.alloc(32),
    adminToken: 'a',
    tenantStore: { kind: 'fs', dataDir },
    tossApiBase: 'https://x',
  };
  return createApp({ config, store });
}

describe('GET /healthz', () => {
  it('returns ok', async () => {
    const app = await smokeApp();
    const res = await app.request('/healthz');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok' });
  });
});

describe('legacy /verify is removed', () => {
  it('returns 404', async () => {
    const app = await smokeApp();
    const res = await app.request('/verify', { method: 'POST', body: '{}' });
    expect(res.status).toBe(404);
  });
});
