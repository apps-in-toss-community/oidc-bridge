import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

interface MockSecret {
  name: string;
  versions: { name: string; payload: Buffer; enabled: boolean }[];
  labels: Record<string, string>;
}

function makeMockClient() {
  const secrets = new Map<string, MockSecret>();
  const client = {
    // biome-ignore lint/suspicious/noExplicitAny: mock harness for @google-cloud/secret-manager API surface
    createSecret: vi.fn(async ({ secretId, secret }: any) => {
      const name = `projects/p/secrets/${secretId}`;
      secrets.set(secretId, { name, versions: [], labels: secret?.labels ?? {} });
      return [{ name }];
    }),
    // biome-ignore lint/suspicious/noExplicitAny: mock harness for @google-cloud/secret-manager API surface
    addSecretVersion: vi.fn(async ({ parent, payload }: any) => {
      const id = parent.split('/').pop()!;
      const s = secrets.get(id);
      if (!s) throw new Error(`secret ${id} not found`);
      // Disable previous versions on add.
      for (const v of s.versions) v.enabled = false;
      s.versions.push({
        name: `${parent}/versions/${s.versions.length + 1}`,
        payload: Buffer.from(payload.data),
        enabled: true,
      });
      return [{ name: s.versions.at(-1)!.name }];
    }),
    // biome-ignore lint/suspicious/noExplicitAny: mock harness for @google-cloud/secret-manager API surface
    accessSecretVersion: vi.fn(async ({ name }: any) => {
      const id = name.split('/')[3];
      const s = secrets.get(id);
      if (!s) {
        // biome-ignore lint/suspicious/noExplicitAny: mock harness for @google-cloud/secret-manager API surface
        const err: any = new Error('NOT_FOUND');
        err.code = 5;
        throw err;
      }
      const enabled = s.versions.find((v) => v.enabled);
      if (!enabled) throw new Error(`no enabled version for ${id}`);
      return [{ payload: { data: enabled.payload } }];
    }),
    // biome-ignore lint/suspicious/noExplicitAny: mock harness for @google-cloud/secret-manager API surface
    listSecretsAsync: vi.fn(async function* ({ parent: _parent, filter: _filter }: any) {
      for (const s of secrets.values()) yield s;
    }),
    // biome-ignore lint/suspicious/noExplicitAny: mock harness for @google-cloud/secret-manager API surface
    deleteSecret: vi.fn(async ({ name }: any) => {
      const id = name.split('/').pop()!;
      secrets.delete(id);
    }),
    projectPath: (p: string) => `projects/${p}`,
  };
  return { client, secrets };
}

describe('gcpsm-store', () => {
  it('round-trips create + get + delete via mocked SecretManagerServiceClient', async () => {
    vi.resetModules();
    const { client, secrets } = makeMockClient();
    vi.doMock('@google-cloud/secret-manager', () => ({
      // Regular function (not arrow) so it can be used with `new`.
      // biome-ignore lint/suspicious/noExplicitAny: mock harness for @google-cloud/secret-manager API surface
      SecretManagerServiceClient: vi.fn(function (this: any) {
        return client;
      }),
    }));
    const { createGcpsmStore } = await import('./gcpsm-store.js');
    const store = await createGcpsmStore('p');

    const { tenant, client_secret } = await store.create({
      name: 't',
      environment: 'sandbox',
      cert_pem: certPem,
      key_pem: keyPem,
    });
    expect(client_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(secrets.has(`oidc-bridge-tenant-${tenant.id}`)).toBe(true);

    const fetched = await store.get(tenant.id);
    expect(fetched).toEqual(tenant);

    await store.delete(tenant.id);
    expect(await store.get(tenant.id)).toBeNull();
  });
});
