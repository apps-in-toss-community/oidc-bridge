import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { encryptColumn } from './apps/encryption.js';
import { deriveSealingKey } from './master-keys/index.js';
import { createMtlsMaterialAccessor, selectTossAdapter } from './server.js';
import type { Storage } from './storage/interface.js';
import type { AppRecord } from './storage/types.js';
import { MockTossAdapter } from './toss/mock-adapter.js';
import { RealTossAdapter } from './toss/real-adapter.js';

describe('selectTossAdapter', () => {
  const orig = { ...process.env };
  beforeEach(() => {
    delete process.env.BRIDGE_TOSS_ADAPTER;
  });
  afterEach(() => {
    process.env = { ...orig };
  });

  const deps = {
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => null,
  };

  it('mock when BRIDGE_TOSS_ADAPTER=mock', () => {
    process.env.BRIDGE_TOSS_ADAPTER = 'mock';
    expect(selectTossAdapter(process.env, deps)).toBeInstanceOf(MockTossAdapter);
  });

  it('real otherwise', () => {
    expect(selectTossAdapter(process.env, deps)).toBeInstanceOf(RealTossAdapter);
  });
});

describe('createMtlsMaterialAccessor', () => {
  it('round-trips: encrypts cert+key into AppRecord, decrypts to PEM strings', async () => {
    const masterKey = randomBytes(32);
    const appId = 'app_test_001';
    const sealingKey = deriveSealingKey({ masterKey, appId });
    const aad = Buffer.from(appId, 'utf8');
    const certPem = '-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----\n';
    const keyPem = '-----BEGIN PRIVATE KEY-----\nGHIJKL\n-----END PRIVATE KEY-----\n';
    const certEnc = encryptColumn({ key: sealingKey, plaintext: Buffer.from(certPem), aad });
    const keyEnc = encryptColumn({ key: sealingKey, plaintext: Buffer.from(keyPem), aad });

    const fakeApp: AppRecord = {
      id: appId,
      sealingKeyVersion: 1,
      mtlsCertEnc: certEnc,
      mtlsKeyEnc: keyEnc,
    } as unknown as AppRecord;
    const storage = { getApp: async (id: string) => (id === appId ? fakeApp : null) } as Storage;

    const accessor = createMtlsMaterialAccessor({
      storage,
      getMasterKey: async () => masterKey,
    });
    const out = await accessor(appId);
    expect(out).toEqual({ certPem, keyPem });
    expect(await accessor('missing')).toBeNull();
  });
});
