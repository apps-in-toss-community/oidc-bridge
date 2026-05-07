import { describe, expect, it } from 'vitest';
import { equals } from '../core/bytes.js';
import { webCryptoKdf } from '../core/kdf.js';
import { deriveSealingKey } from './hkdf.js';

describe('deriveSealingKey', () => {
  it('is deterministic for the same inputs', async () => {
    const master = Buffer.alloc(32, 0xab);
    const k1 = await deriveSealingKey({ masterKey: master, appId: 'a_1' });
    const k2 = await deriveSealingKey({ masterKey: master, appId: 'a_1' });
    expect(equals(k1, k2)).toBe(true);
    expect(k1).toHaveLength(32);
  });

  it('differs by appId', async () => {
    const master = Buffer.alloc(32, 0xab);
    const k1 = await deriveSealingKey({ masterKey: master, appId: 'a_1' });
    const k2 = await deriveSealingKey({ masterKey: master, appId: 'a_2' });
    expect(equals(k1, k2)).toBe(false);
  });

  it('differs by masterKey', async () => {
    const k1 = await deriveSealingKey({ masterKey: Buffer.alloc(32, 0xab), appId: 'a_1' });
    const k2 = await deriveSealingKey({ masterKey: Buffer.alloc(32, 0xcd), appId: 'a_1' });
    expect(equals(k1, k2)).toBe(false);
  });

  it('rejects master keys shorter than 32 bytes', async () => {
    await expect(deriveSealingKey({ masterKey: Buffer.alloc(16), appId: 'a_1' })).rejects.toThrow(
      /master key must be at least 32 bytes/,
    );
  });

  it('rejects empty appId', async () => {
    await expect(deriveSealingKey({ masterKey: Buffer.alloc(32), appId: '' })).rejects.toThrow(
      /appId required/,
    );
  });

  it('webCryptoKdf injection produces byte-equal output to default (Node)', async () => {
    const master = Buffer.alloc(32, 0xab);
    const nodeOut = await deriveSealingKey({ masterKey: master, appId: 'a_1' });
    const wcOut = await deriveSealingKey({ masterKey: master, appId: 'a_1', kdf: webCryptoKdf });
    expect(equals(nodeOut, wcOut)).toBe(true);
  });
});
