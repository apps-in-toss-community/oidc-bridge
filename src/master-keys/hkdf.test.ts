import { describe, expect, it } from 'vitest';
import { deriveSealingKey } from './hkdf.js';

describe('deriveSealingKey', () => {
  it('is deterministic for the same inputs', () => {
    const master = Buffer.alloc(32, 0xab);
    const k1 = deriveSealingKey({ masterKey: master, appId: 'a_1' });
    const k2 = deriveSealingKey({ masterKey: master, appId: 'a_1' });
    expect(k1.equals(k2)).toBe(true);
    expect(k1).toHaveLength(32);
  });

  it('differs by appId', () => {
    const master = Buffer.alloc(32, 0xab);
    const k1 = deriveSealingKey({ masterKey: master, appId: 'a_1' });
    const k2 = deriveSealingKey({ masterKey: master, appId: 'a_2' });
    expect(k1.equals(k2)).toBe(false);
  });

  it('differs by masterKey', () => {
    const k1 = deriveSealingKey({ masterKey: Buffer.alloc(32, 0xab), appId: 'a_1' });
    const k2 = deriveSealingKey({ masterKey: Buffer.alloc(32, 0xcd), appId: 'a_1' });
    expect(k1.equals(k2)).toBe(false);
  });

  it('rejects master keys shorter than 32 bytes', () => {
    expect(() => deriveSealingKey({ masterKey: Buffer.alloc(16), appId: 'a_1' })).toThrow(
      /master key must be at least 32 bytes/,
    );
  });

  it('rejects empty appId', () => {
    expect(() => deriveSealingKey({ masterKey: Buffer.alloc(32), appId: '' })).toThrow(
      /appId required/,
    );
  });
});
