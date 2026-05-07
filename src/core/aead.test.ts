import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { nodeAead } from '../runtime/node-aead.js';
import type { Aead } from './aead.js';
import { webCryptoAead } from './aead.js';
import { fromUtf8 } from './bytes.js';

const IMPLS: Array<[string, Aead]> = [
  ['webCryptoAead', webCryptoAead],
  ['nodeAead', nodeAead],
];

describe.each(IMPLS)('%s', (_name, aead) => {
  function makeKey(): Uint8Array {
    return new Uint8Array(randomBytes(32));
  }
  function makeIv(): Uint8Array {
    return new Uint8Array(randomBytes(12));
  }

  it('round-trip: seal then open returns plaintext', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('test-aad');
    const plaintext = fromUtf8('hello interop world');

    const { ciphertext, tag } = await aead.seal({ key, iv, aad, plaintext });
    const result = await aead.open({ key, iv, aad, ciphertext, tag });

    expect(result).toEqual(plaintext);
  });

  it('wrong key fails', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('aad');
    const plaintext = fromUtf8('secret');

    const { ciphertext, tag } = await aead.seal({ key, iv, aad, plaintext });
    const wrongKey = makeKey();

    await expect(aead.open({ key: wrongKey, iv, aad, ciphertext, tag })).rejects.toThrow();
  });

  it('wrong AAD fails', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('correct-aad');
    const plaintext = fromUtf8('secret');

    const { ciphertext, tag } = await aead.seal({ key, iv, aad, plaintext });
    const wrongAad = fromUtf8('wrong-aad');

    await expect(aead.open({ key, iv, aad: wrongAad, ciphertext, tag })).rejects.toThrow();
  });

  it('tampered tag fails', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('aad');
    const plaintext = fromUtf8('secret');

    const { ciphertext, tag } = await aead.seal({ key, iv, aad, plaintext });
    const tamperedTag = new Uint8Array(tag);
    tamperedTag[0] = (tamperedTag[0]! ^ 0xff) & 0xff;

    await expect(aead.open({ key, iv, aad, ciphertext, tag: tamperedTag })).rejects.toThrow();
  });

  it('tampered ciphertext byte fails', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('aad');
    const plaintext = fromUtf8('secret data long enough');

    const { ciphertext, tag } = await aead.seal({ key, iv, aad, plaintext });
    const tamperedCt = new Uint8Array(ciphertext);
    tamperedCt[0] = (tamperedCt[0]! ^ 0x01) & 0xff;

    await expect(aead.open({ key, iv, aad, ciphertext: tamperedCt, tag })).rejects.toThrow();
  });

  it('tampered IV fails', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('aad');
    const plaintext = fromUtf8('secret');

    const { ciphertext, tag } = await aead.seal({ key, iv, aad, plaintext });
    const tamperedIv = new Uint8Array(iv);
    tamperedIv[0] = (tamperedIv[0]! ^ 0xff) & 0xff;

    await expect(aead.open({ key, iv: tamperedIv, aad, ciphertext, tag })).rejects.toThrow();
  });

  it('empty plaintext round-trips', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('aad');
    const plaintext = new Uint8Array(0);

    const { ciphertext, tag } = await aead.seal({ key, iv, aad, plaintext });
    const result = await aead.open({ key, iv, aad, ciphertext, tag });

    expect(result).toEqual(plaintext);
  });

  it('empty AAD round-trips', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = new Uint8Array(0);
    const plaintext = fromUtf8('data with empty aad');

    const { ciphertext, tag } = await aead.seal({ key, iv, aad, plaintext });
    const result = await aead.open({ key, iv, aad, ciphertext, tag });

    expect(result).toEqual(plaintext);
  });
});

describe('cross-impl interop', () => {
  function makeKey(): Uint8Array {
    return new Uint8Array(randomBytes(32));
  }
  function makeIv(): Uint8Array {
    return new Uint8Array(randomBytes(12));
  }

  it('seal with Node, open with WebCrypto', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('cross-impl-aad');
    const plaintext = fromUtf8('interop payload sealed by Node');

    const { ciphertext, tag } = await nodeAead.seal({ key, iv, aad, plaintext });
    const result = await webCryptoAead.open({ key, iv, aad, ciphertext, tag });

    expect(result).toEqual(plaintext);
  });

  it('seal with WebCrypto, open with Node', async () => {
    const key = makeKey();
    const iv = makeIv();
    const aad = fromUtf8('cross-impl-aad');
    const plaintext = fromUtf8('interop payload sealed by WebCrypto');

    const { ciphertext, tag } = await webCryptoAead.seal({ key, iv, aad, plaintext });
    const result = await nodeAead.open({ key, iv, aad, ciphertext, tag });

    expect(result).toEqual(plaintext);
  });
});
