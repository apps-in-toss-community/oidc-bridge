export interface Digest {
  digest(algo: 'SHA-256', input: Uint8Array): Promise<Uint8Array>;
}

export const webCryptoDigest: Digest = {
  async digest(_algo, input) {
    // Ensure we have a view over a plain ArrayBuffer (not SharedArrayBuffer).
    const view =
      input.buffer instanceof ArrayBuffer
        ? input
        : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    const buf = await crypto.subtle.digest('SHA-256', view as unknown as ArrayBuffer);
    return new Uint8Array(buf);
  },
};
