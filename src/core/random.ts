export interface Random {
  bytes(n: number): Uint8Array;
  uuid(): string;
}

export const webCryptoRandom: Random = {
  bytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  },
  uuid() {
    return crypto.randomUUID();
  },
};
