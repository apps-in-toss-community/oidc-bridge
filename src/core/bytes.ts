const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: false });

export function fromUtf8(s: string): Uint8Array {
  return TEXT_ENCODER.encode(s);
}

export function toUtf8(u: Uint8Array): string {
  return TEXT_DECODER.decode(u);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Constant-time byte equality. Suitable for comparing secret hashes.
 * Returns false immediately if lengths differ (length is not secret here —
 * all SHA-256 hashes are 32 bytes, so equal-length is guaranteed in practice).
 */
export function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toBase64Url(u: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]!);
  const std = btoa(bin);
  return std.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(s: string): Uint8Array {
  let std = s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const pad = std.length % 4;
  if (pad === 2) std += '==';
  else if (pad === 3) std += '=';
  else if (pad === 1) throw new Error('fromBase64Url: invalid base64url length');
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const HEX_CHARS = '0123456789abcdef';

export function toHex(u: Uint8Array): string {
  let s = '';
  for (let i = 0; i < u.length; i++) {
    const b = u[i]!;
    s += HEX_CHARS[b >> 4];
    s += HEX_CHARS[b & 0x0f];
  }
  return s;
}

export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('fromHex: odd-length input');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexNibble(s.charCodeAt(i * 2));
    const lo = hexNibble(s.charCodeAt(i * 2 + 1));
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function hexNibble(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10;
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10;
  throw new Error('fromHex: non-hex character');
}
