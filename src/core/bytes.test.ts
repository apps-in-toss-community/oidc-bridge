import { describe, expect, it } from 'vitest';
import {
  concat,
  constantTimeEquals,
  equals,
  fromBase64Url,
  fromHex,
  fromUtf8,
  toBase64Url,
  toHex,
  toUtf8,
} from './bytes.js';

describe('bytes', () => {
  it('fromUtf8 / toUtf8 round-trips ASCII', () => {
    const u = fromUtf8('hello');
    expect(toUtf8(u)).toBe('hello');
  });

  it('fromUtf8 / toUtf8 round-trips multi-byte (Korean + emoji)', () => {
    const u = fromUtf8('hello 토스 ✨');
    expect(toUtf8(u)).toBe('hello 토스 ✨');
  });

  it('fromUtf8 returns a Uint8Array (not Buffer-tagged for Workers)', () => {
    const u = fromUtf8('x');
    expect(u).toBeInstanceOf(Uint8Array);
  });

  it('toBase64Url encodes without padding and url-safe', () => {
    const raw = new Uint8Array([0xff, 0x00, 0xab, 0xcd]);
    const b = toBase64Url(raw);
    expect(b).not.toMatch(/=$/);
    expect(b).not.toMatch(/[+/]/);
  });

  it('toBase64Url / fromBase64Url round-trips', () => {
    const raw = new Uint8Array([0xff, 0x00, 0xab, 0xcd, 0x12, 0x34, 0x56, 0x78]);
    const b = toBase64Url(raw);
    expect(equals(fromBase64Url(b), raw)).toBe(true);
  });

  it('fromBase64Url accepts input with or without padding', () => {
    const raw = new Uint8Array([0x10, 0x20]);
    const b = toBase64Url(raw);
    expect(equals(fromBase64Url(b), raw)).toBe(true);
    expect(equals(fromBase64Url(`${b}==`), raw)).toBe(true);
  });

  it('concat joins multiple Uint8Arrays in order', () => {
    const out = concat(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5]));
    expect(Array.from(out)).toEqual([1, 2, 3, 4, 5]);
  });

  it('concat returns empty array when given no args', () => {
    expect(concat().length).toBe(0);
  });

  it('equals returns true for byte-identical arrays', () => {
    expect(equals(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it('equals returns false for differing length or bytes', () => {
    expect(equals(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(equals(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });

  it('toHex / fromHex round-trip', () => {
    const raw = new Uint8Array([0x00, 0xff, 0x10, 0xab]);
    expect(toHex(raw)).toBe('00ff10ab');
    expect(equals(fromHex('00ff10ab'), raw)).toBe(true);
  });

  it('fromHex accepts upper-case input', () => {
    expect(equals(fromHex('00FF10AB'), new Uint8Array([0x00, 0xff, 0x10, 0xab]))).toBe(true);
  });

  it('fromHex rejects odd-length input', () => {
    expect(() => fromHex('abc')).toThrow();
  });

  it('fromHex rejects non-hex characters', () => {
    expect(() => fromHex('zz')).toThrow();
  });
});

describe('constantTimeEquals', () => {
  it('returns true for byte-identical arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(constantTimeEquals(a, b)).toBe(true);
  });

  it('returns false for different-length arrays', () => {
    expect(constantTimeEquals(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
    expect(constantTimeEquals(new Uint8Array([]), new Uint8Array([0]))).toBe(false);
  });

  it('returns false when one bit differs', () => {
    const a = new Uint8Array([0xff, 0x00, 0xab]);
    const b = new Uint8Array([0xff, 0x01, 0xab]); // one bit flip
    expect(constantTimeEquals(a, b)).toBe(false);
  });

  it('returns true for two empty arrays', () => {
    expect(constantTimeEquals(new Uint8Array([]), new Uint8Array([]))).toBe(true);
  });
});
