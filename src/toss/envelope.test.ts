import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseTossEnvelope } from './envelope.js';

describe('parseTossEnvelope', () => {
  it('parses SUCCESS envelope', () => {
    const raw = readFileSync('src/__fixtures__/toss-generate-token.success.json', 'utf8');
    const result = parseTossEnvelope(JSON.parse(raw));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toMatchObject({ accessToken: expect.any(String) });
    }
  });

  it('parses FAIL envelope', () => {
    const raw = readFileSync('src/__fixtures__/toss-generate-token.fail.json', 'utf8');
    const result = parseTossEnvelope(JSON.parse(raw));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('INVALID_AUTHORIZATION_CODE');
    }
  });

  it('rejects unknown resultType', () => {
    expect(() => parseTossEnvelope({ resultType: 'WAT' })).toThrow();
  });

  it('rejects missing success body on SUCCESS', () => {
    expect(() => parseTossEnvelope({ resultType: 'SUCCESS' })).toThrow();
  });
});
