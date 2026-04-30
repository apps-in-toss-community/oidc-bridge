import { describe, expect, it } from 'vitest';
import { extractClientCredentials } from './client-auth.js';

describe('extractClientCredentials', () => {
  it('reads client_secret_basic header', () => {
    const enc = Buffer.from('tnt_aaaa:secret-xyz').toString('base64');
    const out = extractClientCredentials({
      authorizationHeader: `Basic ${enc}`,
      bodyClientId: undefined,
      bodyClientSecret: undefined,
    });
    expect(out).toEqual({ client_id: 'tnt_aaaa', client_secret: 'secret-xyz' });
  });

  it('reads client_secret_post body fields', () => {
    const out = extractClientCredentials({
      authorizationHeader: undefined,
      bodyClientId: 'tnt_aaaa',
      bodyClientSecret: 'secret-xyz',
    });
    expect(out).toEqual({ client_id: 'tnt_aaaa', client_secret: 'secret-xyz' });
  });

  it('rejects when both methods are present (RFC 6749 §2.3.1)', () => {
    const enc = Buffer.from('tnt_aaaa:secret-xyz').toString('base64');
    expect(() =>
      extractClientCredentials({
        authorizationHeader: `Basic ${enc}`,
        bodyClientId: 'tnt_bbbb',
        bodyClientSecret: 'other',
      }),
    ).toThrow(/multiple/);
  });

  it('returns null when neither method is present', () => {
    expect(
      extractClientCredentials({
        authorizationHeader: undefined,
        bodyClientId: undefined,
        bodyClientSecret: undefined,
      }),
    ).toBeNull();
  });

  it('rejects malformed Basic header', () => {
    expect(() =>
      extractClientCredentials({
        authorizationHeader: 'Basic notbase64!!',
        bodyClientId: undefined,
        bodyClientSecret: undefined,
      }),
    ).toThrow(/basic/i);
  });
});
