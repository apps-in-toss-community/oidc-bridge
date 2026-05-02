import { describe, expect, it } from 'vitest';
import { resolveClientAuth } from './client-auth.js';

describe('resolveClientAuth', () => {
  it('returns public when no Authorization header and no client_secret in body', () => {
    const r = resolveClientAuth({
      authorization: undefined,
      bodyClientId: 'app_abc',
      bodyClientSecret: undefined,
    });
    expect(r).toEqual({ kind: 'public' });
  });

  it('returns confidential from client_secret_basic', () => {
    const auth = `Basic ${Buffer.from('app_abc:s3cret').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: 'app_abc',
      bodyClientSecret: undefined,
    });
    expect(r).toEqual({ kind: 'confidential', clientId: 'app_abc', plainSecret: 's3cret' });
  });

  it('returns confidential from client_secret_basic when body has no client_id', () => {
    const auth = `Basic ${Buffer.from('app_abc:s3cret').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: undefined,
      bodyClientSecret: undefined,
    });
    expect(r).toEqual({ kind: 'confidential', clientId: 'app_abc', plainSecret: 's3cret' });
  });

  it('returns confidential from client_secret_post', () => {
    const r = resolveClientAuth({
      authorization: undefined,
      bodyClientId: 'app_abc',
      bodyClientSecret: 's3cret',
    });
    expect(r).toEqual({ kind: 'confidential', clientId: 'app_abc', plainSecret: 's3cret' });
  });

  it('rejects mixing Basic + body client_secret', () => {
    const auth = `Basic ${Buffer.from('app_abc:s3cret').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: 'app_abc',
      bodyClientSecret: 's3cret',
    });
    expect(r.kind).toBe('invalid');
    if (r.kind === 'invalid') expect(r.reason).toMatch(/multiple/);
  });

  it('rejects Basic when body client_id mismatches Basic-decoded client_id', () => {
    const auth = `Basic ${Buffer.from('app_abc:s3cret').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: 'app_other',
      bodyClientSecret: undefined,
    });
    expect(r.kind).toBe('invalid');
    if (r.kind === 'invalid') expect(r.reason).toMatch(/mismatch/);
  });

  it('rejects malformed Basic (non-base64 chars)', () => {
    const r = resolveClientAuth({
      authorization: 'Basic !!!!',
      bodyClientId: 'app_abc',
      bodyClientSecret: undefined,
    });
    expect(r.kind).toBe('invalid');
  });

  it('rejects Basic without colon', () => {
    const auth = `Basic ${Buffer.from('justaname').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: 'justaname',
      bodyClientSecret: undefined,
    });
    expect(r.kind).toBe('invalid');
  });

  it('ignores non-Basic Authorization (treats as public)', () => {
    const r = resolveClientAuth({
      authorization: 'Bearer ait_xxx',
      bodyClientId: 'app_abc',
      bodyClientSecret: undefined,
    });
    expect(r).toEqual({ kind: 'public' });
  });

  it('treats empty client_secret_post as public (avoids accidental confidential)', () => {
    const r = resolveClientAuth({
      authorization: undefined,
      bodyClientId: 'app_abc',
      bodyClientSecret: '',
    });
    expect(r).toEqual({ kind: 'public' });
  });
});
