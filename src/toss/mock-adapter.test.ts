import { describe, expect, it } from 'vitest';
import { TossUpstreamError } from './adapter.js';
import { MockTossAdapter } from './mock-adapter.js';

describe('MockTossAdapter', () => {
  const adapter = new MockTossAdapter();
  const ctx = { appId: 'app_test' };

  it('generateToken happy path returns parsed token set', async () => {
    const ts = await adapter.generateToken(ctx, { authorizationCode: 'good' });
    expect(ts.accessToken).toBe('TOSS_AT_OPAQUE_FIXTURE');
    expect(ts.refreshToken).toBe('TOSS_RT_OPAQUE_FIXTURE');
    expect(ts.scope).toEqual(['openid', 'profile', 'user_key']);
  });

  it('generateToken fail-code throws invalid_grant', async () => {
    await expect(
      adapter.generateToken(ctx, { authorizationCode: 'fail-code' }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });

  it('generateToken network-error-code throws upstream_error', async () => {
    await expect(
      adapter.generateToken(ctx, { authorizationCode: 'network-error-code' }),
    ).rejects.toMatchObject({ code: 'upstream_error' });
  });

  it('loginMe happy returns userKey + scope', async () => {
    const me = await adapter.loginMe(ctx, { accessToken: 'TOSS_AT_OPAQUE_FIXTURE' });
    expect(me.userKey).toBe(42);
    expect(me.scope).toEqual(['openid', 'profile', 'user_key']);
    expect(me.agreedTerms).toEqual(['service', 'marketing']);
  });

  it('loginMe fail-at throws upstream_error', async () => {
    await expect(adapter.loginMe(ctx, { accessToken: 'fail-at' })).rejects.toBeInstanceOf(
      TossUpstreamError,
    );
  });

  it('refresh happy returns refreshed AT/RT', async () => {
    const ts = await adapter.refreshToken(ctx, { refreshToken: 'TOSS_RT_OPAQUE_FIXTURE' });
    expect(ts.accessToken).toBe('TOSS_AT_OPAQUE_REFRESHED');
    expect(ts.refreshToken).toBe('TOSS_RT_OPAQUE_REFRESHED');
  });

  it('refresh fail-rt throws invalid_grant', async () => {
    await expect(adapter.refreshToken(ctx, { refreshToken: 'fail-rt' })).rejects.toMatchObject({
      code: 'invalid_grant',
    });
  });

  it('accessRemove happy records the call', async () => {
    const a = new MockTossAdapter();
    await a.accessRemove(ctx, { accessToken: 'TOSS_AT_OPAQUE_FIXTURE' });
    expect(a.accessRemoveCalls).toEqual([
      { appId: 'app_test', accessToken: 'TOSS_AT_OPAQUE_FIXTURE' },
    ]);
  });

  it('accessRemove fail-at throws upstream_error', async () => {
    await expect(adapter.accessRemove(ctx, { accessToken: 'fail-at' })).rejects.toMatchObject({
      code: 'upstream_error',
    });
  });
});
