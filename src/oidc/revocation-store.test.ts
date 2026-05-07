import { describe, expect, it } from 'vitest';
import { createInMemoryRevocationStore } from './revocation-store.js';

describe('InMemoryRevocationStore', () => {
  it('reports unknown tokens as not revoked', async () => {
    const s = createInMemoryRevocationStore();
    expect(await s.isRevoked({ appId: 'a', token: 'ait_x' })).toBe(false);
  });

  it('marks and reports revoked', async () => {
    const s = createInMemoryRevocationStore();
    await s.revoke({ appId: 'a', token: 'ait_x' });
    expect(await s.isRevoked({ appId: 'a', token: 'ait_x' })).toBe(true);
  });

  it('scopes by appId', async () => {
    const s = createInMemoryRevocationStore();
    await s.revoke({ appId: 'a', token: 'ait_x' });
    expect(await s.isRevoked({ appId: 'b', token: 'ait_x' })).toBe(false);
  });

  it('idempotent on repeat revoke', async () => {
    const s = createInMemoryRevocationStore();
    await s.revoke({ appId: 'a', token: 'ait_x' });
    await s.revoke({ appId: 'a', token: 'ait_x' });
    expect(await s.isRevoked({ appId: 'a', token: 'ait_x' })).toBe(true);
  });
});
