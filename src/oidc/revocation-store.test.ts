import { describe, expect, it } from 'vitest';
import { createInMemoryRevocationStore } from './revocation-store.js';

describe('InMemoryRevocationStore', () => {
  it('reports unknown tokens as not revoked', () => {
    const s = createInMemoryRevocationStore();
    expect(s.isRevoked({ appId: 'a', token: 'ait_x' })).toBe(false);
  });

  it('marks and reports revoked', () => {
    const s = createInMemoryRevocationStore();
    s.revoke({ appId: 'a', token: 'ait_x' });
    expect(s.isRevoked({ appId: 'a', token: 'ait_x' })).toBe(true);
  });

  it('scopes by appId', () => {
    const s = createInMemoryRevocationStore();
    s.revoke({ appId: 'a', token: 'ait_x' });
    expect(s.isRevoked({ appId: 'b', token: 'ait_x' })).toBe(false);
  });

  it('idempotent on repeat revoke', () => {
    const s = createInMemoryRevocationStore();
    s.revoke({ appId: 'a', token: 'ait_x' });
    s.revoke({ appId: 'a', token: 'ait_x' });
    expect(s.isRevoked({ appId: 'a', token: 'ait_x' })).toBe(true);
  });
});
