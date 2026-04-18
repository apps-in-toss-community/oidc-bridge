import { describe, expect, it } from 'vitest';
import { placeholder } from './server.js';

describe('oidc-bridge', () => {
  it('placeholder returns WIP marker', () => {
    expect(placeholder()).toBe('oidc-bridge (WIP)');
  });
});
