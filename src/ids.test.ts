import { describe, expect, it } from 'vitest';
import { type IdKind, newId } from './ids.js';

describe('newId', () => {
  it.each<[IdKind, string]>([
    ['user', 'user_'],
    ['workspace', 'ws_'],
    ['app', 'app_'],
    ['api_token', 'tok_'],
    ['user_session', 'ses_'],
    ['master_key', 'mk_'],
    ['audit', 'au_'],
  ])('produces a %s id with prefix %s', (kind, prefix) => {
    const id = newId(kind);
    expect(id.startsWith(prefix)).toBe(true);
    expect(id.length).toBeGreaterThan(prefix.length + 8);
  });

  it('produces unique values', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i += 1) seen.add(newId('app'));
    expect(seen.size).toBe(1000);
  });
});
