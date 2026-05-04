import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { runJwksProbe } from './jwks-probe.js';

function rsaPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}

describe('runJwksProbe', () => {
  it('green for a valid RSA-2048 PEM that signs+verifies', async () => {
    const pem = rsaPem();
    const r = await runJwksProbe({ activeKid: 'k1', signingKeys: { k1: pem } });
    expect(r.state).toBe('green');
  });

  it('red when active kid has no PEM', async () => {
    const r = await runJwksProbe({ activeKid: 'missing', signingKeys: { k1: rsaPem() } });
    expect(r.state).toBe('red');
    expect(r.detail).toContain('missing');
  });

  it('red when PEM is malformed', async () => {
    const r = await runJwksProbe({ activeKid: 'k1', signingKeys: { k1: 'not a pem' } });
    expect(r.state).toBe('red');
  });

  it('reports inactive-kid count when there are extra signing keys', async () => {
    const r = await runJwksProbe({
      activeKid: 'k1',
      signingKeys: { k1: rsaPem(), k2: rsaPem() },
    });
    expect(r.state).toBe('green');
    expect(r.detail).toContain('2 keys');
  });
});
