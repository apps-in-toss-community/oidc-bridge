import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { recordHealthz, resetLastHealthz } from './last-healthz.js';
import { runStatusProbes } from './probes.js';

function rsaPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}

describe('runStatusProbes', () => {
  let dir: string;
  let sqlitePath: string;
  const pem = rsaPem();
  const savedKeyHex = process.env.MASTER_KEY_1_HEX;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-status-'));
    sqlitePath = join(dir, 'test.db');
    process.env.MASTER_KEY_1_HEX = '00'.repeat(32);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    if (savedKeyHex === undefined) delete process.env.MASTER_KEY_1_HEX;
    else process.env.MASTER_KEY_1_HEX = savedKeyHex;
  });

  it('returns four named probes (db, master-key, jwks, last-healthz)', async () => {
    resetLastHealthz();
    recordHealthz();
    const items = await runStatusProbes({
      db: { storage: 'sqlite', sqlitePath },
      masterKey: { provider: 'env', version: 1 },
      jwks: { activeKid: 'k1', signingKeys: { k1: pem } },
    });
    const names = items.map((i) => i.name).sort();
    expect(names).toEqual(['db', 'jwks', 'last-healthz', 'master-key']);
  });

  it('last-healthz is yellow when never hit', async () => {
    resetLastHealthz();
    const items = await runStatusProbes({
      db: { storage: 'sqlite', sqlitePath },
      masterKey: { provider: 'env', version: 1 },
      jwks: { activeKid: 'k1', signingKeys: { k1: pem } },
    });
    expect(items.find((i) => i.name === 'last-healthz')?.state).toBe('yellow');
  });

  it('last-healthz is green when recent', async () => {
    resetLastHealthz();
    recordHealthz();
    const items = await runStatusProbes({
      db: { storage: 'sqlite', sqlitePath },
      masterKey: { provider: 'env', version: 1 },
      jwks: { activeKid: 'k1', signingKeys: { k1: pem } },
    });
    expect(items.find((i) => i.name === 'last-healthz')?.state).toBe('green');
  });

  it('last-healthz is red when stale (>5 min)', async () => {
    resetLastHealthz();
    recordHealthz(new Date(Date.now() - 6 * 60_000));
    const items = await runStatusProbes({
      db: { storage: 'sqlite', sqlitePath },
      masterKey: { provider: 'env', version: 1 },
      jwks: { activeKid: 'k1', signingKeys: { k1: pem } },
    });
    expect(items.find((i) => i.name === 'last-healthz')?.state).toBe('red');
  });
});
