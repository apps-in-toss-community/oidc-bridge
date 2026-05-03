import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { RealTossAdapter } from '../../src/toss/real-adapter.js';

const LIVE = process.env.TOSS_LIVE_TEST === '1';

describe.runIf(LIVE)('RealTossAdapter (live, sandbox)', () => {
  const certPath = process.env.TOSS_LIVE_CERT_PATH;
  const keyPath = process.env.TOSS_LIVE_KEY_PATH;
  const authCode = process.env.TOSS_LIVE_AUTH_CODE;
  const apiBase = process.env.TOSS_API_BASE ?? 'https://apps-in-toss-api.toss.im';

  it('full happy path: generate-token → login-me → access-remove', async () => {
    if (!certPath || !keyPath || !authCode) {
      throw new Error('TOSS_LIVE_CERT_PATH, TOSS_LIVE_KEY_PATH, TOSS_LIVE_AUTH_CODE all required');
    }
    const certPem = readFileSync(certPath, 'utf8');
    const keyPem = readFileSync(keyPath, 'utf8');
    const adapter = new RealTossAdapter({
      apiBase,
      getMtlsMaterial: async () => ({ certPem, keyPem }),
    });
    const ts = await adapter.generateToken({ appId: 'live' }, { authorizationCode: authCode });
    expect(ts.accessToken.length).toBeGreaterThan(20);
    expect(ts.refreshToken.length).toBeGreaterThan(20);
    expect(ts.expiresIn).toBeGreaterThan(0);

    const me = await adapter.loginMe({ appId: 'live' }, { accessToken: ts.accessToken });
    expect(me.userKey).toBeGreaterThan(0);
    expect(me.scope.length).toBeGreaterThan(0);

    await adapter.accessRemove({ appId: 'live' }, { userKey: String(me.userKey) });
  }, 30_000);
});
