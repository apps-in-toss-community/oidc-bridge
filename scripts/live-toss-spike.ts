import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createNodeMtlsFactory } from '../src/runtime/node-mtls.js';
import { RealTossAdapter } from '../src/toss/real-adapter.js';

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`Missing required env: ${name}`);
    process.exit(2);
  }
  return v;
}

const PII_KEYS = new Set([
  'name',
  'phone',
  'phoneNumber',
  'birthday',
  'ci',
  'gender',
  'nationality',
  'email',
]);

function redactPii(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(redactPii);
  if (node && typeof node === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) {
      out[k] = PII_KEYS.has(k) ? 'REDACTED_PII' : redactPii(v);
    }
    return out;
  }
  return node;
}

function writeFixture(name: string, body: unknown) {
  const dest = resolve(process.cwd(), 'src/toss/fixtures', name);
  writeFileSync(dest, `${JSON.stringify(body, null, 2)}\n`);
  console.log('  •', name);
}

async function main() {
  const certPath = requireEnv('TOSS_LIVE_CERT_PATH');
  const keyPath = requireEnv('TOSS_LIVE_KEY_PATH');
  const apiBase = process.env.TOSS_API_BASE ?? 'https://apps-in-toss-api.toss.im';
  const authCode = requireEnv('TOSS_LIVE_AUTH_CODE');
  const certPem = readFileSync(certPath, 'utf8');
  const keyPem = readFileSync(keyPath, 'utf8');

  const fixturesDir = resolve(process.cwd(), 'src/toss/fixtures');
  mkdirSync(fixturesDir, { recursive: true });

  const mtlsFactory = createNodeMtlsFactory({
    apiBase,
    getMtlsMaterial: async () => ({ certPem, keyPem }),
  });
  const adapter = new RealTossAdapter({ apiBase, mtlsFactory });

  const ts = await adapter.generateToken({ appId: 'spike' }, { authorizationCode: authCode });
  writeFixture('generate-token-success.real.json', {
    resultType: 'SUCCESS',
    success: {
      accessToken: 'REDACTED_AT',
      refreshToken: 'REDACTED_RT',
      expiresIn: ts.expiresIn,
      scope: ts.scope.join(' '),
    },
  });

  try {
    await adapter.generateToken(
      { appId: 'spike' },
      { authorizationCode: `definitely-not-a-real-code-${Date.now()}` },
    );
  } catch (err) {
    const upstreamCode =
      (err as { cause?: { upstreamCode?: string } })?.cause?.upstreamCode ?? 'UNKNOWN';
    writeFixture('generate-token-fail.real.json', {
      resultType: 'FAIL',
      error: { code: upstreamCode, message: (err as Error).message },
    });
  }

  const me = await adapter.loginMe({ appId: 'spike' }, { accessToken: ts.accessToken });
  writeFixture(
    'login-me-success.real.json',
    redactPii({
      resultType: 'SUCCESS',
      success: {
        userKey: 0,
        scope: me.scope.join(' '),
        agreedTerms: me.agreedTerms,
        encryptedPii: me.encryptedPii ?? null,
      },
    }),
  );

  const ts2 = await adapter.refreshToken({ appId: 'spike' }, { refreshToken: ts.refreshToken });
  writeFixture('refresh-token-success.real.json', {
    resultType: 'SUCCESS',
    success: {
      accessToken: 'REDACTED_AT',
      refreshToken: 'REDACTED_RT',
      expiresIn: ts2.expiresIn,
      scope: ts2.scope.join(' '),
    },
  });

  await adapter.accessRemove({ appId: 'spike' }, { userKey: String(me.userKey) });
  writeFixture('access-remove-success.real.json', { resultType: 'SUCCESS', success: {} });

  console.log('Wrote 5 real fixtures to', fixturesDir);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
