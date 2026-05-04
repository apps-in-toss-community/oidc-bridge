import { TossUpstreamError } from '../../../src/toss/adapter.js';
import { RealTossAdapter } from '../../../src/toss/real-adapter.js';
import type { ProbeItem } from '../../output.js';

export interface TossProbeOpts {
  apiBase: string;
  certPem: string | undefined;
  keyPem: string | undefined;
  /**
   * Optional Toss access token. Without it the probe still calls /login-me
   * with a placeholder string; a `Toss FAIL` envelope (e.g. INVALID_TOKEN)
   * is treated as a probe success because it proves mTLS handshake worked.
   */
  accessToken?: string;
  fetchImpl?: typeof fetch;
  buildDispatcher?: (opts: { certPem: string; keyPem: string }) => unknown;
}

const PLACEHOLDER_AT = 'doctor_probe_placeholder_at';

export async function runTossProbe(opts: TossProbeOpts): Promise<ProbeItem> {
  if (!opts.certPem || !opts.keyPem) {
    return {
      name: 'toss',
      state: 'yellow',
      detail: 'no sandbox cert/key provided; skipping (use --cert/--key to enable)',
    };
  }
  const certPem = opts.certPem;
  const keyPem = opts.keyPem;
  const adapter = new RealTossAdapter({
    apiBase: opts.apiBase,
    getMtlsMaterial: async () => ({ certPem, keyPem }),
    ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
    ...(opts.buildDispatcher !== undefined ? { buildDispatcher: opts.buildDispatcher } : {}),
  });
  try {
    await adapter.loginMe({ appId: 'doctor' }, { accessToken: opts.accessToken ?? PLACEHOLDER_AT });
    return {
      name: 'toss',
      state: 'green',
      detail: 'login-me SUCCESS (mTLS + access-token both valid)',
    };
  } catch (err) {
    if (err instanceof TossUpstreamError) {
      // FAIL envelopes from /login-me surface here. Their message starts
      // with "Toss FAIL: <CODE>: <message>" — handshake worked, AT was
      // rejected (which is the expected outcome with a placeholder).
      if (err.code === 'invalid_grant' || err.message.includes('Toss FAIL')) {
        return {
          name: 'toss',
          state: 'green',
          detail: `mTLS handshake ok; Toss returned FAIL (${err.message})`,
        };
      }
      // Network / TLS / 5xx → upstream_error without a Toss FAIL marker.
      return {
        name: 'toss',
        state: 'red',
        detail: `mTLS or network failure: ${err.message}`,
      };
    }
    return { name: 'toss', state: 'red', detail: (err as Error).message };
  }
}
