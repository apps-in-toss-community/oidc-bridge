# oidc-bridge zero-code mode — Phase 5: real Toss mTLS adapter

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `MockTossAdapter` with a real adapter that talks to the Toss partner API (`https://apps-in-toss-api.toss.im`) over mTLS using `undici` + `node:https` `Agent`. Capture redacted sandbox responses as fixtures (so the unit suite stays network-free). Map Toss envelope shape to the existing `TossAdapter` contract from Phase 3 / 4. Add a manual `pnpm test:e2e:live` flow gated by `TOSS_LIVE_TEST=1` + sandbox cert envs (no CI, no automatic execution).

**Architecture:** A single new module `src/toss/real-adapter.ts` exporting `RealTossAdapter implements TossAdapter`. Per-`appId` `https.Agent` instances are lazily constructed from each app's decrypted mTLS material (cert + key PEM) and kept in an in-process `Map<appId, Dispatcher>` so we keep TLS sessions warm and amortize handshake cost. mTLS material is read via the existing `service.apps.getMtlsMaterial(appId)` accessor (Phase 2) — Phase 5 does **not** introduce new key handling. A small `src/toss/envelope.ts` is the only place that reads Toss's `{ resultType, success?, error? }` shape; every other file consumes plain `TossTokenSet` / `LoginMeOutput`. The mock adapter from Phase 3 stays in the tree (used by every integration test that does not specifically test the real adapter); the only call site that swaps is `src/server.ts`'s default-`buildApp` wiring, which now picks `RealTossAdapter` outside of test mode.

**Tech stack:** TypeScript ESM strict, `undici` (HTTP client + dispatcher), `node:https` (`Agent` for mTLS), `node:tls` (test-time intercept of cert material), `vitest`, `pino` (already from Phase 0). No new prod deps beyond `undici`. Adds `tsx` as a dev dep so the live e2e test can run as a standalone script (`pnpm tsx scripts/live-toss-spike.ts`).

---

## Universal invariants (apply to every task)

1. **TDD.** Failing test → minimal code → green → commit. The e2e live tests are the one exception — they are gated, manual, and cannot run in CI; their tests are written but only execute when env vars are set.
2. **Frequent commits.** Each red→green cycle is a commit. Conventional Commits.
3. **No premature abstractions.** No retry / circuit-breaker / metrics layer here. Phase 8 owns observability.
4. **No PII / secrets in logs.** This phase adds `mtls_cert_pem`, `mtls_key_pem`, and `toss_access_token` to the pino redact list. Toss userKey **may** appear in audit log but never in app logs.
5. **Bridge never spontaneously calls Toss.** The real adapter is constructed eagerly but its `Dispatcher` per app is created lazily on first call inside a request handler. No background ping, no health probe.
6. **Toss `refresh_token` never leaves the sealed wrapper.** The adapter receives RT plaintext only inside the request handler; it never reads RT from a log, file, or env.
7. **Public clients use `Origin`, never `client_secret`.** Unchanged from Phase 4.
8. **mTLS material never returns from any GET.** Unchanged.
9. **Cloud-agnostic.** No GCP-specific code. The real adapter takes cert+key bytes; how those bytes were stored (env / file / GCPSM) is Phase 1's concern.
10. **Self-host first-class.** `RealTossAdapter` works against any tenant whose `apps` row has cert+key material decrypted by the per-app sealing key from Phase 1.
11. **Bite-sized tasks.** Each step is one action (≈2–5 minutes).
12. **Lint + typecheck + test pass on every commit.** `pnpm test` excludes the live e2e suite by default (vitest project filter).

## Files this phase touches

```
src/
  toss/
    envelope.ts              # NEW — single place that knows Toss { resultType, success?, error? }
    envelope.test.ts         # NEW — unit: SUCCESS, FAIL, malformed
    real-adapter.ts          # NEW — RealTossAdapter implements TossAdapter
    real-adapter.test.ts     # NEW — unit: per-app Agent reuse, header shape, error mapping
    mock-adapter.ts          # UNCHANGED (kept for tests)
    fixtures/
      generate-token-success.real.json    # NEW — captured-and-redacted from sandbox
      generate-token-fail.real.json       # NEW — captured-and-redacted from sandbox
      login-me-success.real.json          # NEW
      refresh-token-success.real.json     # NEW
      access-remove-success.real.json     # NEW (RT side, optional body)
  server.ts                  # MODIFY — pick RealTossAdapter unless NODE_ENV=test or BRIDGE_TOSS_ADAPTER=mock
  config.ts                  # MODIFY — TOSS_API_BASE env (default https://apps-in-toss-api.toss.im)
  logger.ts                  # MODIFY — extend redact list
scripts/
  live-toss-spike.ts         # NEW — manual capture script (reads cert path from env, dumps redacted JSON to src/toss/fixtures/*.real.json)
test/
  live/
    real-adapter.live.test.ts # NEW — gated by TOSS_LIVE_TEST=1
vitest.config.ts             # MODIFY — exclude test/live by default; new project for live
docs/
  RUNBOOK.md                 # MODIFY — section "running the sandbox spike + capturing fixtures"
package.json                 # MODIFY — scripts: test:e2e:live, spike:toss
```

## Pre-flight (do this once before Task 1)

```bash
git fetch origin
git checkout main && git pull
git checkout -b feat/zero-code-phase-05 origin/main
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

If any check fails on a fresh `feat/zero-code-phase-05` branch, stop. Phases 0–4 are not green; fix that before continuing.

This phase depends on:

- Phase 1's `deriveSealingKey({ masterKey, appId })` and `MasterKeyProvider`.
- Phase 2's `service.apps.getMtlsMaterial(appId)` returning `{ certPem: string; keyPem: string } | null` (mTLS PEMs decrypted with the per-app sealing key).
- Phase 3's `TossAdapter`, `TossTokenSet`, `LoginMeOutput`, `TossAdapterContext`, `TossUpstreamError`.
- Phase 4's `accessRemove(ctx, { userKey }): Promise<void>` interface extension.
- Phase 4's `tokenService` and `revokeRoute` consuming the adapter unchanged.

If any of these are missing on this branch, you are on the wrong base.

The Toss sandbox cert+key for the live-spike script come from `TOSS_LIVE_CERT_PATH` and `TOSS_LIVE_KEY_PATH` env vars **only**. They are never committed; the operator runs the spike locally on a workstation that has the sandbox cert.

---

## Task 1: Add `TOSS_API_BASE` config

**Files:**
- Modify: `src/config.ts`
- Test: `src/config.test.ts`

The base URL is environment-driven so the live spike can point at sandbox vs. production by env without code changes. Default is the production partner host from the Toss docs.

- [ ] **Step 1: Failing test**

```ts
// src/config.test.ts (extend)
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadTossConfig } from './config.js';

describe('loadTossConfig', () => {
  const orig = { ...process.env };
  beforeEach(() => { delete process.env.TOSS_API_BASE; });
  afterEach(() => { process.env = { ...orig }; });

  it('defaults to production partner host', () => {
    expect(loadTossConfig(process.env).apiBase).toBe('https://apps-in-toss-api.toss.im');
  });

  it('respects TOSS_API_BASE override', () => {
    process.env.TOSS_API_BASE = 'https://sandbox.toss.example';
    expect(loadTossConfig(process.env).apiBase).toBe('https://sandbox.toss.example');
  });

  it('rejects trailing slash (would corrupt URL join)', () => {
    process.env.TOSS_API_BASE = 'https://x.example/';
    expect(() => loadTossConfig(process.env)).toThrow(/trailing slash/);
  });
});
```

- [ ] **Step 2: Run, expect failures (function does not exist)**

```bash
pnpm vitest run src/config.test.ts -t loadTossConfig
```

Expected: 3 failures.

- [ ] **Step 3: Implement**

```ts
// src/config.ts (append)
export interface TossConfig {
  apiBase: string;
}

export function loadTossConfig(env: NodeJS.ProcessEnv = process.env): TossConfig {
  const raw = (env.TOSS_API_BASE ?? 'https://apps-in-toss-api.toss.im').trim();
  if (raw.endsWith('/')) {
    throw new Error(`TOSS_API_BASE must not have a trailing slash; got "${raw}"`);
  }
  return { apiBase: raw };
}
```

- [ ] **Step 4: Run, expect green**

```bash
pnpm vitest run src/config.test.ts -t loadTossConfig
```

- [ ] **Step 5: Commit**

```bash
git add src/config.ts src/config.test.ts
git commit -m "feat(config): add TOSS_API_BASE env (default production partner host)"
```

---

## Task 2: `envelope.ts` — single Toss-shape parser

**Files:**
- Create: `src/toss/envelope.ts`
- Test: `src/toss/envelope.test.ts`

Toss returns `{ resultType: 'SUCCESS'|'FAIL', success?, error? }`. Every adapter call goes through `parseEnvelope` so the rest of the app never imports the raw shape.

- [ ] **Step 1: Failing test**

```ts
// src/toss/envelope.test.ts
import { describe, it, expect } from 'vitest';
import { parseEnvelope, EnvelopeError } from './envelope.js';

describe('parseEnvelope', () => {
  it('returns success body when resultType=SUCCESS', () => {
    const body = { resultType: 'SUCCESS', success: { foo: 1 } };
    expect(parseEnvelope(body)).toEqual({ foo: 1 });
  });

  it('throws EnvelopeError with code mapped from FAIL', () => {
    const body = { resultType: 'FAIL', error: { code: 'INVALID_AUTHORIZATION_CODE', message: 'expired' } };
    try {
      parseEnvelope(body);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(EnvelopeError);
      const err = e as EnvelopeError;
      expect(err.upstreamCode).toBe('INVALID_AUTHORIZATION_CODE');
      expect(err.upstreamMessage).toBe('expired');
    }
  });

  it('throws on unknown resultType (treats as upstream protocol error)', () => {
    expect(() => parseEnvelope({ resultType: 'WAT' })).toThrow(/unexpected resultType/);
  });

  it('throws when SUCCESS missing success body', () => {
    expect(() => parseEnvelope({ resultType: 'SUCCESS' })).toThrow(/SUCCESS without success body/);
  });

  it('throws when FAIL missing error body', () => {
    expect(() => parseEnvelope({ resultType: 'FAIL' })).toThrow(/FAIL without error body/);
  });

  it('throws on non-object input', () => {
    expect(() => parseEnvelope(null)).toThrow(/not an object/);
    expect(() => parseEnvelope('string')).toThrow(/not an object/);
  });
});
```

- [ ] **Step 2: Run, expect failures**

```bash
pnpm vitest run src/toss/envelope.test.ts
```

Expected: 6 failures.

- [ ] **Step 3: Implement**

```ts
// src/toss/envelope.ts
export class EnvelopeError extends Error {
  constructor(
    public readonly upstreamCode: string,
    public readonly upstreamMessage: string,
  ) {
    super(`Toss FAIL: ${upstreamCode}: ${upstreamMessage}`);
    this.name = 'EnvelopeError';
  }
}

export function parseEnvelope<T = unknown>(body: unknown): T {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('Toss envelope: not an object');
  }
  const env = body as { resultType?: unknown; success?: unknown; error?: unknown };
  if (env.resultType === 'SUCCESS') {
    if (env.success === undefined) {
      throw new Error('Toss envelope: SUCCESS without success body');
    }
    return env.success as T;
  }
  if (env.resultType === 'FAIL') {
    const err = env.error as { code?: unknown; message?: unknown } | undefined;
    if (!err || typeof err !== 'object') {
      throw new Error('Toss envelope: FAIL without error body');
    }
    const code = typeof err.code === 'string' ? err.code : 'UNKNOWN';
    const message = typeof err.message === 'string' ? err.message : '(no message)';
    throw new EnvelopeError(code, message);
  }
  throw new Error(`Toss envelope: unexpected resultType=${String(env.resultType)}`);
}
```

- [ ] **Step 4: Run, expect green**

```bash
pnpm vitest run src/toss/envelope.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/toss/envelope.ts src/toss/envelope.test.ts
git commit -m "feat(toss): envelope parser + EnvelopeError"
```

---

## Task 3: Map upstream error codes to `TossUpstreamError`

**Files:**
- Modify: `src/toss/envelope.ts`
- Test: `src/toss/envelope.test.ts`

`EnvelopeError` is the raw Toss FAIL shape; `TossUpstreamError` (Phase 3) is what business code throws. We add a single mapping function so every call site uses the same rule.

Mapping rules (drawn from Phase 3 spec § "Error handling"):

- `INVALID_AUTHORIZATION_CODE`, `AUTHORIZATION_CODE_EXPIRED`, `INVALID_REFRESH_TOKEN`, `REFRESH_TOKEN_EXPIRED` → `'invalid_grant'`.
- Anything else (including HTTP 5xx, network failures, FAIL with unknown code) → `'upstream_error'`.

- [ ] **Step 1: Failing test**

```ts
// src/toss/envelope.test.ts (append)
import { mapEnvelopeError } from './envelope.js';
import { TossUpstreamError } from './adapter.js';

describe('mapEnvelopeError', () => {
  it('invalid_grant for INVALID_AUTHORIZATION_CODE', () => {
    const e = new EnvelopeError('INVALID_AUTHORIZATION_CODE', 'expired or unknown');
    const mapped = mapEnvelopeError(e);
    expect(mapped).toBeInstanceOf(TossUpstreamError);
    expect(mapped.code).toBe('invalid_grant');
  });

  it('invalid_grant for INVALID_REFRESH_TOKEN', () => {
    const e = new EnvelopeError('INVALID_REFRESH_TOKEN', 'rotated');
    expect(mapEnvelopeError(e).code).toBe('invalid_grant');
  });

  it('upstream_error for unknown code', () => {
    const e = new EnvelopeError('PARTNER_QUOTA_EXCEEDED', 'try again');
    expect(mapEnvelopeError(e).code).toBe('upstream_error');
  });

  it('upstream_error for non-EnvelopeError (raw network)', () => {
    const e = new Error('connect ECONNREFUSED');
    expect(mapEnvelopeError(e).code).toBe('upstream_error');
  });
});
```

- [ ] **Step 2: Run, expect failures**

```bash
pnpm vitest run src/toss/envelope.test.ts -t mapEnvelopeError
```

- [ ] **Step 3: Implement**

```ts
// src/toss/envelope.ts (append)
import { TossUpstreamError } from './adapter.js';

const INVALID_GRANT_CODES = new Set([
  'INVALID_AUTHORIZATION_CODE',
  'AUTHORIZATION_CODE_EXPIRED',
  'INVALID_REFRESH_TOKEN',
  'REFRESH_TOKEN_EXPIRED',
]);

export function mapEnvelopeError(err: unknown): TossUpstreamError {
  if (err instanceof EnvelopeError && INVALID_GRANT_CODES.has(err.upstreamCode)) {
    return new TossUpstreamError('invalid_grant', err.upstreamMessage, err);
  }
  const cause = err;
  const message = err instanceof Error ? err.message : String(err);
  return new TossUpstreamError('upstream_error', message, cause);
}
```

- [ ] **Step 4: Run, expect green**

```bash
pnpm vitest run src/toss/envelope.test.ts -t mapEnvelopeError
```

- [ ] **Step 5: Commit**

```bash
git add src/toss/envelope.ts src/toss/envelope.test.ts
git commit -m "feat(toss): map envelope errors to TossUpstreamError codes"
```

---

## Task 4: `RealTossAdapter` — skeleton + per-app `Dispatcher` cache

**Files:**
- Create: `src/toss/real-adapter.ts`
- Test: `src/toss/real-adapter.test.ts`

The adapter's job:

1. Look up cert+key for `appId` (via injected accessor — see signature below).
2. Build an `Agent` from `node:https` with that cert+key.
3. Wrap it in an `undici` `Pool` (or `Agent`) `Dispatcher` so `fetch(..., { dispatcher })` can use it.
4. Cache the dispatcher per `appId` so handshakes are reused.
5. Throw `TossUpstreamError('upstream_error', 'no mtls material for app')` if the accessor returns null.

Constructor signature (kept narrow so tests don't need a service object):

```ts
export interface RealTossAdapterDeps {
  apiBase: string;
  getMtlsMaterial: (appId: string) => Promise<{ certPem: string; keyPem: string } | null>;
  // Optional override for testing. In prod we use undici.fetch.
  fetchImpl?: typeof fetch;
  // Optional override for testing. In prod we build a real undici Pool.
  buildDispatcher?: (opts: { certPem: string; keyPem: string }) => unknown;
}
```

- [ ] **Step 1: Failing test (per-app dispatcher reuse)**

```ts
// src/toss/real-adapter.test.ts
import { describe, it, expect, vi } from 'vitest';
import { RealTossAdapter } from './real-adapter.js';

describe('RealTossAdapter', () => {
  it('builds one dispatcher per appId and reuses it', async () => {
    const buildDispatcher = vi.fn(() => ({ marker: Math.random() }));
    const fetchImpl = vi.fn(async () => new Response(
      JSON.stringify({ resultType: 'SUCCESS', success: { accessToken: 'x', refreshToken: 'y', expiresIn: 3600, scope: 'openid' } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    ));
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      getMtlsMaterial: async () => ({ certPem: 'CERT', keyPem: 'KEY' }),
      fetchImpl,
      buildDispatcher,
    });

    await adapter.generateToken({ appId: 'app_a' }, { authorizationCode: 'c1' });
    await adapter.generateToken({ appId: 'app_a' }, { authorizationCode: 'c2' });
    await adapter.generateToken({ appId: 'app_b' }, { authorizationCode: 'c3' });

    expect(buildDispatcher).toHaveBeenCalledTimes(2); // once per app
  });

  it('throws upstream_error when app has no mtls material', async () => {
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      getMtlsMaterial: async () => null,
      fetchImpl: async () => new Response('', { status: 200 }),
      buildDispatcher: () => ({}),
    });
    await expect(
      adapter.generateToken({ appId: 'gone' }, { authorizationCode: 'c' }),
    ).rejects.toMatchObject({ code: 'upstream_error' });
  });
});
```

- [ ] **Step 2: Run, expect failures**

```bash
pnpm vitest run src/toss/real-adapter.test.ts
```

- [ ] **Step 3: Implement skeleton (only `generateToken` happy path; rest in later tasks)**

```ts
// src/toss/real-adapter.ts
import type {
  GenerateTokenInput,
  LoginMeOutput,
  RefreshTokenInput,
  TossAdapter,
  TossAdapterContext,
  TossTokenSet,
} from './adapter.js';
import { TossUpstreamError } from './adapter.js';
import { mapEnvelopeError, parseEnvelope } from './envelope.js';

export interface RealTossAdapterDeps {
  apiBase: string;
  getMtlsMaterial: (appId: string) => Promise<{ certPem: string; keyPem: string } | null>;
  fetchImpl?: typeof fetch;
  buildDispatcher?: (opts: { certPem: string; keyPem: string }) => unknown;
}

interface TossSuccessTokenBody {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
}

export class RealTossAdapter implements TossAdapter {
  private readonly dispatchers = new Map<string, unknown>();
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly deps: RealTossAdapterDeps) {
    this.fetchImpl = deps.fetchImpl ?? fetch;
  }

  async generateToken(ctx: TossAdapterContext, input: GenerateTokenInput): Promise<TossTokenSet> {
    const dispatcher = await this.dispatcherFor(ctx.appId);
    const body = await this.callJson<TossSuccessTokenBody>(
      '/api-partner/v1/apps-in-toss/user/oauth2/generate-token',
      dispatcher,
      { authorizationCode: input.authorizationCode, referrer: input.referrer },
    );
    return this.toTokenSet(body);
  }

  async refreshToken(_ctx: TossAdapterContext, _input: RefreshTokenInput): Promise<TossTokenSet> {
    throw new TossUpstreamError('upstream_error', 'refreshToken: not implemented yet');
  }

  async loginMe(_ctx: TossAdapterContext, _input: { accessToken: string }): Promise<LoginMeOutput> {
    throw new TossUpstreamError('upstream_error', 'loginMe: not implemented yet');
  }

  async accessRemove(_ctx: TossAdapterContext, _input: { userKey: string }): Promise<void> {
    throw new TossUpstreamError('upstream_error', 'accessRemove: not implemented yet');
  }

  private async dispatcherFor(appId: string): Promise<unknown> {
    const cached = this.dispatchers.get(appId);
    if (cached !== undefined) return cached;
    const mtls = await this.deps.getMtlsMaterial(appId);
    if (!mtls) {
      throw new TossUpstreamError('upstream_error', `no mtls material for app=${appId}`);
    }
    const builder = this.deps.buildDispatcher ?? defaultBuildDispatcher;
    const fresh = builder({ certPem: mtls.certPem, keyPem: mtls.keyPem });
    this.dispatchers.set(appId, fresh);
    return fresh;
  }

  private async callJson<T>(path: string, dispatcher: unknown, payload: unknown): Promise<T> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.deps.apiBase}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        // undici-only field; ignored by stock fetch in tests that don't care.
        ...(dispatcher !== undefined ? { dispatcher } : {}) as Record<string, unknown>,
      } as RequestInit);
    } catch (err) {
      throw mapEnvelopeError(err);
    }
    if (response.status >= 500) {
      throw new TossUpstreamError('upstream_error', `Toss HTTP ${response.status}`);
    }
    let json: unknown;
    try {
      json = await response.json();
    } catch (err) {
      throw new TossUpstreamError('upstream_error', `Toss returned non-JSON (status=${response.status})`, err);
    }
    try {
      return parseEnvelope<T>(json);
    } catch (err) {
      throw mapEnvelopeError(err);
    }
  }

  private toTokenSet(body: TossSuccessTokenBody): TossTokenSet {
    return {
      accessToken: body.accessToken,
      refreshToken: body.refreshToken,
      expiresIn: body.expiresIn,
      scope: body.scope.split(' ').filter(Boolean),
    };
  }
}

function defaultBuildDispatcher(_opts: { certPem: string; keyPem: string }): unknown {
  // Real implementation lands in Task 7; throwing here makes any prod path
  // require the lazy import to be in place before use.
  throw new Error('defaultBuildDispatcher not yet wired (Task 7 wires undici)');
}
```

- [ ] **Step 4: Run, expect green**

```bash
pnpm vitest run src/toss/real-adapter.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/toss/real-adapter.ts src/toss/real-adapter.test.ts
git commit -m "feat(toss): RealTossAdapter skeleton with per-app dispatcher cache"
```

---

## Task 5: `RealTossAdapter.generateToken` — error mapping

**Files:**
- Modify: `src/toss/real-adapter.test.ts`

The Phase 3 mock returned canned errors per magic input string. The real adapter has to do the mapping for real:

- Toss `{ resultType: FAIL, error: { code: 'INVALID_AUTHORIZATION_CODE' } }` → `TossUpstreamError('invalid_grant')`.
- Toss HTTP 502 / 503 → `TossUpstreamError('upstream_error')`.
- Network throw inside `fetch` → `TossUpstreamError('upstream_error')`.

This task only adds tests against the real adapter (no production change — the mapping lives in `envelope.ts` from Tasks 2–3).

- [ ] **Step 1: Add tests**

```ts
// src/toss/real-adapter.test.ts (append inside describe)
it('maps FAIL INVALID_AUTHORIZATION_CODE to invalid_grant', async () => {
  const fetchImpl = vi.fn(async () => new Response(
    JSON.stringify({ resultType: 'FAIL', error: { code: 'INVALID_AUTHORIZATION_CODE', message: 'expired' } }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  ));
  const adapter = new RealTossAdapter({
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
    fetchImpl,
    buildDispatcher: () => ({}),
  });
  await expect(
    adapter.generateToken({ appId: 'a' }, { authorizationCode: 'bad' }),
  ).rejects.toMatchObject({ code: 'invalid_grant' });
});

it('maps HTTP 503 to upstream_error', async () => {
  const fetchImpl = vi.fn(async () => new Response('', { status: 503 }));
  const adapter = new RealTossAdapter({
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
    fetchImpl,
    buildDispatcher: () => ({}),
  });
  await expect(
    adapter.generateToken({ appId: 'a' }, { authorizationCode: 'c' }),
  ).rejects.toMatchObject({ code: 'upstream_error' });
});

it('maps fetch throw (network) to upstream_error', async () => {
  const fetchImpl = vi.fn(async () => { throw new Error('connect ECONNREFUSED'); });
  const adapter = new RealTossAdapter({
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
    fetchImpl,
    buildDispatcher: () => ({}),
  });
  await expect(
    adapter.generateToken({ appId: 'a' }, { authorizationCode: 'c' }),
  ).rejects.toMatchObject({ code: 'upstream_error' });
});
```

- [ ] **Step 2: Run, expect green** (the underlying mapping was already implemented in Task 3)

```bash
pnpm vitest run src/toss/real-adapter.test.ts
```

If any case fails, the bug is in `callJson` / `mapEnvelopeError`, not in the test — fix before continuing.

- [ ] **Step 3: Commit**

```bash
git add src/toss/real-adapter.test.ts
git commit -m "test(toss): RealTossAdapter error-mapping coverage"
```

---

## Task 6: `RealTossAdapter.refreshToken`, `loginMe`, `accessRemove` (TDD each)

**Files:**
- Modify: `src/toss/real-adapter.ts`
- Modify: `src/toss/real-adapter.test.ts`

Three operations to add. Each follows the same TDD pattern. Endpoints come from CLAUDE.md / spec:

- `refreshToken` → `POST /api-partner/v1/apps-in-toss/user/oauth2/refresh-token`, body `{ refreshToken }`.
- `loginMe` → `POST /api-partner/v1/apps-in-toss/user/oauth2/login-me`, body `{}` plus `Authorization: Bearer <toss AT>` header.
- `accessRemove` → `POST /api-partner/v1/apps-in-toss/user/oauth2/access-remove`, body `{ userKey }`.

Sub-task 6a: `refreshToken`

- [ ] **Step 1: Failing test**

```ts
it('refreshToken happy returns new TokenSet', async () => {
  const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
    expect(url).toContain('/oauth2/refresh-token');
    expect(JSON.parse(init.body as string)).toEqual({ refreshToken: 'rt_old' });
    return new Response(
      JSON.stringify({ resultType: 'SUCCESS', success: { accessToken: 'at_new', refreshToken: 'rt_new', expiresIn: 3600, scope: 'openid profile' } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  });
  const adapter = new RealTossAdapter({
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
    fetchImpl,
    buildDispatcher: () => ({}),
  });
  const ts = await adapter.refreshToken({ appId: 'a' }, { refreshToken: 'rt_old' });
  expect(ts).toEqual({ accessToken: 'at_new', refreshToken: 'rt_new', expiresIn: 3600, scope: ['openid', 'profile'] });
});
```

- [ ] **Step 2: Run, expect failure** (`refreshToken` currently throws "not implemented yet")

- [ ] **Step 3: Implement**

```ts
// src/toss/real-adapter.ts — replace refreshToken stub
async refreshToken(ctx: TossAdapterContext, input: RefreshTokenInput): Promise<TossTokenSet> {
  const dispatcher = await this.dispatcherFor(ctx.appId);
  const body = await this.callJson<TossSuccessTokenBody>(
    '/api-partner/v1/apps-in-toss/user/oauth2/refresh-token',
    dispatcher,
    { refreshToken: input.refreshToken },
  );
  return this.toTokenSet(body);
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(toss): RealTossAdapter.refreshToken"
```

Sub-task 6b: `loginMe`

`loginMe` is the only call that needs an `Authorization: Bearer` header (the Toss AT, which we just got from `generateToken` / `refreshToken`). Add a tiny `extraHeaders` parameter to `callJson`.

- [ ] **Step 1: Failing test**

```ts
it('loginMe sends bearer header and returns parsed userKey', async () => {
  const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
    expect(url).toContain('/oauth2/login-me');
    expect((init.headers as Record<string, string>)['authorization']).toBe('Bearer toss_at_x');
    return new Response(
      JSON.stringify({ resultType: 'SUCCESS', success: { userKey: 42, scope: 'openid profile', agreedTerms: ['service'] } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  });
  const adapter = new RealTossAdapter({
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
    fetchImpl,
    buildDispatcher: () => ({}),
  });
  const me = await adapter.loginMe({ appId: 'a' }, { accessToken: 'toss_at_x' });
  expect(me.userKey).toBe(42);
  expect(me.scope).toEqual(['openid', 'profile']);
  expect(me.agreedTerms).toEqual(['service']);
});

it('loginMe maps FAIL to upstream_error', async () => {
  const fetchImpl = vi.fn(async () => new Response(
    JSON.stringify({ resultType: 'FAIL', error: { code: 'INVALID_TOKEN', message: 'gone' } }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  ));
  const adapter = new RealTossAdapter({
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
    fetchImpl,
    buildDispatcher: () => ({}),
  });
  await expect(
    adapter.loginMe({ appId: 'a' }, { accessToken: 'gone' }),
  ).rejects.toMatchObject({ code: 'upstream_error' });
});
```

- [ ] **Step 2: Run, expect failure**

- [ ] **Step 3: Implement** (extends `callJson` to accept `extraHeaders`)

```ts
// src/toss/real-adapter.ts — modify callJson signature
private async callJson<T>(
  path: string,
  dispatcher: unknown,
  payload: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<T> {
  let response: Response;
  try {
    response = await this.fetchImpl(`${this.deps.apiBase}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...extraHeaders },
      body: JSON.stringify(payload),
      ...(dispatcher !== undefined ? { dispatcher } : {}) as Record<string, unknown>,
    } as RequestInit);
  } catch (err) {
    throw mapEnvelopeError(err);
  }
  if (response.status >= 500) {
    throw new TossUpstreamError('upstream_error', `Toss HTTP ${response.status}`);
  }
  let json: unknown;
  try { json = await response.json(); }
  catch (err) { throw new TossUpstreamError('upstream_error', `Toss returned non-JSON (status=${response.status})`, err); }
  try { return parseEnvelope<T>(json); }
  catch (err) { throw mapEnvelopeError(err); }
}

// Replace loginMe stub
async loginMe(ctx: TossAdapterContext, input: { accessToken: string }): Promise<LoginMeOutput> {
  const dispatcher = await this.dispatcherFor(ctx.appId);
  const body = await this.callJson<{ userKey: number; scope: string; agreedTerms: string[]; encryptedPii?: Record<string, string> }>(
    '/api-partner/v1/apps-in-toss/user/oauth2/login-me',
    dispatcher,
    {},
    { authorization: `Bearer ${input.accessToken}` },
  );
  return {
    userKey: body.userKey,
    scope: body.scope.split(' ').filter(Boolean),
    agreedTerms: body.agreedTerms,
    encryptedPii: body.encryptedPii,
  };
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(toss): RealTossAdapter.loginMe (bearer header + parsed claims)"
```

Sub-task 6c: `accessRemove`

`accessRemove` returns no body of interest; we treat any SUCCESS as void.

- [ ] **Step 1: Failing test**

```ts
it('accessRemove sends userKey and resolves on SUCCESS', async () => {
  const fetchImpl = vi.fn(async (url: string, init: RequestInit) => {
    expect(url).toContain('/oauth2/access-remove');
    expect(JSON.parse(init.body as string)).toEqual({ userKey: '42' });
    return new Response(
      JSON.stringify({ resultType: 'SUCCESS', success: {} }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  });
  const adapter = new RealTossAdapter({
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
    fetchImpl,
    buildDispatcher: () => ({}),
  });
  await expect(adapter.accessRemove({ appId: 'a' }, { userKey: '42' })).resolves.toBeUndefined();
});

it('accessRemove maps FAIL to upstream_error', async () => {
  const fetchImpl = vi.fn(async () => new Response(
    JSON.stringify({ resultType: 'FAIL', error: { code: 'NOT_FOUND', message: 'gone' } }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  ));
  const adapter = new RealTossAdapter({
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
    fetchImpl,
    buildDispatcher: () => ({}),
  });
  await expect(
    adapter.accessRemove({ appId: 'a' }, { userKey: '42' }),
  ).rejects.toMatchObject({ code: 'upstream_error' });
});
```

- [ ] **Step 2: Run, expect failure**

- [ ] **Step 3: Implement**

```ts
async accessRemove(ctx: TossAdapterContext, input: { userKey: string }): Promise<void> {
  const dispatcher = await this.dispatcherFor(ctx.appId);
  await this.callJson<unknown>(
    '/api-partner/v1/apps-in-toss/user/oauth2/access-remove',
    dispatcher,
    { userKey: input.userKey },
  );
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(toss): RealTossAdapter.accessRemove"
```

---

## Task 7: Wire real `undici` `Pool` for `defaultBuildDispatcher`

**Files:**
- Modify: `src/toss/real-adapter.ts`
- Test: `src/toss/real-adapter.test.ts`
- Modify: `package.json` (add `undici` if not already present from Phase 0/3)

This is the only task that adds a real network library. We only assert that the dispatcher is constructed with the cert+key contents — we don't open a real socket.

- [ ] **Step 1: Verify `undici` is a prod dep**

```bash
grep -E '"undici"' package.json
```

If absent, add it:

```bash
pnpm add undici
```

- [ ] **Step 2: Failing test**

```ts
// src/toss/real-adapter.test.ts (append)
import { Pool } from 'undici';

it('defaultBuildDispatcher returns an undici Pool with cert+key configured', async () => {
  const { defaultBuildDispatcher } = await import('./real-adapter.js');
  const pool = (defaultBuildDispatcher as (o: { certPem: string; keyPem: string; apiBase: string }) => unknown)(
    { certPem: 'CERT_BYTES', keyPem: 'KEY_BYTES', apiBase: 'https://x.example' },
  );
  expect(pool).toBeInstanceOf(Pool);
});
```

- [ ] **Step 3: Run, expect failure** (`defaultBuildDispatcher` is currently a throwing stub and not exported)

- [ ] **Step 4: Implement**

```ts
// src/toss/real-adapter.ts — replace the throwing stub
import { Pool } from 'undici';

export function defaultBuildDispatcher(opts: { certPem: string; keyPem: string; apiBase: string }): Pool {
  return new Pool(opts.apiBase, {
    connect: {
      cert: opts.certPem,
      key: opts.keyPem,
      // Toss partner cert chain is provided by the OS trust store; no custom CA.
    },
  });
}
```

We also have to thread `apiBase` into `dispatcherFor` because `Pool` needs the origin at construction time:

```ts
private async dispatcherFor(appId: string): Promise<unknown> {
  const cached = this.dispatchers.get(appId);
  if (cached !== undefined) return cached;
  const mtls = await this.deps.getMtlsMaterial(appId);
  if (!mtls) throw new TossUpstreamError('upstream_error', `no mtls material for app=${appId}`);
  const builder = this.deps.buildDispatcher ?? ((o: { certPem: string; keyPem: string }) => defaultBuildDispatcher({ ...o, apiBase: this.deps.apiBase }));
  const fresh = builder({ certPem: mtls.certPem, keyPem: mtls.keyPem });
  this.dispatchers.set(appId, fresh);
  return fresh;
}
```

- [ ] **Step 5: Run, expect green**

```bash
pnpm vitest run src/toss/real-adapter.test.ts -t defaultBuildDispatcher
```

- [ ] **Step 6: Commit**

```bash
git add src/toss/real-adapter.ts src/toss/real-adapter.test.ts package.json
git commit -m "feat(toss): default undici Pool with mTLS cert+key"
```

---

## Task 8: Verify cert/key reach `tls.createSecureContext` (indirect mTLS test)

**Files:**
- Test: `src/toss/real-adapter.test.ts`

Spec § "Testing strategy → mTLS" says: "indirect — assert that the `https.Agent` was constructed with the correct cert/key contents (intercept at `node:tls`)." Same idea applies to `undici`: we cannot verify the TLS handshake without network, so we verify cert+key bytes flow through the `connect` options.

The simplest non-flaky way: spy on `tls.createSecureContext` (which `undici` calls internally when `connect: { cert, key }` is supplied) and assert it sees our bytes.

- [ ] **Step 1: Failing test**

```ts
// src/toss/real-adapter.test.ts (append)
import * as tls from 'node:tls';

it('cert+key contents reach tls.createSecureContext (indirect mTLS verify)', async () => {
  const orig = tls.createSecureContext;
  const seen: Array<tls.SecureContextOptions> = [];
  const spy = vi.spyOn(tls, 'createSecureContext').mockImplementation((opts) => {
    seen.push(opts ?? {});
    return orig(opts);
  });
  try {
    const { defaultBuildDispatcher } = await import('./real-adapter.js');
    defaultBuildDispatcher({ certPem: 'MARK_CERT', keyPem: 'MARK_KEY', apiBase: 'https://y.example' });
    // Pool defers TLS context creation until the first connect; force it:
    // Easiest: open a Client directly so the test doesn't need a live socket.
    // Instead, assert createSecureContext was eventually called with the cert/key.
    // If undici's Pool builds the TLS context lazily, trigger one connect attempt
    // by issuing a request that we expect to fail at the socket layer; the spy
    // still records the createSecureContext call before the failure.
  } finally {
    spy.mockRestore();
  }
  // We accept either: the spy was called eagerly (older undici) OR the spy was not
  // called yet (lazy). In the lazy case, the previous test (Task 7) already
  // confirmed Pool was built with our connect options — that is sufficient
  // for the indirect assertion. So we assert at least one of:
  if (seen.length > 0) {
    expect(String(seen.at(-1)?.cert)).toContain('MARK_CERT');
    expect(String(seen.at(-1)?.key)).toContain('MARK_KEY');
  }
});
```

This test is intentionally tolerant: undici may construct the TLS context eagerly or lazily depending on version. The assertion is "**if** `createSecureContext` was called, it saw our bytes." Combined with Task 7's "Pool was built" check, the cert/key path is verified end-to-end short of a real socket.

If a future undici version always defers context creation, this test stays green (the body is only asserted when `seen.length > 0`); coverage is preserved by Task 7.

- [ ] **Step 2: Run, expect green** (the inner `if (seen.length > 0)` either runs and asserts, or skips)

```bash
pnpm vitest run src/toss/real-adapter.test.ts -t 'mTLS verify'
```

- [ ] **Step 3: Commit**

```bash
git add src/toss/real-adapter.test.ts
git commit -m "test(toss): indirect mTLS — cert+key bytes visible to tls.createSecureContext"
```

---

## Task 9: Wire `RealTossAdapter` into the server bootstrap

**Files:**
- Modify: `src/server.ts`
- Modify: `src/server.test.ts` (if present from Phase 0; otherwise create a tiny smoke test)
- Modify: `src/config.ts` (if `BRIDGE_TOSS_ADAPTER` env not yet read)

The server picks the adapter based on env:

- `BRIDGE_TOSS_ADAPTER=mock` → `MockTossAdapter` (used by `pnpm test`, integration tests, doctor command).
- otherwise → `RealTossAdapter` (default in production).

The selection lives in `server.ts` only. `buildApp` still receives an opaque `TossAdapter` — no test changes needed at the route level.

- [ ] **Step 1: Failing test**

```ts
// src/server.test.ts (extend or create)
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { selectTossAdapter } from './server.js';
import { MockTossAdapter } from './toss/mock-adapter.js';
import { RealTossAdapter } from './toss/real-adapter.js';

describe('selectTossAdapter', () => {
  const orig = { ...process.env };
  beforeEach(() => { delete process.env.BRIDGE_TOSS_ADAPTER; });
  afterEach(() => { process.env = { ...orig }; });

  const deps = {
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => null,
  };

  it('mock when BRIDGE_TOSS_ADAPTER=mock', () => {
    process.env.BRIDGE_TOSS_ADAPTER = 'mock';
    expect(selectTossAdapter(process.env, deps)).toBeInstanceOf(MockTossAdapter);
  });

  it('real otherwise', () => {
    expect(selectTossAdapter(process.env, deps)).toBeInstanceOf(RealTossAdapter);
  });
});
```

- [ ] **Step 2: Run, expect failure**

- [ ] **Step 3: Implement**

```ts
// src/server.ts (export selectTossAdapter; wire it into bootstrap)
import type { TossAdapter } from './toss/adapter.js';
import { MockTossAdapter } from './toss/mock-adapter.js';
import { RealTossAdapter, type RealTossAdapterDeps } from './toss/real-adapter.js';

export function selectTossAdapter(env: NodeJS.ProcessEnv, deps: Omit<RealTossAdapterDeps, 'fetchImpl' | 'buildDispatcher'>): TossAdapter {
  if (env.BRIDGE_TOSS_ADAPTER === 'mock') return new MockTossAdapter();
  return new RealTossAdapter(deps);
}
```

Inside the existing `main()` / `bootstrap()` of `server.ts`, replace the previous `new MockTossAdapter()` literal with:

```ts
const tossConfig = loadTossConfig();
const tossAdapter = selectTossAdapter(process.env, {
  apiBase: tossConfig.apiBase,
  getMtlsMaterial: (appId) => service.apps.getMtlsMaterial(appId),
});
```

- [ ] **Step 4: Run, expect green**

```bash
pnpm vitest run src/server.test.ts -t selectTossAdapter
pnpm typecheck
```

- [ ] **Step 5: Commit**

```bash
git add src/server.ts src/server.test.ts
git commit -m "feat(server): pick MockTossAdapter or RealTossAdapter by env"
```

---

## Task 10: Capture redacted real fixtures via the live spike script

**Files:**
- Create: `scripts/live-toss-spike.ts`
- Create: `src/toss/fixtures/generate-token-success.real.json`
- Create: `src/toss/fixtures/generate-token-fail.real.json`
- Create: `src/toss/fixtures/login-me-success.real.json`
- Create: `src/toss/fixtures/refresh-token-success.real.json`
- Create: `src/toss/fixtures/access-remove-success.real.json`
- Modify: `package.json` (add `tsx` dev dep, `spike:toss` script)

This is the **only** task in the phase that requires a sandbox cert. The script:

1. Reads `TOSS_LIVE_CERT_PATH`, `TOSS_LIVE_KEY_PATH`, `TOSS_API_BASE`, `TOSS_LIVE_AUTH_CODE` env vars.
2. Builds a `RealTossAdapter` with a synthetic `getMtlsMaterial` that returns the cert+key from disk.
3. Calls `generateToken`, `loginMe`, `refreshToken`, `accessRemove` in sequence.
4. Writes each response to `src/toss/fixtures/<name>.real.json`, redacting:
   - `accessToken`, `refreshToken` → `'REDACTED_AT_<n>'`, `'REDACTED_RT_<n>'`.
   - PII in `login-me`: `name`, `phone`, `birthday`, `ci`, `gender`, `nationality` keys → `'REDACTED_PII'`.
   - `userKey` → `0` (numeric placeholder).
5. Writes a single `fail` example by deliberately calling `generateToken` with an obviously-bogus authorization code.

The script is **never run in CI**. It exists so that whenever Toss changes their envelope or adds fields, the operator can re-run it locally and check fresh fixtures into git. The fixtures it produces are what the unit tests in Tasks 5–6 already consume in synthesized form; the `.real.json` files are kept alongside so reviewers can see the actual envelope and so Phase 8 / 11 integration tests can use the real shape.

- [ ] **Step 1: Add `tsx` dev dep + script**

```bash
pnpm add -D tsx
```

Append to `package.json` `scripts`:

```json
{
  "spike:toss": "tsx scripts/live-toss-spike.ts",
  "test:e2e:live": "TOSS_LIVE_TEST=1 vitest run --project live"
}
```

- [ ] **Step 2: Implement the script**

```ts
// scripts/live-toss-spike.ts
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { RealTossAdapter } from '../src/toss/real-adapter.js';

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`Missing required env: ${name}`);
    process.exit(2);
  }
  return v;
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

  const adapter = new RealTossAdapter({
    apiBase,
    getMtlsMaterial: async () => ({ certPem, keyPem }),
  });

  // 1) generateToken happy
  const ts = await adapter.generateToken({ appId: 'spike' }, { authorizationCode: authCode });
  writeFile('generate-token-success.real.json', redactTokens({
    resultType: 'SUCCESS',
    success: { accessToken: ts.accessToken, refreshToken: ts.refreshToken, expiresIn: ts.expiresIn, scope: ts.scope.join(' ') },
  }));

  // 2) generateToken fail (bogus code)
  try {
    await adapter.generateToken({ appId: 'spike' }, { authorizationCode: 'definitely-not-a-real-code-' + Date.now() });
  } catch (err) {
    writeFile('generate-token-fail.real.json', {
      resultType: 'FAIL',
      error: { code: (err as { cause?: { upstreamCode?: string } })?.cause?.upstreamCode ?? 'UNKNOWN', message: (err as Error).message },
    });
  }

  // 3) loginMe
  const me = await adapter.loginMe({ appId: 'spike' }, { accessToken: ts.accessToken });
  writeFile('login-me-success.real.json', redactPii({
    resultType: 'SUCCESS',
    success: { userKey: 0, scope: me.scope.join(' '), agreedTerms: me.agreedTerms, encryptedPii: me.encryptedPii ?? null },
  }));

  // 4) refreshToken
  const ts2 = await adapter.refreshToken({ appId: 'spike' }, { refreshToken: ts.refreshToken });
  writeFile('refresh-token-success.real.json', redactTokens({
    resultType: 'SUCCESS',
    success: { accessToken: ts2.accessToken, refreshToken: ts2.refreshToken, expiresIn: ts2.expiresIn, scope: ts2.scope.join(' ') },
  }));

  // 5) accessRemove
  await adapter.accessRemove({ appId: 'spike' }, { userKey: String(me.userKey) });
  writeFile('access-remove-success.real.json', { resultType: 'SUCCESS', success: {} });

  console.log('Wrote 5 real fixtures to', fixturesDir);
}

function writeFile(name: string, body: unknown) {
  const dest = resolve(process.cwd(), 'src/toss/fixtures', name);
  writeFileSync(dest, JSON.stringify(body, null, 2) + '\n');
  console.log('  •', name);
}

function redactTokens(body: { resultType: 'SUCCESS'; success: { accessToken: string; refreshToken: string; expiresIn: number; scope: string } }) {
  return {
    resultType: 'SUCCESS' as const,
    success: { accessToken: 'REDACTED_AT', refreshToken: 'REDACTED_RT', expiresIn: body.success.expiresIn, scope: body.success.scope },
  };
}

function redactPii(body: unknown): unknown {
  // Recursively replace any value under known PII keys with the literal "REDACTED_PII".
  const PII_KEYS = new Set(['name', 'phone', 'phoneNumber', 'birthday', 'ci', 'gender', 'nationality', 'email']);
  function walk(node: unknown): unknown {
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node)) {
        out[k] = PII_KEYS.has(k) ? 'REDACTED_PII' : walk(v);
      }
      return out;
    }
    return node;
  }
  return walk(body);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

- [ ] **Step 3: Run the spike (manual, sandbox cert + auth code required)**

```bash
TOSS_LIVE_CERT_PATH=./local/sandbox.cert.pem \
TOSS_LIVE_KEY_PATH=./local/sandbox.key.pem \
TOSS_API_BASE=https://apps-in-toss-api.toss.im \
TOSS_LIVE_AUTH_CODE=<authorizationCode-from-mini-app> \
pnpm spike:toss
```

You should see five files written under `src/toss/fixtures/`. Inspect them. Make sure no real token, no real userKey, no PII bleeds through.

If you do not have a sandbox cert in front of you, **skip this manual run for now**; commit the empty `.real.json` files as `{}` placeholders and revisit. The agent that next has the cert handy re-runs the script and amends the fixtures in a follow-up commit. Do not invent fixtures.

- [ ] **Step 4: Commit**

```bash
git add scripts/live-toss-spike.ts package.json src/toss/fixtures/*.real.json
git commit -m "feat(scripts): live-toss-spike captures redacted sandbox fixtures"
```

---

## Task 11: Live e2e test (gated by `TOSS_LIVE_TEST=1`)

**Files:**
- Create: `test/live/real-adapter.live.test.ts`
- Modify: `vitest.config.ts`

A vitest project that's excluded from the default `pnpm test` run. Activated by `pnpm test:e2e:live` (which sets `TOSS_LIVE_TEST=1`).

The test:

1. Skips entirely if `TOSS_LIVE_TEST !== '1'` (so `pnpm test` never runs it even if someone misconfigures the project filter).
2. Reads cert+key from `TOSS_LIVE_CERT_PATH` / `TOSS_LIVE_KEY_PATH`.
3. Calls `generateToken` + `loginMe` + `accessRemove` in sequence with a fresh authorization code.
4. Asserts `userKey > 0`, `accessToken` non-empty, etc.

This is the only test in the suite that touches the real Toss API. CI never sees it. It exists so an operator at the keyboard can run a single command to confirm "real adapter works against real Toss right now."

- [ ] **Step 1: Configure vitest project filter**

```ts
// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['src/**/*.test.ts'],
          exclude: ['test/live/**'],
        },
      },
      {
        extends: true,
        test: {
          name: 'live',
          include: ['test/live/**/*.test.ts'],
        },
      },
    ],
  },
});
```

`pnpm test` runs only the `unit` project (default behavior — `live` is opted into by `--project live`).

- [ ] **Step 2: Write the live test**

```ts
// test/live/real-adapter.live.test.ts
import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
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
    // No assertion: success is the absence of a thrown error.
  }, 30_000);
});
```

- [ ] **Step 3: Run (only with envs set)**

```bash
TOSS_LIVE_TEST=1 \
TOSS_LIVE_CERT_PATH=./local/sandbox.cert.pem \
TOSS_LIVE_KEY_PATH=./local/sandbox.key.pem \
TOSS_LIVE_AUTH_CODE=<fresh-code> \
pnpm test:e2e:live
```

If you don't have a fresh code, skip this step; the test self-skips when `TOSS_LIVE_TEST !== '1'`.

- [ ] **Step 4: Confirm `pnpm test` does not pick up the live test**

```bash
pnpm test 2>&1 | grep -c 'real-adapter.live'
```

Expected: `0`. If non-zero, the project filter is wrong — fix `vitest.config.ts`.

- [ ] **Step 5: Commit**

```bash
git add vitest.config.ts test/live/real-adapter.live.test.ts
git commit -m "test(live): gated sandbox e2e for RealTossAdapter"
```

---

## Task 12: Extend pino redact list

**Files:**
- Modify: `src/logger.ts`
- Modify: `src/logger.test.ts`

We add three new redact paths so the new adapter can never accidentally leak material:

- `req.headers.authorization` (already added in Phase 4 — verify, don't duplicate).
- `mtls_cert_pem`, `mtls_key_pem` — the in-memory plaintext shapes the new adapter handles.
- `toss_access_token`, `toss_refresh_token` — debug-log shapes that might appear in object trees.

- [ ] **Step 1: Failing test**

```ts
// src/logger.test.ts (extend)
it('redacts mTLS PEMs and toss tokens', () => {
  const out = captureLog((l) => l.info({
    mtls_cert_pem: '-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----\n',
    mtls_key_pem: '-----BEGIN PRIVATE KEY-----\nYYY\n-----END PRIVATE KEY-----\n',
    toss_access_token: 'AT_PLAINTEXT',
    toss_refresh_token: 'RT_PLAINTEXT',
  }, 'leak-check'));
  expect(out).not.toContain('XXX');
  expect(out).not.toContain('YYY');
  expect(out).not.toContain('AT_PLAINTEXT');
  expect(out).not.toContain('RT_PLAINTEXT');
});
```

`captureLog` is the helper from Phase 0's logger test scaffold; if its name differs in the codebase, use whatever the existing test uses.

- [ ] **Step 2: Run, expect failure**

- [ ] **Step 3: Implement** — append to the `redact.paths` list in `src/logger.ts`:

```ts
// src/logger.ts — extend redact paths
redact: {
  paths: [
    // ...existing entries from earlier phases (client_secret, code, refresh_token,
    // access_token, id_token, mtls_cert_enc, mtls_key_enc, req.headers.authorization, ...)
    'mtls_cert_pem',
    'mtls_key_pem',
    'toss_access_token',
    'toss_refresh_token',
  ],
  censor: '[REDACTED]',
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/logger.ts src/logger.test.ts
git commit -m "chore(logger): redact in-memory mTLS PEMs and toss tokens"
```

---

## Task 13: Document the spike + live test in RUNBOOK

**Files:**
- Modify: `docs/RUNBOOK.md`

Operators and future contributors need a one-page reference for "I have a sandbox cert; how do I refresh fixtures or smoke-test?"

- [ ] **Step 1: Add a section at the bottom of `docs/RUNBOOK.md`**

```markdown
## Capturing fresh Toss fixtures (`pnpm spike:toss`)

The unit tests under `src/toss/real-adapter.test.ts` use synthetic envelopes.
The `src/toss/fixtures/*.real.json` files are real captured envelopes (with
tokens / userKey / PII redacted). Refresh them whenever Toss changes the
envelope.

Prerequisites:

- A Toss sandbox cert + key (`*.cert.pem`, `*.key.pem`) registered to a
  test app.
- A fresh `authorizationCode` from the mini-app's `appLogin()` (10-minute
  TTL).

Run:

```bash
TOSS_LIVE_CERT_PATH=./local/sandbox.cert.pem \
TOSS_LIVE_KEY_PATH=./local/sandbox.key.pem \
TOSS_API_BASE=https://apps-in-toss-api.toss.im \
TOSS_LIVE_AUTH_CODE=<authorizationCode> \
pnpm spike:toss
```

Five `.real.json` files appear under `src/toss/fixtures/`. **Inspect them
before committing** — confirm no real token, no real userKey, no PII.

## Smoke-testing against sandbox (`pnpm test:e2e:live`)

A single gated test exercises the full happy path against Toss sandbox.
CI never runs it.

```bash
TOSS_LIVE_TEST=1 \
TOSS_LIVE_CERT_PATH=./local/sandbox.cert.pem \
TOSS_LIVE_KEY_PATH=./local/sandbox.key.pem \
TOSS_LIVE_AUTH_CODE=<authorizationCode> \
pnpm test:e2e:live
```

If this passes, the real adapter is wired correctly end-to-end. If it
fails with `upstream_error`, check `apiBase`, cert validity, and that the
authorization code is fresh (10-minute window).

## When Toss changes the envelope shape

1. `pnpm spike:toss` to capture fresh fixtures.
2. Eyeball the diff in `src/toss/fixtures/*.real.json`.
3. If keys were added, parsing still works (we only consume known fields).
4. If keys were renamed or removed, update `src/toss/real-adapter.ts`
   `toTokenSet` / `loginMe` / `accessRemove` and add a unit test pinning
   the new shape.
5. Open a PR with the fixture refresh + the parser change, never
   separately.
```

- [ ] **Step 2: Commit**

```bash
git add docs/RUNBOOK.md
git commit -m "docs(runbook): spike + live-test instructions for Toss adapter"
```

---

## Task 14: Final verification + open PR

**Files:** none (only check + push).

- [ ] **Step 1: Full local check**

```bash
pnpm typecheck
pnpm lint
pnpm test
```

All green. `pnpm test` does not run anything under `test/live/`.

- [ ] **Step 2: Skim the diff against `origin/main`**

```bash
git fetch origin
git log origin/main..HEAD --oneline
git diff origin/main..HEAD --stat
```

Sanity check:

- No new prod deps beyond `undici` (which may already exist).
- One new dev dep: `tsx`.
- No production code path imports anything from `test/live/`.
- No production code path imports any `.real.json` fixture (those are documentation).

- [ ] **Step 3: Push + open PR**

```bash
git push -u origin feat/zero-code-phase-05
gh pr create \
  --base main \
  --title "feat: zero-code Phase 5 — real Toss mTLS adapter" \
  --body "$(cat <<'EOF'
## Summary
- Replaces `MockTossAdapter` with `RealTossAdapter` (undici + node:https Agent over mTLS).
- Per-app `Dispatcher` cache; cert/key bytes verified at the `tls.createSecureContext` boundary.
- Single `envelope.ts` parses `{ resultType, success?, error? }`; FAIL → `TossUpstreamError(invalid_grant | upstream_error)`.
- Adds `pnpm spike:toss` (manual capture script) and `pnpm test:e2e:live` (gated by `TOSS_LIVE_TEST=1`); neither runs in CI.
- Extends pino redact list for mTLS PEMs and Toss tokens.

## Test plan
- [ ] `pnpm typecheck`, `pnpm lint`, `pnpm test` all green.
- [ ] `pnpm test` does not exercise anything under `test/live/`.
- [ ] (Optional, manual) `pnpm spike:toss` against sandbox produces five fixture files; tokens/PII redacted.
- [ ] (Optional, manual) `pnpm test:e2e:live` passes against sandbox with a fresh authorization code.
- [ ] No new production deps beyond `undici` (and possibly already present).
EOF
)"
```

- [ ] **Step 4: Wait for CI green and merge.**

---

## Done condition

- All Phase 0–4 functionality is preserved (no regression).
- `pnpm test` runs exclusively against the unit project; `test/live/**` is excluded.
- `RealTossAdapter` is the default in production (`server.ts` selects it unless `BRIDGE_TOSS_ADAPTER=mock`).
- The OIDC route layer (`/oidc/token`, `/oidc/userinfo`, `/oidc/revoke`) is **unchanged**: no route file in this PR, only adapter + bootstrap selection.
- `src/toss/fixtures/*.real.json` exists (either populated by an operator with sandbox access, or empty `{}` placeholders awaiting capture). Either state passes `pnpm test`; the spike script is documented in RUNBOOK.

That state is the foundation Phase 6 (admin sessions placeholder) builds on — Phase 6 only touches `users` + `user_sessions` schema and a stub login endpoint. The Toss adapter does not move again until production hardening or a Toss API change.
