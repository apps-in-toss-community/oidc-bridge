# oidc-bridge zero-code mode — Phase 3: OIDC token endpoint (public client, mock Toss)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up `POST /oidc/token` for `grant_type=authorization_code` and `grant_type=refresh_token` against a **mocked Toss adapter**, plus RS256 id_token signing with JWKS publication and OIDC discovery. Public-client (origin auth) only — confidential-client auth lands in Phase 4. Real Toss mTLS adapter lands in Phase 5.

**Architecture:** A `TossAdapter` interface that this phase implements as `MockTossAdapter` (deterministic fixtures, no network). Sealed `ait_*` tokens use AES-256-GCM with per-app HKDF-derived sealing key (Phase 1's `deriveSealingKey`) and a 1-byte version prefix. RS256 id_tokens are signed by a JWKS-managed RSA-2048 keypair stored as PEM in env (`OIDC_SIGNING_KEY_<kid>_PEM`) with `OIDC_ACTIVE_KID` selecting the active signer; verification accepts any active `kid`. All flows funnel through a `tokenService` that the route handler calls; refresh re-uses the same service.

**Tech stack:** TypeScript ESM strict, Hono 4.x, `jose` (sign + JWKS), `node:crypto` (AES-GCM, HKDF — already from Phase 1), `zod` (already from Phase 2), `vitest`, `pino` (already from Phase 0).

---

## Universal invariants (apply to every task)

1. **TDD.** Failing test → minimal code → green → commit. No "implement the test later" tasks.
2. **Frequent commits.** Each red→green cycle is a commit. Conventional Commits: `feat:` `fix:` `refactor:` `test:` `docs:` `chore:`.
3. **No premature abstractions.** Three duplicate lines is fine. Add a helper when a concrete second caller appears.
4. **No PII / secrets in logs.** The pino redact list (Phase 0) covers `client_secret`, `refresh_token`, `mtls_cert_enc`, `mtls_key_enc`, `code`, `access_token`. This phase adds `id_token` and `code_verifier` to that list.
5. **Bridge never spontaneously calls Toss.** Toss is only called inside an inbound OIDC request handler. (Mock adapter still respects this — it's only invoked from a request path.)
6. **Toss `refresh_token` never leaves the sealed wrapper.** No endpoint, log, or error message exposes it.
7. **Public clients use `Origin`, never `client_secret`.** This phase is public-client only.
8. **mTLS material never returns from any GET.** No GET on apps changes in this phase; the masking established in Phase 2 stands.
9. **Cloud-agnostic.** No GCP-specific code.
10. **Self-host first-class.** RSA keys via `OIDC_SIGNING_KEY_*_PEM` env in self-host; same env names in Cloud Run (Phase 10 will source them from Secret Manager but the app code path is identical).
11. **Bite-sized tasks.** Each step is one action (≈2–5 minutes). If a step looks larger, split it.
12. **Lint + typecheck + test pass on every commit.** Pre-commit hook enforces locally; CI enforces on PRs.

## Files this phase touches

```
src/
  oidc/
    sealed-token.ts        # NEW — wrap/unwrap ait_* opaque tokens
    sealed-token.test.ts   # NEW — roundtrip + tamper rejection
    signing-keys.ts        # NEW — load RSA PEMs from env, expose JWKS + signer
    signing-keys.test.ts   # NEW — JWKS shape + sign+verify roundtrip
    id-token.ts            # NEW — mint id_token with claim mapping
    id-token.test.ts       # NEW — claim mapping + sign+verify
    discovery.ts           # NEW — discovery doc shape from issuer config
    discovery.test.ts      # NEW — shape assertions
    jwks-route.ts          # NEW — GET /.well-known/jwks.json
    discovery-route.ts     # NEW — GET /.well-known/openid-configuration
    token-route.ts         # NEW — POST /oidc/token (public client)
    token-route.test.ts    # NEW — happy + invalid_client + invalid_grant
    token-service.ts       # NEW — orchestrates Toss adapter + sealing + id_token
    token-service.test.ts  # NEW — uses MockTossAdapter
    errors.ts              # NEW — OAuth-shape error mapping helper
  toss/
    adapter.ts             # NEW — TossAdapter interface
    mock-adapter.ts        # NEW — MockTossAdapter (fixtures)
    mock-adapter.test.ts   # NEW — covers SUCCESS + FAIL fixtures
    fixtures/
      generate-token-success.json    # NEW — redacted Toss SUCCESS
      generate-token-fail.json       # NEW — redacted Toss FAIL
      login-me-success.json          # NEW
      refresh-token-success.json     # NEW
  config.ts                # MODIFY — add OIDC issuer + signing key env reads
  app.ts                   # MODIFY — mount discovery, jwks, token routes
```

```
docs/
  RUNBOOK.md               # MODIFY — add "rotating OIDC signing keys"
```

## Pre-flight (do this once before Task 1)

```bash
git fetch origin
git checkout main && git pull
git checkout -b feat/zero-code-phase-03 origin/main
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

If any check fails on a fresh `feat/zero-code-phase-03` branch, stop. Phase 0–2 invariants are not green; fix that before continuing.

This phase depends on Phase 1's `deriveSealingKey({ masterKey, appId })`, the `Storage` interface, and the `MasterKeyProvider`; and Phase 2's `Service` (specifically `service.apps.getByClientId(clientId)`) and audit-log writer. If any of these are missing, you are on the wrong branch.

---

## Task 1: Add OIDC config envs

**Files:**
- Modify: `src/config.ts`
- Test: `src/config.test.ts`

We add five envs:
- `OIDC_ISSUER` — required, e.g. `https://oidc-bridge.aitc.dev`. No trailing slash.
- `OIDC_ACTIVE_KID` — required, e.g. `2026-05-01-a`. Must match a `OIDC_SIGNING_KEY_<kid>_PEM` env.
- `OIDC_SIGNING_KEY_<KID>_PEM` — RSA-2048 private key PEM. One required (the active one); additional accepted-only kids are allowed.
- `ID_TOKEN_TTL_SECONDS` — optional, default `3600` (1h).
- `OIDC_DEFAULT_SCOPE` — optional, default `openid profile user_key`.

- [ ] **Step 1: Add failing test for `loadOidcConfig`**

```ts
// src/config.test.ts (extend existing file)
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadOidcConfig } from './config.js';

describe('loadOidcConfig', () => {
  const orig = { ...process.env };
  beforeEach(() => {
    for (const k of Object.keys(process.env)) {
      if (k.startsWith('OIDC_') || k === 'ID_TOKEN_TTL_SECONDS') delete process.env[k];
    }
  });
  afterEach(() => {
    process.env = { ...orig };
  });

  it('reads issuer + active kid + signing key PEMs', () => {
    process.env.OIDC_ISSUER = 'https://oidc-bridge.aitc.dev';
    process.env.OIDC_ACTIVE_KID = 'k1';
    process.env['OIDC_SIGNING_KEY_K1_PEM'] = '-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n';
    const cfg = loadOidcConfig(process.env);
    expect(cfg.issuer).toBe('https://oidc-bridge.aitc.dev');
    expect(cfg.activeKid).toBe('k1');
    expect(cfg.signingKeys).toEqual([
      { kid: 'k1', pem: '-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n' },
    ]);
    expect(cfg.idTokenTtlSeconds).toBe(3600);
    expect(cfg.defaultScope).toBe('openid profile user_key');
  });

  it('throws when active kid has no PEM', () => {
    process.env.OIDC_ISSUER = 'https://x';
    process.env.OIDC_ACTIVE_KID = 'missing';
    expect(() => loadOidcConfig(process.env)).toThrow(/OIDC_SIGNING_KEY_MISSING_PEM/);
  });

  it('rejects trailing slash in issuer', () => {
    process.env.OIDC_ISSUER = 'https://x/';
    process.env.OIDC_ACTIVE_KID = 'k1';
    process.env['OIDC_SIGNING_KEY_K1_PEM'] = 'pem';
    expect(() => loadOidcConfig(process.env)).toThrow(/trailing slash/);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

```bash
pnpm vitest run src/config.test.ts
```
Expected: FAIL — `loadOidcConfig` not exported.

- [ ] **Step 3: Implement `loadOidcConfig`**

Add to `src/config.ts`:

```ts
export interface SigningKeyEntry {
  kid: string;
  pem: string;
}

export interface OidcConfig {
  issuer: string;
  activeKid: string;
  signingKeys: SigningKeyEntry[];
  idTokenTtlSeconds: number;
  defaultScope: string;
}

export function loadOidcConfig(env: NodeJS.ProcessEnv = process.env): OidcConfig {
  const issuer = req(env, 'OIDC_ISSUER');
  if (issuer.endsWith('/')) {
    throw new Error('OIDC_ISSUER must not have a trailing slash');
  }
  const activeKid = req(env, 'OIDC_ACTIVE_KID');
  const signingKeys: SigningKeyEntry[] = [];
  const prefix = 'OIDC_SIGNING_KEY_';
  const suffix = '_PEM';
  for (const [k, v] of Object.entries(env)) {
    if (!k.startsWith(prefix) || !k.endsWith(suffix) || !v) continue;
    const kid = k.slice(prefix.length, -suffix.length).toLowerCase();
    signingKeys.push({ kid, pem: v });
  }
  const hasActive = signingKeys.some((s) => s.kid === activeKid.toLowerCase());
  if (!hasActive) {
    throw new Error(`OIDC_SIGNING_KEY_MISSING_PEM: no OIDC_SIGNING_KEY_${activeKid.toUpperCase()}_PEM env`);
  }
  const ttl = env.ID_TOKEN_TTL_SECONDS ? Number.parseInt(env.ID_TOKEN_TTL_SECONDS, 10) : 3600;
  if (!Number.isFinite(ttl) || ttl <= 0) throw new Error('ID_TOKEN_TTL_SECONDS must be positive integer');
  const defaultScope = env.OIDC_DEFAULT_SCOPE ?? 'openid profile user_key';
  return { issuer, activeKid: activeKid.toLowerCase(), signingKeys, idTokenTtlSeconds: ttl, defaultScope };
}

function req(env: NodeJS.ProcessEnv, k: string): string {
  const v = env[k];
  if (!v) throw new Error(`${k} required`);
  return v;
}
```

- [ ] **Step 4: Run test, expect pass**

```bash
pnpm vitest run src/config.test.ts
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/config.ts src/config.test.ts
git commit -m "feat(config): load OIDC issuer + multi-kid signing keys"
```

---

## Task 2: Sealed token wrap (no decrypt yet)

**Files:**
- Create: `src/oidc/sealed-token.ts`
- Test: `src/oidc/sealed-token.test.ts`

Format (§5.4 of spec): `ait_<base64url(version || iv || ciphertext || tag)>`. Version 1 byte. AAD = `app_id || toss_user_key || sealing_key_version`.

- [ ] **Step 1: Write failing roundtrip test (wrap only, decrypt asserts later in Task 3)**

```ts
// src/oidc/sealed-token.test.ts
import { describe, it, expect } from 'vitest';
import { wrapSealedToken } from './sealed-token.js';

describe('wrapSealedToken', () => {
  const sealingKey = Buffer.alloc(32, 7); // 32-byte all-7s key
  const payload = {
    appId: 'app_abc',
    tossUserKey: 'u_42',
    tossAt: 'TOSS_AT_OPAQUE',
    tossRt: 'TOSS_RT_OPAQUE',
    tossAtExp: 1735689600,
    issuedAt: 1735686000,
  };

  it('produces ait_-prefixed base64url with version byte 1', () => {
    const token = wrapSealedToken({
      sealingKey,
      sealingKeyVersion: 1,
      payload,
    });
    expect(token).toMatch(/^ait_[A-Za-z0-9_-]+$/);
    const body = token.slice(4);
    const buf = Buffer.from(body, 'base64url');
    expect(buf[0]).toBe(1);
    // 1 (version) + 12 (iv) + ciphertext + 16 (tag) >= 30
    expect(buf.length).toBeGreaterThan(30);
  });

  it('different calls produce different IVs and ciphertexts', () => {
    const t1 = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    const t2 = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    expect(t1).not.toBe(t2);
  });
});
```

- [ ] **Step 2: Run test, expect failure**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `wrapSealedToken`**

```ts
// src/oidc/sealed-token.ts
import { randomBytes, createCipheriv } from 'node:crypto';

export interface SealedPayload {
  appId: string;
  tossUserKey: string;
  tossAt: string;
  tossRt: string;
  tossAtExp: number;   // unix seconds
  issuedAt: number;    // unix seconds
}

export interface WrapInput {
  sealingKey: Buffer;          // 32 bytes (per-app HKDF-derived)
  sealingKeyVersion: number;   // 1..255
  payload: SealedPayload;
}

const VERSION_BYTES = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export function wrapSealedToken(input: WrapInput): string {
  if (input.sealingKey.length !== 32) throw new Error('sealingKey must be 32 bytes');
  if (input.sealingKeyVersion < 1 || input.sealingKeyVersion > 255) {
    throw new Error('sealingKeyVersion must fit in 1 byte');
  }
  const iv = randomBytes(IV_BYTES);
  const aad = buildAad(input.payload.appId, input.payload.tossUserKey, input.sealingKeyVersion);
  const cipher = createCipheriv('aes-256-gcm', input.sealingKey, iv);
  cipher.setAAD(aad);
  const plaintext = Buffer.from(JSON.stringify(input.payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  if (tag.length !== TAG_BYTES) throw new Error('GCM tag length unexpected');
  const versionByte = Buffer.from([input.sealingKeyVersion]);
  const sealed = Buffer.concat([versionByte, iv, ciphertext, tag]);
  return `ait_${sealed.toString('base64url')}`;
}

export function buildAad(appId: string, tossUserKey: string, version: number): Buffer {
  return Buffer.from(`${appId} ${tossUserKey} ${version}`, 'utf8');
}
```

- [ ] **Step 4: Run test, expect pass**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/oidc/sealed-token.ts src/oidc/sealed-token.test.ts
git commit -m "feat(oidc): wrap ait_* sealed tokens with AES-GCM"
```

---

## Task 3: Sealed token unwrap + tamper rejection

**Files:**
- Modify: `src/oidc/sealed-token.ts`
- Modify: `src/oidc/sealed-token.test.ts`

- [ ] **Step 1: Add failing tests**

```ts
// extend src/oidc/sealed-token.test.ts
import { wrapSealedToken, unwrapSealedToken } from './sealed-token.js';

describe('unwrapSealedToken', () => {
  const sealingKey = Buffer.alloc(32, 7);
  const payload = {
    appId: 'app_abc',
    tossUserKey: 'u_42',
    tossAt: 'TOSS_AT_OPAQUE',
    tossRt: 'TOSS_RT_OPAQUE',
    tossAtExp: 1735689600,
    issuedAt: 1735686000,
  };

  it('roundtrips a wrapped token', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    const got = unwrapSealedToken({
      token: tok,
      resolveKey: (version) => {
        expect(version).toBe(1);
        return sealingKey;
      },
      expectedAppId: payload.appId,
      expectedTossUserKey: payload.tossUserKey,
    });
    expect(got).toEqual(payload);
  });

  it('rejects tampered ciphertext', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    const body = Buffer.from(tok.slice(4), 'base64url');
    body[20] ^= 0x01; // flip a byte inside the ciphertext region
    const tampered = `ait_${body.toString('base64url')}`;
    expect(() =>
      unwrapSealedToken({
        token: tampered,
        resolveKey: () => sealingKey,
        expectedAppId: payload.appId,
        expectedTossUserKey: payload.tossUserKey,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });

  it('rejects swap to different app via expectedAppId AAD mismatch', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    expect(() =>
      unwrapSealedToken({
        token: tok,
        resolveKey: () => sealingKey,
        expectedAppId: 'app_other',
        expectedTossUserKey: payload.tossUserKey,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });

  it('rejects token without ait_ prefix', () => {
    expect(() =>
      unwrapSealedToken({
        token: 'notait_abc',
        resolveKey: () => sealingKey,
        expectedAppId: payload.appId,
        expectedTossUserKey: payload.tossUserKey,
      }),
    ).toThrow(/SEALED_TOKEN_BAD_FORMAT/);
  });
});
```

- [ ] **Step 2: Run, expect failure (unwrap missing)**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```

- [ ] **Step 3: Implement `unwrapSealedToken`**

Append to `src/oidc/sealed-token.ts`:

```ts
import { createDecipheriv } from 'node:crypto';

export interface UnwrapInput {
  token: string;
  resolveKey: (sealingKeyVersion: number) => Buffer;
  expectedAppId: string;
  expectedTossUserKey: string;
}

export function unwrapSealedToken(input: UnwrapInput): SealedPayload {
  if (!input.token.startsWith('ait_')) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  let buf: Buffer;
  try {
    buf = Buffer.from(input.token.slice(4), 'base64url');
  } catch {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  if (buf.length < VERSION_BYTES + IV_BYTES + TAG_BYTES + 1) {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  const version = buf[0]!;
  const iv = buf.subarray(VERSION_BYTES, VERSION_BYTES + IV_BYTES);
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(VERSION_BYTES + IV_BYTES, buf.length - TAG_BYTES);
  const key = input.resolveKey(version);
  if (key.length !== 32) throw new Error('SEALED_TOKEN_BAD_KEY');
  const aad = buildAad(input.expectedAppId, input.expectedTossUserKey, version);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  const parsed = JSON.parse(plaintext.toString('utf8')) as SealedPayload;
  if (parsed.appId !== input.expectedAppId || parsed.tossUserKey !== input.expectedTossUserKey) {
    // Should be impossible if AAD bound them — extra defense in depth.
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  return parsed;
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/sealed-token.ts src/oidc/sealed-token.test.ts
git commit -m "feat(oidc): unwrap ait_* sealed tokens with tamper rejection"
```

---

## Task 4: Cross-version replay rejection test

**Files:**
- Modify: `src/oidc/sealed-token.test.ts`

The AAD includes `sealing_key_version`, so wrapping under version=1 cannot be unwrapped under version=2 (AAD mismatch). Lock this down with an explicit test — it's a security invariant.

- [ ] **Step 1: Write failing test** (will already pass since AAD covers this; we're locking the invariant)

```ts
// extend src/oidc/sealed-token.test.ts
it('rejects cross-version replay (v1 wrapper read with v2 key resolver)', () => {
  const v1Key = Buffer.alloc(32, 7);
  const v2Key = Buffer.alloc(32, 9);
  const tok = wrapSealedToken({ sealingKey: v1Key, sealingKeyVersion: 1, payload });
  // The version byte is 1, so resolveKey is called with 1 — but if a malicious
  // caller forged the leading byte to 2, AAD would include version=2 and
  // GCM auth would fail. Simulate by flipping the version byte.
  const body = Buffer.from(tok.slice(4), 'base64url');
  body[0] = 2; // forge version
  const forged = `ait_${body.toString('base64url')}`;
  expect(() =>
    unwrapSealedToken({
      token: forged,
      resolveKey: (v) => (v === 2 ? v2Key : v1Key),
      expectedAppId: payload.appId,
      expectedTossUserKey: payload.tossUserKey,
    }),
  ).toThrow(/SEALED_TOKEN_TAMPERED/);
});
```

- [ ] **Step 2: Run, expect pass (since AAD already binds version)**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```

If it fails, the AAD code is wrong — fix it; do not weaken the test.

- [ ] **Step 3: Commit**

```bash
git add src/oidc/sealed-token.test.ts
git commit -m "test(oidc): lock cross-version replay rejection on sealed tokens"
```

---

## Task 5: Per-app sealing key resolver

**Files:**
- Create: `src/oidc/app-sealing-key.ts`
- Test: `src/oidc/app-sealing-key.test.ts`

Glue between the master-key provider (Phase 1) and `unwrapSealedToken`. Given `(appId, sealingKeyVersion)`, it returns the 32-byte sealing key.

- [ ] **Step 1: Write failing test**

```ts
// src/oidc/app-sealing-key.test.ts
import { describe, it, expect } from 'vitest';
import { createAppSealingKeyResolver } from './app-sealing-key.js';
import { deriveSealingKey } from '../crypto/hkdf.js'; // from Phase 1

describe('createAppSealingKeyResolver', () => {
  it('derives the same key as deriveSealingKey for the matching version', async () => {
    const masterV1 = Buffer.alloc(32, 1);
    const masterV2 = Buffer.alloc(32, 2);
    const provider = {
      async getKeyBytes(version: number) {
        if (version === 1) return masterV1;
        if (version === 2) return masterV2;
        throw new Error('no such version');
      },
      async listVersions() { return [1, 2]; },
    };
    const resolver = createAppSealingKeyResolver({ provider });
    const expected = deriveSealingKey({ masterKey: masterV1, appId: 'app_x' });
    const got = await resolver({ appId: 'app_x', sealingKeyVersion: 1 });
    expect(got.equals(expected)).toBe(true);
  });

  it('throws when provider does not have the version', async () => {
    const provider = {
      async getKeyBytes() { throw new Error('NOT_FOUND'); },
      async listVersions() { return [1]; },
    };
    const resolver = createAppSealingKeyResolver({ provider });
    await expect(resolver({ appId: 'app_x', sealingKeyVersion: 99 })).rejects.toThrow(/NOT_FOUND/);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/app-sealing-key.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/app-sealing-key.ts
import { deriveSealingKey } from '../crypto/hkdf.js';
import type { MasterKeyProvider } from '../crypto/master-key-provider.js';

export interface AppSealingKeyResolver {
  (input: { appId: string; sealingKeyVersion: number }): Promise<Buffer>;
}

export function createAppSealingKeyResolver(opts: { provider: MasterKeyProvider }): AppSealingKeyResolver {
  return async ({ appId, sealingKeyVersion }) => {
    const masterKey = await opts.provider.getKeyBytes(sealingKeyVersion);
    return deriveSealingKey({ masterKey, appId });
  };
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/app-sealing-key.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/app-sealing-key.ts src/oidc/app-sealing-key.test.ts
git commit -m "feat(oidc): per-app sealing key resolver bridging master keys + HKDF"
```

---

## Task 6: Signing-key registry from PEMs

**Files:**
- Create: `src/oidc/signing-keys.ts`
- Test: `src/oidc/signing-keys.test.ts`

Loads the PEMs from `OidcConfig.signingKeys`, exposes a `KeyLike` for the active signer and a JWKS document containing **all** loaded keys (for rotation overlap during JWKS-cache TTL on consumers).

- [ ] **Step 1: Generate a test RSA-2048 PEM at test time**

We don't ship a fixture PEM — tests generate one with `node:crypto.generateKeyPairSync`. This keeps the repo free of cryptographic material.

- [ ] **Step 2: Write failing test**

```ts
// src/oidc/signing-keys.test.ts
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, jwtVerify, createLocalJWKSet } from 'jose';
import { createSigningKeyRegistry } from './signing-keys.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

describe('createSigningKeyRegistry', () => {
  it('exposes the active signer and a JWKS containing every loaded kid', async () => {
    const pemA = genPem();
    const pemB = genPem();
    const reg = await createSigningKeyRegistry({
      activeKid: 'a',
      signingKeys: [
        { kid: 'a', pem: pemA },
        { kid: 'b', pem: pemB },
      ],
    });
    const jwks = reg.jwks();
    expect(jwks.keys.map((k) => k.kid).sort()).toEqual(['a', 'b']);
    for (const k of jwks.keys) {
      expect(k.alg).toBe('RS256');
      expect(k.use).toBe('sig');
      expect(k.kty).toBe('RSA');
    }
    const signed = await new SignJWT({ hello: 'world' })
      .setProtectedHeader({ alg: 'RS256', kid: reg.activeKid })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(reg.activeSigner);
    const set = createLocalJWKSet(jwks);
    const { payload } = await jwtVerify(signed, set);
    expect(payload.hello).toBe('world');
  });

  it('throws when activeKid not in signingKeys', async () => {
    const pem = genPem();
    await expect(
      createSigningKeyRegistry({ activeKid: 'missing', signingKeys: [{ kid: 'a', pem }] }),
    ).rejects.toThrow(/activeKid/);
  });
});
```

- [ ] **Step 3: Run, expect failure**

```bash
pnpm vitest run src/oidc/signing-keys.test.ts
```

- [ ] **Step 4: Install `jose`**

```bash
pnpm add jose@^5
```

(`jose@5` ships ESM-first; verify `node_modules/jose/package.json` has `"type": "module"` after install.)

- [ ] **Step 5: Implement registry**

```ts
// src/oidc/signing-keys.ts
import { importPKCS8, exportJWK, type KeyLike, type JWK } from 'jose';

export interface SigningKeyEntry {
  kid: string;
  pem: string;
}

export interface SigningKeyRegistry {
  activeKid: string;
  activeSigner: KeyLike;
  jwks(): { keys: JWK[] };
}

export async function createSigningKeyRegistry(opts: {
  activeKid: string;
  signingKeys: SigningKeyEntry[];
}): Promise<SigningKeyRegistry> {
  if (!opts.signingKeys.some((s) => s.kid === opts.activeKid)) {
    throw new Error(`activeKid "${opts.activeKid}" not in signingKeys`);
  }
  const loaded: { kid: string; key: KeyLike }[] = [];
  for (const s of opts.signingKeys) {
    const key = await importPKCS8(s.pem, 'RS256');
    loaded.push({ kid: s.kid, key });
  }
  const active = loaded.find((l) => l.kid === opts.activeKid)!;
  const jwksKeys: JWK[] = await Promise.all(
    loaded.map(async ({ kid, key }) => {
      const jwk = await exportJWK(key);
      // exportJWK on a private key yields private params; strip to public.
      return { kid, alg: 'RS256', use: 'sig', kty: jwk.kty, n: jwk.n, e: jwk.e };
    }),
  );
  return {
    activeKid: opts.activeKid,
    activeSigner: active.key,
    jwks: () => ({ keys: jwksKeys }),
  };
}
```

- [ ] **Step 6: Run, expect pass**

```bash
pnpm vitest run src/oidc/signing-keys.test.ts
```

- [ ] **Step 7: Commit**

```bash
git add src/oidc/signing-keys.ts src/oidc/signing-keys.test.ts package.json pnpm-lock.yaml
git commit -m "feat(oidc): RSA signing key registry + JWKS export"
```

---

## Task 7: id_token minting

**Files:**
- Create: `src/oidc/id-token.ts`
- Test: `src/oidc/id-token.test.ts`

Mints the id_token from `(app, tossClaims, now)`. Claim mapping per §6.5 of the M1 spec carried into zero-code mode:
- `sub` = stringified `tossClaims.userKey`
- `iss` = `OIDC_ISSUER`
- `aud` = `app.clientId`
- `iat` = now (s)
- `exp` = now + `idTokenTtlSeconds`
- `nbf` = now
- `provider` = `"toss"`
- `scope` = `tossClaims.scope.join(' ')`
- `toss:userKey` = numeric (preserved type)
- `toss:agreedTerms` = string[] passthrough
- `toss:tossAccessTokenExpiresAt` = `tossAtExp` unix seconds

- [ ] **Step 1: Failing test**

```ts
// src/oidc/id-token.test.ts
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { createSigningKeyRegistry } from './signing-keys.js';
import { mintIdToken } from './id-token.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

describe('mintIdToken', () => {
  it('signs an RS256 JWT with mapped claims', async () => {
    const pem = genPem();
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem }],
    });
    const now = 1735686000;
    const jwt = await mintIdToken({
      issuer: 'https://oidc-bridge.aitc.dev',
      ttlSeconds: 3600,
      registry: reg,
      app: { clientId: 'app_abc' },
      tossClaims: {
        userKey: 42,
        scope: ['openid', 'profile', 'user_key'],
        agreedTerms: ['service'],
        tossAtExp: now + 1800,
      },
      now,
    });
    const { payload, protectedHeader } = await jwtVerify(jwt, createLocalJWKSet(reg.jwks()));
    expect(protectedHeader.alg).toBe('RS256');
    expect(protectedHeader.kid).toBe('k1');
    expect(payload.iss).toBe('https://oidc-bridge.aitc.dev');
    expect(payload.aud).toBe('app_abc');
    expect(payload.sub).toBe('42');
    expect(payload.iat).toBe(now);
    expect(payload.exp).toBe(now + 3600);
    expect(payload.nbf).toBe(now);
    expect(payload.provider).toBe('toss');
    expect(payload.scope).toBe('openid profile user_key');
    expect(payload['toss:userKey']).toBe(42);
    expect(payload['toss:agreedTerms']).toEqual(['service']);
    expect(payload['toss:tossAccessTokenExpiresAt']).toBe(now + 1800);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/id-token.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/id-token.ts
import { SignJWT } from 'jose';
import type { SigningKeyRegistry } from './signing-keys.js';

export interface TossClaimsForIdToken {
  userKey: number;
  scope: string[];
  agreedTerms: string[];
  tossAtExp: number; // unix seconds
}

export interface MintInput {
  issuer: string;
  ttlSeconds: number;
  registry: SigningKeyRegistry;
  app: { clientId: string };
  tossClaims: TossClaimsForIdToken;
  now: number; // unix seconds (injected for testability)
}

export async function mintIdToken(input: MintInput): Promise<string> {
  const exp = input.now + input.ttlSeconds;
  return await new SignJWT({
    provider: 'toss',
    scope: input.tossClaims.scope.join(' '),
    'toss:userKey': input.tossClaims.userKey,
    'toss:agreedTerms': input.tossClaims.agreedTerms,
    'toss:tossAccessTokenExpiresAt': input.tossClaims.tossAtExp,
  })
    .setProtectedHeader({ alg: 'RS256', kid: input.registry.activeKid })
    .setIssuer(input.issuer)
    .setAudience(input.app.clientId)
    .setSubject(String(input.tossClaims.userKey))
    .setIssuedAt(input.now)
    .setNotBefore(input.now)
    .setExpirationTime(exp)
    .sign(input.registry.activeSigner);
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/id-token.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/id-token.ts src/oidc/id-token.test.ts
git commit -m "feat(oidc): mint RS256 id_token with Toss claim mapping"
```

---

## Task 8: OIDC discovery doc + JWKS route

**Files:**
- Create: `src/oidc/discovery.ts`
- Create: `src/oidc/discovery.test.ts`
- Create: `src/oidc/jwks-route.ts`
- Create: `src/oidc/discovery-route.ts`

Exact shape from spec §5.7. `authorization_endpoint` and `response_types_supported` are intentionally omitted.

- [ ] **Step 1: Failing test for `buildDiscovery`**

```ts
// src/oidc/discovery.test.ts
import { describe, it, expect } from 'vitest';
import { buildDiscovery } from './discovery.js';

describe('buildDiscovery', () => {
  it('produces the spec-locked shape', () => {
    const doc = buildDiscovery({ issuer: 'https://oidc-bridge.aitc.dev' });
    expect(doc).toEqual({
      issuer: 'https://oidc-bridge.aitc.dev',
      jwks_uri: 'https://oidc-bridge.aitc.dev/.well-known/jwks.json',
      token_endpoint: 'https://oidc-bridge.aitc.dev/oidc/token',
      userinfo_endpoint: 'https://oidc-bridge.aitc.dev/oidc/userinfo',
      revocation_endpoint: 'https://oidc-bridge.aitc.dev/oidc/revoke',
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
        'none',
      ],
      id_token_signing_alg_values_supported: ['RS256'],
      subject_types_supported: ['public'],
      scopes_supported: ['openid', 'profile', 'user_key'],
      claims_supported: [
        'sub', 'iss', 'aud', 'exp', 'iat', 'nbf',
        'provider', 'scope',
        'toss:userKey', 'toss:agreedTerms', 'toss:tossAccessTokenExpiresAt',
      ],
      code_challenge_methods_supported: ['S256'],
    });
  });

  it('does not include authorization_endpoint or response_types_supported', () => {
    const doc = buildDiscovery({ issuer: 'https://x' }) as Record<string, unknown>;
    expect(doc.authorization_endpoint).toBeUndefined();
    expect(doc.response_types_supported).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/discovery.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/discovery.ts
export interface DiscoveryDoc {
  issuer: string;
  jwks_uri: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  revocation_endpoint: string;
  grant_types_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  id_token_signing_alg_values_supported: string[];
  subject_types_supported: string[];
  scopes_supported: string[];
  claims_supported: string[];
  code_challenge_methods_supported: string[];
}

export function buildDiscovery(opts: { issuer: string }): DiscoveryDoc {
  const i = opts.issuer;
  return {
    issuer: i,
    jwks_uri: `${i}/.well-known/jwks.json`,
    token_endpoint: `${i}/oidc/token`,
    userinfo_endpoint: `${i}/oidc/userinfo`,
    revocation_endpoint: `${i}/oidc/revoke`,
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'none',
    ],
    id_token_signing_alg_values_supported: ['RS256'],
    subject_types_supported: ['public'],
    scopes_supported: ['openid', 'profile', 'user_key'],
    claims_supported: [
      'sub', 'iss', 'aud', 'exp', 'iat', 'nbf',
      'provider', 'scope',
      'toss:userKey', 'toss:agreedTerms', 'toss:tossAccessTokenExpiresAt',
    ],
    code_challenge_methods_supported: ['S256'],
  };
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/discovery.test.ts
```

- [ ] **Step 5: Implement discovery route**

```ts
// src/oidc/discovery-route.ts
import { Hono } from 'hono';
import { buildDiscovery } from './discovery.js';

export function discoveryRoute(opts: { issuer: string }) {
  const app = new Hono();
  app.get('/.well-known/openid-configuration', (c) => c.json(buildDiscovery({ issuer: opts.issuer })));
  return app;
}
```

- [ ] **Step 6: Implement JWKS route**

```ts
// src/oidc/jwks-route.ts
import { Hono } from 'hono';
import type { SigningKeyRegistry } from './signing-keys.js';

export function jwksRoute(opts: { registry: SigningKeyRegistry }) {
  const app = new Hono();
  app.get('/.well-known/jwks.json', (c) => {
    c.header('cache-control', 'public, max-age=300');
    return c.json(opts.registry.jwks());
  });
  return app;
}
```

- [ ] **Step 7: Commit**

```bash
git add src/oidc/discovery.ts src/oidc/discovery.test.ts src/oidc/discovery-route.ts src/oidc/jwks-route.ts
git commit -m "feat(oidc): discovery + JWKS routes"
```

---

## Task 9: Wire discovery + JWKS into app, integration-test the shape

**Files:**
- Modify: `src/app.ts`
- Test: `src/app.test.ts` (extend) or create `src/oidc/discovery-route.test.ts`

- [ ] **Step 1: Failing integration test (Hono `app.request`)**

```ts
// src/oidc/discovery-route.test.ts
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { buildApp } from '../app.js';
import { createSigningKeyRegistry } from './signing-keys.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

describe('discovery + jwks integration', () => {
  it('serves both endpoints with consistent jwks_uri', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const app = await buildApp({
      // minimal seam — buildApp will accept these in the next step
      oidcConfig: {
        issuer: 'https://oidc-bridge.aitc.dev',
        activeKid: 'k1',
        signingKeys: [],
        idTokenTtlSeconds: 3600,
        defaultScope: 'openid profile user_key',
      },
      signingKeyRegistry: reg,
    } as any); // until buildApp signature is updated below
    const disc = await app.request('/.well-known/openid-configuration');
    expect(disc.status).toBe(200);
    const discJson = await disc.json();
    expect(discJson.jwks_uri).toBe('https://oidc-bridge.aitc.dev/.well-known/jwks.json');
    const jwks = await app.request('/.well-known/jwks.json');
    expect(jwks.status).toBe(200);
    const jwksJson = await jwks.json();
    expect(jwksJson.keys[0].kid).toBe('k1');
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/discovery-route.test.ts
```

- [ ] **Step 3: Update `buildApp` to accept `oidcConfig` + `signingKeyRegistry`**

In `src/app.ts`, extend the existing `BuildAppOpts` (Phase 0/2) and mount the routes. Keep the existing admin + healthz mounts unchanged.

```ts
// src/app.ts (additions)
import { discoveryRoute } from './oidc/discovery-route.js';
import { jwksRoute } from './oidc/jwks-route.js';
import type { OidcConfig } from './config.js';
import type { SigningKeyRegistry } from './oidc/signing-keys.js';

export interface BuildAppOpts {
  // ... existing fields from Phase 0/2 (logger, service, ...)
  oidcConfig: OidcConfig;
  signingKeyRegistry: SigningKeyRegistry;
}

// Inside buildApp (after admin routes are mounted):
app.route('/', discoveryRoute({ issuer: opts.oidcConfig.issuer }));
app.route('/', jwksRoute({ registry: opts.signingKeyRegistry }));
```

If existing `BuildAppOpts` does not exist as a named type, lift the parameter shape to one now — Phases 4+ rely on this.

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/discovery-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/app.ts src/oidc/discovery-route.test.ts
git commit -m "feat(app): mount OIDC discovery + JWKS routes"
```

---

## Task 10: TossAdapter interface

**Files:**
- Create: `src/toss/adapter.ts`

Defines the contract every adapter (mock + real) must satisfy. Phase 5 swaps the implementation; the rest of the bridge depends only on this interface.

- [ ] **Step 1: Define types (no test yet — pure interface)**

```ts
// src/toss/adapter.ts
export interface GenerateTokenInput {
  authorizationCode: string;
  referrer?: string;
}

export interface TossTokenSet {
  accessToken: string;
  refreshToken: string;
  expiresIn: number; // seconds
  scope: string[];   // already split
}

export interface LoginMeOutput {
  userKey: number;
  scope: string[];
  agreedTerms: string[];
  // Encrypted PII passthrough left for later phases:
  encryptedPii?: Record<string, string>;
}

export interface RefreshTokenInput {
  refreshToken: string;
}

export interface TossAdapterContext {
  appId: string;
  // Phase 5 will use this to look up mTLS material from this app row.
  // Mock adapter ignores it.
}

export interface TossAdapter {
  generateToken(ctx: TossAdapterContext, input: GenerateTokenInput): Promise<TossTokenSet>;
  refreshToken(ctx: TossAdapterContext, input: RefreshTokenInput): Promise<TossTokenSet>;
  loginMe(ctx: TossAdapterContext, input: { accessToken: string }): Promise<LoginMeOutput>;
  // accessRemove + envelope helpers land in later phases.
}

export class TossUpstreamError extends Error {
  constructor(
    public readonly code: 'invalid_grant' | 'upstream_error',
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'TossUpstreamError';
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/toss/adapter.ts
git commit -m "feat(toss): adapter interface + TossUpstreamError"
```

---

## Task 11: MockTossAdapter + fixtures

**Files:**
- Create: `src/toss/fixtures/generate-token-success.json`
- Create: `src/toss/fixtures/generate-token-fail.json`
- Create: `src/toss/fixtures/login-me-success.json`
- Create: `src/toss/fixtures/refresh-token-success.json`
- Create: `src/toss/mock-adapter.ts`
- Test: `src/toss/mock-adapter.test.ts`

The mock keys behavior off the input authorization code:
- `code === 'fail-code'` → throws `TossUpstreamError('invalid_grant', ...)`
- `code === 'network-error-code'` → throws `TossUpstreamError('upstream_error', ...)`
- otherwise → returns the SUCCESS fixture

`refreshToken`:
- input `'fail-rt'` → `invalid_grant`
- otherwise → returns refresh SUCCESS fixture (different AT/RT each call so identity is observable)

`loginMe`:
- input AT === `'fail-at'` → throws `upstream_error`
- otherwise → returns login-me SUCCESS fixture

- [ ] **Step 1: Create the fixture JSON files**

`src/toss/fixtures/generate-token-success.json`:
```json
{
  "resultType": "SUCCESS",
  "success": {
    "accessToken": "TOSS_AT_OPAQUE_FIXTURE",
    "refreshToken": "TOSS_RT_OPAQUE_FIXTURE",
    "expiresIn": 3600,
    "scope": "openid profile user_key"
  }
}
```

`src/toss/fixtures/generate-token-fail.json`:
```json
{
  "resultType": "FAIL",
  "error": {
    "code": "INVALID_AUTHORIZATION_CODE",
    "message": "expired or unknown"
  }
}
```

`src/toss/fixtures/login-me-success.json`:
```json
{
  "resultType": "SUCCESS",
  "success": {
    "userKey": 42,
    "scope": "openid profile user_key",
    "agreedTerms": ["service", "marketing"]
  }
}
```

`src/toss/fixtures/refresh-token-success.json`:
```json
{
  "resultType": "SUCCESS",
  "success": {
    "accessToken": "TOSS_AT_OPAQUE_REFRESHED",
    "refreshToken": "TOSS_RT_OPAQUE_REFRESHED",
    "expiresIn": 3600,
    "scope": "openid profile user_key"
  }
}
```

These are Toss envelope shape (per CLAUDE.md and spec) — Phase 5 captures real redacted responses replacing these.

- [ ] **Step 2: Failing test**

```ts
// src/toss/mock-adapter.test.ts
import { describe, it, expect } from 'vitest';
import { MockTossAdapter } from './mock-adapter.js';
import { TossUpstreamError } from './adapter.js';

describe('MockTossAdapter', () => {
  const adapter = new MockTossAdapter();
  const ctx = { appId: 'app_test' };

  it('generateToken happy path returns parsed token set', async () => {
    const ts = await adapter.generateToken(ctx, { authorizationCode: 'good' });
    expect(ts.accessToken).toBe('TOSS_AT_OPAQUE_FIXTURE');
    expect(ts.refreshToken).toBe('TOSS_RT_OPAQUE_FIXTURE');
    expect(ts.scope).toEqual(['openid', 'profile', 'user_key']);
  });

  it('generateToken fail-code throws invalid_grant', async () => {
    await expect(
      adapter.generateToken(ctx, { authorizationCode: 'fail-code' }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });

  it('generateToken network-error-code throws upstream_error', async () => {
    await expect(
      adapter.generateToken(ctx, { authorizationCode: 'network-error-code' }),
    ).rejects.toMatchObject({ code: 'upstream_error' });
  });

  it('loginMe happy returns userKey + scope', async () => {
    const me = await adapter.loginMe(ctx, { accessToken: 'TOSS_AT_OPAQUE_FIXTURE' });
    expect(me.userKey).toBe(42);
    expect(me.scope).toEqual(['openid', 'profile', 'user_key']);
    expect(me.agreedTerms).toEqual(['service', 'marketing']);
  });

  it('loginMe fail-at throws upstream_error', async () => {
    await expect(adapter.loginMe(ctx, { accessToken: 'fail-at' })).rejects.toBeInstanceOf(TossUpstreamError);
  });

  it('refresh happy returns refreshed AT/RT', async () => {
    const ts = await adapter.refreshToken(ctx, { refreshToken: 'TOSS_RT_OPAQUE_FIXTURE' });
    expect(ts.accessToken).toBe('TOSS_AT_OPAQUE_REFRESHED');
    expect(ts.refreshToken).toBe('TOSS_RT_OPAQUE_REFRESHED');
  });

  it('refresh fail-rt throws invalid_grant', async () => {
    await expect(
      adapter.refreshToken(ctx, { refreshToken: 'fail-rt' }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });
});
```

- [ ] **Step 3: Run, expect failure**

```bash
pnpm vitest run src/toss/mock-adapter.test.ts
```

- [ ] **Step 4: Implement MockTossAdapter**

```ts
// src/toss/mock-adapter.ts
import {
  type TossAdapter,
  type TossAdapterContext,
  type GenerateTokenInput,
  type RefreshTokenInput,
  type TossTokenSet,
  type LoginMeOutput,
  TossUpstreamError,
} from './adapter.js';
import gtSuccess from './fixtures/generate-token-success.json' with { type: 'json' };
import rtSuccess from './fixtures/refresh-token-success.json' with { type: 'json' };
import meSuccess from './fixtures/login-me-success.json' with { type: 'json' };

interface SuccessGenerate { accessToken: string; refreshToken: string; expiresIn: number; scope: string }
interface SuccessLoginMe { userKey: number; scope: string; agreedTerms: string[] }

export class MockTossAdapter implements TossAdapter {
  async generateToken(_ctx: TossAdapterContext, input: GenerateTokenInput): Promise<TossTokenSet> {
    if (input.authorizationCode === 'fail-code') {
      throw new TossUpstreamError('invalid_grant', 'mock fail-code');
    }
    if (input.authorizationCode === 'network-error-code') {
      throw new TossUpstreamError('upstream_error', 'mock network-error-code');
    }
    const s = (gtSuccess as { success: SuccessGenerate }).success;
    return { accessToken: s.accessToken, refreshToken: s.refreshToken, expiresIn: s.expiresIn, scope: s.scope.split(' ') };
  }

  async refreshToken(_ctx: TossAdapterContext, input: RefreshTokenInput): Promise<TossTokenSet> {
    if (input.refreshToken === 'fail-rt') {
      throw new TossUpstreamError('invalid_grant', 'mock fail-rt');
    }
    const s = (rtSuccess as { success: SuccessGenerate }).success;
    return { accessToken: s.accessToken, refreshToken: s.refreshToken, expiresIn: s.expiresIn, scope: s.scope.split(' ') };
  }

  async loginMe(_ctx: TossAdapterContext, input: { accessToken: string }): Promise<LoginMeOutput> {
    if (input.accessToken === 'fail-at') {
      throw new TossUpstreamError('upstream_error', 'mock fail-at');
    }
    const s = (meSuccess as { success: SuccessLoginMe }).success;
    return { userKey: s.userKey, scope: s.scope.split(' '), agreedTerms: s.agreedTerms };
  }
}
```

> Note: `with { type: 'json' }` is the modern import-attribute syntax supported by Node 22+; tsdown handles it. If your tsconfig lacks `"resolveJsonModule": true`, add it now.

- [ ] **Step 5: Run, expect pass**

```bash
pnpm vitest run src/toss/mock-adapter.test.ts
```

- [ ] **Step 6: Commit**

```bash
git add src/toss/mock-adapter.ts src/toss/mock-adapter.test.ts src/toss/fixtures/
git commit -m "feat(toss): mock adapter + redacted Toss fixtures"
```

---

## Task 12: OAuth-shape error helper

**Files:**
- Create: `src/oidc/errors.ts`
- Test: `src/oidc/errors.test.ts`

Maps internal errors to `{ status, body: { error, error_description } }` per spec §8. The route handler calls this; tests on the route assert the result.

- [ ] **Step 1: Failing test**

```ts
// src/oidc/errors.test.ts
import { describe, it, expect } from 'vitest';
import { TossUpstreamError } from '../toss/adapter.js';
import { toOAuthError } from './errors.js';

describe('toOAuthError', () => {
  it('maps invalid_request', () => {
    const r = toOAuthError({ code: 'invalid_request', description: 'missing grant_type' });
    expect(r).toEqual({ status: 400, body: { error: 'invalid_request', error_description: 'missing grant_type' } });
  });

  it('maps invalid_client to 401', () => {
    const r = toOAuthError({ code: 'invalid_client', description: 'unknown client_id' });
    expect(r.status).toBe(401);
    expect(r.body.error).toBe('invalid_client');
  });

  it('maps invalid_grant to 401', () => {
    const r = toOAuthError({ code: 'invalid_grant', description: 'rejected by upstream' });
    expect(r.status).toBe(401);
  });

  it('maps TossUpstreamError(invalid_grant)', () => {
    const e = new TossUpstreamError('invalid_grant', 'fail');
    const r = toOAuthError(e);
    expect(r).toEqual({ status: 401, body: { error: 'invalid_grant', error_description: 'fail' } });
  });

  it('maps TossUpstreamError(upstream_error) to 502', () => {
    const e = new TossUpstreamError('upstream_error', 'net');
    const r = toOAuthError(e);
    expect(r.status).toBe(502);
    expect(r.body.error).toBe('upstream_error');
  });

  it('falls back to server_error 500 for unknown', () => {
    const r = toOAuthError(new Error('boom'));
    expect(r).toEqual({ status: 500, body: { error: 'server_error', error_description: 'unexpected server error' } });
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/errors.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/errors.ts
import { TossUpstreamError } from '../toss/adapter.js';

export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unsupported_grant_type'
  | 'app_not_verified'
  | 'upstream_error'
  | 'server_misconfigured'
  | 'server_unavailable'
  | 'server_error';

export interface OAuthErrorInput {
  code: OAuthErrorCode;
  description: string;
}

export interface OAuthErrorResponse {
  status: number;
  body: { error: OAuthErrorCode; error_description: string };
}

const STATUS: Record<OAuthErrorCode, number> = {
  invalid_request: 400,
  invalid_client: 401,
  invalid_grant: 401,
  unsupported_grant_type: 400,
  app_not_verified: 403,
  upstream_error: 502,
  server_misconfigured: 500,
  server_unavailable: 500,
  server_error: 500,
};

export function toOAuthError(input: OAuthErrorInput | Error): OAuthErrorResponse {
  if (input instanceof TossUpstreamError) {
    return { status: STATUS[input.code], body: { error: input.code, error_description: input.message } };
  }
  if (input instanceof Error) {
    return { status: 500, body: { error: 'server_error', error_description: 'unexpected server error' } };
  }
  return { status: STATUS[input.code], body: { error: input.code, error_description: input.description } };
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/errors.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/errors.ts src/oidc/errors.test.ts
git commit -m "feat(oidc): OAuth-shape error mapping"
```

---

## Task 13: Token service — authorization_code flow

**Files:**
- Create: `src/oidc/token-service.ts`
- Test: `src/oidc/token-service.test.ts`

The service is the orchestrator. Routes only marshal HTTP. The service:
1. Calls `TossAdapter.generateToken`.
2. Calls `TossAdapter.loginMe` with the new AT.
3. Mints id_token.
4. Wraps `ait_access_token` (with `tossAt`) and `ait_refresh_token` (with `tossRt`) — same payload shape but two distinct sealed envelopes.
5. Returns the token-endpoint response.

Why two seals: spec §6.1 says response includes both `access_token` and `refresh_token` as `ait_*`. The unwrap consumer (`/oidc/userinfo`, `/oidc/refresh`) decides which sub-field it cares about.

- [ ] **Step 1: Failing test using MockTossAdapter**

```ts
// src/oidc/token-service.test.ts
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createSigningKeyRegistry } from './signing-keys.js';
import { createTokenService } from './token-service.js';
import { unwrapSealedToken } from './sealed-token.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

describe('tokenService.authorizationCode', () => {
  it('returns ait_AT/RT, id_token, expires_in, scope and seals Toss tokens', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const sealingKey = Buffer.alloc(32, 11);
    const service = createTokenService({
      adapter: new MockTossAdapter(),
      registry: reg,
      issuer: 'https://oidc-bridge.aitc.dev',
      idTokenTtlSeconds: 3600,
      resolveAppSealingKey: async () => sealingKey,
      now: () => 1735686000,
    });
    const out = await service.authorizationCode({
      app: { id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1 },
      authorizationCode: 'good',
      referrer: undefined,
    });
    expect(out.token_type).toBe('Bearer');
    expect(out.expires_in).toBe(3600);
    expect(out.scope).toBe('openid profile user_key');
    expect(out.access_token).toMatch(/^ait_/);
    expect(out.refresh_token).toMatch(/^ait_/);
    expect(out.id_token.split('.')).toHaveLength(3);
    const at = unwrapSealedToken({
      token: out.access_token,
      resolveKey: () => sealingKey,
      expectedAppId: 'app_abc',
      expectedTossUserKey: '42',
    });
    expect(at.tossAt).toBe('TOSS_AT_OPAQUE_FIXTURE');
    expect(at.tossRt).toBe('TOSS_RT_OPAQUE_FIXTURE');
  });

  it('propagates Toss invalid_grant', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const service = createTokenService({
      adapter: new MockTossAdapter(),
      registry: reg,
      issuer: 'https://x',
      idTokenTtlSeconds: 3600,
      resolveAppSealingKey: async () => Buffer.alloc(32, 1),
      now: () => 1,
    });
    await expect(
      service.authorizationCode({
        app: { id: 'a', clientId: 'a', sealingKeyVersion: 1 },
        authorizationCode: 'fail-code',
      }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/token-service.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/token-service.ts
import type { TossAdapter, TossTokenSet, LoginMeOutput } from '../toss/adapter.js';
import type { SigningKeyRegistry } from './signing-keys.js';
import { mintIdToken } from './id-token.js';
import { wrapSealedToken } from './sealed-token.js';

export interface AppForTokenService {
  id: string;
  clientId: string;
  sealingKeyVersion: number;
}

export interface AuthorizationCodeInput {
  app: AppForTokenService;
  authorizationCode: string;
  referrer?: string;
}

export interface RefreshTokenInput {
  app: AppForTokenService;
  unwrappedRt: { tossRt: string; tossUserKey: string };
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  id_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
}

export interface TokenServiceDeps {
  adapter: TossAdapter;
  registry: SigningKeyRegistry;
  issuer: string;
  idTokenTtlSeconds: number;
  resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
  now: () => number; // unix seconds
}

export interface TokenService {
  authorizationCode(input: AuthorizationCodeInput): Promise<TokenResponse>;
  refresh(input: RefreshTokenInput): Promise<TokenResponse>;
}

export function createTokenService(deps: TokenServiceDeps): TokenService {
  return {
    authorizationCode: async (input) => {
      const ts = await deps.adapter.generateToken({ appId: input.app.id }, {
        authorizationCode: input.authorizationCode,
        referrer: input.referrer,
      });
      const me = await deps.adapter.loginMe({ appId: input.app.id }, { accessToken: ts.accessToken });
      return finalize(deps, input.app, ts, me);
    },
    refresh: async (input) => {
      const ts = await deps.adapter.refreshToken({ appId: input.app.id }, { refreshToken: input.unwrappedRt.tossRt });
      const me = await deps.adapter.loginMe({ appId: input.app.id }, { accessToken: ts.accessToken });
      return finalize(deps, input.app, ts, me);
    },
  };
}

async function finalize(
  deps: TokenServiceDeps,
  app: AppForTokenService,
  ts: TossTokenSet,
  me: LoginMeOutput,
): Promise<TokenResponse> {
  const now = deps.now();
  const tossAtExp = now + ts.expiresIn;
  const sealingKey = await deps.resolveAppSealingKey({ appId: app.id, sealingKeyVersion: app.sealingKeyVersion });
  const sealCommon = {
    sealingKey,
    sealingKeyVersion: app.sealingKeyVersion,
    payload: {
      appId: app.id,
      tossUserKey: String(me.userKey),
      tossAt: ts.accessToken,
      tossRt: ts.refreshToken,
      tossAtExp,
      issuedAt: now,
    },
  };
  const accessToken = wrapSealedToken(sealCommon);
  const refreshToken = wrapSealedToken(sealCommon); // distinct random IV → distinct ciphertext
  const idToken = await mintIdToken({
    issuer: deps.issuer,
    ttlSeconds: deps.idTokenTtlSeconds,
    registry: deps.registry,
    app: { clientId: app.clientId },
    tossClaims: {
      userKey: me.userKey,
      scope: ts.scope,
      agreedTerms: me.agreedTerms,
      tossAtExp,
    },
    now,
  });
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    id_token: idToken,
    token_type: 'Bearer',
    expires_in: ts.expiresIn,
    scope: ts.scope.join(' '),
  };
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/token-service.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/token-service.ts src/oidc/token-service.test.ts
git commit -m "feat(oidc): token service authorization_code flow"
```

---

## Task 14: Token service — refresh_token flow + roundtrip test

**Files:**
- Modify: `src/oidc/token-service.test.ts`

The implementation already shipped in Task 13 (the `refresh` method). Add a roundtrip test that drives both methods end-to-end.

- [ ] **Step 1: Failing test**

```ts
// extend src/oidc/token-service.test.ts
describe('tokenService.refresh', () => {
  it('round-trips: auth_code → refresh → unwrap shows new Toss tokens', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const sealingKey = Buffer.alloc(32, 11);
    const service = createTokenService({
      adapter: new MockTossAdapter(),
      registry: reg,
      issuer: 'https://x',
      idTokenTtlSeconds: 3600,
      resolveAppSealingKey: async () => sealingKey,
      now: () => 100,
    });
    const first = await service.authorizationCode({
      app: { id: 'a', clientId: 'a', sealingKeyVersion: 1 },
      authorizationCode: 'good',
    });
    const firstUnwrapped = unwrapSealedToken({
      token: first.refresh_token,
      resolveKey: () => sealingKey,
      expectedAppId: 'a',
      expectedTossUserKey: '42',
    });
    const second = await service.refresh({
      app: { id: 'a', clientId: 'a', sealingKeyVersion: 1 },
      unwrappedRt: { tossRt: firstUnwrapped.tossRt, tossUserKey: firstUnwrapped.tossUserKey },
    });
    const secondUnwrapped = unwrapSealedToken({
      token: second.access_token,
      resolveKey: () => sealingKey,
      expectedAppId: 'a',
      expectedTossUserKey: '42',
    });
    expect(secondUnwrapped.tossAt).toBe('TOSS_AT_OPAQUE_REFRESHED');
    expect(secondUnwrapped.tossRt).toBe('TOSS_RT_OPAQUE_REFRESHED');
  });

  it('refresh propagates invalid_grant from Toss', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const service = createTokenService({
      adapter: new MockTossAdapter(),
      registry: reg,
      issuer: 'https://x',
      idTokenTtlSeconds: 3600,
      resolveAppSealingKey: async () => Buffer.alloc(32, 11),
      now: () => 1,
    });
    await expect(
      service.refresh({
        app: { id: 'a', clientId: 'a', sealingKeyVersion: 1 },
        unwrappedRt: { tossRt: 'fail-rt', tossUserKey: '42' },
      }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });
});
```

- [ ] **Step 2: Run, expect pass**

```bash
pnpm vitest run src/oidc/token-service.test.ts
```

If it fails, the implementation in Task 13 was incomplete; fix `refresh`.

- [ ] **Step 3: Commit**

```bash
git add src/oidc/token-service.test.ts
git commit -m "test(oidc): refresh roundtrip + invalid_grant"
```

---

## Task 15: Origin allowlist check + zod body schemas

**Files:**
- Create: `src/oidc/origin-check.ts`
- Test: `src/oidc/origin-check.test.ts`
- Create: `src/oidc/token-schemas.ts`

`originIsAllowed(origin, app.allowedOrigins)`: strict equality, default-deny, empty list = deny. (Spec §9 — `ALLOWED_ORIGINS` env supplements per-app; that env layer arrives in Phase 8 rate-limit/observability work. Phase 3 is per-app only.)

- [ ] **Step 1: Failing test**

```ts
// src/oidc/origin-check.test.ts
import { describe, it, expect } from 'vitest';
import { originIsAllowed } from './origin-check.js';

describe('originIsAllowed', () => {
  it('strict equality on allowed list', () => {
    expect(originIsAllowed('https://app.example.com', ['https://app.example.com'])).toBe(true);
    expect(originIsAllowed('https://APP.example.com', ['https://app.example.com'])).toBe(false);
    expect(originIsAllowed('https://app.example.com/', ['https://app.example.com'])).toBe(false);
    expect(originIsAllowed('https://evil.example.com', ['https://app.example.com'])).toBe(false);
  });

  it('returns false for missing origin', () => {
    expect(originIsAllowed(undefined, ['https://app.example.com'])).toBe(false);
    expect(originIsAllowed('', ['https://app.example.com'])).toBe(false);
  });

  it('returns false for empty allowlist (default deny)', () => {
    expect(originIsAllowed('https://app.example.com', [])).toBe(false);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/origin-check.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/origin-check.ts
export function originIsAllowed(origin: string | undefined, allowed: string[]): boolean {
  if (!origin) return false;
  if (allowed.length === 0) return false;
  return allowed.includes(origin);
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/origin-check.test.ts
```

- [ ] **Step 5: Add zod schemas for request bodies**

```ts
// src/oidc/token-schemas.ts
import { z } from 'zod';

export const tokenAuthorizationCodeBody = z.object({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  client_id: z.string().min(1),
  redirect_uri: z.string().optional(),
  code_verifier: z.string().optional(),
  // referrer is a Toss-specific param the bridge may pass through (mini-app context).
  referrer: z.string().optional(),
});

export const tokenRefreshBody = z.object({
  grant_type: z.literal('refresh_token'),
  refresh_token: z.string().min(1),
  client_id: z.string().min(1),
});

export const tokenBody = z.discriminatedUnion('grant_type', [
  tokenAuthorizationCodeBody,
  tokenRefreshBody,
]);

export type TokenBody = z.infer<typeof tokenBody>;
```

- [ ] **Step 6: Commit**

```bash
git add src/oidc/origin-check.ts src/oidc/origin-check.test.ts src/oidc/token-schemas.ts
git commit -m "feat(oidc): origin allowlist + token request schemas"
```

---

## Task 16: Token route — happy path (authorization_code)

**Files:**
- Create: `src/oidc/token-route.ts`
- Test: `src/oidc/token-route.test.ts`

The route handler is thin: parse body (form-encoded **or** JSON, per OAuth — §6.1 examples are form-style; spec doesn't forbid JSON, so accept both), look up app by `client_id`, run public-client auth (`Origin` allowlist check), call service, return JSON. Audit-log the success.

> Form-encoded vs JSON: OAuth 2.0 RFC 6749 §3.2 mandates `application/x-www-form-urlencoded` for the token endpoint. Bridge accepts both for SDK ergonomics — many JS clients default to JSON. No Content-Type → 400 `invalid_request`.

- [ ] **Step 1: Failing test (happy authorization_code via JSON body)**

```ts
// src/oidc/token-route.test.ts
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { Hono } from 'hono';
import { tokenRoute } from './token-route.js';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createSigningKeyRegistry } from './signing-keys.js';
import { createTokenService } from './token-service.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

interface FakeAppRow {
  id: string;
  clientId: string;
  sealingKeyVersion: number;
  allowedOrigins: string[];
  ownershipStatus: 'active' | 'lapsed' | 'pending';
}

function fakeService(app: FakeAppRow) {
  return {
    apps: {
      async getByClientId(clientId: string) {
        return clientId === app.clientId ? app : null;
      },
    },
    audit: { append: async () => {} },
  };
}

async function buildHarness(opts: {
  app: FakeAppRow;
  authorizationCode?: string;
}) {
  const reg = await createSigningKeyRegistry({
    activeKid: 'k1',
    signingKeys: [{ kid: 'k1', pem: genPem() }],
  });
  const sealingKey = Buffer.alloc(32, 11);
  const tokenService = createTokenService({
    adapter: new MockTossAdapter(),
    registry: reg,
    issuer: 'https://oidc-bridge.aitc.dev',
    idTokenTtlSeconds: 3600,
    resolveAppSealingKey: async () => sealingKey,
    now: () => 1735686000,
  });
  const app = new Hono();
  app.route('/', tokenRoute({
    service: fakeService(opts.app) as any,
    tokenService,
  }));
  return app;
}

describe('POST /oidc/token (public client)', () => {
  const app: FakeAppRow = {
    id: 'app_abc',
    clientId: 'app_abc',
    sealingKeyVersion: 1,
    allowedOrigins: ['https://app.example.com'],
    ownershipStatus: 'active',
  };

  it('happy authorization_code via JSON body', async () => {
    const h = await buildHarness({ app });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://app.example.com',
      },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: 'app_abc' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.token_type).toBe('Bearer');
    expect(body.access_token).toMatch(/^ait_/);
    expect(body.refresh_token).toMatch(/^ait_/);
    expect(body.id_token.split('.')).toHaveLength(3);
  });

  it('happy authorization_code via form-encoded body', async () => {
    const h = await buildHarness({ app });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'https://app.example.com',
      },
      body: 'grant_type=authorization_code&code=good&client_id=app_abc',
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toMatch(/^ait_/);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/token-route.ts
import { Hono } from 'hono';
import type { Service } from '../service/types.js'; // Phase 2
import type { TokenService } from './token-service.js';
import { tokenBody } from './token-schemas.js';
import { originIsAllowed } from './origin-check.js';
import { toOAuthError } from './errors.js';
import { unwrapSealedToken } from './sealed-token.js';

export interface TokenRouteOpts {
  service: Service; // Phase 2 service (apps + audit)
  tokenService: TokenService;
}

export function tokenRoute(opts: TokenRouteOpts) {
  const app = new Hono();

  app.post('/oidc/token', async (c) => {
    let raw: unknown;
    const ct = c.req.header('content-type') ?? '';
    try {
      if (ct.includes('application/json')) {
        raw = await c.req.json();
      } else if (ct.includes('application/x-www-form-urlencoded')) {
        const form = await c.req.parseBody();
        raw = form;
      } else {
        const e = toOAuthError({ code: 'invalid_request', description: 'unsupported content-type' });
        return c.json(e.body, e.status as never);
      }
    } catch {
      const e = toOAuthError({ code: 'invalid_request', description: 'malformed body' });
      return c.json(e.body, e.status as never);
    }
    const parsed = tokenBody.safeParse(raw);
    if (!parsed.success) {
      const e = toOAuthError({ code: 'invalid_request', description: parsed.error.issues[0]?.message ?? 'bad body' });
      return c.json(e.body, e.status as never);
    }
    const body = parsed.data;
    const appRow = await opts.service.apps.getByClientId(body.client_id);
    if (!appRow) {
      const e = toOAuthError({ code: 'invalid_client', description: 'unknown client_id' });
      return c.json(e.body, e.status as never);
    }
    // Public-client auth: Origin must be in allowlist.
    const origin = c.req.header('origin');
    if (!originIsAllowed(origin, appRow.allowedOrigins)) {
      const e = toOAuthError({ code: 'invalid_client', description: 'origin not allowed' });
      return c.json(e.body, e.status as never);
    }
    try {
      if (body.grant_type === 'authorization_code') {
        const out = await opts.tokenService.authorizationCode({
          app: { id: appRow.id, clientId: appRow.clientId, sealingKeyVersion: appRow.sealingKeyVersion },
          authorizationCode: body.code,
          referrer: body.referrer,
        });
        await opts.service.audit.append({
          actor: { type: 'app', id: appRow.id },
          action: 'oidc.token.issue',
          target: { type: 'app', id: appRow.id },
          details: { grant_type: 'authorization_code' },
        });
        return c.json(out);
      }
      // refresh_token
      const unwrapped = unwrapSealedToken({
        token: body.refresh_token,
        resolveKey: async (v) => {
          // The route resolver is sync in unwrapSealedToken (Task 3) — we wrap by
          // pre-resolving the key here is not possible without a sync path.
          // tokenService consumes resolveAppSealingKey async. We call it ahead.
          throw new Error('UNREACHABLE — see refresh handling below');
        },
        expectedAppId: appRow.id,
        expectedTossUserKey: '', // filled below — see two-step unwrap
      } as never);
      void unwrapped;
      return c.text('unreachable', 500);
    } catch (err) {
      const oe = toOAuthError(err as Error);
      return c.json(oe.body, oe.status as never);
    }
  });

  return app;
}
```

The above intentionally **does not** finish the refresh path — it stubs out so the happy-path tests for `authorization_code` pass first. Refresh is Task 17 (which converts `unwrapSealedToken` to support an async resolver, or pre-resolves the key).

- [ ] **Step 4: Run, expect happy `authorization_code` tests pass**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/token-route.ts src/oidc/token-route.test.ts
git commit -m "feat(oidc): POST /oidc/token authorization_code happy path"
```

---

## Task 17: Refresh path on the route + sync key resolution

**Files:**
- Modify: `src/oidc/token-route.ts`
- Modify: `src/oidc/sealed-token.ts` (no — keep sync; pre-resolve key)
- Modify: `src/oidc/token-route.test.ts`

`unwrapSealedToken` keeps its sync `resolveKey` (Task 3) — we pre-resolve the sealing key for the app from the request body's `client_id`, then unwrap. This is consistent with the design: per-`(appId, version)` key, and the `client_id` ties the request to the app.

But: the version byte is *inside* the wrapper. We don't know the version until we peek at byte 0. So we add a tiny helper `peekSealedTokenVersion(token)` that reads the leading byte without decrypting.

- [ ] **Step 1: Add failing test for `peekSealedTokenVersion`**

```ts
// extend src/oidc/sealed-token.test.ts
import { peekSealedTokenVersion } from './sealed-token.js';

describe('peekSealedTokenVersion', () => {
  it('returns the version byte without decrypting', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    expect(peekSealedTokenVersion(tok)).toBe(1);
  });

  it('throws on bad format', () => {
    expect(() => peekSealedTokenVersion('xxx')).toThrow(/SEALED_TOKEN_BAD_FORMAT/);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```

- [ ] **Step 3: Implement `peekSealedTokenVersion`**

Append to `src/oidc/sealed-token.ts`:

```ts
export function peekSealedTokenVersion(token: string): number {
  if (!token.startsWith('ait_')) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  let buf: Buffer;
  try {
    buf = Buffer.from(token.slice(4), 'base64url');
  } catch {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  if (buf.length < 1) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  return buf[0]!;
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```

- [ ] **Step 5: Failing test for refresh on the route**

```ts
// extend src/oidc/token-route.test.ts
describe('POST /oidc/token (refresh_token)', () => {
  const app: FakeAppRow = {
    id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1,
    allowedOrigins: ['https://app.example.com'], ownershipStatus: 'active',
  };

  it('happy refresh after authorization_code', async () => {
    const h = await buildHarness({ app });
    const first = await (await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: 'app_abc' }),
    })).json();
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: 'app_abc' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toMatch(/^ait_/);
    expect(body.access_token).not.toBe(first.access_token);
  });

  it('refresh with tampered token returns 401 invalid_grant', async () => {
    const h = await buildHarness({ app });
    const first = await (await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: 'app_abc' }),
    })).json();
    const tampered = first.refresh_token.slice(0, -4) + 'AAAA';
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: tampered, client_id: 'app_abc' }),
    });
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe('invalid_grant');
  });
});
```

- [ ] **Step 6: Run, expect failure**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 7: Replace the `refresh_token` block in `tokenRoute`**

Replace the stubbed branch with:

```ts
// Inside tokenRoute's handler, replace the refresh stub with:
if (body.grant_type === 'refresh_token') {
  let version: number;
  try {
    version = peekSealedTokenVersion(body.refresh_token);
  } catch {
    const e = toOAuthError({ code: 'invalid_grant', description: 'refresh_token format' });
    return c.json(e.body, e.status as never);
  }
  // We need to know expectedTossUserKey to bind AAD. Two-step solution:
  // 1) Construct a "probe" unwrap with an empty userKey is wrong (AAD mismatch).
  // 2) Instead, embed the userKey in the refresh_token payload only and let
  //    the resolver re-derive AAD from the *plaintext* userKey by attempting
  //    decryption with a permissive AAD-builder.
  // Cleanest: pass expectedTossUserKey via a side-channel. Since the wrapper
  // payload contains tossUserKey and the route doesn't yet know it, expose a
  // variant `unwrapSealedTokenAnyUser` that decrypts with AAD bound to the
  // declared (peeked) version + the *claimed* userKey extracted post-decrypt.
  // Implementation choice for Phase 3: introduce `unwrapSealedTokenForApp`
  // which reads the userKey from the inner JSON only after AAD-validated decrypt
  // with the userKey field. Since AAD includes userKey, this seems circular —
  // resolved by using a deterministic AAD that does NOT depend on userKey for
  // the unwrap path of refresh_token specifically? No — that weakens AAD.
  //
  // Real solution: refresh_token format includes userKey *outside* the sealed
  // payload as a clear-text hint, and AAD binds to that hint. We adjust the
  // sealed-token format below to carry userKey hint in the wrapper. This is a
  // small extension of Task 2/3 — see Step 8 below.
}
```

- [ ] **Step 8: Realize the design issue and revise the sealed-token format**

The hint needed is: how does the unwrapper know `expectedTossUserKey` before decrypting? Three choices:

1. **Embed a userKey hint in the wrapper preamble** (e.g., `version || userKey_len || userKey || iv || ct || tag`), AAD binds the hint. Tampering with the hint flips AAD → GCM auth fails. *This is the chosen path.*
2. Drop AAD-binding to userKey — weaker.
3. Carry userKey as a separate request parameter — leaks PII to the form.

Update `wrapSealedToken` and `unwrapSealedToken` to embed and verify the userKey hint. This is a one-time format extension. Since Phase 3 is the first phase to ship sealed tokens, no migration is needed — but lock the format with tests.

- [ ] **Step 9: Update sealed-token format (revised wrap/unwrap + tests)**

Replace `src/oidc/sealed-token.ts`:

```ts
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

export interface SealedPayload {
  appId: string;
  tossUserKey: string;
  tossAt: string;
  tossRt: string;
  tossAtExp: number;
  issuedAt: number;
}

export interface WrapInput {
  sealingKey: Buffer;
  sealingKeyVersion: number;
  payload: SealedPayload;
}

const VERSION_BYTES = 1;
const USERKEY_LEN_BYTES = 1;     // userKey hint is a short ASCII string, ≤255 bytes
const IV_BYTES = 12;
const TAG_BYTES = 16;

export function wrapSealedToken(input: WrapInput): string {
  if (input.sealingKey.length !== 32) throw new Error('sealingKey must be 32 bytes');
  if (input.sealingKeyVersion < 1 || input.sealingKeyVersion > 255) {
    throw new Error('sealingKeyVersion must fit in 1 byte');
  }
  const userKeyBuf = Buffer.from(input.payload.tossUserKey, 'utf8');
  if (userKeyBuf.length > 255) throw new Error('tossUserKey too long');
  const iv = randomBytes(IV_BYTES);
  const aad = buildAad(input.payload.appId, input.payload.tossUserKey, input.sealingKeyVersion);
  const cipher = createCipheriv('aes-256-gcm', input.sealingKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(input.payload), 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const sealed = Buffer.concat([
    Buffer.from([input.sealingKeyVersion]),
    Buffer.from([userKeyBuf.length]),
    userKeyBuf,
    iv,
    ciphertext,
    tag,
  ]);
  return `ait_${sealed.toString('base64url')}`;
}

export interface UnwrapInput {
  token: string;
  resolveKey: (sealingKeyVersion: number) => Buffer;
  expectedAppId: string;
}

export function unwrapSealedToken(input: UnwrapInput): SealedPayload {
  const { version, userKey, iv, ciphertext, tag } = parseSealed(input.token);
  const key = input.resolveKey(version);
  if (key.length !== 32) throw new Error('SEALED_TOKEN_BAD_KEY');
  const aad = buildAad(input.expectedAppId, userKey, version);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  const parsed = JSON.parse(plaintext.toString('utf8')) as SealedPayload;
  if (parsed.appId !== input.expectedAppId || parsed.tossUserKey !== userKey) {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  return parsed;
}

export function peekSealedTokenVersion(token: string): number {
  return parseSealed(token).version;
}

export function peekSealedTokenUserKey(token: string): string {
  return parseSealed(token).userKey;
}

function parseSealed(token: string) {
  if (!token.startsWith('ait_')) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  let buf: Buffer;
  try {
    buf = Buffer.from(token.slice(4), 'base64url');
  } catch {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  if (buf.length < VERSION_BYTES + USERKEY_LEN_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const version = buf[0]!;
  const userKeyLen = buf[1]!;
  const userKeyEnd = VERSION_BYTES + USERKEY_LEN_BYTES + userKeyLen;
  if (buf.length < userKeyEnd + IV_BYTES + TAG_BYTES + 1) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const userKey = buf.subarray(VERSION_BYTES + USERKEY_LEN_BYTES, userKeyEnd).toString('utf8');
  const iv = buf.subarray(userKeyEnd, userKeyEnd + IV_BYTES);
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(userKeyEnd + IV_BYTES, buf.length - TAG_BYTES);
  return { version, userKey, iv, ciphertext, tag };
}

export function buildAad(appId: string, tossUserKey: string, version: number): Buffer {
  return Buffer.from(`${appId} ${tossUserKey} ${version}`, 'utf8');
}
```

- [ ] **Step 10: Update sealed-token tests for new format**

In `src/oidc/sealed-token.test.ts`, drop `expectedTossUserKey` from `unwrapSealedToken` calls and add a `peekSealedTokenUserKey` test:

```ts
import { wrapSealedToken, unwrapSealedToken, peekSealedTokenVersion, peekSealedTokenUserKey } from './sealed-token.js';

it('peeks userKey hint without decrypting', () => {
  const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
  expect(peekSealedTokenUserKey(tok)).toBe('u_42');
});

// In existing roundtrip + tamper tests, replace
//    unwrapSealedToken({ ..., expectedAppId, expectedTossUserKey })
// with
//    unwrapSealedToken({ ..., expectedAppId })
// and tampering the userKey hint must also fail.
it('rejects tampered userKey hint', () => {
  const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
  const buf = Buffer.from(tok.slice(4), 'base64url');
  // userKey starts at index 2; flip a byte
  buf[2] ^= 0x01;
  const forged = `ait_${buf.toString('base64url')}`;
  expect(() =>
    unwrapSealedToken({ token: forged, resolveKey: () => sealingKey, expectedAppId: payload.appId }),
  ).toThrow(/SEALED_TOKEN_TAMPERED/);
});
```

Update existing test `it('rejects tampered ciphertext', ...)` byte index from 20 to one inside the new ciphertext region (`userKeyEnd + IV_BYTES + 4`).

- [ ] **Step 11: Run all sealed-token tests, expect pass**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```

If existing token-service / token-route tests now break (they pass `expectedTossUserKey`), update those too in this commit.

- [ ] **Step 12: Update token-service and token-route to use new unwrap signature**

In `src/oidc/token-service.ts`, the service does not call unwrap directly (the route does in refresh path), so no change needed.

In `src/oidc/token-route.ts`, finish the refresh branch:

```ts
// inside tokenRoute handler, replace the entire refresh block with:
if (body.grant_type === 'refresh_token') {
  let version: number;
  try {
    version = peekSealedTokenVersion(body.refresh_token);
  } catch {
    const e = toOAuthError({ code: 'invalid_grant', description: 'refresh_token format' });
    return c.json(e.body, e.status as never);
  }
  let unwrapped: ReturnType<typeof unwrapSealedToken>;
  try {
    const sealingKey = await opts.resolveAppSealingKey({ appId: appRow.id, sealingKeyVersion: version });
    unwrapped = unwrapSealedToken({
      token: body.refresh_token,
      resolveKey: () => sealingKey,
      expectedAppId: appRow.id,
    });
  } catch {
    const e = toOAuthError({ code: 'invalid_grant', description: 'refresh_token rejected' });
    return c.json(e.body, e.status as never);
  }
  try {
    const out = await opts.tokenService.refresh({
      app: { id: appRow.id, clientId: appRow.clientId, sealingKeyVersion: version },
      unwrappedRt: { tossRt: unwrapped.tossRt, tossUserKey: unwrapped.tossUserKey },
    });
    await opts.service.audit.append({
      actor: { type: 'app', id: appRow.id },
      action: 'oidc.token.refresh',
      target: { type: 'app', id: appRow.id },
      details: {},
    });
    return c.json(out);
  } catch (err) {
    const oe = toOAuthError(err as Error);
    return c.json(oe.body, oe.status as never);
  }
}
```

Add `resolveAppSealingKey` to `TokenRouteOpts`:

```ts
export interface TokenRouteOpts {
  service: Service;
  tokenService: TokenService;
  resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
}
```

Wire it through in `buildHarness` (test) and in `app.ts` (Task 19).

- [ ] **Step 13: Run token-route tests, expect pass**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 14: Commit**

```bash
git add src/oidc/sealed-token.ts src/oidc/sealed-token.test.ts src/oidc/token-route.ts src/oidc/token-route.test.ts
git commit -m "feat(oidc): refresh_token flow + userKey hint in sealed format"
```

---

## Task 18: Token route — error cases

**Files:**
- Modify: `src/oidc/token-route.test.ts`

Tests for the spec §8 error rows that apply to public client + authorization_code in this phase:

- 400 `invalid_request` — missing fields, malformed body, bad content-type
- 401 `invalid_client` — unknown client_id, bad origin
- 401 `invalid_grant` — Toss FAIL on authorization_code
- 502 `upstream_error` — Toss network failure
- 403 `app_not_verified` — `ownershipStatus !== 'active'`

> Spec §8 row "App not yet verified, production traffic" maps to ownership state. In Phase 2, ownership states are `pending | active | lapsed | grace`. The route blocks unless `active`. (`grace` and `lapsed` are admin-side states; user-facing flows treat them as not-active.)

- [ ] **Step 1: Failing tests**

```ts
// extend src/oidc/token-route.test.ts
describe('POST /oidc/token error cases (public client)', () => {
  const baseApp: FakeAppRow = {
    id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1,
    allowedOrigins: ['https://app.example.com'], ownershipStatus: 'active',
  };

  it('400 invalid_request when content-type missing', async () => {
    const h = await buildHarness({ app: baseApp });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { origin: 'https://app.example.com' },
      body: 'whatever',
    });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('invalid_request');
  });

  it('400 invalid_request when grant_type missing', async () => {
    const h = await buildHarness({ app: baseApp });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ code: 'good', client_id: 'app_abc' }),
    });
    expect(res.status).toBe(400);
  });

  it('401 invalid_client when client_id unknown', async () => {
    const h = await buildHarness({ app: baseApp });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: 'unknown' }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe('invalid_client');
  });

  it('401 invalid_client when Origin not allowed', async () => {
    const h = await buildHarness({ app: baseApp });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://evil.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: 'app_abc' }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe('invalid_client');
  });

  it('401 invalid_grant when Toss rejects code', async () => {
    const h = await buildHarness({ app: baseApp });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'fail-code', client_id: 'app_abc' }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe('invalid_grant');
  });

  it('502 upstream_error when Toss network fails', async () => {
    const h = await buildHarness({ app: baseApp });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'network-error-code', client_id: 'app_abc' }),
    });
    expect(res.status).toBe(502);
    expect((await res.json()).error).toBe('upstream_error');
  });

  it('403 app_not_verified when ownership not active', async () => {
    const pendingApp = { ...baseApp, ownershipStatus: 'pending' as const };
    const h = await buildHarness({ app: pendingApp });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: 'app_abc' }),
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe('app_not_verified');
  });
});
```

- [ ] **Step 2: Run, expect failure (ownership check missing)**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 3: Add ownership gate to `tokenRoute`**

In `tokenRoute`, after looking up `appRow` and before the origin check, add:

```ts
if (appRow.ownershipStatus !== 'active') {
  const e = toOAuthError({ code: 'app_not_verified', description: 'app ownership not active' });
  return c.json(e.body, e.status as never);
}
```

The other error rows already work via the existing handler.

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/token-route.ts src/oidc/token-route.test.ts
git commit -m "feat(oidc): token endpoint error cases + ownership gate"
```

---

## Task 19: Wire token route + sealing-key resolver into app

**Files:**
- Modify: `src/app.ts`
- Test: `src/oidc/token-route.test.ts` (extend with full app integration)

- [ ] **Step 1: Failing test asserting `buildApp` mounts `/oidc/token`**

```ts
// extend src/oidc/token-route.test.ts
import { buildApp } from '../app.js';

describe('buildApp wiring', () => {
  it('mounts /oidc/token', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const sealingKey = Buffer.alloc(32, 11);
    const fakeApp: FakeAppRow = {
      id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1,
      allowedOrigins: ['https://app.example.com'], ownershipStatus: 'active',
    };
    const app = await buildApp({
      service: fakeService(fakeApp) as any,
      oidcConfig: {
        issuer: 'https://oidc-bridge.aitc.dev',
        activeKid: 'k1', signingKeys: [], idTokenTtlSeconds: 3600,
        defaultScope: 'openid profile user_key',
      },
      signingKeyRegistry: reg,
      tossAdapter: new MockTossAdapter(),
      resolveAppSealingKey: async () => sealingKey,
      now: () => 1735686000,
    } as any);
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: 'app_abc' }),
    });
    expect(res.status).toBe(200);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 3: Update `buildApp`**

```ts
// src/app.ts (additions)
import { tokenRoute } from './oidc/token-route.js';
import { createTokenService } from './oidc/token-service.js';
import type { TossAdapter } from './toss/adapter.js';

export interface BuildAppOpts {
  // ... existing fields (logger, service)
  oidcConfig: OidcConfig;
  signingKeyRegistry: SigningKeyRegistry;
  tossAdapter: TossAdapter;
  resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
  now?: () => number;
}

export async function buildApp(opts: BuildAppOpts) {
  // ... existing code ...
  const tokenService = createTokenService({
    adapter: opts.tossAdapter,
    registry: opts.signingKeyRegistry,
    issuer: opts.oidcConfig.issuer,
    idTokenTtlSeconds: opts.oidcConfig.idTokenTtlSeconds,
    resolveAppSealingKey: opts.resolveAppSealingKey,
    now: opts.now ?? (() => Math.floor(Date.now() / 1000)),
  });
  app.route('/', tokenRoute({
    service: opts.service,
    tokenService,
    resolveAppSealingKey: opts.resolveAppSealingKey,
  }));
  // ... existing discovery + jwks mounts (Task 9) ...
  return app;
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/app.ts src/oidc/token-route.test.ts
git commit -m "feat(app): mount /oidc/token + token service"
```

---

## Task 20: Server bootstrap — load OIDC config + signing keys

**Files:**
- Modify: `src/server.ts` (Phase 0 entrypoint)

Compose the new pieces in `src/server.ts` so `pnpm dev` and `pnpm start` actually run a working OIDC bridge against the mock adapter. Phase 5 swaps to the real adapter.

- [ ] **Step 1: Update `src/server.ts`**

```ts
// src/server.ts (additions; keep existing imports + storage/service init from earlier phases)
import { loadOidcConfig } from './config.js';
import { createSigningKeyRegistry } from './oidc/signing-keys.js';
import { createAppSealingKeyResolver } from './oidc/app-sealing-key.js';
import { MockTossAdapter } from './toss/mock-adapter.js';
import { buildApp } from './app.js';

async function main() {
  // ... existing logger, storage, masterKeyProvider, service setup ...
  const oidcConfig = loadOidcConfig(process.env);
  const signingKeyRegistry = await createSigningKeyRegistry({
    activeKid: oidcConfig.activeKid,
    signingKeys: oidcConfig.signingKeys,
  });
  const resolveAppSealingKey = createAppSealingKeyResolver({ provider: masterKeyProvider });
  const app = await buildApp({
    logger,
    service,
    oidcConfig,
    signingKeyRegistry,
    tossAdapter: new MockTossAdapter(),
    resolveAppSealingKey,
  });
  // ... existing serve(...) ...
}
```

- [ ] **Step 2: Add a `.env.example` block (or extend existing)**

```bash
# .env.example
# ... earlier phases ...

# OIDC
OIDC_ISSUER=http://localhost:8080
OIDC_ACTIVE_KID=k1
# Generate once for local dev:
#   node --eval 'import("node:crypto").then(({generateKeyPairSync})=>{const {privateKey}=generateKeyPairSync("rsa",{modulusLength:2048});console.log(privateKey.export({format:"pem",type:"pkcs8"}).toString())})'
OIDC_SIGNING_KEY_K1_PEM=
ID_TOKEN_TTL_SECONDS=3600
```

- [ ] **Step 3: Smoke-test manually**

```bash
# Generate a dev key
node -e 'import("node:crypto").then(({generateKeyPairSync})=>{const {privateKey}=generateKeyPairSync("rsa",{modulusLength:2048});process.stdout.write(privateKey.export({format:"pem",type:"pkcs8"}).toString())})' > /tmp/dev-key.pem
export OIDC_ISSUER=http://localhost:8080
export OIDC_ACTIVE_KID=k1
export OIDC_SIGNING_KEY_K1_PEM="$(cat /tmp/dev-key.pem)"
# ... earlier phase envs (DB_URL, MASTER_KEY_PROVIDER, etc.)
pnpm dev &
sleep 2
curl -s http://localhost:8080/.well-known/openid-configuration | jq .
curl -s http://localhost:8080/.well-known/jwks.json | jq .
kill %1 2>/dev/null || true
rm /tmp/dev-key.pem
```

Both `curl`s should print JSON. JWKS contains `{ keys: [ { kid: "k1", alg: "RS256", ... } ] }`.

- [ ] **Step 4: Commit**

```bash
git add src/server.ts .env.example
git commit -m "feat(server): wire OIDC config + signing keys + mock Toss"
```

---

## Task 21: Logger redact list — extend for this phase

**Files:**
- Modify: `src/logger.ts` (Phase 0)
- Test: `src/logger.test.ts` (Phase 0)

Phase 0 set up a redact list. This phase adds `id_token` and `code_verifier` (and ensures `code` is already there).

- [ ] **Step 1: Failing test**

```ts
// extend src/logger.test.ts
it('redacts id_token and code_verifier', () => {
  const { logger, captured } = makeTestLogger();
  logger.info({
    id_token: 'header.payload.signature',
    code_verifier: 'long-random-string',
  }, 'test');
  expect(captured[0].id_token).toBe('[Redacted]');
  expect(captured[0].code_verifier).toBe('[Redacted]');
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/logger.test.ts
```

- [ ] **Step 3: Add to redact list**

In `src/logger.ts`, append `'id_token'` and `'code_verifier'` to the redact paths array.

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/logger.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/logger.ts src/logger.test.ts
git commit -m "chore(log): redact id_token + code_verifier"
```

---

## Task 22: RUNBOOK — rotating OIDC signing keys

**Files:**
- Modify: `docs/RUNBOOK.md`

Add a section that an ops human can follow without reading code.

- [ ] **Step 1: Add section**

````markdown
## Rotating OIDC signing keys

The bridge supports overlapping signing keys. Add the new key first, switch the
active kid, then drop the old key after consumers' JWKS caches expire (typical
TTL: 5 minutes; max observed: 1 hour).

1. Generate a new RSA-2048 PEM (PKCS#8):
   ```bash
   node -e 'import("node:crypto").then(({generateKeyPairSync})=>{const {privateKey}=generateKeyPairSync("rsa",{modulusLength:2048});process.stdout.write(privateKey.export({format:"pem",type:"pkcs8"}).toString())})' > new-key.pem
   ```
2. Pick a kid (e.g. `2026-05-15-a` — the date helps audit). Set:
   ```
   OIDC_SIGNING_KEY_2026-05-15-A_PEM=<contents of new-key.pem>
   ```
   The kid in env names is uppercased; the registry lowercases it. Match the
   value you pick for `OIDC_ACTIVE_KID`.
3. Restart the bridge **without** changing `OIDC_ACTIVE_KID`. The new key is
   now in JWKS but not yet signing. Verify:
   ```bash
   curl -s https://oidc-bridge.aitc.dev/.well-known/jwks.json | jq '.keys[].kid'
   ```
4. Wait at least 6 hours so consumer JWKS caches see the new kid.
5. Set `OIDC_ACTIVE_KID=2026-05-15-a` and restart. New id_tokens sign with the
   new key. Consumers verify with whichever key matches the token's kid.
6. After 24 hours of new-token-only signing, drop the old key env and restart.
````

- [ ] **Step 2: Commit**

```bash
git add docs/RUNBOOK.md
git commit -m "docs: signing-key rotation runbook"
```

---

## Task 23: Final verification

- [ ] **Step 1: Run the full suite**

```bash
pnpm typecheck && pnpm lint && pnpm test
```

All three must be clean.

- [ ] **Step 2: Confirm shape against spec**

Verify by inspection of the running bridge (Task 20 smoke):
- `GET /.well-known/openid-configuration` matches the §5.7 shape exactly (including the omitted `authorization_endpoint`).
- `GET /.well-known/jwks.json` returns `{ keys: [{ kty: "RSA", alg: "RS256", use: "sig", kid, n, e }] }`.
- `POST /oidc/token` with `grant_type=authorization_code, code=good, client_id=<seeded>` and an allowed Origin returns `{ access_token, refresh_token, id_token, token_type: "Bearer", expires_in, scope }`.
- The id_token `iss/aud/sub/iat/exp/nbf/provider/scope` and `toss:*` claims all match §5.7 / §6.5.
- Sealed tokens decode under their per-app HKDF-derived key only.

- [ ] **Step 3: Verify nothing leaks via logs**

In the smoke run above, grep stdout for the values `'TOSS_AT_OPAQUE_FIXTURE'`, `'TOSS_RT_OPAQUE_FIXTURE'`, and the dev RSA private-key PEM body. Expect zero matches.

```bash
pnpm dev > /tmp/bridge.log 2>&1 &
# ... drive a successful /oidc/token request via curl ...
kill %1
grep -E 'TOSS_AT_OPAQUE_FIXTURE|TOSS_RT_OPAQUE_FIXTURE|BEGIN PRIVATE KEY' /tmp/bridge.log && echo "LEAK" || echo "clean"
```

If a leak is found, fix the redact list before merging.

- [ ] **Step 4: Push and open PR**

```bash
git push -u origin feat/zero-code-phase-03
gh pr create --base main --title "feat: zero-code Phase 3 — OIDC token endpoint (public client, mock Toss)" --body "$(cat <<'EOF'
## Summary
- POST /oidc/token with grant_type=authorization_code (public-client origin auth)
- POST /oidc/token with grant_type=refresh_token (sealed-token roundtrip)
- RS256 id_token signing with multi-kid JWKS publication
- OIDC discovery doc at /.well-known/openid-configuration
- Sealed ait_* tokens (AES-256-GCM, AAD-bound to app + userKey + version)
- MockTossAdapter + redacted Toss SUCCESS/FAIL fixtures
- Plan: docs/superpowers/plans/2026-05-01-zero-code-phase-03-oidc-token-public.md

## Test plan
- [x] pnpm typecheck && pnpm lint && pnpm test
- [x] manual smoke: discovery + jwks served, authorization_code + refresh roundtrip
- [x] log redaction: no Toss tokens or PEM bodies in stdout
EOF
)"
```

---

## Phase 3 done condition

- All 23 tasks ticked.
- `pnpm typecheck && pnpm lint && pnpm test` clean.
- A consumer hitting `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json` (e.g. Supabase's id_token verifier) sees a spec-compliant doc and a JWKS containing the active kid.
- A request to `POST /oidc/token` against the **mock Toss adapter** returns `{ access_token: "ait_...", refresh_token: "ait_...", id_token: "<jwt>", token_type, expires_in, scope }`.
- The refresh_token round-trips: a fresh `authorization_code` issuance feeds a `refresh_token` request that returns a new pair with new Toss-side AT/RT visible inside the sealed wrapper.
- Origin enforcement, ownership gate, and Toss FAIL/network handling all return the spec-mandated OAuth error shapes.
- No Toss tokens, RSA private keys, refresh tokens, or id_tokens appear in stdout logs.

That state is the foundation Phase 4 (userinfo, revoke, confidential-client auth) builds on.
