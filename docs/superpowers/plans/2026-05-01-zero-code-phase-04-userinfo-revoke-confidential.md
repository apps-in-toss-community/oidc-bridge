# oidc-bridge zero-code mode — Phase 4: userinfo + revoke + confidential client

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `GET /oidc/userinfo`, `POST /oidc/revoke`, optional `GET /oidc/raw-tokens` (apps with `raw_tokens_enabled=true` only), and confidential-client authentication on `POST /oidc/token` (`client_secret_basic` + `client_secret_post`). Origin enforcement is hardened (treat malformed Origin headers as denial). Still backed by `MockTossAdapter` from Phase 3 — Phase 5 swaps in the real Toss mTLS adapter.

**Architecture:** Userinfo and revoke unwrap the same sealed `ait_*` token format Phase 3 introduced. A `clientAuth(req, app)` resolver examines the request once and reports whether the call was authenticated as `public`, `confidential`, or unauthenticated, then the route trusts that classification. Revocation list is an in-memory `RevocationStore` keyed by `(appId, sealedTokenSha256)` — per-instance, fine for the initial release per spec §9 ("Local revocation list is in-memory per instance"). Raw-tokens lives on a separate route that mirrors userinfo's bearer-unwrap pipeline but explicitly never echoes the refresh token.

**Tech stack:** Same as Phase 3. Adds nothing new at the dependency level — uses existing `bcryptjs` (Phase 2), `jose`, `zod`, `node:crypto`.

---

## Universal invariants (apply to every task)

1. **TDD.** Failing test → minimal code → green → commit.
2. **Frequent commits.** Each red→green cycle is a commit. Conventional Commits.
3. **No premature abstractions.** Three duplicate lines is fine.
4. **No PII / secrets in logs.** Phase 0 redact list already covers `client_secret`, `refresh_token`, `code`, `access_token`, `id_token`, `code_verifier`, `mtls_*`. This phase adds nothing new to the redact list — verify in Task 17 that `Authorization` headers and `token` form fields are not logged.
5. **Bridge never spontaneously calls Toss.** Userinfo and revoke (when handling a refresh token) call Toss only inside the request handler.
6. **Toss `refresh_token` never leaves the sealed wrapper.** Userinfo only unwraps the AT side; raw-tokens never returns the RT; revoke uses the RT to call `access-remove` and discards it.
7. **Public clients use `Origin`, never `client_secret`.** Confidential clients use `client_secret_basic` or `client_secret_post`. **Mixing the two on the same call is rejected** — locked down with explicit tests in Task 12.
8. **mTLS material never returns from any GET.** No GET on apps changes here.
9. **Cloud-agnostic.** No GCP-specific paths.
10. **Self-host first-class.** Same code path everywhere.
11. **Bite-sized tasks.** One action per step.
12. **Lint + typecheck + test pass on every commit.**

## Files this phase touches

```
src/
  oidc/
    client-auth.ts         # NEW — resolveClientAuth(req, app)
    client-auth.test.ts    # NEW — basic + post + public + mixed rejection
    userinfo-route.ts      # NEW — GET /oidc/userinfo
    userinfo-route.test.ts # NEW — happy + invalid bearer + revoked + Toss FAIL
    revoke-route.ts        # NEW — POST /oidc/revoke
    revoke-route.test.ts   # NEW — always-200 + access-remove called for RTs
    revocation-store.ts    # NEW — in-memory revocation set
    revocation-store.test.ts # NEW
    raw-tokens-route.ts    # NEW — GET /oidc/raw-tokens (opt-in)
    raw-tokens-route.test.ts # NEW — 404 default, 200 when enabled, no RT
    bearer.ts              # NEW — parseBearerHeader helper
    bearer.test.ts         # NEW
    token-route.ts         # MODIFY — wire confidential-client auth, harden Origin
    token-route.test.ts    # MODIFY — confidential-client tests
  toss/
    adapter.ts             # MODIFY — add accessRemove method
    mock-adapter.ts        # MODIFY — implement accessRemove (counter for assertions)
    mock-adapter.test.ts   # MODIFY — accessRemove tests
  service/
    types.ts               # MODIFY — add apps.toggleRawTokens (admin) — only if not in Phase 2
  app.ts                   # MODIFY — mount userinfo, revoke, raw-tokens routes
docs/
  RUNBOOK.md               # MODIFY — confidential-client setup + raw-tokens runbook entries
```

## Pre-flight

```bash
git fetch origin
git checkout main && git pull
git checkout -b feat/zero-code-phase-04 origin/main
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

Phase 4 depends on Phase 3's sealed token primitives (`wrapSealedToken`, `unwrapSealedToken`, `peekSealedTokenVersion`, `peekSealedTokenUserKey`), the `tokenRoute` (extended here), the `tokenService`, the `MockTossAdapter`, and the `Service.apps.getByClientId` shape. Phase 2's `verifyClientSecret(plain, hashes[])` is required for confidential auth.

If any of those are missing, you are on the wrong branch.

---

## Task 1: Bearer header parser

**Files:**
- Create: `src/oidc/bearer.ts`
- Test: `src/oidc/bearer.test.ts`

A tiny helper used by userinfo, revoke (when caller passes Bearer instead of body — RFC 7009 doesn't require this but doesn't forbid it; we accept body only per spec but the parser is also used by raw-tokens), and the `client_secret_basic` path.

- [ ] **Step 1: Failing test**

```ts
// src/oidc/bearer.test.ts
import { describe, it, expect } from 'vitest';
import { parseBearer } from './bearer.js';

describe('parseBearer', () => {
  it('extracts the token from Bearer scheme', () => {
    expect(parseBearer('Bearer ait_abc')).toBe('ait_abc');
    expect(parseBearer('bearer ait_abc')).toBe('ait_abc'); // case-insensitive scheme
  });
  it('returns null for missing or wrong scheme', () => {
    expect(parseBearer(undefined)).toBe(null);
    expect(parseBearer('')).toBe(null);
    expect(parseBearer('Basic abcd')).toBe(null);
    expect(parseBearer('Bearer')).toBe(null);
    expect(parseBearer('Bearer  ')).toBe(null);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/bearer.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/bearer.ts
export function parseBearer(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return m ? m[1]! : null;
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/bearer.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/bearer.ts src/oidc/bearer.test.ts
git commit -m "feat(oidc): bearer header parser"
```

---

## Task 2: Revocation store (in-memory)

**Files:**
- Create: `src/oidc/revocation-store.ts`
- Test: `src/oidc/revocation-store.test.ts`

Keyed by sha256 of the full `ait_*` string scoped to `appId`. We store hashes, not the tokens themselves, so a memory dump doesn't leak credentials.

- [ ] **Step 1: Failing test**

```ts
// src/oidc/revocation-store.test.ts
import { describe, it, expect } from 'vitest';
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
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/revocation-store.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/revocation-store.ts
import { createHash } from 'node:crypto';

export interface RevocationStore {
  revoke(input: { appId: string; token: string }): void;
  isRevoked(input: { appId: string; token: string }): boolean;
}

export function createInMemoryRevocationStore(): RevocationStore {
  const set = new Set<string>();
  const key = (appId: string, token: string): string => {
    const h = createHash('sha256').update(`${appId} ${token}`).digest('hex');
    return h;
  };
  return {
    revoke({ appId, token }) {
      set.add(key(appId, token));
    },
    isRevoked({ appId, token }) {
      return set.has(key(appId, token));
    },
  };
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/revocation-store.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/revocation-store.ts src/oidc/revocation-store.test.ts
git commit -m "feat(oidc): in-memory revocation store"
```

---

## Task 3: Userinfo route — happy path

**Files:**
- Create: `src/oidc/userinfo-route.ts`
- Test: `src/oidc/userinfo-route.test.ts`

`GET /oidc/userinfo` with `Authorization: Bearer ait_<access_token>`. Pipeline:

1. Parse bearer; missing/wrong scheme → 401 `invalid_token` (spec §8 doesn't tabulate userinfo errors specifically, but RFC 6750 §3.1 lists `invalid_token` for protected resources; we use it).
2. Peek the userKey hint and version.
3. Resolve the per-app sealing key (we still need `appId` to derive — comes from `peekSealedTokenAppId`? No — the wrapper does **not** store `appId` outside ciphertext. Solution: extract `client_id` from the Authorization-adjacent... no, userinfo doesn't have a body. Spec §6.2: "Bridge unwraps the sealed AT, extracts `(app_id, toss_user_key, toss_at)`." So `appId` must come *from* the wrapper. Either we add `appId` to the preamble, or we accept that the route must try every app. The clean fix: **add `appId` to the preamble alongside `userKey`**, AAD-bound the same way. Tightens the format.

This is a second sealed-token format extension. Phase 3's plan flagged `appId` as inside the ciphertext only, with AAD binding `appId`. That worked for `/oidc/token` because the request body carried `client_id`, which gave the route `appId` before unwrap. Userinfo has no body. Add `appId` to the preamble now (Task 4 below) — it's a one-time format change, no migrations because no production tokens exist.

- [ ] **Step 1: Move on to Task 4 to extend the sealed-token format first**

(Userinfo route work resumes in Task 5, after the format extension.)

---

## Task 4: Sealed-token format extension — appId hint

**Files:**
- Modify: `src/oidc/sealed-token.ts`
- Modify: `src/oidc/sealed-token.test.ts`
- Modify: `src/oidc/token-route.ts` (consumes it)

Add an `appId` length-prefixed hint to the preamble. New format:

```
ait_<base64url(
  version (1)
  || appIdLen (1)
  || appId (n)
  || userKeyLen (1)
  || userKey (m)
  || iv (12)
  || ciphertext
  || tag (16)
)>
```

AAD = `${appId} ${userKey} ${version}` (unchanged conceptually — the AAD construction already used these three fields; now they all come from the preamble).

- [ ] **Step 1: Failing test**

```ts
// extend src/oidc/sealed-token.test.ts
import { peekSealedTokenAppId, peekSealedTokenUserKey, peekSealedTokenVersion } from './sealed-token.js';

describe('peekSealedTokenAppId', () => {
  it('reads appId from preamble', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    expect(peekSealedTokenAppId(tok)).toBe(payload.appId);
  });
});

it('rejects tampered appId hint', () => {
  const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
  const buf = Buffer.from(tok.slice(4), 'base64url');
  // appId starts at index 2; flip a byte inside it
  buf[2] ^= 0x01;
  const forged = `ait_${buf.toString('base64url')}`;
  expect(() => unwrapSealedToken({ token: forged, resolveKey: () => sealingKey, expectedAppId: payload.appId }))
    .toThrow(/SEALED_TOKEN_TAMPERED/);
});

it('unwrapSealedTokenWithoutExpectedApp uses the preamble appId', () => {
  const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
  const got = unwrapSealedTokenWithoutExpectedApp({
    token: tok,
    resolveKey: () => sealingKey,
  });
  expect(got.payload).toEqual(payload);
  expect(got.appIdHint).toBe(payload.appId);
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```

- [ ] **Step 3: Update format + add the new helpers**

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
const APPID_LEN_BYTES = 1;
const USERKEY_LEN_BYTES = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export function wrapSealedToken(input: WrapInput): string {
  if (input.sealingKey.length !== 32) throw new Error('sealingKey must be 32 bytes');
  if (input.sealingKeyVersion < 1 || input.sealingKeyVersion > 255) {
    throw new Error('sealingKeyVersion must fit in 1 byte');
  }
  const appIdBuf = Buffer.from(input.payload.appId, 'utf8');
  if (appIdBuf.length === 0 || appIdBuf.length > 255) throw new Error('appId length out of range');
  const userKeyBuf = Buffer.from(input.payload.tossUserKey, 'utf8');
  if (userKeyBuf.length === 0 || userKeyBuf.length > 255) throw new Error('tossUserKey length out of range');
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
    Buffer.from([appIdBuf.length]),
    appIdBuf,
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
  const parts = parseSealed(input.token);
  if (parts.appId !== input.expectedAppId) throw new Error('SEALED_TOKEN_TAMPERED');
  return decryptOrThrow(parts, input.resolveKey, input.expectedAppId);
}

export interface UnwrapAnyAppOutput {
  appIdHint: string;
  payload: SealedPayload;
}

export function unwrapSealedTokenWithoutExpectedApp(input: {
  token: string;
  resolveKey: (sealingKeyVersion: number) => Buffer;
}): UnwrapAnyAppOutput {
  const parts = parseSealed(input.token);
  const payload = decryptOrThrow(parts, input.resolveKey, parts.appId);
  return { appIdHint: parts.appId, payload };
}

export function peekSealedTokenVersion(token: string): number {
  return parseSealed(token).version;
}

export function peekSealedTokenAppId(token: string): string {
  return parseSealed(token).appId;
}

export function peekSealedTokenUserKey(token: string): string {
  return parseSealed(token).userKey;
}

interface ParsedSealed {
  version: number;
  appId: string;
  userKey: string;
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

function parseSealed(token: string): ParsedSealed {
  if (!token.startsWith('ait_')) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  let buf: Buffer;
  try {
    buf = Buffer.from(token.slice(4), 'base64url');
  } catch {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  let off = 0;
  if (buf.length < off + VERSION_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const version = buf[off]!;
  off += VERSION_BYTES;
  if (buf.length < off + APPID_LEN_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const appIdLen = buf[off]!;
  off += APPID_LEN_BYTES;
  if (buf.length < off + appIdLen) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const appId = buf.subarray(off, off + appIdLen).toString('utf8');
  off += appIdLen;
  if (buf.length < off + USERKEY_LEN_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const userKeyLen = buf[off]!;
  off += USERKEY_LEN_BYTES;
  if (buf.length < off + userKeyLen) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const userKey = buf.subarray(off, off + userKeyLen).toString('utf8');
  off += userKeyLen;
  if (buf.length < off + IV_BYTES + TAG_BYTES + 1) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const iv = buf.subarray(off, off + IV_BYTES);
  off += IV_BYTES;
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(off, buf.length - TAG_BYTES);
  return { version, appId, userKey, iv, ciphertext, tag };
}

function decryptOrThrow(parts: ParsedSealed, resolveKey: (v: number) => Buffer, expectedAppId: string): SealedPayload {
  const key = resolveKey(parts.version);
  if (key.length !== 32) throw new Error('SEALED_TOKEN_BAD_KEY');
  const aad = buildAad(expectedAppId, parts.userKey, parts.version);
  const decipher = createDecipheriv('aes-256-gcm', key, parts.iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(parts.tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(parts.ciphertext), decipher.final()]);
  } catch {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  const parsed = JSON.parse(plaintext.toString('utf8')) as SealedPayload;
  if (parsed.appId !== expectedAppId || parsed.tossUserKey !== parts.userKey) {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  return parsed;
}

export function buildAad(appId: string, tossUserKey: string, version: number): Buffer {
  return Buffer.from(`${appId} ${tossUserKey} ${version}`, 'utf8');
}
```

- [ ] **Step 4: Update Phase 3's tampered-byte index in `src/oidc/sealed-token.test.ts`**

The byte indices for "tampered ciphertext" and "tampered userKey hint" tests need to move. With the new format, `appId='app_abc'` (7 bytes) follows the version byte. The new offsets:
- byte 0 = version
- byte 1 = appIdLen
- bytes 2..(2+appIdLen-1) = appId
- next byte = userKeyLen
- next bytes = userKey
- next 12 bytes = iv
- ... ciphertext ...
- last 16 bytes = tag

Adjust the existing `'rejects tampered ciphertext'` test to flip a byte inside the ciphertext region (e.g., index `tok-decoded.length - TAG_BYTES - 4`). Adjust `'rejects tampered userKey hint'` to flip a byte inside the userKey region (after `appId`).

```ts
// inside src/oidc/sealed-token.test.ts replace existing tampered tests with:
it('rejects tampered ciphertext', () => {
  const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
  const buf = Buffer.from(tok.slice(4), 'base64url');
  buf[buf.length - 17 - 1] ^= 0x01; // a byte just before the tag (inside ciphertext)
  const tampered = `ait_${buf.toString('base64url')}`;
  expect(() => unwrapSealedToken({ token: tampered, resolveKey: () => sealingKey, expectedAppId: payload.appId }))
    .toThrow(/SEALED_TOKEN_TAMPERED/);
});

it('rejects tampered userKey hint', () => {
  const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
  const buf = Buffer.from(tok.slice(4), 'base64url');
  // version(1) + appIdLen(1) + appId(7 for 'app_abc') + userKeyLen(1) → first userKey byte
  const userKeyStart = 1 + 1 + Buffer.from(payload.appId, 'utf8').length + 1;
  buf[userKeyStart] ^= 0x01;
  const forged = `ait_${buf.toString('base64url')}`;
  expect(() => unwrapSealedToken({ token: forged, resolveKey: () => sealingKey, expectedAppId: payload.appId }))
    .toThrow(/SEALED_TOKEN_TAMPERED/);
});
```

- [ ] **Step 5: Run all sealed-token tests, expect pass**

```bash
pnpm vitest run src/oidc/sealed-token.test.ts
```

- [ ] **Step 6: Run token-route tests — these also unwrap and might pick up the new format transparently**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

If they fail, the route's `peekSealedTokenVersion` + `unwrapSealedToken` calls are still compatible (the public API didn't change for those). Adjust only if a test asserted an exact byte length somewhere — none should.

- [ ] **Step 7: Commit**

```bash
git add src/oidc/sealed-token.ts src/oidc/sealed-token.test.ts
git commit -m "feat(oidc): bind appId in sealed token preamble for body-less unwrap"
```

---

## Task 5: Userinfo route — happy path (resumed)

**Files:**
- Create: `src/oidc/userinfo-route.ts`
- Test: `src/oidc/userinfo-route.test.ts`

Now with `peekSealedTokenAppId`, the userinfo route can identify the app before unwrap.

Userinfo response shape (per spec §6.2 + RFC OIDC core 5.3.2): same claims as id_token, plus PII passthrough. Phase 4 returns:

```json
{
  "sub": "<userKey as string>",
  "provider": "toss",
  "scope": "openid profile user_key",
  "toss:userKey": 42,
  "toss:agreedTerms": ["service", "marketing"],
  "toss:tossAccessTokenExpiresAt": <unix>
}
```

PII passthrough fields are not in the mock fixture. Phase 5 adds them when the real Toss adapter starts returning encrypted PII (`encryptedPii`). For now, if `loginMe` returns `encryptedPii`, splat it into the response under top-level keys verbatim.

- [ ] **Step 1: Failing test**

```ts
// src/oidc/userinfo-route.test.ts
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { generateKeyPairSync } from 'node:crypto';
import { wrapSealedToken } from './sealed-token.js';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createInMemoryRevocationStore } from './revocation-store.js';
import { userinfoRoute } from './userinfo-route.js';

interface FakeAppRow {
  id: string; clientId: string; sealingKeyVersion: number;
  allowedOrigins: string[]; ownershipStatus: 'active' | 'pending' | 'lapsed';
  rawTokensEnabled: boolean;
}

function fakeService(app: FakeAppRow) {
  return {
    apps: {
      async getById(id: string) { return id === app.id ? app : null; },
    },
    audit: { append: async () => {} },
  };
}

const sealingKey = Buffer.alloc(32, 13);

function makeAt(app: FakeAppRow, userKey = '42', tossAt = 'TOSS_AT_OPAQUE_FIXTURE'): string {
  return wrapSealedToken({
    sealingKey,
    sealingKeyVersion: app.sealingKeyVersion,
    payload: {
      appId: app.id,
      tossUserKey: userKey,
      tossAt,
      tossRt: 'TOSS_RT_OPAQUE_FIXTURE',
      tossAtExp: 1735689600,
      issuedAt: 1735686000,
    },
  });
}

function buildHarness(app: FakeAppRow, opts: { revocationStore?: ReturnType<typeof createInMemoryRevocationStore> } = {}) {
  const h = new Hono();
  h.route('/', userinfoRoute({
    service: fakeService(app) as any,
    tossAdapter: new MockTossAdapter(),
    resolveAppSealingKey: async () => sealingKey,
    revocationStore: opts.revocationStore ?? createInMemoryRevocationStore(),
  }));
  return h;
}

describe('GET /oidc/userinfo', () => {
  const app: FakeAppRow = {
    id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1,
    allowedOrigins: ['https://app.example.com'], ownershipStatus: 'active',
    rawTokensEnabled: false,
  };

  it('returns mapped claims for a valid AT', async () => {
    const h = buildHarness(app);
    const at = makeAt(app);
    const res = await h.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.sub).toBe('42');
    expect(body.provider).toBe('toss');
    expect(body.scope).toBe('openid profile user_key');
    expect(body['toss:userKey']).toBe(42);
    expect(body['toss:agreedTerms']).toEqual(['service', 'marketing']);
    expect(typeof body['toss:tossAccessTokenExpiresAt']).toBe('number');
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/userinfo-route.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/userinfo-route.ts
import { Hono } from 'hono';
import type { Service } from '../service/types.js';
import type { TossAdapter } from '../toss/adapter.js';
import { parseBearer } from './bearer.js';
import {
  peekSealedTokenAppId,
  peekSealedTokenVersion,
  unwrapSealedToken,
} from './sealed-token.js';
import type { RevocationStore } from './revocation-store.js';

export interface UserinfoRouteOpts {
  service: Service;
  tossAdapter: TossAdapter;
  resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
  revocationStore: RevocationStore;
}

function bearerError(c: Parameters<Parameters<Hono['get']>[1]>[0], description: string) {
  c.header('www-authenticate', `Bearer error="invalid_token", error_description="${description}"`);
  return c.json({ error: 'invalid_token', error_description: description }, 401);
}

export function userinfoRoute(opts: UserinfoRouteOpts) {
  const app = new Hono();

  app.get('/oidc/userinfo', async (c) => {
    const token = parseBearer(c.req.header('authorization'));
    if (!token) return bearerError(c, 'missing or malformed bearer');

    let appId: string;
    let version: number;
    try {
      appId = peekSealedTokenAppId(token);
      version = peekSealedTokenVersion(token);
    } catch {
      return bearerError(c, 'malformed token');
    }

    const appRow = await opts.service.apps.getById(appId);
    if (!appRow) return bearerError(c, 'unknown app');

    if (opts.revocationStore.isRevoked({ appId, token })) {
      return bearerError(c, 'token revoked');
    }

    let payload;
    try {
      const sealingKey = await opts.resolveAppSealingKey({ appId, sealingKeyVersion: version });
      payload = unwrapSealedToken({ token, resolveKey: () => sealingKey, expectedAppId: appId });
    } catch {
      return bearerError(c, 'token rejected');
    }

    let me;
    try {
      me = await opts.tossAdapter.loginMe({ appId }, { accessToken: payload.tossAt });
    } catch {
      return c.json({ error: 'upstream_error', error_description: 'login-me failed' }, 502);
    }

    const out: Record<string, unknown> = {
      sub: String(me.userKey),
      provider: 'toss',
      scope: me.scope.join(' '),
      'toss:userKey': me.userKey,
      'toss:agreedTerms': me.agreedTerms,
      'toss:tossAccessTokenExpiresAt': payload.tossAtExp,
    };
    if (me.encryptedPii) Object.assign(out, me.encryptedPii);
    return c.json(out);
  });

  return app;
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/userinfo-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/userinfo-route.ts src/oidc/userinfo-route.test.ts
git commit -m "feat(oidc): GET /oidc/userinfo happy path"
```

---

## Task 6: Userinfo error cases

**Files:**
- Modify: `src/oidc/userinfo-route.test.ts`

- [ ] **Step 1: Failing tests**

```ts
// extend src/oidc/userinfo-route.test.ts
describe('GET /oidc/userinfo error cases', () => {
  const app: FakeAppRow = {
    id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1,
    allowedOrigins: ['https://app.example.com'], ownershipStatus: 'active',
    rawTokensEnabled: false,
  };

  it('401 invalid_token when Authorization missing', async () => {
    const h = buildHarness(app);
    const res = await h.request('/oidc/userinfo');
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toMatch(/Bearer/);
    expect((await res.json()).error).toBe('invalid_token');
  });

  it('401 invalid_token when scheme is not Bearer', async () => {
    const h = buildHarness(app);
    const res = await h.request('/oidc/userinfo', { headers: { authorization: 'Basic abcdef' } });
    expect(res.status).toBe(401);
  });

  it('401 invalid_token for malformed token', async () => {
    const h = buildHarness(app);
    const res = await h.request('/oidc/userinfo', { headers: { authorization: 'Bearer not-a-token' } });
    expect(res.status).toBe(401);
  });

  it('401 invalid_token when app unknown', async () => {
    const otherApp: FakeAppRow = { ...app, id: 'app_other' };
    const at = makeAt(otherApp);
    const h = buildHarness(app); // service only knows app, not app_other
    const res = await h.request('/oidc/userinfo', { headers: { authorization: `Bearer ${at}` } });
    expect(res.status).toBe(401);
  });

  it('401 invalid_token for tampered token', async () => {
    const h = buildHarness(app);
    const at = makeAt(app);
    const tampered = at.slice(0, -4) + 'AAAA';
    const res = await h.request('/oidc/userinfo', { headers: { authorization: `Bearer ${tampered}` } });
    expect(res.status).toBe(401);
  });

  it('401 invalid_token when token is revoked', async () => {
    const store = createInMemoryRevocationStore();
    const at = makeAt(app);
    store.revoke({ appId: app.id, token: at });
    const h = buildHarness(app, { revocationStore: store });
    const res = await h.request('/oidc/userinfo', { headers: { authorization: `Bearer ${at}` } });
    expect(res.status).toBe(401);
    expect((await res.json()).error_description).toMatch(/revoked/);
  });

  it('502 upstream_error when Toss login-me fails', async () => {
    const h = buildHarness(app);
    const at = makeAt(app, '42', 'fail-at');
    const res = await h.request('/oidc/userinfo', { headers: { authorization: `Bearer ${at}` } });
    expect(res.status).toBe(502);
    expect((await res.json()).error).toBe('upstream_error');
  });
});
```

- [ ] **Step 2: Run, expect pass (since the implementation already covers these)**

```bash
pnpm vitest run src/oidc/userinfo-route.test.ts
```

If any fail, the userinfo handler is missing the corresponding branch — fix it. Don't weaken the test.

- [ ] **Step 3: Commit**

```bash
git add src/oidc/userinfo-route.test.ts
git commit -m "test(oidc): userinfo error cases"
```

---

## Task 7: Wire userinfo route into app

**Files:**
- Modify: `src/app.ts`
- Modify: `src/server.ts` (pass revocationStore)

- [ ] **Step 1: Failing test asserting `buildApp` mounts `/oidc/userinfo`**

Add to an existing test file (e.g., `src/oidc/userinfo-route.test.ts`):

```ts
import { buildApp } from '../app.js';
// ... existing imports ...

it('buildApp mounts /oidc/userinfo', async () => {
  const reg = await createSigningKeyRegistry({
    activeKid: 'k1',
    signingKeys: [{ kid: 'k1', pem: genPem() }],
  });
  const sealingKey = Buffer.alloc(32, 13);
  const fakeApp: FakeAppRow = {
    id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1,
    allowedOrigins: ['https://app.example.com'], ownershipStatus: 'active',
    rawTokensEnabled: false,
  };
  const built = await buildApp({
    service: fakeService(fakeApp) as any,
    oidcConfig: {
      issuer: 'https://x', activeKid: 'k1', signingKeys: [],
      idTokenTtlSeconds: 3600, defaultScope: 'openid profile user_key',
    },
    signingKeyRegistry: reg,
    tossAdapter: new MockTossAdapter(),
    resolveAppSealingKey: async () => sealingKey,
    revocationStore: createInMemoryRevocationStore(),
    now: () => 1735686000,
  } as any);
  const at = makeAt(fakeApp);
  const res = await built.request('/oidc/userinfo', { headers: { authorization: `Bearer ${at}` } });
  expect(res.status).toBe(200);
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/userinfo-route.test.ts
```

- [ ] **Step 3: Update `buildApp`**

```ts
// src/app.ts (additions)
import { userinfoRoute } from './oidc/userinfo-route.js';
import type { RevocationStore } from './oidc/revocation-store.js';

export interface BuildAppOpts {
  // ... existing fields ...
  revocationStore: RevocationStore;
}

// Inside buildApp:
app.route('/', userinfoRoute({
  service: opts.service,
  tossAdapter: opts.tossAdapter,
  resolveAppSealingKey: opts.resolveAppSealingKey,
  revocationStore: opts.revocationStore,
}));
```

In `src/server.ts`, construct an `InMemoryRevocationStore` once and pass it:

```ts
import { createInMemoryRevocationStore } from './oidc/revocation-store.js';

const revocationStore = createInMemoryRevocationStore();
const app = await buildApp({
  // ... existing args ...
  revocationStore,
});
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/userinfo-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/app.ts src/server.ts src/oidc/userinfo-route.test.ts
git commit -m "feat(app): mount /oidc/userinfo + wire revocation store"
```

---

## Task 8: Toss adapter — `accessRemove`

**Files:**
- Modify: `src/toss/adapter.ts`
- Modify: `src/toss/mock-adapter.ts`
- Modify: `src/toss/mock-adapter.test.ts`

`accessRemove` is the operation that, given a Toss `userKey`, invalidates the user's Toss-side session. Spec §6.3: invoked from `/oidc/revoke` when revoking a refresh token.

- [ ] **Step 1: Add to interface**

```ts
// src/toss/adapter.ts (extend)
export interface TossAdapter {
  // ... existing methods ...
  accessRemove(ctx: TossAdapterContext, input: { userKey: string }): Promise<void>;
}
```

- [ ] **Step 2: Failing test**

```ts
// extend src/toss/mock-adapter.test.ts
describe('MockTossAdapter.accessRemove', () => {
  it('records calls (for assertions in revoke flow)', async () => {
    const adapter = new MockTossAdapter();
    await adapter.accessRemove({ appId: 'app_a' }, { userKey: '42' });
    expect(adapter.accessRemoveCalls).toEqual([{ appId: 'app_a', userKey: '42' }]);
  });
  it('throws upstream_error for fail-userkey to simulate Toss network', async () => {
    const adapter = new MockTossAdapter();
    await expect(adapter.accessRemove({ appId: 'a' }, { userKey: 'fail-userkey' }))
      .rejects.toMatchObject({ code: 'upstream_error' });
  });
});
```

- [ ] **Step 3: Run, expect failure**

```bash
pnpm vitest run src/toss/mock-adapter.test.ts
```

- [ ] **Step 4: Implement**

In `src/toss/mock-adapter.ts`:

```ts
export class MockTossAdapter implements TossAdapter {
  // ... existing fields/methods ...
  public readonly accessRemoveCalls: { appId: string; userKey: string }[] = [];

  async accessRemove(ctx: TossAdapterContext, input: { userKey: string }): Promise<void> {
    if (input.userKey === 'fail-userkey') {
      throw new TossUpstreamError('upstream_error', 'mock fail-userkey');
    }
    this.accessRemoveCalls.push({ appId: ctx.appId, userKey: input.userKey });
  }
}
```

- [ ] **Step 5: Run, expect pass**

```bash
pnpm vitest run src/toss/mock-adapter.test.ts
```

- [ ] **Step 6: Commit**

```bash
git add src/toss/adapter.ts src/toss/mock-adapter.ts src/toss/mock-adapter.test.ts
git commit -m "feat(toss): adapter.accessRemove + mock implementation"
```

---

## Task 9: Revoke route — RFC 7009 always-200

**Files:**
- Create: `src/oidc/revoke-route.ts`
- Test: `src/oidc/revoke-route.test.ts`

`POST /oidc/revoke` accepts `application/x-www-form-urlencoded` with `token=ait_*` and optional `token_type_hint=access_token|refresh_token`. Always returns 200 unless infrastructure failure.

For Phase 4 (no client auth on revoke yet — spec §6.3 doesn't require it; the token itself is the auth-bearer in the sense that knowing it lets you revoke it):
1. Parse body → extract `token`.
2. If token isn't `ait_*`, return 200 (RFC 7009 unknown handling).
3. Peek `appId` and `userKey`; if peek fails, return 200.
4. Look up app; if missing, return 200.
5. Try unwrap. If unwrap succeeds → mark revoked; if it's a refresh token (we can't tell from format alone, so use `token_type_hint`, defaulting to `access_token`), call `accessRemove({ userKey: payload.tossUserKey })`. Errors from `accessRemove` are swallowed (RFC 7009 always-200) but logged.
6. Audit-log the revocation attempt.

> Spec §6.3 wording: "If the token is a refresh token, Bridge calls Toss `/access-remove` ... If access token only, Bridge marks the wrapper as revoked locally". The `token_type_hint` parameter (RFC 7009 §2.1) is the canonical way to distinguish — present if the caller knows.

- [ ] **Step 1: Failing test**

```ts
// src/oidc/revoke-route.test.ts
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { wrapSealedToken } from './sealed-token.js';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createInMemoryRevocationStore } from './revocation-store.js';
import { revokeRoute } from './revoke-route.js';

const sealingKey = Buffer.alloc(32, 13);

interface FakeAppRow { id: string; clientId: string; sealingKeyVersion: number; }
function fakeService(app: FakeAppRow) {
  return {
    apps: { async getById(id: string) { return id === app.id ? app : null; } },
    audit: { append: async () => {} },
  };
}

function makeToken(app: FakeAppRow, userKey = '42'): string {
  return wrapSealedToken({
    sealingKey,
    sealingKeyVersion: app.sealingKeyVersion,
    payload: {
      appId: app.id, tossUserKey: userKey,
      tossAt: 'TOSS_AT_OPAQUE_FIXTURE', tossRt: 'TOSS_RT_OPAQUE_FIXTURE',
      tossAtExp: 1735689600, issuedAt: 1735686000,
    },
  });
}

function buildHarness(app: FakeAppRow, opts?: { adapter?: MockTossAdapter; store?: ReturnType<typeof createInMemoryRevocationStore> }) {
  const h = new Hono();
  const adapter = opts?.adapter ?? new MockTossAdapter();
  const store = opts?.store ?? createInMemoryRevocationStore();
  h.route('/', revokeRoute({
    service: fakeService(app) as any,
    tossAdapter: adapter,
    resolveAppSealingKey: async () => sealingKey,
    revocationStore: store,
  }));
  return { app: h, adapter, store };
}

describe('POST /oidc/revoke', () => {
  const app: FakeAppRow = { id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1 };

  it('returns 200 for unknown token', async () => {
    const { app: h } = buildHarness(app);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'token=not-ait',
    });
    expect(res.status).toBe(200);
  });

  it('marks an access_token revoked locally and does NOT call accessRemove', async () => {
    const { app: h, adapter, store } = buildHarness(app);
    const at = makeToken(app);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(at)}&token_type_hint=access_token`,
    });
    expect(res.status).toBe(200);
    expect(store.isRevoked({ appId: app.id, token: at })).toBe(true);
    expect(adapter.accessRemoveCalls).toEqual([]);
  });

  it('refresh_token hint triggers accessRemove on Toss', async () => {
    const { app: h, adapter, store } = buildHarness(app);
    const rt = makeToken(app);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(rt)}&token_type_hint=refresh_token`,
    });
    expect(res.status).toBe(200);
    expect(adapter.accessRemoveCalls).toEqual([{ appId: app.id, userKey: '42' }]);
    expect(store.isRevoked({ appId: app.id, token: rt })).toBe(true);
  });

  it('still returns 200 even if accessRemove on Toss fails', async () => {
    const { app: h } = buildHarness(app);
    const rt = wrapSealedToken({
      sealingKey, sealingKeyVersion: 1,
      payload: {
        appId: app.id, tossUserKey: 'fail-userkey',
        tossAt: 'x', tossRt: 'x', tossAtExp: 1, issuedAt: 1,
      },
    });
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(rt)}&token_type_hint=refresh_token`,
    });
    expect(res.status).toBe(200);
  });

  it('returns 200 when token is malformed but parseable as ait_', async () => {
    const { app: h } = buildHarness(app);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'token=ait_AAAAA',
    });
    expect(res.status).toBe(200);
  });

  it('returns 200 with no body params (treats as unknown token)', async () => {
    const { app: h } = buildHarness(app);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: '',
    });
    expect(res.status).toBe(200);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/revoke-route.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/revoke-route.ts
import { Hono } from 'hono';
import { z } from 'zod';
import type { Service } from '../service/types.js';
import type { TossAdapter } from '../toss/adapter.js';
import type { RevocationStore } from './revocation-store.js';
import {
  peekSealedTokenAppId,
  peekSealedTokenVersion,
  unwrapSealedToken,
} from './sealed-token.js';

export interface RevokeRouteOpts {
  service: Service;
  tossAdapter: TossAdapter;
  resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
  revocationStore: RevocationStore;
}

const revokeBody = z.object({
  token: z.string().optional(),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
});

export function revokeRoute(opts: RevokeRouteOpts) {
  const app = new Hono();

  app.post('/oidc/revoke', async (c) => {
    let raw: unknown;
    const ct = c.req.header('content-type') ?? '';
    try {
      if (ct.includes('application/x-www-form-urlencoded')) {
        raw = await c.req.parseBody();
      } else if (ct.includes('application/json')) {
        raw = await c.req.json();
      } else {
        return c.body(null, 200); // RFC 7009 always-200
      }
    } catch {
      return c.body(null, 200);
    }
    const parsed = revokeBody.safeParse(raw);
    if (!parsed.success || !parsed.data.token) return c.body(null, 200);
    const token = parsed.data.token;
    if (!token.startsWith('ait_')) return c.body(null, 200);

    let appId: string;
    let version: number;
    try {
      appId = peekSealedTokenAppId(token);
      version = peekSealedTokenVersion(token);
    } catch {
      return c.body(null, 200);
    }
    const appRow = await opts.service.apps.getById(appId);
    if (!appRow) return c.body(null, 200);

    let payload;
    try {
      const sealingKey = await opts.resolveAppSealingKey({ appId, sealingKeyVersion: version });
      payload = unwrapSealedToken({ token, resolveKey: () => sealingKey, expectedAppId: appId });
    } catch {
      return c.body(null, 200);
    }

    opts.revocationStore.revoke({ appId, token });

    if (parsed.data.token_type_hint === 'refresh_token') {
      try {
        await opts.tossAdapter.accessRemove({ appId }, { userKey: payload.tossUserKey });
      } catch {
        // RFC 7009 always-200 — swallow upstream errors.
      }
    }

    await opts.service.audit.append({
      actor: { type: 'app', id: appId },
      action: 'oidc.token.revoke',
      target: { type: 'app', id: appId },
      details: { hint: parsed.data.token_type_hint ?? 'unspecified' },
    });
    return c.body(null, 200);
  });

  return app;
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/revoke-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/revoke-route.ts src/oidc/revoke-route.test.ts
git commit -m "feat(oidc): POST /oidc/revoke (RFC 7009 always-200)"
```

---

## Task 10: Wire revoke route into app

**Files:**
- Modify: `src/app.ts`
- Test: `src/oidc/revoke-route.test.ts` (extend)

- [ ] **Step 1: Failing test**

```ts
// extend src/oidc/revoke-route.test.ts
import { buildApp } from '../app.js';
// ... reuse existing makeToken / fakeService ...

it('buildApp mounts /oidc/revoke', async () => {
  const reg = await createSigningKeyRegistry({
    activeKid: 'k1',
    signingKeys: [{ kid: 'k1', pem: genPem() }],
  });
  const fakeApp = { id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1 };
  const built = await buildApp({
    service: fakeService(fakeApp) as any,
    oidcConfig: {
      issuer: 'https://x', activeKid: 'k1', signingKeys: [],
      idTokenTtlSeconds: 3600, defaultScope: 'openid profile user_key',
    },
    signingKeyRegistry: reg,
    tossAdapter: new MockTossAdapter(),
    resolveAppSealingKey: async () => sealingKey,
    revocationStore: createInMemoryRevocationStore(),
  } as any);
  const res = await built.request('/oidc/revoke', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'token=not-ait',
  });
  expect(res.status).toBe(200);
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/revoke-route.test.ts
```

- [ ] **Step 3: Update `buildApp`**

```ts
// src/app.ts
import { revokeRoute } from './oidc/revoke-route.js';

// Inside buildApp:
app.route('/', revokeRoute({
  service: opts.service,
  tossAdapter: opts.tossAdapter,
  resolveAppSealingKey: opts.resolveAppSealingKey,
  revocationStore: opts.revocationStore,
}));
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/revoke-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/app.ts src/oidc/revoke-route.test.ts
git commit -m "feat(app): mount /oidc/revoke"
```

---

## Task 11: Confidential-client auth resolver

**Files:**
- Create: `src/oidc/client-auth.ts`
- Test: `src/oidc/client-auth.test.ts`

Three input shapes per spec §6.1 + RFC 6749 §2.3:
- `client_secret_basic`: `Authorization: Basic base64(client_id:client_secret)`. Body's `client_id` (if present) **must match** the Authorization decode; mismatch is `invalid_client`.
- `client_secret_post`: body has `client_id` and `client_secret`.
- Public: neither `Authorization: Basic` nor `client_secret` in body. Origin header carries the auth.

Mixing methods (e.g., `Authorization: Basic ...` AND a body `client_secret`) is `invalid_client` — RFC 6749 §2.3 prohibits multiple auth methods per request.

The resolver returns `{ kind: 'public' } | { kind: 'confidential', plainSecret: string } | { kind: 'invalid', reason: string }`. Origin check stays in the route (it depends on the resolved app's `allowedOrigins`).

- [ ] **Step 1: Failing test**

```ts
// src/oidc/client-auth.test.ts
import { describe, it, expect } from 'vitest';
import { resolveClientAuth } from './client-auth.js';

describe('resolveClientAuth', () => {
  it('returns public when no Authorization header and no client_secret in body', () => {
    const r = resolveClientAuth({
      authorization: undefined,
      bodyClientId: 'app_abc',
      bodyClientSecret: undefined,
    });
    expect(r).toEqual({ kind: 'public' });
  });

  it('returns confidential from client_secret_basic', () => {
    const auth = `Basic ${Buffer.from('app_abc:s3cret').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: 'app_abc',
      bodyClientSecret: undefined,
    });
    expect(r).toEqual({ kind: 'confidential', clientId: 'app_abc', plainSecret: 's3cret' });
  });

  it('returns confidential from client_secret_post', () => {
    const r = resolveClientAuth({
      authorization: undefined,
      bodyClientId: 'app_abc',
      bodyClientSecret: 's3cret',
    });
    expect(r).toEqual({ kind: 'confidential', clientId: 'app_abc', plainSecret: 's3cret' });
  });

  it('rejects mixing Basic + body client_secret', () => {
    const auth = `Basic ${Buffer.from('app_abc:s3cret').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: 'app_abc',
      bodyClientSecret: 's3cret',
    });
    expect(r.kind).toBe('invalid');
    expect((r as { reason: string }).reason).toMatch(/multiple/);
  });

  it('rejects Basic when body client_id mismatches Basic-decoded client_id', () => {
    const auth = `Basic ${Buffer.from('app_abc:s3cret').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: 'app_other',
      bodyClientSecret: undefined,
    });
    expect(r.kind).toBe('invalid');
    expect((r as { reason: string }).reason).toMatch(/mismatch/);
  });

  it('rejects malformed Basic', () => {
    const r = resolveClientAuth({
      authorization: 'Basic !!!!',
      bodyClientId: 'app_abc',
      bodyClientSecret: undefined,
    });
    expect(r.kind).toBe('invalid');
  });

  it('rejects Basic without colon', () => {
    const auth = `Basic ${Buffer.from('justaname').toString('base64')}`;
    const r = resolveClientAuth({
      authorization: auth,
      bodyClientId: 'justaname',
      bodyClientSecret: undefined,
    });
    expect(r.kind).toBe('invalid');
  });

  it('ignores non-Basic Authorization (treats as public)', () => {
    const r = resolveClientAuth({
      authorization: 'Bearer ait_xxx',
      bodyClientId: 'app_abc',
      bodyClientSecret: undefined,
    });
    expect(r).toEqual({ kind: 'public' });
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/client-auth.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/client-auth.ts
export type ClientAuthResult =
  | { kind: 'public' }
  | { kind: 'confidential'; clientId: string; plainSecret: string }
  | { kind: 'invalid'; reason: string };

export interface ClientAuthInput {
  authorization: string | undefined;
  bodyClientId: string;
  bodyClientSecret: string | undefined;
}

export function resolveClientAuth(input: ClientAuthInput): ClientAuthResult {
  const basic = parseBasic(input.authorization);
  const hasBasic = basic !== null;
  const hasBodySecret = typeof input.bodyClientSecret === 'string' && input.bodyClientSecret.length > 0;
  if (hasBasic && hasBodySecret) {
    return { kind: 'invalid', reason: 'multiple authentication methods' };
  }
  if (hasBasic) {
    if (basic.malformed) return { kind: 'invalid', reason: 'malformed Basic credentials' };
    if (basic.clientId !== input.bodyClientId) {
      return { kind: 'invalid', reason: 'client_id mismatch between Basic and body' };
    }
    return { kind: 'confidential', clientId: basic.clientId, plainSecret: basic.secret };
  }
  if (hasBodySecret) {
    return { kind: 'confidential', clientId: input.bodyClientId, plainSecret: input.bodyClientSecret! };
  }
  return { kind: 'public' };
}

interface ParsedBasic {
  malformed: boolean;
  clientId: string;
  secret: string;
}

function parseBasic(authorization: string | undefined): ParsedBasic | null {
  if (!authorization) return null;
  const m = /^Basic\s+(\S+)\s*$/i.exec(authorization);
  if (!m) return null;
  let decoded: string;
  try {
    decoded = Buffer.from(m[1]!, 'base64').toString('utf8');
  } catch {
    return { malformed: true, clientId: '', secret: '' };
  }
  if (!/^[\x20-\x7e]+$/.test(decoded)) {
    return { malformed: true, clientId: '', secret: '' };
  }
  const idx = decoded.indexOf(':');
  if (idx < 0) return { malformed: true, clientId: '', secret: '' };
  return { malformed: false, clientId: decoded.slice(0, idx), secret: decoded.slice(idx + 1) };
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/client-auth.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/client-auth.ts src/oidc/client-auth.test.ts
git commit -m "feat(oidc): client auth resolver (basic + post + public)"
```

---

## Task 12: Wire confidential-client auth into `/oidc/token`

**Files:**
- Modify: `src/oidc/token-route.ts`
- Modify: `src/oidc/token-schemas.ts` (allow `client_secret` in body for confidential)
- Modify: `src/oidc/token-route.test.ts` (extend)

- [ ] **Step 1: Extend body schema**

```ts
// src/oidc/token-schemas.ts (revise)
import { z } from 'zod';

export const tokenAuthorizationCodeBody = z.object({
  grant_type: z.literal('authorization_code'),
  code: z.string().min(1),
  client_id: z.string().min(1),
  redirect_uri: z.string().optional(),
  code_verifier: z.string().optional(),
  referrer: z.string().optional(),
  client_secret: z.string().optional(),
});

export const tokenRefreshBody = z.object({
  grant_type: z.literal('refresh_token'),
  refresh_token: z.string().min(1),
  client_id: z.string().min(1),
  client_secret: z.string().optional(),
});

export const tokenBody = z.discriminatedUnion('grant_type', [
  tokenAuthorizationCodeBody,
  tokenRefreshBody,
]);
export type TokenBody = z.infer<typeof tokenBody>;
```

- [ ] **Step 2: Failing tests for confidential-client scenarios**

```ts
// extend src/oidc/token-route.test.ts
import bcrypt from 'bcryptjs';

describe('POST /oidc/token (confidential client)', () => {
  // FakeAppRow needs clientSecretHashes for these tests
  interface ConfApp extends FakeAppRow { clientSecretHashes: string[] }
  function fakeServiceConf(app: ConfApp) {
    return {
      apps: { async getByClientId(clientId: string) { return clientId === app.clientId ? app : null; } },
      audit: { append: async () => {} },
    };
  }
  async function buildHarnessConf(app: ConfApp) {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1', signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const sealingKey = Buffer.alloc(32, 11);
    const tokenService = createTokenService({
      adapter: new MockTossAdapter(),
      registry: reg,
      issuer: 'https://x',
      idTokenTtlSeconds: 3600,
      resolveAppSealingKey: async () => sealingKey,
      now: () => 1735686000,
    });
    const h = new Hono();
    h.route('/', tokenRoute({
      service: fakeServiceConf(app) as any,
      tokenService,
      resolveAppSealingKey: async () => sealingKey,
    }));
    return h;
  }

  const plain = 's3cret';
  const hash = bcrypt.hashSync(plain, 10);
  const app: ConfApp = {
    id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1,
    allowedOrigins: [], // empty — confidential clients don't rely on Origin
    ownershipStatus: 'active',
    clientSecretHashes: [hash],
  };

  it('happy with client_secret_basic', async () => {
    const h = await buildHarnessConf(app);
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Basic ${Buffer.from(`${app.clientId}:${plain}`).toString('base64')}`,
      },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: app.clientId }),
    });
    expect(res.status).toBe(200);
  });

  it('happy with client_secret_post', async () => {
    const h = await buildHarnessConf(app);
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code', code: 'good',
        client_id: app.clientId, client_secret: plain,
      }),
    });
    expect(res.status).toBe(200);
  });

  it('401 invalid_client when secret wrong', async () => {
    const h = await buildHarnessConf(app);
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Basic ${Buffer.from(`${app.clientId}:wrong`).toString('base64')}`,
      },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: app.clientId }),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe('invalid_client');
  });

  it('401 invalid_client when both Basic and body client_secret present', async () => {
    const h = await buildHarnessConf(app);
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Basic ${Buffer.from(`${app.clientId}:${plain}`).toString('base64')}`,
      },
      body: JSON.stringify({
        grant_type: 'authorization_code', code: 'good',
        client_id: app.clientId, client_secret: plain,
      }),
    });
    expect(res.status).toBe(401);
  });

  it('confidential overlap: still accepts after rotation when both hashes valid', async () => {
    const newPlain = 'newsecret';
    const newHash = bcrypt.hashSync(newPlain, 10);
    const rotated: ConfApp = { ...app, clientSecretHashes: [hash, newHash] };
    const h = await buildHarnessConf(rotated);
    for (const p of [plain, newPlain]) {
      const res = await h.request('/oidc/token', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Basic ${Buffer.from(`${rotated.clientId}:${p}`).toString('base64')}`,
        },
        body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: rotated.clientId }),
      });
      expect(res.status).toBe(200);
    }
  });
});
```

- [ ] **Step 3: Run, expect failure**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 4: Update `tokenRoute` to honor confidential auth**

In `src/oidc/token-route.ts`, after parsing the body and before the origin check, branch on `resolveClientAuth`. The new structure:

```ts
import { resolveClientAuth } from './client-auth.js';
import { verifyClientSecret } from '../service/secrets.js'; // Phase 2 export

// Inside the handler, after we have parsed body and looked up appRow:

const authResult = resolveClientAuth({
  authorization: c.req.header('authorization'),
  bodyClientId: body.client_id,
  bodyClientSecret: body.client_secret,
});
if (authResult.kind === 'invalid') {
  const e = toOAuthError({ code: 'invalid_client', description: authResult.reason });
  return c.json(e.body, e.status as never);
}

if (authResult.kind === 'confidential') {
  const ok = await verifyClientSecret(authResult.plainSecret, appRow.clientSecretHashes ?? []);
  if (!ok) {
    const e = toOAuthError({ code: 'invalid_client', description: 'invalid client_secret' });
    return c.json(e.body, e.status as never);
  }
} else {
  // public — origin check (existing code)
  const origin = c.req.header('origin');
  if (!originIsAllowed(origin, appRow.allowedOrigins)) {
    const e = toOAuthError({ code: 'invalid_client', description: 'origin not allowed' });
    return c.json(e.body, e.status as never);
  }
}
```

The `app` passed to `tokenService` is the same shape regardless of auth kind. The test fakeServiceConf returns the row with `clientSecretHashes`; existing public-client tests don't supply that field — they use `Origin` and the public branch never reads `clientSecretHashes`.

- [ ] **Step 5: Run, expect pass**

```bash
pnpm vitest run src/oidc/token-route.test.ts
```

- [ ] **Step 6: Commit**

```bash
git add src/oidc/token-route.ts src/oidc/token-schemas.ts src/oidc/token-route.test.ts
git commit -m "feat(oidc): confidential-client auth (basic + post) on /oidc/token"
```

---

## Task 13: Origin enforcement hardening

**Files:**
- Modify: `src/oidc/origin-check.ts`
- Modify: `src/oidc/origin-check.test.ts`

Spec §9: "Origin enforcement: strict equality; default-deny." Phase 3 covered the basics. Phase 4 hardens against:
- multiple `Origin` headers (Hono sees the first; that's fine, but we still validate)
- whitespace and casing in the value (no normalization — strict equality)
- `null` literal Origin (sandbox iframes send `null`; spec is default-deny — we reject)

- [ ] **Step 1: Failing tests**

```ts
// extend src/oidc/origin-check.test.ts
it('rejects literal "null" origin', () => {
  expect(originIsAllowed('null', ['https://app.example.com'])).toBe(false);
  expect(originIsAllowed('null', ['null'])).toBe(false); // never allow even if listed
});

it('rejects origin with surrounding whitespace', () => {
  expect(originIsAllowed(' https://app.example.com', ['https://app.example.com'])).toBe(false);
  expect(originIsAllowed('https://app.example.com ', ['https://app.example.com'])).toBe(false);
});

it('rejects allowlist entries that are themselves bogus', () => {
  // empty / non-https entries are not honored even if a request sent the same string
  expect(originIsAllowed('', [''])).toBe(false);
  expect(originIsAllowed('null', ['null'])).toBe(false);
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/origin-check.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/origin-check.ts
const FORBIDDEN_VALUES = new Set(['null', '']);

export function originIsAllowed(origin: string | undefined, allowed: string[]): boolean {
  if (!origin) return false;
  if (origin !== origin.trim()) return false;
  if (FORBIDDEN_VALUES.has(origin)) return false;
  if (allowed.length === 0) return false;
  // Filter forbidden values from allowlist defensively, in case a stored row contains junk.
  for (const a of allowed) {
    if (FORBIDDEN_VALUES.has(a)) continue;
    if (a === origin) return true;
  }
  return false;
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/origin-check.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/origin-check.ts src/oidc/origin-check.test.ts
git commit -m "fix(oidc): harden origin allowlist against null/whitespace"
```

---

## Task 14: Raw-tokens route — 404 by default, 200 when enabled, never returns RT

**Files:**
- Create: `src/oidc/raw-tokens-route.ts`
- Test: `src/oidc/raw-tokens-route.test.ts`

`GET /oidc/raw-tokens` with `Authorization: Bearer ait_<access_token>`. Returns 404 (look like the route doesn't exist) when `apps.rawTokensEnabled === false`. When enabled, returns `{ access_token: <toss_AT>, expires_in: <toss_AT_exp - now> }`. Audit-logged on every successful call. **Never** returns the refresh token — even by accident.

- [ ] **Step 1: Failing test**

```ts
// src/oidc/raw-tokens-route.test.ts
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { wrapSealedToken } from './sealed-token.js';
import { createInMemoryRevocationStore } from './revocation-store.js';
import { rawTokensRoute } from './raw-tokens-route.js';

const sealingKey = Buffer.alloc(32, 13);

interface FakeAppRow { id: string; clientId: string; sealingKeyVersion: number; rawTokensEnabled: boolean; }
function fakeService(app: FakeAppRow) {
  return {
    apps: { async getById(id: string) { return id === app.id ? app : null; } },
    audit: { append: async () => {} },
  };
}

function makeAt(app: FakeAppRow): string {
  return wrapSealedToken({
    sealingKey, sealingKeyVersion: app.sealingKeyVersion,
    payload: {
      appId: app.id, tossUserKey: '42',
      tossAt: 'TOSS_AT_OPAQUE_FIXTURE', tossRt: 'TOSS_RT_OPAQUE_FIXTURE',
      tossAtExp: 1735690000, issuedAt: 1735686000,
    },
  });
}

function buildHarness(app: FakeAppRow) {
  const h = new Hono();
  h.route('/', rawTokensRoute({
    service: fakeService(app) as any,
    resolveAppSealingKey: async () => sealingKey,
    revocationStore: createInMemoryRevocationStore(),
    now: () => 1735686100,
  }));
  return h;
}

describe('GET /oidc/raw-tokens', () => {
  const disabledApp: FakeAppRow = {
    id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1, rawTokensEnabled: false,
  };
  const enabledApp: FakeAppRow = { ...disabledApp, rawTokensEnabled: true };

  it('returns 404 when rawTokensEnabled is false', async () => {
    const h = buildHarness(disabledApp);
    const at = makeAt(disabledApp);
    const res = await h.request('/oidc/raw-tokens', { headers: { authorization: `Bearer ${at}` } });
    expect(res.status).toBe(404);
  });

  it('returns access_token and expires_in when enabled', async () => {
    const h = buildHarness(enabledApp);
    const at = makeAt(enabledApp);
    const res = await h.request('/oidc/raw-tokens', { headers: { authorization: `Bearer ${at}` } });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toBe('TOSS_AT_OPAQUE_FIXTURE');
    expect(body.expires_in).toBe(1735690000 - 1735686100);
  });

  it('never returns refresh_token', async () => {
    const h = buildHarness(enabledApp);
    const at = makeAt(enabledApp);
    const res = await h.request('/oidc/raw-tokens', { headers: { authorization: `Bearer ${at}` } });
    const body = await res.json();
    expect(body).not.toHaveProperty('refresh_token');
    expect(JSON.stringify(body)).not.toContain('TOSS_RT_OPAQUE_FIXTURE');
  });

  it('returns 401 when no bearer', async () => {
    const h = buildHarness(enabledApp);
    const res = await h.request('/oidc/raw-tokens');
    expect(res.status).toBe(401);
  });

  it('returns 401 when token revoked', async () => {
    const at = makeAt(enabledApp);
    const store = createInMemoryRevocationStore();
    store.revoke({ appId: enabledApp.id, token: at });
    const h = new Hono();
    h.route('/', rawTokensRoute({
      service: fakeService(enabledApp) as any,
      resolveAppSealingKey: async () => sealingKey,
      revocationStore: store,
      now: () => 1735686100,
    }));
    const res = await h.request('/oidc/raw-tokens', { headers: { authorization: `Bearer ${at}` } });
    expect(res.status).toBe(401);
  });

  it('returns expires_in clamped to 0 when AT already expired', async () => {
    const h = new Hono();
    h.route('/', rawTokensRoute({
      service: fakeService(enabledApp) as any,
      resolveAppSealingKey: async () => sealingKey,
      revocationStore: createInMemoryRevocationStore(),
      now: () => 9999999999,
    }));
    const at = makeAt(enabledApp);
    const res = await h.request('/oidc/raw-tokens', { headers: { authorization: `Bearer ${at}` } });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.expires_in).toBe(0);
  });
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/raw-tokens-route.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/oidc/raw-tokens-route.ts
import { Hono } from 'hono';
import type { Service } from '../service/types.js';
import type { RevocationStore } from './revocation-store.js';
import { parseBearer } from './bearer.js';
import {
  peekSealedTokenAppId,
  peekSealedTokenVersion,
  unwrapSealedToken,
} from './sealed-token.js';

export interface RawTokensRouteOpts {
  service: Service;
  resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
  revocationStore: RevocationStore;
  now: () => number;
}

export function rawTokensRoute(opts: RawTokensRouteOpts) {
  const app = new Hono();

  app.get('/oidc/raw-tokens', async (c) => {
    const token = parseBearer(c.req.header('authorization'));
    if (!token) {
      c.header('www-authenticate', 'Bearer error="invalid_token"');
      return c.json({ error: 'invalid_token' }, 401);
    }

    let appId: string;
    let version: number;
    try {
      appId = peekSealedTokenAppId(token);
      version = peekSealedTokenVersion(token);
    } catch {
      c.header('www-authenticate', 'Bearer error="invalid_token"');
      return c.json({ error: 'invalid_token' }, 401);
    }

    const appRow = await opts.service.apps.getById(appId);
    if (!appRow) {
      c.header('www-authenticate', 'Bearer error="invalid_token"');
      return c.json({ error: 'invalid_token' }, 401);
    }

    if (!appRow.rawTokensEnabled) {
      // Look like the route doesn't exist for this app.
      return c.json({ error: 'not_found' }, 404);
    }

    if (opts.revocationStore.isRevoked({ appId, token })) {
      c.header('www-authenticate', 'Bearer error="invalid_token", error_description="revoked"');
      return c.json({ error: 'invalid_token' }, 401);
    }

    let payload;
    try {
      const sealingKey = await opts.resolveAppSealingKey({ appId, sealingKeyVersion: version });
      payload = unwrapSealedToken({ token, resolveKey: () => sealingKey, expectedAppId: appId });
    } catch {
      c.header('www-authenticate', 'Bearer error="invalid_token"');
      return c.json({ error: 'invalid_token' }, 401);
    }

    await opts.service.audit.append({
      actor: { type: 'app', id: appId },
      action: 'oidc.raw-tokens.read',
      target: { type: 'app', id: appId },
      details: {},
    });

    const expiresIn = Math.max(0, payload.tossAtExp - opts.now());
    return c.json({ access_token: payload.tossAt, expires_in: expiresIn });
  });

  return app;
}
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/raw-tokens-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/oidc/raw-tokens-route.ts src/oidc/raw-tokens-route.test.ts
git commit -m "feat(oidc): GET /oidc/raw-tokens (opt-in, never returns RT)"
```

---

## Task 15: Wire raw-tokens route into app

**Files:**
- Modify: `src/app.ts`
- Test: `src/oidc/raw-tokens-route.test.ts` (extend)

- [ ] **Step 1: Failing test**

```ts
// extend src/oidc/raw-tokens-route.test.ts
import { buildApp } from '../app.js';
// ... reuse existing imports ...

it('buildApp mounts /oidc/raw-tokens', async () => {
  const reg = await createSigningKeyRegistry({
    activeKid: 'k1', signingKeys: [{ kid: 'k1', pem: genPem() }],
  });
  const fakeApp: FakeAppRow = {
    id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1, rawTokensEnabled: true,
  };
  const built = await buildApp({
    service: fakeService(fakeApp) as any,
    oidcConfig: {
      issuer: 'https://x', activeKid: 'k1', signingKeys: [],
      idTokenTtlSeconds: 3600, defaultScope: 'openid profile user_key',
    },
    signingKeyRegistry: reg,
    tossAdapter: new MockTossAdapter(),
    resolveAppSealingKey: async () => sealingKey,
    revocationStore: createInMemoryRevocationStore(),
    now: () => 1735686100,
  } as any);
  const at = makeAt(fakeApp);
  const res = await built.request('/oidc/raw-tokens', { headers: { authorization: `Bearer ${at}` } });
  expect(res.status).toBe(200);
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/oidc/raw-tokens-route.test.ts
```

- [ ] **Step 3: Update `buildApp`**

```ts
// src/app.ts
import { rawTokensRoute } from './oidc/raw-tokens-route.js';

export interface BuildAppOpts {
  // ... existing ...
  now?: () => number;
}

// Inside buildApp, after the userinfo + revoke mounts:
const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
app.route('/', rawTokensRoute({
  service: opts.service,
  resolveAppSealingKey: opts.resolveAppSealingKey,
  revocationStore: opts.revocationStore,
  now,
}));
```

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/oidc/raw-tokens-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/app.ts src/oidc/raw-tokens-route.test.ts
git commit -m "feat(app): mount /oidc/raw-tokens"
```

---

## Task 16: End-to-end happy path test (token → userinfo → revoke)

**Files:**
- Create: `src/oidc/zero-code-flow.test.ts`

This is the highest-value integration: a public-client mini-app gets a sealed AT, calls userinfo, then revokes the refresh token. All in-process, mocked Toss.

- [ ] **Step 1: Failing test**

```ts
// src/oidc/zero-code-flow.test.ts
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { buildApp } from '../app.js';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createSigningKeyRegistry } from './signing-keys.js';
import { createInMemoryRevocationStore } from './revocation-store.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

interface FakeAppRow {
  id: string; clientId: string; sealingKeyVersion: number;
  allowedOrigins: string[]; ownershipStatus: 'active';
  rawTokensEnabled: boolean; clientSecretHashes: string[];
}

function fakeService(app: FakeAppRow) {
  return {
    apps: {
      async getByClientId(clientId: string) { return clientId === app.clientId ? app : null; },
      async getById(id: string) { return id === app.id ? app : null; },
    },
    audit: { append: async () => {} },
  };
}

describe('zero-code flow end-to-end (mock Toss)', () => {
  it('token → userinfo → revoke pipeline succeeds', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1', signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const sealingKey = Buffer.alloc(32, 22);
    const adapter = new MockTossAdapter();
    const fakeApp: FakeAppRow = {
      id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1,
      allowedOrigins: ['https://app.example.com'], ownershipStatus: 'active',
      rawTokensEnabled: false, clientSecretHashes: [],
    };
    const app = await buildApp({
      service: fakeService(fakeApp) as any,
      oidcConfig: {
        issuer: 'https://oidc-bridge.aitc.dev',
        activeKid: 'k1', signingKeys: [],
        idTokenTtlSeconds: 3600,
        defaultScope: 'openid profile user_key',
      },
      signingKeyRegistry: reg,
      tossAdapter: adapter,
      resolveAppSealingKey: async () => sealingKey,
      revocationStore: createInMemoryRevocationStore(),
      now: () => 1735686000,
    } as any);

    // 1. /oidc/token
    const tokenRes = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({ grant_type: 'authorization_code', code: 'good', client_id: 'app_abc' }),
    });
    expect(tokenRes.status).toBe(200);
    const tokens = await tokenRes.json();

    // 2. /oidc/userinfo
    const infoRes = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(infoRes.status).toBe(200);
    const info = await infoRes.json();
    expect(info.sub).toBe('42');
    expect(info.provider).toBe('toss');

    // 3. /oidc/revoke (refresh_token)
    const revokeRes = await app.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(tokens.refresh_token)}&token_type_hint=refresh_token`,
    });
    expect(revokeRes.status).toBe(200);
    expect(adapter.accessRemoveCalls).toEqual([{ appId: 'app_abc', userKey: '42' }]);

    // 4. After revoke, the access token should not work for userinfo
    //    (we revoked the RT, not the AT — so AT still works locally; spec §6.3 says
    //    only the RT triggers Toss accessRemove; local AT marking is for AT revocation.
    //    Here we additionally verify our revoke marks the RT locally.)
    const infoAgain = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    // AT was not revoked, so this still 200.
    expect(infoAgain.status).toBe(200);

    // 5. Now revoke the AT explicitly.
    await app.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(tokens.access_token)}&token_type_hint=access_token`,
    });
    const infoAfterAtRevoke = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(infoAfterAtRevoke.status).toBe(401);
  });
});
```

- [ ] **Step 2: Run, expect pass (everything implemented)**

```bash
pnpm vitest run src/oidc/zero-code-flow.test.ts
```

If anything fails, the previous tasks have a gap. Fix it; don't weaken the test.

- [ ] **Step 3: Commit**

```bash
git add src/oidc/zero-code-flow.test.ts
git commit -m "test(oidc): zero-code flow end-to-end (token → userinfo → revoke)"
```

---

## Task 17: Log redaction audit

**Files:**
- Modify: `src/logger.test.ts` (Phase 0)

The redact list already has `id_token`, `access_token`, `refresh_token`, `client_secret`, `code`, `code_verifier`. This phase introduces no new field names that would carry sensitive material — but `Authorization` headers can carry both `Bearer ait_*` and `Basic base64(id:secret)`. Phase 0's logger middleware should not emit raw Authorization headers; verify this.

- [ ] **Step 1: Failing test (assumes a `logRequestMiddleware` or similar Phase 0 middleware)**

```ts
// extend src/logger.test.ts
it('does not emit raw Authorization header values via the request logger', () => {
  const { logger, captured } = makeTestLogger();
  // simulate a structured request log
  logger.info({
    req: {
      method: 'POST',
      url: '/oidc/token',
      headers: { authorization: 'Bearer ait_secret', 'content-type': 'application/json' },
    },
  }, 'request');
  // The redact path must zero out req.headers.authorization
  const flat = JSON.stringify(captured[0]);
  expect(flat).not.toContain('ait_secret');
});

it('redacts top-level token form field', () => {
  const { logger, captured } = makeTestLogger();
  logger.info({ token: 'ait_secret' }, 'revoke attempt');
  const flat = JSON.stringify(captured[0]);
  expect(flat).not.toContain('ait_secret');
});
```

- [ ] **Step 2: Run, expect failure (Phase 0 redact list lacks `req.headers.authorization` and `token`)**

```bash
pnpm vitest run src/logger.test.ts
```

- [ ] **Step 3: Extend redact list**

In `src/logger.ts`, add to the `redact.paths`:
- `'req.headers.authorization'`
- `'res.headers.authorization'`
- `'token'`

- [ ] **Step 4: Run, expect pass**

```bash
pnpm vitest run src/logger.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/logger.ts src/logger.test.ts
git commit -m "chore(log): redact authorization headers + token form field"
```

---

## Task 18: RUNBOOK — confidential clients + raw-tokens

**Files:**
- Modify: `docs/RUNBOOK.md`

Two new sections.

- [ ] **Step 1: Append to RUNBOOK**

````markdown
## Adding a confidential client (Edge Function operator)

Confidential clients hold a `client_secret` and authenticate `/oidc/token`
calls with `client_secret_basic` or `client_secret_post`. They do **not** use
the `Origin` header for auth.

1. Issue a secret via the admin CLI:
   ```bash
   oidc-bridge app rotate-secret --app-id app_abc
   ```
   The plaintext is shown **once**. Store it in your operator's secret store
   (Supabase Edge Function secret, GCP Secret Manager, etc.).
2. Use `client_secret_basic` from the operator:
   ```ts
   const auth = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
   await fetch(`${BRIDGE}/oidc/token`, {
     method: 'POST',
     headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
     body: new URLSearchParams({
       grant_type: 'authorization_code',
       code: authorizationCode,
       client_id: clientId,
     }),
   });
   ```
3. Rotation overlap: `app rotate-secret` adds a new hash and keeps the old
   one. Both are accepted until you call:
   ```bash
   oidc-bridge app rotate-secret --app-id app_abc --drop-previous
   ```

Confidential clients can have `allowed_origins` empty — Origin is ignored
when an `Authorization: Basic` header is present.

## Enabling raw-tokens for an app

Raw-tokens (`GET /oidc/raw-tokens`) returns the underlying Toss access token.
Default-off; opt in per app:

```bash
oidc-bridge app raw-tokens --app-id app_abc --enable
```

The endpoint never returns the refresh token. To refresh, the operator calls
`/oidc/token grant_type=refresh_token` — Bridge stays the lifecycle authority.

Disable:
```bash
oidc-bridge app raw-tokens --app-id app_abc --disable
```

When disabled, `GET /oidc/raw-tokens` returns 404 — the route looks absent for
that app.

## Revoking tokens

`POST /oidc/revoke` accepts:
- `token=ait_<access_token> token_type_hint=access_token` — local-only mark.
- `token=ait_<refresh_token> token_type_hint=refresh_token` — local mark + Toss `/access-remove`.

Always returns 200. The local revocation list is per-instance in-memory;
restarting the bridge clears it. For a permanent kill switch in self-host,
rotate the master key (the old wrapper version becomes unrecoverable once you
remove the old key bytes).
````

- [ ] **Step 2: Commit**

```bash
git add docs/RUNBOOK.md
git commit -m "docs: confidential-client + raw-tokens + revoke runbook"
```

---

## Task 19: Final verification

- [ ] **Step 1: Full check**

```bash
pnpm typecheck && pnpm lint && pnpm test
```

All clean.

- [ ] **Step 2: Manual smoke**

Use the dev RSA key from Phase 3's smoke step. Seed an app via the admin CLI (Phase 2):

```bash
# Phase 2 admin commands assumed available
oidc-bridge workspace create --name local
oidc-bridge app create --workspace-id <ws> --name local-mini --allowed-origins http://localhost:5173 --owner-domain example.com
# capture the printed client_id; mark as 'active' for local dev (BRIDGE_STAGE=alpha auto-marks):
export BRIDGE_STAGE=alpha
pnpm dev &
sleep 2
CID=<paste>
# /oidc/token (mock 'good' code)
curl -s -X POST http://localhost:8080/oidc/token \
  -H 'origin: http://localhost:5173' \
  -H 'content-type: application/json' \
  -d "{\"grant_type\":\"authorization_code\",\"code\":\"good\",\"client_id\":\"$CID\"}" | tee /tmp/tokens.json | jq .

AT=$(jq -r .access_token /tmp/tokens.json)
RT=$(jq -r .refresh_token /tmp/tokens.json)

# /oidc/userinfo
curl -s -H "authorization: Bearer $AT" http://localhost:8080/oidc/userinfo | jq .

# /oidc/revoke (RT)
curl -s -X POST http://localhost:8080/oidc/revoke \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data "token=$RT&token_type_hint=refresh_token" -o /dev/null -w '%{http_code}\n'
# Expect 200

# /oidc/revoke (AT)
curl -s -X POST http://localhost:8080/oidc/revoke \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data "token=$AT&token_type_hint=access_token" -o /dev/null -w '%{http_code}\n'
# Expect 200

# /oidc/userinfo after AT revoke → 401
curl -s -o /dev/null -w '%{http_code}\n' -H "authorization: Bearer $AT" http://localhost:8080/oidc/userinfo
# Expect 401

# /oidc/raw-tokens (default disabled → 404)
curl -s -o /dev/null -w '%{http_code}\n' -H "authorization: Bearer $AT" http://localhost:8080/oidc/raw-tokens
# Expect 404

kill %1
```

- [ ] **Step 3: Log leak check**

```bash
pnpm dev > /tmp/bridge.log 2>&1 &
# drive a successful flow as in Step 2
grep -E 'TOSS_AT_OPAQUE_FIXTURE|TOSS_RT_OPAQUE_FIXTURE|BEGIN PRIVATE KEY|ait_' /tmp/bridge.log && echo "LEAK" || echo "clean"
kill %1
```

`ait_` substrings can legitimately appear in routing logs (URL path), but no full token value should appear. If a full token shows up, extend the redact list before merging.

- [ ] **Step 4: Push and open PR**

```bash
git push -u origin feat/zero-code-phase-04
gh pr create --base main --title "feat: zero-code Phase 4 — userinfo, revoke, confidential client" --body "$(cat <<'EOF'
## Summary
- GET /oidc/userinfo (sealed-AT bearer → mock Toss /login-me)
- POST /oidc/revoke (RFC 7009 always-200; refresh_token hint triggers Toss accessRemove)
- GET /oidc/raw-tokens (opt-in, never returns RT)
- /oidc/token confidential-client auth: client_secret_basic + client_secret_post + rotation overlap
- Origin enforcement hardened (null/whitespace rejection)
- Sealed token format: appId hint added to preamble for body-less unwrap
- Plan: docs/superpowers/plans/2026-05-01-zero-code-phase-04-userinfo-revoke-confidential.md

## Test plan
- [x] pnpm typecheck && pnpm lint && pnpm test
- [x] zero-code flow integration test (token → userinfo → revoke → 401)
- [x] manual smoke: confidential-client + raw-tokens off/on
- [x] log redaction: no Toss tokens, secrets, or PEM bodies in stdout
EOF
)"
```

---

## Phase 4 done condition

- All 19 tasks ticked.
- `pnpm typecheck && pnpm lint && pnpm test` clean.
- A mini-app can call `/oidc/token` (public + Origin auth) → `/oidc/userinfo` (Bearer sealed AT) → `/oidc/revoke` end-to-end against the mock adapter.
- An Edge Function operator can call `/oidc/token` with `client_secret_basic` or `client_secret_post`; mismatch / wrong secret / mixed methods all return 401 `invalid_client`.
- `/oidc/raw-tokens` returns 404 unless `apps.rawTokensEnabled === true`; when enabled, returns `{ access_token, expires_in }` and never any sign of the refresh token.
- Origin allowlist rejects `null`, whitespace-padded, and unknown origins.
- Logs contain no Toss tokens, no `ait_*` token bodies, no `client_secret`, no PEM bodies, no `Authorization` header values.

That state is the foundation Phase 5 (real Toss mTLS adapter) builds on — Phase 5 swaps `MockTossAdapter` for a real `undici`-backed adapter without touching any of the route, service, or sealed-token code shipped here.
