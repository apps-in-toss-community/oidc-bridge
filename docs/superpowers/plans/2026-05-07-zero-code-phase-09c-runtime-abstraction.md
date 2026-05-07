# oidc-bridge zero-code mode — Phase 09c: runtime abstraction (Workers-ready core)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple the OIDC core from Node-specific APIs so it can later run on **both** Node 24 (existing self-host + Vultr public instance) and Cloudflare Workers (Phase 10c–14c). After this phase, `src/runtime/node.ts` boots the same core that a future `src/runtime/workers.ts` will boot — all crypto, AEAD, HKDF, mTLS, storage and master-key access flows through interfaces that have a portable implementation. The Workers entry point itself, the D1 schema, the multi-tenant control plane, and the actual deploy come in later phases (10c–14c). This phase keeps Node parity green: every existing test that passed on `main` still passes after this PR.

**Architecture:** Replace direct `node:crypto` / `Buffer` / `node:https` imports in the core with three runtime ports — `Aead`, `Kdf`, `Random` — each with a Node implementation (current behavior, just relocated) and a stub Workers implementation (uses `crypto.subtle` / `Uint8Array`). The mTLS adapter gains a `MtlsClient` interface so a future Workers binding-based client can replace `undici.Pool`. `MasterKeyProvider` returns `Uint8Array` (super-set of `Buffer`); a Workers `BindingMasterKeyProvider` is added (reads from `env.MASTER_KEY_V*` Workers secrets). Storage gets a third adapter — `D1Storage` — implementing the same `Storage` interface conformance suite, alongside the existing pg + sqlite adapters. The pino logger is wrapped behind a `Logger` interface so a Workers entry can swap in a Workers-friendly JSON-line logger. The runtime entry point (`src/server.ts`) is split into `src/runtime/node.ts` (existing behavior) plus a new `src/runtime/workers.ts` (returns a Hono app fetched by the Workers `fetch` handler). The Workers entry is _wired but unused in production_ — Phase 10c sets up wrangler, secrets, and the actual deploy.

**Tech stack:** TypeScript ESM strict, Hono (already runtime-agnostic), `crypto.subtle` (WebCrypto, present in both Node 18+ and Workers), `Uint8Array` (instead of `Buffer`) at module boundaries, `undici` (Node-only, kept behind `MtlsClient.NodeUndici`), Cloudflare `D1Database` types from `@cloudflare/workers-types` (dev-only). No new prod deps. Adds `@cloudflare/workers-types` as a dev dep so Workers types are available without pulling in Workers runtime in Node.

---

## Universal invariants (apply to every task)

1. **Node parity.** Every existing test that passes on `main` must still pass after each task. The Workers path is additive; nothing existing changes behavior.
2. **TDD.** Failing test → minimal code → green → commit. Each port (`Aead`, `Kdf`, `Random`, `MtlsClient`, `Logger`) gets a contract test that runs against **both** the Node and the WebCrypto/Workers implementation.
3. **Frequent commits.** Each red→green cycle is a commit. Conventional Commits.
4. **No premature abstraction beyond the named ports.** Don't generalize `Storage` further, don't introduce a DI container, don't refactor unrelated modules. The 12 tasks below are the scope.
5. **No PII / secrets in logs.** The `Logger` abstraction must preserve the existing pino redact list semantics.
6. **`Buffer` allowed inside Node-only modules; forbidden at port boundaries.** The interfaces must speak `Uint8Array`. Inside `src/runtime/node.ts` and Node-only adapters, `Buffer` is fine (it _is_ a `Uint8Array`).
7. **No Workers runtime imports in Node entry.** `src/runtime/node.ts` must not import `src/runtime/workers.ts` and vice versa. Shared core is in `src/core/` (or remains in existing dirs that don't pull either runtime).
8. **mTLS material never returns from any GET.** Unchanged from prior phases.
9. **No GCP-specific code.** Phase 10 (GCP Cloud Run) is cancelled in favor of Phase 10c (CF Workers). This phase removes any latent GCP assumption that blocks Workers.
10. **No D1 schema migration runner yet.** D1 migrations land in Phase 11c. This phase only adds the D1 adapter that targets the existing 7-table layout, hand-mirrored from `schema.sqlite.ts` with D1-compatible types.
11. **Bite-sized tasks.** Each task is ≈30–90 minutes. Commit at every green.
12. **Lint + typecheck + test pass on every commit.** `pnpm typecheck && pnpm lint && pnpm test` is the gate.

## Files this phase touches

```
src/
  core/                          # NEW — runtime-portable core (no Node-only imports)
    aead.ts                      # NEW — Aead interface + WebCrypto AES-GCM impl
    aead.test.ts                 # NEW — contract test (runs against both impls)
    kdf.ts                       # NEW — Kdf interface + WebCrypto HKDF impl
    kdf.test.ts                  # NEW
    random.ts                    # NEW — Random interface + WebCrypto getRandomValues impl
    random.test.ts               # NEW
    bytes.ts                     # NEW — Uint8Array helpers (concat, fromUtf8, toUtf8, fromBase64Url, toBase64Url)
    bytes.test.ts                # NEW
    logger.ts                    # NEW — Logger interface
  runtime/
    node.ts                      # NEW — Node entry (moved from src/server.ts)
    node-aead.ts                 # NEW — Aead impl using node:crypto (parity with current sealed-token)
    node-kdf.ts                  # NEW — Kdf impl using node:crypto hkdfSync
    node-random.ts               # NEW — Random impl using node:crypto randomBytes
    node-logger.ts               # NEW — pino-backed Logger (wraps existing createLogger)
    workers.ts                   # NEW — Workers entry (Hono app fetcher); not yet deployed
    workers-logger.ts            # NEW — Workers-friendly JSON-line Logger
    workers-master-key-provider.ts # NEW — reads from Workers env bindings
  server.ts                      # MODIFY — re-export runtime/node.ts (kept as compat shim, drops to one line)
  oidc/
    sealed-token.ts              # MODIFY — accepts Aead + Random ports; default still uses Node ports
    sealed-token.test.ts         # MODIFY — additional pass against WebCrypto Aead
  apps/
    encryption.ts                # MODIFY — accepts Aead port; default still Node
    encryption.test.ts           # MODIFY — additional pass against WebCrypto
  master-keys/
    hkdf.ts                      # MODIFY — accepts Kdf port; default still Node hkdfSync
    hkdf.test.ts                 # MODIFY — additional pass against WebCrypto HKDF
    provider.ts                  # MODIFY — return type Uint8Array (was Buffer)
    env-provider.ts              # MODIFY — return Uint8Array
    file-provider.ts             # MODIFY — return Uint8Array
    cache.ts                     # MODIFY — cache Uint8Array
    index.ts                     # MODIFY — re-export new types
  middleware/
    request-id.ts                # MODIFY — use Random port (no node:crypto)
    pino-http.ts                 # MODIFY — use Kdf port for hash (or replace createHash with subtle.digest)
  oidc/revocation-store.ts       # MODIFY — replace createHash with subtle.digest via core port
  toss/
    mtls-client.ts               # NEW — MtlsClient interface (no undici / no Workers binding leak)
    mtls-client-undici.ts        # NEW — Node impl using undici Pool (extracted from real-adapter.ts)
    mtls-client-undici.test.ts   # NEW — moved from real-adapter.test.ts where applicable
    real-adapter.ts              # MODIFY — depends on MtlsClient interface, not undici directly
    real-adapter.test.ts         # MODIFY — uses fake MtlsClient
  storage/
    d1.ts                        # NEW — D1Storage implements Storage
    d1.test.ts                   # NEW — runs runStorageConformance against in-memory D1 (miniflare)
    schema.d1.ts                 # NEW — drizzle SQLite schema mirrored for D1 (uses drizzle-orm/sqlite-core; D1 dialect identical at the type level)
  sessions/store.ts              # MODIFY — Random port (no node:crypto)
  apps/secrets.ts                # MODIFY — Random + Kdf ports
  logger.ts                      # MODIFY — extract createLogger into runtime/node-logger.ts; this file becomes the Logger interface re-export
docs/
  superpowers/specs/2026-05-07-cloudflare-cloud-separation.md  # UNCHANGED (already merged via #43; referenced from this plan)
package.json                     # MODIFY — add @cloudflare/workers-types dev dep, miniflare dev dep
tsconfig.json                    # MODIFY — types: ["@cloudflare/workers-types"] for runtime/workers.ts only via project ref or // <reference />
vitest.config.ts                 # MODIFY — new project for d1.test.ts (uses miniflare); existing projects unchanged
```

## Pre-flight (do this once before Task 1)

```bash
git fetch origin
git checkout main && git pull
git checkout -b feat/zero-code-phase-09c-runtime-abstraction origin/main
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

If any check fails on a fresh `feat/zero-code-phase-09c-runtime-abstraction` branch, stop. Phases 0–8 are not green; fix that before continuing.

This phase depends on:

- Phase 1's `deriveSealingKey` and `MasterKeyProvider` (env + file).
- Phase 2's `apps` table with `mtlsCertEnc` / `mtlsKeyEnc` AEAD-sealed columns.
- Phase 3's sealed `ait_*` token format.
- Phase 5's `RealTossAdapter` (Node + undici implementation).
- Phase 7's `cli/bootstrap` and `doctor` commands (still Node-only after this phase; no change).
- Phase 8's `/status`, rate-limit, request-id middleware (the Random/Kdf migration touches these).

If any of these are missing on this branch, you are on the wrong base.

The cloud-separation spec is the authoritative architectural reference: [`docs/superpowers/specs/2026-05-07-cloudflare-cloud-separation.md`](../specs/2026-05-07-cloudflare-cloud-separation.md). §3.1 (mTLS via Workers binding — already prototype-validated, GA), §4.1 (D1 schema), §7.2 (1,000 cert/account ceiling + multi-account sharding design choices) are the relevant sections. **The earlier internal note that Workers mTLS binding is "Beta" is stale** — the prototype validated production-stable e2e handshake against `apps-in-toss-api.toss.im`.

Brand reminder: this is the **community (unofficial)** oidc-bridge. No "official", no "powered by Toss", no claim of partnership. See `CLAUDE.md`.

---

## Task 1: Add `bytes.ts` — Uint8Array utilities

**Files:**
- Create: `src/core/bytes.ts`, `src/core/bytes.test.ts`

The core needs portable `Uint8Array` ↔ utf8 / base64url helpers. `Buffer.from(s, 'utf8')` and `buf.toString('base64url')` are Node-only at the surface level. Workers has `TextEncoder` / `TextDecoder` and standard `btoa` + URL-safe transformation. We isolate this into one file so the rest of `core/` is free of `Buffer` imports.

- [ ] **Step 1: Failing test**

```ts
// src/core/bytes.test.ts
import { describe, it, expect } from 'vitest';
import { fromUtf8, toUtf8, fromBase64Url, toBase64Url, concat, equals } from './bytes.js';

describe('bytes', () => {
  it('fromUtf8 / toUtf8 round-trips', () => {
    const u = fromUtf8('hello 토스 ✨');
    expect(toUtf8(u)).toBe('hello 토스 ✨');
  });
  it('toBase64Url / fromBase64Url round-trips with no padding', () => {
    const raw = new Uint8Array([0xff, 0x00, 0xab, 0xcd]);
    const b = toBase64Url(raw);
    expect(b).not.toMatch(/=$/);
    expect(b).not.toMatch(/[+/]/);
    expect(equals(fromBase64Url(b), raw)).toBe(true);
  });
  it('concat joins multiple Uint8Arrays', () => {
    const out = concat(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5]));
    expect(Array.from(out)).toEqual([1, 2, 3, 4, 5]);
  });
});
```

- [ ] **Step 2: Run, expect failures.** `pnpm vitest run src/core/bytes.test.ts`

- [ ] **Step 3: Implement** `src/core/bytes.ts` using `TextEncoder` / `TextDecoder` and a standards-only base64url codec (no `Buffer`).

- [ ] **Step 4: Run, expect green.**

- [ ] **Step 5: Commit** `feat(core): add Uint8Array bytes helpers (utf8, base64url, concat, equals)`

---

## Task 2: `Aead` port — interface + WebCrypto + Node impls

**Files:**
- Create: `src/core/aead.ts`, `src/core/aead.test.ts`
- Create: `src/runtime/node-aead.ts`

`Aead` exposes `seal({ key, iv?, aad, plaintext })` and `open({ key, iv, aad, ciphertext, tag })`. The WebCrypto impl is the default, lives in `core/`. `runtime/node-aead.ts` provides a Node-specific impl (using `createCipheriv('aes-256-gcm', ...)`) so we can _prove_ the Node and WebCrypto outputs are interop-able (a Node-sealed token must open under WebCrypto and vice versa). Both impls work on `Uint8Array` only.

- [ ] **Step 1: Contract test** — same `describe.each([nodeAead, webCryptoAead])` block. Cases: round-trip, wrong AAD fails, wrong key fails, tag-tamper fails, IV-tamper fails, **cross-impl roundtrip** (seal with Node, open with WebCrypto).

- [ ] **Step 2: Run, expect failures.**

- [ ] **Step 3: Implement** WebCrypto impl in `core/aead.ts` (uses `crypto.subtle.importKey` + `encrypt`/`decrypt`); Node impl in `runtime/node-aead.ts` (uses `node:crypto`).

- [ ] **Step 4: Run, expect green.** Both impls pass the same contract.

- [ ] **Step 5: Commit** `feat(core): add Aead port + WebCrypto + Node impls (interop-verified)`

---

## Task 3: `Kdf` port — HKDF (WebCrypto + Node)

**Files:**
- Create: `src/core/kdf.ts`, `src/core/kdf.test.ts`
- Create: `src/runtime/node-kdf.ts`
- Modify: `src/master-keys/hkdf.ts` to accept a `Kdf` port (default = Node impl), return `Uint8Array`.
- Modify: `src/master-keys/hkdf.test.ts` to add a WebCrypto pass.

`Kdf` exposes `deriveBits({ secret, salt, info, hash, lengthBytes })`. The current `deriveSealingKey` is `hkdfSync('sha256', mk, salt, 'ait/seal/v1', 32)` — wrap that. WebCrypto's `crypto.subtle.deriveBits({ name: 'HKDF', hash, salt, info }, ...)` produces the same bytes for the same inputs. Contract test verifies cross-impl byte-equal output.

- [ ] **Step 1: Contract test** — `describe.each([nodeKdf, webCryptoKdf])` with vectors that match the existing `deriveSealingKey` test vectors so existing sealed tokens stay decryptable.

- [ ] **Step 2: Run, expect failures.**

- [ ] **Step 3: Implement** WebCrypto + Node impls; migrate `deriveSealingKey` to take `kdf?: Kdf` arg with Node default; return type changes from `Buffer` to `Uint8Array`.

- [ ] **Step 4: Update callers.** Every caller of `deriveSealingKey` now receives `Uint8Array`. Where Node code immediately needs a `Buffer`, do `Buffer.from(uint8.buffer, uint8.byteOffset, uint8.byteLength)` at the boundary (Node-only modules).

- [ ] **Step 5: Run, expect green.** Existing sealed tokens still decrypt.

- [ ] **Step 6: Commit** `feat(master-keys): Kdf port + Uint8Array return type, sealed tokens stay valid`

---

## Task 4: `Random` port + replace `node:crypto` callsites

**Files:**
- Create: `src/core/random.ts`, `src/core/random.test.ts`
- Create: `src/runtime/node-random.ts`
- Modify: `src/middleware/request-id.ts`, `src/sessions/store.ts`, `src/apps/secrets.ts`, `src/oidc/sealed-token.ts`, `src/apps/encryption.ts` to take a `Random` port (default = Node impl).

`Random.bytes(n: number): Uint8Array` and `Random.uuid(): string`. WebCrypto: `crypto.getRandomValues(new Uint8Array(n))` and `crypto.randomUUID()`. Node: `randomBytes(n)` and `randomUUID()`.

- [ ] **Step 1: Contract test** — both impls produce 16-byte outputs of expected length, distinct across calls, UUID matches RFC 4122 v4 regex.

- [ ] **Step 2: Replace callsites.** The four files above stop importing `node:crypto`. Default-construct the Node `Random` impl at the runtime entry; inject through existing factory functions.

- [ ] **Step 3: Run existing tests.** They must all pass — randomness is only an interface change, not a behavior change.

- [ ] **Step 4: Commit** `feat(core): Random port; remove node:crypto from middleware/sessions/oidc`

---

## Task 5: Replace `createHash` with `subtle.digest`

**Files:**
- Modify: `src/oidc/revocation-store.ts`, `src/middleware/pino-http.ts`
- Extend: `src/core/kdf.ts` _or_ a new `src/core/digest.ts` for `digest('SHA-256', bytes): Promise<Uint8Array>`.

Two callsites use `createHash('sha256').update(...).digest('hex')` synchronously. WebCrypto only offers async `subtle.digest`. The migration: make these callsites async (they already are async-friendly — the revocation store and the pino http middleware can await without callsite damage), and replace with the `Digest` port.

- [ ] **Step 1: Failing test.** Existing tests for `revocation-store.ts` and `pino-http.ts` should still pass; add one new test that asserts `digest` produces the same bytes as `createHash('sha256').digest()` for a fixed input.

- [ ] **Step 2: Implement.** `core/digest.ts` exports `Digest` interface + WebCrypto impl; `runtime/node-digest.ts` exports Node impl using `createHash`.

- [ ] **Step 3: Migrate callsites.** Both become `async`. Their callers already operate inside async handlers.

- [ ] **Step 4: Run, expect green.**

- [ ] **Step 5: Commit** `refactor: digest via subtle.digest port; eliminate createHash from middleware/oidc`

---

## Task 6: `Logger` port — extract from pino

**Files:**
- Create: `src/core/logger.ts` (interface)
- Create: `src/runtime/node-logger.ts` (pino-backed impl, copies current `src/logger.ts` body)
- Create: `src/runtime/workers-logger.ts` (JSON-line `console.log` impl with same redact list semantics)
- Modify: `src/logger.ts` — re-export interface; delegate `createLogger` for Node.
- Modify: callsites that import directly from `pino` (audit there are none in the core). Core code only sees the `Logger` interface.

Interface:

```ts
export interface Logger {
  info(obj: Record<string, unknown>, msg?: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
  debug(obj: Record<string, unknown>, msg?: string): void;
  child(bindings: Record<string, unknown>): Logger;
}
```

- [ ] **Step 1: Contract test** — both impls accept the same shape, both honor a redact list (asserted by reading the formatted output and ensuring known sensitive keys are masked as `[REDACTED]`).

- [ ] **Step 2: Implement** WorkersLogger that emits one-line JSON to `console.log` with redact applied via the same key list.

- [ ] **Step 3: Migrate** `pino-http.ts` and any other consumer to take a `Logger` arg instead of importing pino.

- [ ] **Step 4: Run, expect green.** `pnpm test` — pino redact existing tests still pass.

- [ ] **Step 5: Commit** `feat(core): Logger port; pino moves to Node runtime adapter`

---

## Task 7: `MasterKeyProvider` returns `Uint8Array`; add Workers binding provider

**Files:**
- Modify: `src/master-keys/provider.ts` — `getKeyBytes(version): Promise<Uint8Array>` (was `Buffer`).
- Modify: `src/master-keys/env-provider.ts`, `file-provider.ts`, `cache.ts` — return `Uint8Array`.
- Create: `src/runtime/workers-master-key-provider.ts` — reads Workers `env.MASTER_KEY_V<n>_HEX` (or whatever Phase 10c picks; placeholder spec name) into `Uint8Array` via `core/bytes.fromHex`.

Internally, `Buffer extends Uint8Array`, so existing Node consumers don't break — but the **interface** speaks `Uint8Array`. Code paths that explicitly require `Buffer` (e.g. `pg` driver `bytea` writes) wrap at the call site.

- [ ] **Step 1: Test.** `provider.test.ts` asserts `result instanceof Uint8Array` (was `Buffer.isBuffer`). Add a test for the Workers provider using a fake `env` object (no Workers runtime needed).

- [ ] **Step 2: Migrate.** Tighten existing tests; verify `Buffer.from(uint8.buffer, ...)` boundary handling at pg/sqlite write callsites.

- [ ] **Step 3: Run, expect green.**

- [ ] **Step 4: Commit** `feat(master-keys): Uint8Array return + Workers binding provider`

---

## Task 8: `MtlsClient` interface — extract Node undici impl

**Files:**
- Create: `src/toss/mtls-client.ts` — interface
- Create: `src/toss/mtls-client-undici.ts` — Node impl extracted from current `RealTossAdapter`
- Modify: `src/toss/real-adapter.ts` — depend on `MtlsClient`, not on `undici.Pool`
- Modify: `src/toss/real-adapter.test.ts` — uses a fake `MtlsClient` (replaces `fetchImpl` indirection)
- Create: `src/toss/mtls-client-undici.test.ts` — the existing undici-specific assertions move here

Interface:

```ts
export interface MtlsRequest {
  url: string;          // absolute URL
  method: 'POST' | 'GET' | 'DELETE';
  headers: Record<string, string>;
  body?: Uint8Array | undefined;
}
export interface MtlsResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}
export interface MtlsClient {
  request(opts: {
    appId: string;
    cert: { certPem: string; keyPem: string };
    request: MtlsRequest;
  }): Promise<MtlsResponse>;
}
```

The undici impl manages a `Pool` per `appId` keyed cert hash (existing behavior). The future Workers impl (Phase 12c) will use `env.TOSS_MTLS.fetch(...)` against a Worker-bound mTLS cert and so can return `MtlsResponse` shape directly. Note that the existing `real-adapter.ts` already abstracts over `fetchImpl` and `buildDispatcher` — this task converts those two parameters into one cohesive `MtlsClient`.

- [ ] **Step 1: Move tests.** All undici-aware tests move to `mtls-client-undici.test.ts`. `real-adapter.test.ts` stops constructing dispatchers and uses a `FakeMtlsClient` that returns canned `MtlsResponse`.

- [ ] **Step 2: Extract impl.** `mtls-client-undici.ts` owns the per-app `Pool` cache.

- [ ] **Step 3: Migrate `RealTossAdapter`** to take a `MtlsClient` constructor arg; the `dispatchers` map and `fetchImpl` are gone.

- [ ] **Step 4: Run, expect green.** Existing live e2e test (`pnpm test:e2e:live`, gated) still works against the undici impl.

- [ ] **Step 5: Commit** `refactor(toss): MtlsClient port; undici impl extracted from RealTossAdapter`

---

## Task 9: AEAD migration — sealed tokens + column encryption use `Aead` port

**Files:**
- Modify: `src/oidc/sealed-token.ts` — uses `Aead` + `Random` ports; signature stays sync where possible (note: WebCrypto seal/open is async; `wrapSealedToken` and `unwrapSealedToken` become async).
- Modify: every caller of `wrapSealedToken` / `unwrapSealedToken` — they all live in async handlers (`token-route.ts`, `userinfo-route.ts`, `revoke-route.ts`, `raw-tokens-route.ts`), so awaiting is local change only.
- Modify: `src/apps/encryption.ts` — same migration.
- Modify: callsites in `src/apps/service.ts`, `src/apps/routes.ts`, `src/server.ts` for the encrypt/decrypt column path.

Critical correctness invariant: a sealed token issued before this PR (same master key + sealing key version + AAD) must still unwrap successfully after this PR. The contract test from Task 2 already verifies cross-impl roundtrip; here we lock it in at the application layer with **golden vectors** — a small set of `(plaintext, sealing-key, aad, sealed-blob)` tuples checked into `__fixtures__/sealed-tokens.json` that must keep opening across the migration.

- [ ] **Step 1: Capture golden vectors** by running the current code on `main` against a fixed seed and saving the outputs.

- [ ] **Step 2: Failing test** that loads the golden fixtures and asserts they still open after the migration.

- [ ] **Step 3: Migrate** to `Aead` + `Random` ports. `wrapSealedToken` → `async wrapSealedToken`. Update all callers.

- [ ] **Step 4: Run, expect green.** Golden fixtures pass; all integration tests pass.

- [ ] **Step 5: Commit** `refactor(oidc): sealed tokens use Aead port; golden vectors locked`

---

## Task 10: D1 storage adapter

**Files:**
- Create: `src/storage/schema.d1.ts` — drizzle SQLite schema for D1 (mirrors `schema.sqlite.ts`; D1 uses the same `drizzle-orm/sqlite-core` types so this is a near-copy that uses `drizzle-orm/d1` driver in `d1.ts`).
- Create: `src/storage/d1.ts` — `createD1Storage({ db })` returning `Storage`. Uses `drizzle-orm/d1` for query building; binds `D1Database` from `@cloudflare/workers-types`.
- Create: `src/storage/d1.test.ts` — runs `runStorageConformance` against an in-process D1 (via `miniflare`'s `D1Database` simulator).
- Modify: `vitest.config.ts` — new project for d1 tests with `pool: 'forks'` (miniflare uses workers under the hood; forks for isolation).
- Modify: `package.json` — add `miniflare` and `@cloudflare/workers-types` as dev deps; new `pnpm db:generate:d1` script.

**Important:** D1 has a few SQLite-feature gaps (no `WITHOUT ROWID` declaration, no certain pragmas at runtime, statement timeout limits). The storage conformance suite catches behavioral differences. If a test fails on D1 but passes on sqlite, **fix the D1 path** — do not weaken the conformance assertion.

- [ ] **Step 1: Schema.** Hand-mirror `schema.sqlite.ts` into `schema.d1.ts`. The drizzle output dir is `src/drizzle/d1/`.

- [ ] **Step 2: Adapter.** `d1.ts` implements every `Storage` method; reuses the SQL-level logic from `sqlite.ts` where the dialect is identical, but binds `D1Database.prepare(...).bind(...).first()/all()/run()` style under the hood (drizzle-orm/d1 handles this).

- [ ] **Step 3: Conformance.** The new test file invokes `runStorageConformance('d1', { open, cleanup })` where `open` returns a fresh in-memory `D1Database` from miniflare on each call.

- [ ] **Step 4: Run, expect green.** All existing storage conformance assertions pass on D1.

- [ ] **Step 5: Commit** `feat(storage): D1 adapter passes Storage conformance suite`

---

## Task 11: Runtime split — `runtime/node.ts` + `runtime/workers.ts`

**Files:**
- Create: `src/runtime/node.ts` — moves the body of current `src/server.ts` (the bootstrap / wiring logic).
- Modify: `src/server.ts` → one-line shim that re-exports from `runtime/node.ts` (preserves `pnpm start` and any external imports).
- Create: `src/runtime/workers.ts` — exports a `default { fetch(req, env, ctx) }` Workers handler. Construction wires:
  - `D1Storage` (env.DB)
  - `WorkersMasterKeyProvider` (env)
  - WebCrypto `Aead` / `Kdf` / `Random` / `Digest`
  - `WorkersLogger`
  - `RealTossAdapter` with a Node-only-incompatible `MtlsClient` placeholder that `throw new Error('NOT_IMPLEMENTED — Phase 12c')` so the Workers entry compiles and serves `/healthz` + `/.well-known/openid-configuration` end-to-end (signing key fetch + JWKS work without mTLS), but `/oidc/token` returns 501 until Phase 12c lands the `MtlsClient.WorkersBinding` impl.
- Modify: `tsconfig.json` to limit `@cloudflare/workers-types` to the `runtime/workers.ts` file via a triple-slash reference; the rest of the project must not see Workers globals.

- [ ] **Step 1: Move** the body of `src/server.ts` to `src/runtime/node.ts`. `src/server.ts` becomes `export * from './runtime/node.js';`.

- [ ] **Step 2: Workers entry skeleton.** Construct the app via the same `createApp(...)` factory. Export the Workers handler.

- [ ] **Step 3: Smoke test.** Add `src/runtime/workers.test.ts` that imports the handler, invokes `await handler.fetch(new Request('http://x/healthz'), fakeEnv, ctx)` and asserts 200. This proves the wiring compiles and responds for at least the no-mTLS routes.

- [ ] **Step 4: Run, expect green.** `pnpm typecheck` passes (Workers types isolated to one file). `pnpm test` passes. `/oidc/token` test in the Workers smoke explicitly asserts 501 (NOT_IMPLEMENTED), making the gap visible.

- [ ] **Step 5: Commit** `feat(runtime): split node + workers entries; workers serves /healthz, /oidc/token returns 501 (Phase 12c)`

---

## Task 12: Final verification + open PR

- [ ] **Step 1: Run full gate.**

  ```bash
  pnpm typecheck && pnpm lint && pnpm test
  ```

- [ ] **Step 2: Run gated live e2e** (manual, optional but recommended):

  ```bash
  TOSS_LIVE_TEST=1 pnpm test:e2e:live
  ```

  No regressions vs. main expected.

- [ ] **Step 3: Manual smoke** of Node entry:

  ```bash
  pnpm dev
  curl -s http://localhost:8080/healthz
  curl -s http://localhost:8080/.well-known/openid-configuration | jq .issuer
  ```

- [ ] **Step 4: Update CLAUDE.md status row** for Phase 09c → ✅ main (after merge); add a short Standing Decisions entry capturing:
  - "Core ports (`Aead`/`Kdf`/`Random`/`Digest`/`Logger`/`MtlsClient`) live in `src/core/`. Node and Workers adapters live in `src/runtime/`. No `node:crypto` / `Buffer` imports outside Node adapters."
  - "WebCrypto `seal`/`open` is async; `wrapSealedToken` / `unwrapSealedToken` are async. Sealed tokens issued before this PR remain valid (golden-vector test enforces this)."

- [ ] **Step 5: Open PR.**

  ```bash
  gh pr create --title "feat: zero-code Phase 09c — runtime abstraction (Workers-ready core)" \
               --body-file .github/pr-bodies/phase-09c.md
  ```

  PR body sections:
  - **Summary** — what each port abstracts, why, and the runtime split.
  - **Compatibility** — Node parity invariant, golden sealed-token vectors, no behavior change for existing deploys.
  - **What this is _not_** — Phase 10c–14c roadmap (CF deploy, mTLS binding wiring, control plane, dual-cloud cutover) is tracked in the umbrella TODO and the cloud-separation spec.
  - **Test plan** — typecheck/lint/test/e2e:live results + screenshots / curl outputs from Step 3.

- [ ] **Step 6: Merge** with squash, delete branch, sync main worktree (`git checkout main && git pull --ff-only`).

- [ ] **Step 7: Update umbrella TODO** — Phase 09c row → completed, Phase 10c (CF wrangler/secrets/deploy) → next-up. Use a follow-up commit on umbrella main per CLAUDE.md sync policy.

---

## Summary

After this phase, `oidc-bridge` core has a portable surface:

- **Crypto** — `Aead`, `Kdf`, `Random`, `Digest` ports; Node + WebCrypto adapters; cross-impl interop verified by contract tests and golden sealed-token vectors.
- **Bytes** — `Uint8Array` at all port boundaries; `Buffer` confined to Node adapters.
- **mTLS** — `MtlsClient` port; undici impl extracted; Workers impl pluggable in Phase 12c.
- **Storage** — third adapter (`D1Storage`) sitting alongside pg + sqlite, all three passing the same conformance suite.
- **Master keys** — `Uint8Array` return; Workers binding provider added; env + file providers unchanged in behavior.
- **Logger** — interface; pino is a Node adapter; Workers JSON-line adapter added.
- **Runtime** — `runtime/node.ts` (existing prod entry), `runtime/workers.ts` (compiles + serves `/healthz` + discovery; `/oidc/token` returns 501 until Phase 12c).

The Vultr public instance and self-host Docker images keep running on Node 24 unchanged. The Workers entry exists but is not deployed in this phase. Phase 10c (wrangler config + Workers Secrets + first prod deploy of static routes), 11c (D1 schema migrations + multi-tenant control plane wiring), 12c (Workers `MtlsClient` binding impl + e2e against Toss sandbox), 13c (cutover + dual-cloud period), 14c (Vultr decommission) follow.
