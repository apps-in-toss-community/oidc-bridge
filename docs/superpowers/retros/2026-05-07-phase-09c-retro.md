# Phase 09c retro — Runtime abstraction (Workers-ready core)

**Date**: 2026-05-07
**Branch**: `feat/zero-code-phase-09c-runtime-abstraction` (merged + deleted)
**PR**: [#44](https://github.com/apps-in-toss-community/oidc-bridge/pull/44) (squash → `2f625d8`)
**Plan**: [`docs/superpowers/plans/2026-05-07-zero-code-phase-09c-runtime-abstraction.md`](../plans/2026-05-07-zero-code-phase-09c-runtime-abstraction.md)
**Spec context**: [`docs/superpowers/specs/2026-05-07-cloudflare-cloud-separation.md`](../specs/2026-05-07-cloudflare-cloud-separation.md) §6.2 (Hono runtime-agnostic migration)
**Phase 8 retro**: not written (operational wiring landed via #36, #37, #40 alongside #38; no separate retro doc)
**Phase 7 retro (predecessor)**: [`2026-05-05-phase-07-retro.md`](2026-05-05-phase-07-retro.md)

## Goal vs. shipped

Goal: decouple the OIDC core from Node-specific APIs (`node:crypto`,
`Buffer`, `node:https`/undici) so the same Hono app boots later on
Cloudflare Workers (Phase 10c–14c) without rewrites. Production keeps
running on Node 24 unchanged. No new infrastructure shipped — this is
abstraction-only PR.

Shipped: six ports under `src/core/` (`Aead`, `Kdf`, `Random`, `Digest`,
`Logger`, `MtlsClient`), each with a Node adapter under `src/runtime/`
and a WebCrypto/Workers-friendly default. `MasterKeyProvider` returns
`Uint8Array`; new `WorkersMasterKeyProvider` reads from the Workers
`env` parameter. Storage gains a third driver — `D1Storage`
(`drizzle-orm/d1`) — that passes the same `runStorageConformance` suite
as pg + sqlite via miniflare 4 in-memory `D1Database`. The runtime
split lands at the end: `src/server.ts` shrinks to a 31-line shim,
`src/runtime/node.ts` holds the existing bootstrap, and
`src/runtime/workers.ts` is a Cloudflare Workers `default { fetch }`
handler that compiles, serves `/healthz` + discovery + JWKS through
miniflare in tests, and returns 501 `temporarily_unavailable` for
`POST /oidc/token` until Phase 12c lands the `MtlsClient.WorkersBinding`.

Sacred Node parity invariant held — 524 tests on `main` → **550 / 1
skipped** at merge, monotonically growing, every gate green on every
commit.

13 commits squashed into one feature commit. Two passes of
review-fix-loop produced two small portability fixes (Buffer → atob,
REDACT_PATHS extraction) before the second pass came back clean.

## Plan-vs-shipping mismatches (continuing the Phase 6/7 list)

The plan was tighter than Phase 6/7 — most repo-shape claims were
verified during the upfront `Read` over `bytes.ts` (didn't exist yet),
`master-keys/`, `oidc/sealed-token.ts`, `apps/encryption.ts`,
`toss/real-adapter.ts`, `server.ts`. The mismatches that surfaced:

1. **`@cloudflare/workers-types` triple-slash reference**. Plan
   suggested putting `/// <reference types="@cloudflare/workers-types" />`
   at the top of `runtime/workers.ts`. Tried it; broke project-wide
   typecheck because the directive is **global lib augmentation**, not
   file-scoped. Specifically, it tightened Node's `TextDecoder`
   constructor signature so `new TextDecoder('utf-8', { fatal: false })`
   in `src/core/bytes.ts` failed with `TS2345: Property 'ignoreBOM' is
   missing`. Replaced with `import type { D1Database, ExecutionContext
   } from '@cloudflare/workers-types'` — type-only imports are
   file-scoped, no global pollution. `tsconfig.json` `types` array
   stays `["node"]`. This is the kind of thing that's invisible in a
   small file but rots downstream when the project grows.

2. **WebCrypto sync vs. async**. Plan modeled `Aead`/`Kdf` as
   sync-or-async. WebCrypto is **async** (`crypto.subtle.encrypt`,
   `deriveBits`, `digest` all return Promises), so the entire
   sealing-key derivation chain became async. `wrapSealedToken` /
   `unwrapSealedToken` and `encryptColumn` / `decryptColumn` are now
   `Promise`-returning; every caller `await`s. Mechanical change but
   touches a lot of call sites — caught in upfront grep, not at type-
   check time.

3. **Drizzle 0.45 D1 quirks**. SQLite-on-D1 (workerd) has two
   undocumented divergences from `better-sqlite3`-on-`bun`:
   - **No `IF NOT EXISTS` on DDL**. The migration runner has to `CREATE
     TABLE …` (plain) and rely on idempotency via state checks, not
     SQL-level guards.
   - **No `DESC` in expression indexes**. Plain ASC works. Captured in
     CLAUDE.md "Standing decisions" so the next phase doesn't re-discover.
   The `runStorageConformance` matrix surfaced both within minutes of
   running the suite on D1 — same lesson Phase 5 had with
   `bytea`/`updatedAt`.

4. **Sealed-token wire format is the cloud invariant**. Plan said
   "preserve format". The non-obvious part: any bridge instance must
   decrypt any other instance's token regardless of runtime, which
   means **byte-for-byte interop between Node and WebCrypto on the same
   key**. Locked by `src/oidc/__fixtures__/sealed-token-golden.json` —
   one `ait_*` token, deterministic IV, generated once and pinned;
   five cross-impl tests verify Node-issued tokens decrypt under
   WebCrypto and vice versa. Same pattern for `apps/encryption`.

5. **`undici` extracted, not abstracted away**. Plan modeled
   `MtlsClient` as a generic mTLS interface. The Node implementation
   stayed verbatim `undici.Pool` — moved file-by-file to
   `src/runtime/node-mtls.ts` rather than rewritten. The Workers
   binding implementation is the Phase 12c hand-off; for 09c a stub
   factory throws `mtls_not_implemented_workers_phase_09c` if invoked.
   This kept 09c from accidentally touching the production Toss path.

6. **`process.env` purity in `runtime/workers.ts`**. Plan said "no
   `node:*` imports". The stricter rule that emerged: also no
   `process.env` reads. Workers env is the second `fetch` parameter,
   not a global. Caught one stray `process.env.TOSS_API_BASE` during
   the runtime split — fixed before the commit. `grep "process.env"
   src/runtime/workers.ts` is now an invariant.

For 10c's planner: assume nothing about CF Workers' edge cases until
miniflare confirms it. The D1 quirks above came out of running, not
reading docs.

## Cross-runtime byte equality is the unit of correctness

The most generative idea of this phase. A cross-runtime port is "done"
not when both implementations pass their own unit tests, but when:

- Same input → byte-identical output (sealed-token wire, HKDF derived
  key bytes, AES-GCM ciphertext for a fixed IV).
- Either implementation can read what the other wrote.

Both checks are easy to write (compare `Uint8Array` byte-for-byte) and
expose abstraction leaks immediately. The HKDF cross-impl test caught
a subtle issue early: `node:crypto.hkdfSync` returns a `Buffer`,
WebCrypto's `deriveBits` returns an `ArrayBuffer` — two
`Uint8Array.from(...)` wraps later, byte-equal. If we'd only tested
"each impl roundtrips its own output" the divergence would have hidden
until the cloud cutover.

Locking the wire format with a golden vector (one fixed input → one
pinned base64url string) makes the invariant durable across all future
phases. If 12c's Workers MtlsClient ever reaches in and tweaks
sealing semantics, the golden vector test fails before any user-facing
token breaks.

## What `runtime/workers.ts` does *not* do (Phase 12c gap)

The Workers entry compiles, type-checks, and is unit-tested via
miniflare. It serves `/healthz`, `/.well-known/openid-configuration`,
`/.well-known/jwks.json`, and `/admin/*` routes. It does **not** serve
`POST /oidc/token` — the route handler intercepts before Hono dispatch
and returns:

```json
{
  "error": "temporarily_unavailable",
  "error_description": "Workers runtime: mTLS to Toss not yet implemented (Phase 12c). Use the Node/Docker deployment until then."
}
```

The intercept is six lines at the top of the `fetch` handler. Phase
12c removes the `if` block and adds the `MtlsClient.WorkersBinding`
implementation; nothing else needs touching. This is deliberate:

- Returning a structured 501 (rather than a 5xx or routing-failure
  surface) means a caller hitting the wrong cloud sees an actionable
  error, not a deploy bug.
- Keeping `runtime/workers.ts` in the merge tree (rather than gating
  it behind a feature flag or building only on a branch) means TS +
  miniflare are part of CI from day one. The first 10c commit doesn't
  have to fight a stale Workers entry.
- The `temporarily_unavailable` wording matches OAuth 2.0 RFC 6749
  §5.2 — clients that follow the spec retry-with-backoff rather than
  treating it as a hard failure.

## What was deliberately not done

- **No live Toss e2e on Workers**. Stub mTLS factory throws on call.
  Phase 12c needs a real sandbox handshake — out of 09c scope.
- **No Workers deploy artifacts**. No `wrangler.toml`, no Workers
  Secrets, no D1 binding registration. Phase 10c. The `runtime/workers.ts`
  file builds via the same `tsdown` pipeline as Node code; deploy
  tooling lands when the dispatcher repo (`oidc-bridge-cloud`) does.
- **No D1 migration auto-apply**. `runD1Migrations(db)` exists and is
  used in tests, but the Workers `fetch` handler assumes the schema
  is already present. Phase 11c will run `wrangler d1 migrations
  apply` at deploy time.
- **No Hono middleware portability check**. The middleware stack
  (rate-limit, request-id, pino-http) was migrated when its individual
  Node-leaning pieces broke. Some still implicitly assume Node
  primitives at deeper layers (e.g. pino's `pino-http` still wraps
  `IncomingMessage`); Workers gets a thinner middleware path in the
  current code, but a full audit is 10c work.
- **No backwards-compat for the old sync `wrapSealedToken` API**.
  Every caller switched to `await`; tests + types catch the rest. No
  shim.

## Sub-agent delegation observations

Phase 09c was the first phase where subagent delegation paid off
significantly. Pattern:

- **Mirror tasks → haiku/sonnet, dispatched in parallel**. The Node
  adapter implementations of each port (`node-aead.ts`, `node-kdf.ts`,
  `node-random.ts`, `node-digest.ts`) were structurally identical —
  port interface + `node:crypto` call. Sent them in parallel sonnet
  calls with explicit "mirror this WebCrypto impl byte-for-byte" prompts.
  Saved ~30 minutes vs. inline writing, and the cross-impl tests
  caught one drift on first try (HKDF return type, see earlier).
- **Reviewer in opus**. The Pass 1 review subagent ran in opus and
  surfaced two real Workers-portability issues (`Buffer.from(b64)` in
  `client-auth.ts`, `REDACT_PATHS` transitive pino import via
  `node-logger.ts` re-export) that I would have missed inline. Both
  fixes were one-liners but real bugs that would have crashed the
  Workers bundle at module load.
- **shipper subagent for the merge lifecycle**. `pr-shipper`
  (sonnet) handled the squash + branch delete + CI poll without
  burning main-session context. CI was green first try; no fixes
  needed.
- **Wrong choice retroactively**: the D1 driver implementation could
  have been a sonnet mirror of the SQLite driver, but I wrote it
  inline because miniflare's API surface was unfamiliar. Correct
  call empirically — surfaced two D1 quirks during writing, would
  have wasted the agent's time bouncing back errors.

For 10c's planner: Workers infrastructure (wrangler, Secrets, D1
binding wiring) is unfamiliar territory — keep inline until the
shape is concrete, then farm out mirrors.

## Standing decisions captured in CLAUDE.md

The phase produced enough cross-cutting invariants to deserve a
permanent home in CLAUDE.md (committed in the same merge):

- `Buffer` and `node:crypto`/`node:tls`/`undici` imports forbidden
  outside `src/runtime/node-*.ts` (test files excepted).
- `Uint8Array` is the cross-runtime byte type at every port boundary.
- WebCrypto `seal`/`open` is async; all callers `await`.
- Sealed `ait_*` wire format locked by golden vectors; cross-impl
  tests verify Node↔WebCrypto interop.
- Storage has three drivers (`pg`, `sqlite`, `d1`) sharing
  `runStorageConformance`. D1 quirks documented (no `IF NOT EXISTS`,
  no DESC in expression indexes).
- `@cloudflare/workers-types` is **type-only**; no triple-slash
  references. `tsconfig.json` `types` array stays `["node"]`.
- `runtime/workers.ts` reads env from the Workers `env` parameter,
  never `process.env`; no `node:*` imports.

These survive 10c+. Future phases that touch any of the above re-read
the section before changing.

## Touched files (summary)

Ports (new): `src/core/{aead,kdf,random,digest,logger,mtls,bytes,
logger-redact}.ts` + matching `*.test.ts`.

Node adapters (new): `src/runtime/node-{aead,kdf,random,digest,logger,
mtls}.ts` + tests where applicable.

Workers adapters (new): `src/runtime/workers-{logger,master-key-provider,
mtls}.ts` + `workers.ts` + tests via miniflare.

Storage: `src/storage/{schema.d1,d1}.ts` + `d1.test.ts` (third driver,
miniflare-backed). `drizzle.config.d1.ts` (new).

Sealed-token rewrites: `src/oidc/sealed-token.ts`, `src/apps/encryption.ts`
(both became async, ports-driven, with golden-vector tests).

Master keys: `src/master-keys/{hkdf,index,cache,env-provider,
file-provider,provider}.ts` migrated to `Uint8Array` + `Kdf` port.

Runtime split: `src/server.ts` (274 → 31 lines), `src/runtime/node.ts`
(new, 270 lines, holds prior bootstrap), `src/runtime/workers.ts`
(new, 135 lines).

Touched-but-unchanged-semantically: most consumers of `wrapSealedToken`,
`encryptColumn`, master-key reads — added `await`, no logic change.

`CLAUDE.md` — milestones table extended through 14c, status updated,
new "Runtime abstraction (Phase 09c)" standing-decisions section.

84 files changed, 4429 insertions, 820 deletions. No behavior change
visible to a Node 24 / Docker / Vultr operator.

## Next phase pointer

**10c — `oidc-bridge-cloud` private repo scaffold**: dispatcher Worker,
admin endpoints stub, CF API client (account-aware factory), tenant
registry D1 (`cf_account_id` column from day one for future multi-
account sharding). Spec: §4 control plane + §6.1 repo skeleton + §11
open questions Q2 (tenant routing key) and Q3 (admin auth) get
resolved during 10c.
