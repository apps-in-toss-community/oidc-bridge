# Phase 03 plan — amendments (post-Phase-2 audit)

> **Read this BEFORE starting Phase 03 implementation.** This document supersedes the corresponding parts of `2026-05-01-zero-code-phase-03-oidc-token-public.md`.

The original Phase 03 plan was authored before Phase 2 was implemented. Phase 2 shipped with a `Service` interface (`src/apps/service.ts`) that does not match what the Phase 03 plan assumed. Two of the four issues below are already patched in the plan file in-place; the other two require the worker to deviate from the plan's verbatim code as specified here.

## Already patched in the plan file

These were pure search-and-replace and have been applied directly to `2026-05-01-zero-code-phase-03-oidc-token-public.md` — no worker action required:

1. **`'active'` → `'verified'`** (ownership status). The actual `AppOwnershipStatus` type from Phase 1 (`src/storage/types.ts`) is `'pending' | 'verified' | 'lapsed'`. All `'active'` literals in fixtures, type annotations, and the gate check (`appRow.ownershipStatus !== 'verified'`) were mass-replaced.

2. **`'../crypto/hkdf.js'` → `'../master-keys/index.js'`** (HKDF import path). Phase 1 ships HKDF at `src/master-keys/hkdf.ts`, re-exported from `src/master-keys/index.ts`. There is no `src/crypto/` directory.

## Worker must deviate from the plan's verbatim code

These require structural changes that are too invasive to mass-edit safely. Apply them everywhere they appear:

### 3. Use `Storage`, not `Service`, for app lookup

The plan imports `Service` from `'../service/types.js'` (this file does not exist) and calls `opts.service.apps.getByClientId(body.client_id)` (this method does not exist on the Phase 2 `Service`). The Phase 2 `Service` is at `src/apps/service.ts` and only exposes `apps.create / list / get / update / delete / rotateSecret / toggleRawTokens` — no `getByClientId`.

**Correct path**: bypass the service layer. Use the `Storage` interface directly. `Storage` already exposes `getAppByClientId(clientId)` (from Phase 1, `src/storage/interface.ts`).

Applies to **`TokenRouteOpts`**, **`tokenRoute(opts)`**, the test fakes (`fakeService` / `buildHarness`), and any other place `Service` or `service.apps.getByClientId` appears.

```ts
// src/oidc/token-route.ts — corrected shape
import type { Storage } from '../storage/interface.js';
import type { TokenService } from './token-service.js';
// ...

export interface TokenRouteOpts {
  storage: Storage;          // was: service: Service
  tokenService: TokenService;
}

export function tokenRoute(opts: TokenRouteOpts) {
  // ...
  const appRow = await opts.storage.getAppByClientId(body.client_id);  // was: opts.service.apps.getByClientId(...)
  // ...
}
```

```ts
// test fake — replace fakeService with fakeStorage
function fakeStorage(app: FakeAppRow) {
  return {
    async getAppByClientId(clientId: string) {
      return clientId === app.clientId ? app : null;
    },
    appendAudit: async () => {},
    // ...other Storage methods stubbed as needed
  } as unknown as Storage;
}
```

The shape of `FakeAppRow` is whatever `Storage.getAppByClientId` returns (an `AppRecord` from `src/storage/types.ts`). Use the real type — don't recreate.

`buildApp` (the wiring point in `src/app.ts`) likewise should pass `storage: Storage` to `tokenRoute`, not the Phase 2 `Service`.

### 4. Audit writer — use `appendAudit({storage, actor, action, target, details?})`

The plan calls `opts.service.audit.append({actor: {type, id}, action, target: {type, id}, details})` with a structured `actor`/`target`. The Phase 2 `appendAudit` (`src/apps/audit.ts`) signature is:

```ts
appendAudit({
  storage: Storage,
  actor: string,                 // user ID or app ID, plain string
  action: AuditAction,           // string-literal union — extend, see below
  target: string,                // resource ID, plain string
  details?: Record<string, unknown>,
}): Promise<void>
```

**Worker action**:

(a) Extend the `AuditAction` union in `src/apps/audit.ts` to include `'oidc.token.issue'` and `'oidc.token.refresh'`. This is a one-line edit; commit it as the first task of Phase 03 (or fold into the first task that needs auditing).

(b) Replace every plan call site of `opts.service.audit.append(...)` with `await appendAudit({ storage: opts.storage, actor: appRow.id, action: 'oidc.token.issue' /* or 'oidc.token.refresh' */, target: appRow.id, details: { grant_type: ... } })`. Both `actor` and `target` are the app ID string in this phase (the actor is the app itself authenticating via Origin/client_secret, not a human user).

(c) Test fakes mock `appendAudit` indirectly via `Storage.appendAudit: async () => {}` (since `appendAudit` ultimately calls `storage.appendAudit`). No need to mock a separate audit module.

## Sealed-token format extension (note, not a fix)

Task 17 changes the sealed-token format from `version || iv || ciphertext || tag` (spec §5.4) to `version || userKey_len || userKey || iv || ciphertext || tag`. This is intentional — it's the resolution to the AAD-circular-dependency problem flagged in spec §12 decision 17 ("AAD binds `app_id, toss_user_key, sealing_key_version`"). The format extension is correct and does not need to be fixed; just note it in the eventual PR description so spec readers aren't surprised.

## Pre-flight section is stale

The plan's pre-flight section assumes the worker creates a local branch from `origin/main`. That is incorrect — the worker will be in a fresh `gw new`-spawned worktree where the branch already exists and main already has Phases 0+1+2 merged. Skip the pre-flight `git fetch / checkout / branch` steps entirely. Run `pnpm install && pnpm typecheck && pnpm lint && pnpm test` to verify a green baseline, then start Task 1.

## Audit footnote

This amendment was produced 2026-05-02 after Phase 2 (1/2) and (2/2) merged to main (PRs #20 and #21). The cause was the Phase 03 plan being authored against design assumptions that diverged subtly from what Phase 2 ultimately shipped — primarily a hypothetical `Service.apps.getByClientId` method and a structured-object audit writer. The lesson (see also `docs/superpowers/retros/2026-05-02-phase-01-retro.md` for parallel patterns): plans authored ahead of the predecessor phase's implementation should be re-audited at the moment the predecessor merges, not at the moment the successor starts.
