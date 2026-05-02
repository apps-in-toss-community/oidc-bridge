# Phase 2 — Workspaces, Apps, and API_TOKEN admin

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the admin REST surface (workspaces, apps, api_tokens, ownership) and the CLI that wraps it. Apps store their mTLS material encrypted at the column level via the per-app sealing key. `client_secret` values are bcrypt-hashed with rotation overlap. Every admin mutation writes an audit log entry. No OIDC routes yet — that comes in Phase 3.

**Architecture:** A single `auth()` middleware resolves `Authorization: Bearer <api_token>` to a `(user, scopes)` tuple by looking up `sha256(token)` in `api_tokens`. Routes are mounted under `/admin/...`. App writes go through a service layer (`src/apps/service.ts`) that owns the encryption + secret-hashing concerns; routes are thin. CLI commands (`cli/commands/...`) use the same service layer when given `--db-path` (offline mode) or call the REST API when given `--api-url` (online mode).

**Tech stack:** carries Phase 1 deps; adds `bcryptjs` (pure-JS bcrypt to keep build artifacts small and avoid native rebuilds in Docker), `commander` (CLI), `nanoid` (id generation), and zod (input validation). All four are widely used and have no native compile step except bcryptjs's optional one (we use the JS-only path).

---

## Universal invariants

See [`2026-05-01-zero-code-mode-index.md`](./2026-05-01-zero-code-mode-index.md#universal-invariants). Phase 2 leans on:

- **TDD.** Service-layer tests against an in-memory SQLite go red→green→commit.
- **No PII / secrets in logs.** Plaintext client_secret is shown to the user once at create/rotate, never persisted, never logged.
- **mTLS material never returns from any GET.** Admin GET on `apps/:id` returns `mtls_cert_enc: null` and `mtls_key_enc: null` (the schema fields are masked), and the JSON adds an `mtls_present: true` flag instead.
- **Public clients use Origin, not bearer secrets.** Admin auth is API_TOKEN — that does not contradict invariant 7 (admin is not an OIDC client).
- **Lint + typecheck + test pass on every commit.**

## Files touched in this phase

**Created:**

- `src/ids.ts` — id helpers (`newId('user')` etc.).
- `src/ids.test.ts`
- `src/apps/secrets.ts` — bcrypt hash + rotation overlap helpers.
- `src/apps/secrets.test.ts`
- `src/apps/encryption.ts` — encrypt/decrypt mTLS material with per-app sealing key.
- `src/apps/encryption.test.ts`
- `src/apps/service.ts` — service layer (workspaces, apps, api_tokens, ownership).
- `src/apps/service.test.ts`
- `src/apps/auth.ts` — `auth()` middleware (Bearer api_token).
- `src/apps/auth.test.ts`
- `src/apps/routes.ts` — Hono routes under `/admin/...`.
- `src/apps/routes.test.ts`
- `src/apps/ownership.ts` — α auto-verify + 72h grace + lapsed reassign helpers.
- `src/apps/ownership.test.ts`
- `src/apps/audit.ts` — typed audit log writer.
- `src/audit/log.ts` — re-exports `appendAudit` from `apps/audit` (the spec §5.2 module name).
- `cli/index.ts` — commander entrypoint.
- `cli/api-client.ts` — REST client used in online mode.
- `cli/api-client.test.ts`
- `cli/commands/workspace.ts`
- `cli/commands/app.ts`
- `cli/commands/api-token.ts`
- `cli/commands/_shared.ts` — shared option parsing (offline vs online).

**Modified:**

- `src/app.ts` — mount `/admin/*` routes when a service handle is provided.
- `src/app.test.ts` — extend factory to accept dependencies.
- `package.json` — add `bcryptjs`, `commander`, `nanoid`, `zod`.
- `tsconfig.json` — already includes `cli/`.

---

## Pre-flight

```bash
pwd                          # …/oidc-bridge-jwt-signature-verification
git branch --show-current    # zero-code-mode
git status                   # clean
pnpm install --frozen-lockfile
pnpm test                    # all Phase 0+1 tests still green
```

---

## Task 1: Add deps

**Files:**
- Modify: `package.json`, `pnpm-lock.yaml`

- [ ] **Step 1: Install**

```bash
pnpm add bcryptjs@^2.4 commander@^12 nanoid@^5 zod@^3.23
pnpm add -D @types/bcryptjs
```

- [ ] **Step 2: Verify**

```bash
pnpm list bcryptjs commander nanoid zod --depth=0
```

Expected: all four listed under dependencies.

- [ ] **Step 3: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "chore: add bcryptjs + commander + nanoid + zod for Phase 2"
```

---

## Task 2: ID helpers

We use prefixed nanoid IDs (`user_…`, `ws_…`, `app_…`, `tok_…`, `ses_…`, `mk_…`, `au_…`). Prefix makes log lines self-documenting and prevents accidental cross-table mix-ups.

**Files:**
- Create: `src/ids.ts`
- Create: `src/ids.test.ts`

- [ ] **Step 1: Write failing test**

`src/ids.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { newId, type IdKind } from './ids.js';

describe('newId', () => {
  it.each<[IdKind, string]>([
    ['user', 'user_'],
    ['workspace', 'ws_'],
    ['app', 'app_'],
    ['api_token', 'tok_'],
    ['user_session', 'ses_'],
    ['master_key', 'mk_'],
    ['audit', 'au_'],
  ])('produces a %s id with prefix %s', (kind, prefix) => {
    const id = newId(kind);
    expect(id.startsWith(prefix)).toBe(true);
    expect(id.length).toBeGreaterThan(prefix.length + 8);
  });

  it('produces unique values', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i += 1) seen.add(newId('app'));
    expect(seen.size).toBe(1000);
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/ids.test.ts
```

Expected: FAIL — module missing.

- [ ] **Step 3: Implement**

`src/ids.ts`:

```ts
import { customAlphabet } from 'nanoid';

export type IdKind =
  | 'user'
  | 'workspace'
  | 'app'
  | 'api_token'
  | 'user_session'
  | 'master_key'
  | 'audit';

const PREFIX: Record<IdKind, string> = {
  user: 'user_',
  workspace: 'ws_',
  app: 'app_',
  api_token: 'tok_',
  user_session: 'ses_',
  master_key: 'mk_',
  audit: 'au_',
};

// 64-char alphabet with `-_` to avoid base64 padding issues; 21 chars ≈ 125 bits.
const nano = customAlphabet(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  21,
);

export function newId(kind: IdKind): string {
  return `${PREFIX[kind]}${nano()}`;
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/ids.test.ts
```

Expected: PASS (8/8).

- [ ] **Step 5: Commit**

```bash
git add src/ids.ts src/ids.test.ts
git commit -m "feat(ids): prefixed nanoid factory"
```

---

## Task 3: bcrypt secret hashing with rotation overlap

`client_secret` values are stored as a list of bcrypt hashes. Verify scans all hashes and returns true on any match — that's how rotation overlap works (old + new secret valid simultaneously). Add a new hash when issuing a new secret; remove old ones explicitly via the rotate endpoint.

**Files:**
- Create: `src/apps/secrets.ts`
- Create: `src/apps/secrets.test.ts`

- [ ] **Step 1: Write failing test**

`src/apps/secrets.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import {
  generateClientSecret,
  hashClientSecret,
  verifyClientSecret,
  generateApiToken,
  hashApiToken,
  verifyApiToken,
} from './secrets.js';

describe('client secret', () => {
  it('generates a 32-byte URL-safe random string', () => {
    const s = generateClientSecret();
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(s.length).toBeGreaterThan(40);
  });

  it('hashes and verifies a secret', async () => {
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    expect(hash.startsWith('$2')).toBe(true);
    expect(await verifyClientSecret(secret, [hash])).toBe(true);
  });

  it('verifies against any matching hash (rotation overlap)', async () => {
    const old = await hashClientSecret('old-secret');
    const fresh = await hashClientSecret('new-secret');
    expect(await verifyClientSecret('new-secret', [old, fresh])).toBe(true);
    expect(await verifyClientSecret('old-secret', [old, fresh])).toBe(true);
    expect(await verifyClientSecret('wrong', [old, fresh])).toBe(false);
  });

  it('returns false when the hash list is empty', async () => {
    expect(await verifyClientSecret('any', [])).toBe(false);
  });
});

describe('api token', () => {
  it('generates a token with `tok_` prefix', () => {
    const t = generateApiToken();
    expect(t.startsWith('tok_')).toBe(true);
    expect(t.length).toBeGreaterThan(40);
  });

  it('hashes deterministically (sha256)', () => {
    const t = 'tok_xxx';
    expect(hashApiToken(t)).toBe(hashApiToken(t));
    expect(hashApiToken(t)).not.toBe(hashApiToken('tok_yyy'));
    expect(hashApiToken(t)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('verifyApiToken matches generated tokens', () => {
    const t = generateApiToken();
    const h = hashApiToken(t);
    expect(verifyApiToken(t, h)).toBe(true);
    expect(verifyApiToken('tok_zzz', h)).toBe(false);
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/apps/secrets.test.ts
```

Expected: FAIL — module missing.

- [ ] **Step 3: Implement**

`src/apps/secrets.ts`:

```ts
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';

const BCRYPT_ROUNDS = 12;

function urlSafeRandom(byteLen: number): string {
  return randomBytes(byteLen).toString('base64url');
}

export function generateClientSecret(): string {
  return urlSafeRandom(32);
}

export async function hashClientSecret(plain: string): Promise<string> {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

export async function verifyClientSecret(plain: string, hashes: string[]): Promise<boolean> {
  for (const h of hashes) {
    if (await bcrypt.compare(plain, h)) return true;
  }
  return false;
}

export function generateApiToken(): string {
  return `tok_${urlSafeRandom(32)}`;
}

export function hashApiToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function verifyApiToken(plain: string, hash: string): boolean {
  const computed = Buffer.from(hashApiToken(plain), 'hex');
  const expected = Buffer.from(hash, 'hex');
  if (computed.length !== expected.length) return false;
  return timingSafeEqual(computed, expected);
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/apps/secrets.test.ts
```

Expected: PASS (8/8).

- [ ] **Step 5: Commit**

```bash
git add src/apps/secrets.ts src/apps/secrets.test.ts
git commit -m "feat(apps): bcrypt client_secret + sha256 api_token hashing"
```

---

## Task 4: mTLS material encryption

Per-app encryption uses AES-256-GCM with the HKDF-derived sealing key from Phase 1. The encrypted bytes stored in the DB column are `iv || ciphertext || tag` (12 + n + 16 bytes). On rotate-master-key, rewrap is lazy — until then the column carries the version it was encrypted under, kept in `apps.sealing_key_version`.

**Files:**
- Create: `src/apps/encryption.ts`
- Create: `src/apps/encryption.test.ts`

- [ ] **Step 1: Write failing test**

`src/apps/encryption.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { decryptColumn, encryptColumn } from './encryption.js';

describe('column encryption', () => {
  const key = Buffer.alloc(32, 0x42);
  const plaintext = Buffer.from('-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBg...\n-----END PRIVATE KEY-----');
  const aad = Buffer.from('app_xyz', 'utf8');

  it('roundtrips encrypt → decrypt', () => {
    const enc = encryptColumn({ key, plaintext, aad });
    const out = decryptColumn({ key, ciphertext: enc, aad });
    expect(out.equals(plaintext)).toBe(true);
  });

  it('fails when AAD differs', () => {
    const enc = encryptColumn({ key, plaintext, aad });
    expect(() =>
      decryptColumn({ key, ciphertext: enc, aad: Buffer.from('different') }),
    ).toThrow();
  });

  it('fails when key differs', () => {
    const enc = encryptColumn({ key, plaintext, aad });
    expect(() =>
      decryptColumn({ key: Buffer.alloc(32, 0xff), ciphertext: enc, aad }),
    ).toThrow();
  });

  it('produces different ciphertexts for the same input (random IV)', () => {
    const a = encryptColumn({ key, plaintext, aad });
    const b = encryptColumn({ key, plaintext, aad });
    expect(a.equals(b)).toBe(false);
  });

  it('rejects keys not 32 bytes', () => {
    expect(() => encryptColumn({ key: Buffer.alloc(16), plaintext, aad })).toThrow(/32 bytes/);
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/apps/encryption.test.ts
```

- [ ] **Step 3: Implement**

`src/apps/encryption.ts`:

```ts
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export interface EncryptColumnInput {
  key: Buffer;
  plaintext: Buffer;
  aad: Buffer;
}

export interface DecryptColumnInput {
  key: Buffer;
  ciphertext: Buffer;
  aad: Buffer;
}

export function encryptColumn(input: EncryptColumnInput): Buffer {
  if (input.key.length !== KEY_BYTES) throw new Error('encryptColumn: key must be 32 bytes');
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', input.key, iv);
  cipher.setAAD(input.aad);
  const enc = Buffer.concat([cipher.update(input.plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, enc, tag]);
}

export function decryptColumn(input: DecryptColumnInput): Buffer {
  if (input.key.length !== KEY_BYTES) throw new Error('decryptColumn: key must be 32 bytes');
  if (input.ciphertext.length < IV_BYTES + TAG_BYTES) {
    throw new Error('decryptColumn: ciphertext too short');
  }
  const iv = input.ciphertext.subarray(0, IV_BYTES);
  const tag = input.ciphertext.subarray(input.ciphertext.length - TAG_BYTES);
  const enc = input.ciphertext.subarray(IV_BYTES, input.ciphertext.length - TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', input.key, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(input.aad);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/apps/encryption.test.ts
```

Expected: PASS (5/5).

- [ ] **Step 5: Commit**

```bash
git add src/apps/encryption.ts src/apps/encryption.test.ts
git commit -m "feat(apps): AES-256-GCM column encryption with AAD binding"
```

---

## Task 5: Audit log helpers

Typed wrappers over `Storage.appendAudit` so callers don't repeat `id` and `ts` boilerplate, and so we can grep for action names.

**Files:**
- Create: `src/apps/audit.ts`
- Create: `src/audit/log.ts`

- [ ] **Step 1: Implement `src/apps/audit.ts`**

```ts
import { newId } from '../ids.js';
import type { Storage } from '../storage/interface.js';

export type AuditAction =
  | 'user.create'
  | 'workspace.create'
  | 'workspace.update'
  | 'workspace.delete'
  | 'app.create'
  | 'app.update'
  | 'app.delete'
  | 'app.secret.rotate'
  | 'app.raw_tokens.toggle'
  | 'app.ownership.verify'
  | 'app.ownership.lapse'
  | 'api_token.create'
  | 'api_token.delete'
  | 'master_key.rotate';

export interface AppendAuditInput {
  storage: Storage;
  actor: string;
  action: AuditAction;
  target: string;
  details?: Record<string, unknown>;
}

export async function appendAudit(input: AppendAuditInput): Promise<void> {
  await input.storage.appendAudit({
    id: newId('audit'),
    actor: input.actor,
    action: input.action,
    target: input.target,
    detailsJson: input.details ?? {},
  });
}
```

- [ ] **Step 2: Implement re-export `src/audit/log.ts`**

```ts
export { appendAudit, type AuditAction, type AppendAuditInput } from '../apps/audit.js';
```

- [ ] **Step 3: Run typecheck**

```bash
pnpm typecheck
```

Expected: green.

- [ ] **Step 4: Commit**

```bash
git add src/apps/audit.ts src/audit/log.ts
git commit -m "feat(audit): typed action enum + appendAudit helper"
```

---

## Task 6: Ownership state machine

Pure helpers (no I/O). Given env (`BRIDGE_STAGE`) and current time, compute the initial ownership state for a new app, and the next state for an unverified app whose grace has expired.

**Files:**
- Create: `src/apps/ownership.ts`
- Create: `src/apps/ownership.test.ts`

- [ ] **Step 1: Write failing test**

`src/apps/ownership.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { computeInitialOwnership, computeOwnershipAfterGrace } from './ownership.js';

describe('computeInitialOwnership', () => {
  const now = new Date('2026-05-01T00:00:00Z');

  it('auto-verifies in alpha stage', () => {
    expect(computeInitialOwnership({ stage: 'alpha', now })).toEqual({
      ownershipStatus: 'verified',
      ownershipGraceUntil: null,
    });
  });

  it('puts apps into pending with 72h grace outside alpha', () => {
    const out = computeInitialOwnership({ stage: 'beta', now });
    expect(out.ownershipStatus).toBe('pending');
    expect(out.ownershipGraceUntil?.toISOString()).toBe('2026-05-04T00:00:00.000Z');
  });

  it('treats undefined stage as non-alpha', () => {
    const out = computeInitialOwnership({ stage: undefined, now });
    expect(out.ownershipStatus).toBe('pending');
  });
});

describe('computeOwnershipAfterGrace', () => {
  const now = new Date('2026-05-05T00:00:00Z');

  it('returns lapsed when grace has expired and status is pending', () => {
    const out = computeOwnershipAfterGrace({
      ownershipStatus: 'pending',
      ownershipGraceUntil: new Date('2026-05-04T00:00:00Z'),
      now,
    });
    expect(out).toEqual({ ownershipStatus: 'lapsed', ownershipGraceUntil: null });
  });

  it('keeps current state when grace has not expired', () => {
    const out = computeOwnershipAfterGrace({
      ownershipStatus: 'pending',
      ownershipGraceUntil: new Date('2026-05-06T00:00:00Z'),
      now,
    });
    expect(out).toBeNull();
  });

  it('keeps current state when status is verified', () => {
    const out = computeOwnershipAfterGrace({
      ownershipStatus: 'verified',
      ownershipGraceUntil: null,
      now,
    });
    expect(out).toBeNull();
  });

  it('keeps current state when status is already lapsed', () => {
    const out = computeOwnershipAfterGrace({
      ownershipStatus: 'lapsed',
      ownershipGraceUntil: null,
      now,
    });
    expect(out).toBeNull();
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/apps/ownership.test.ts
```

- [ ] **Step 3: Implement `src/apps/ownership.ts`**

```ts
import type { AppOwnershipStatus } from '../storage/types.js';

export type Stage = 'alpha' | 'beta' | 'ga' | undefined;
const GRACE_MS = 72 * 60 * 60 * 1000;

export interface InitialOwnershipInput {
  stage: Stage;
  now: Date;
}

export interface InitialOwnership {
  ownershipStatus: AppOwnershipStatus;
  ownershipGraceUntil: Date | null;
}

export function computeInitialOwnership(input: InitialOwnershipInput): InitialOwnership {
  if (input.stage === 'alpha') {
    return { ownershipStatus: 'verified', ownershipGraceUntil: null };
  }
  return {
    ownershipStatus: 'pending',
    ownershipGraceUntil: new Date(input.now.getTime() + GRACE_MS),
  };
}

export interface OwnershipAfterGraceInput {
  ownershipStatus: AppOwnershipStatus;
  ownershipGraceUntil: Date | null;
  now: Date;
}

/** Returns the new state if a transition is needed, else null. */
export function computeOwnershipAfterGrace(
  input: OwnershipAfterGraceInput,
): InitialOwnership | null {
  if (input.ownershipStatus !== 'pending') return null;
  if (!input.ownershipGraceUntil) return null;
  if (input.ownershipGraceUntil.getTime() > input.now.getTime()) return null;
  return { ownershipStatus: 'lapsed', ownershipGraceUntil: null };
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/apps/ownership.test.ts
```

Expected: PASS (7/7).

- [ ] **Step 5: Commit**

```bash
git add src/apps/ownership.ts src/apps/ownership.test.ts
git commit -m "feat(apps): ownership state machine (initial + after-grace)"
```

---

## Task 7: Service layer — workspaces

The service is the only place outside route handlers that mutates storage. Routes are thin: validate input, call service, format response. Service methods always take a `(ctx, input)` shape where `ctx` carries the storage handle and the actor user id.

**Files:**
- Create: `src/apps/service.ts` (workspaces section)
- Create: `src/apps/service.test.ts` (workspaces tests)

- [ ] **Step 1: Write failing test**

`src/apps/service.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSqliteStorage } from '../storage/sqlite.js';
import type { Storage } from '../storage/interface.js';
import { createService, type Service, type ServiceCtx } from './service.js';

let dir: string;
let storage: Storage;
let svc: Service;
let ctx: ServiceCtx;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-svc-'));
  storage = createSqliteStorage({ path: join(dir, 'test.db') });
  svc = createService({ storage });
  await storage.createUser({ id: 'user_actor', email: 'actor@x.com' });
  ctx = { actorUserId: 'user_actor' };
});

afterEach(async () => {
  await storage.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('service: workspaces', () => {
  it('creates a workspace owned by actor', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    expect(w.ownerUserId).toBe('user_actor');
    expect(w.name).toBe('first');
  });

  it('lists workspaces by owner', async () => {
    await svc.workspaces.create(ctx, { name: 'first' });
    await svc.workspaces.create(ctx, { name: 'second' });
    const list = await svc.workspaces.list(ctx);
    expect(list).toHaveLength(2);
  });

  it('updates workspace name', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    const updated = await svc.workspaces.update(ctx, w.id, { name: 'renamed' });
    expect(updated.name).toBe('renamed');
  });

  it('deletes workspace', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    await svc.workspaces.delete(ctx, w.id);
    const list = await svc.workspaces.list(ctx);
    expect(list).toHaveLength(0);
  });

  it('writes audit entries', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    await svc.workspaces.update(ctx, w.id, { name: 'renamed' });
    await svc.workspaces.delete(ctx, w.id);
    const audits = await storage.listAudit();
    const actions = audits.map((a) => a.action).reverse();
    expect(actions).toEqual(['workspace.create', 'workspace.update', 'workspace.delete']);
  });

  it('refuses cross-owner updates and deletes', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    await storage.createUser({ id: 'user_other', email: 'b@x.com' });
    const otherCtx: ServiceCtx = { actorUserId: 'user_other' };
    await expect(svc.workspaces.update(otherCtx, w.id, { name: 'x' })).rejects.toThrow(/not_found/);
    await expect(svc.workspaces.delete(otherCtx, w.id)).rejects.toThrow(/not_found/);
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/apps/service.test.ts
```

- [ ] **Step 3: Implement `src/apps/service.ts` (workspaces only for now)**

```ts
import { newId } from '../ids.js';
import type { Storage } from '../storage/interface.js';
import type { Workspace } from '../storage/types.js';
import { appendAudit } from './audit.js';

export interface ServiceCtx {
  actorUserId: string;
}

export interface CreateWorkspaceInput {
  name: string;
}

export interface UpdateWorkspaceInput {
  name?: string;
}

export interface Service {
  workspaces: {
    create(ctx: ServiceCtx, input: CreateWorkspaceInput): Promise<Workspace>;
    list(ctx: ServiceCtx): Promise<Workspace[]>;
    get(ctx: ServiceCtx, id: string): Promise<Workspace>;
    update(ctx: ServiceCtx, id: string, input: UpdateWorkspaceInput): Promise<Workspace>;
    delete(ctx: ServiceCtx, id: string): Promise<void>;
  };
}

export interface CreateServiceOptions {
  storage: Storage;
}

export class NotFoundError extends Error {
  constructor(public resource: string) {
    super(`not_found: ${resource}`);
  }
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(`conflict: ${message}`);
  }
}

export function createService(opts: CreateServiceOptions): Service {
  const storage = opts.storage;

  async function getOwnedWorkspace(ctx: ServiceCtx, id: string): Promise<Workspace> {
    const w = await storage.getWorkspace(id);
    if (!w || w.ownerUserId !== ctx.actorUserId) {
      throw new NotFoundError(`workspace ${id}`);
    }
    return w;
  }

  return {
    workspaces: {
      async create(ctx, input) {
        const w = await storage.createWorkspace({
          id: newId('workspace'),
          ownerUserId: ctx.actorUserId,
          name: input.name,
        });
        await appendAudit({
          storage,
          actor: ctx.actorUserId,
          action: 'workspace.create',
          target: w.id,
          details: { name: input.name },
        });
        return w;
      },
      async list(ctx) {
        return storage.listWorkspacesByOwner(ctx.actorUserId);
      },
      async get(ctx, id) {
        return getOwnedWorkspace(ctx, id);
      },
      async update(ctx, id, input) {
        await getOwnedWorkspace(ctx, id);
        const updated = await storage.updateWorkspace(id, input);
        await appendAudit({
          storage,
          actor: ctx.actorUserId,
          action: 'workspace.update',
          target: id,
          details: input,
        });
        return updated;
      },
      async delete(ctx, id) {
        await getOwnedWorkspace(ctx, id);
        await storage.deleteWorkspace(id);
        await appendAudit({
          storage,
          actor: ctx.actorUserId,
          action: 'workspace.delete',
          target: id,
        });
      },
    },
  };
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/apps/service.test.ts
```

Expected: PASS (6/6 in workspaces section).

- [ ] **Step 5: Commit**

```bash
git add src/apps/service.ts src/apps/service.test.ts
git commit -m "feat(apps): service layer for workspaces (create/list/update/delete)"
```

---

## Task 8: Service layer — apps

Adds `svc.apps` to the existing `service.ts`. App create takes plaintext `mtlsCert` + `mtlsKey` and the master key bytes (caller resolved); the service derives the per-app sealing key, encrypts the columns, and stores the version. App create generates a `client_secret` plaintext and a single bcrypt hash, and returns the plaintext to the caller (only chance to see it).

**Files:**
- Modify: `src/apps/service.ts`
- Modify: `src/apps/service.test.ts`

- [ ] **Step 1: Append failing test for apps**

Append to `src/apps/service.test.ts`:

```ts
describe('service: apps', () => {
  const masterKey = Buffer.alloc(32, 0xab);
  const stage = 'alpha';

  async function setupWorkspace() {
    return svc.workspaces.create(ctx, { name: 'ws' });
  }

  it('creates an app with encrypted mTLS, hashed secret, and verified ownership in alpha', async () => {
    const w = await setupWorkspace();
    const result = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-1',
      displayTitle: 'My App',
      mtlsCert: Buffer.from('-----BEGIN CERT-----'),
      mtlsKey: Buffer.from('-----BEGIN PRIVATE KEY-----'),
      allowedOrigins: ['https://app.example.com'],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    expect(result.app.workspaceId).toBe(w.id);
    expect(result.app.ownershipStatus).toBe('verified');
    expect(result.app.clientSecretHashes).toHaveLength(1);
    expect(result.clientSecret).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.clientId).toMatch(/^client_/);
    expect(result.app.mtlsCertEnc.length).toBeGreaterThan(0);
  });

  it('puts new apps in pending with 72h grace when not in alpha', async () => {
    const w = await setupWorkspace();
    const result = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-2',
      displayTitle: 'X',
      mtlsCert: Buffer.from('cert'),
      mtlsKey: Buffer.from('key'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage: 'beta',
    });
    expect(result.app.ownershipStatus).toBe('pending');
    expect(result.app.ownershipGraceUntil).not.toBeNull();
  });

  it('rotate-secret appends a new hash and returns plaintext', async () => {
    const w = await setupWorkspace();
    const created = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-3',
      displayTitle: 'X',
      mtlsCert: Buffer.from('cert'),
      mtlsKey: Buffer.from('key'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    const rotated = await svc.apps.rotateSecret(ctx, created.app.id);
    expect(rotated.clientSecret).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(rotated.app.clientSecretHashes).toHaveLength(2);
  });

  it('refuses cross-workspace access', async () => {
    await storage.createUser({ id: 'user_other', email: 'c@x.com' });
    const otherCtx: ServiceCtx = { actorUserId: 'user_other' };
    const w = await setupWorkspace();
    const created = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-4',
      displayTitle: 'X',
      mtlsCert: Buffer.from('c'),
      mtlsKey: Buffer.from('k'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    await expect(svc.apps.get(otherCtx, created.app.id)).rejects.toThrow(/not_found/);
  });

  it('toggleRawTokens flips the bool and audits', async () => {
    const w = await setupWorkspace();
    const created = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-5',
      displayTitle: 'X',
      mtlsCert: Buffer.from('c'),
      mtlsKey: Buffer.from('k'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    const toggled = await svc.apps.toggleRawTokens(ctx, created.app.id, true);
    expect(toggled.rawTokensEnabled).toBe(true);
  });

  it('rejects duplicate appIdToss in the same workspace', async () => {
    const w = await setupWorkspace();
    await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-dup',
      displayTitle: 'X',
      mtlsCert: Buffer.from('c'),
      mtlsKey: Buffer.from('k'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    await expect(
      svc.apps.create(ctx, {
        workspaceId: w.id,
        appIdToss: 'mini-dup',
        displayTitle: 'Y',
        mtlsCert: Buffer.from('c'),
        mtlsKey: Buffer.from('k'),
        allowedOrigins: [],
        sealingKeyVersion: 1,
        masterKey,
        stage,
      }),
    ).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/apps/service.test.ts
```

- [ ] **Step 3: Extend `src/apps/service.ts`**

Add at the top:

```ts
import { encryptColumn } from './encryption.js';
import { deriveSealingKey } from '../master-keys/index.js';
import { computeInitialOwnership, type Stage } from './ownership.js';
import { generateClientSecret, hashClientSecret } from './secrets.js';
import type { AppRecord } from '../storage/types.js';
```

Inside the `Service` interface:

```ts
export interface CreateAppInput {
  workspaceId: string;
  appIdToss: string;
  displayTitle: string;
  mtlsCert: Buffer;
  mtlsKey: Buffer;
  allowedOrigins: string[];
  sealingKeyVersion: number;
  masterKey: Buffer;
  stage: Stage;
}

export interface CreateAppResult {
  app: AppRecord;
  clientId: string;
  clientSecret: string;
}

export interface RotateSecretResult {
  app: AppRecord;
  clientSecret: string;
}

export interface Service {
  workspaces: {
    create(ctx: ServiceCtx, input: CreateWorkspaceInput): Promise<Workspace>;
    list(ctx: ServiceCtx): Promise<Workspace[]>;
    get(ctx: ServiceCtx, id: string): Promise<Workspace>;
    update(ctx: ServiceCtx, id: string, input: UpdateWorkspaceInput): Promise<Workspace>;
    delete(ctx: ServiceCtx, id: string): Promise<void>;
  };
  apps: {
    create(ctx: ServiceCtx, input: CreateAppInput): Promise<CreateAppResult>;
    list(ctx: ServiceCtx, workspaceId: string): Promise<AppRecord[]>;
    get(ctx: ServiceCtx, id: string): Promise<AppRecord>;
    update(
      ctx: ServiceCtx,
      id: string,
      patch: { displayTitle?: string; allowedOrigins?: string[] },
    ): Promise<AppRecord>;
    delete(ctx: ServiceCtx, id: string): Promise<void>;
    rotateSecret(ctx: ServiceCtx, id: string): Promise<RotateSecretResult>;
    toggleRawTokens(ctx: ServiceCtx, id: string, enabled: boolean): Promise<AppRecord>;
  };
}
```

Inside the factory body, after `workspaces: { … }`:

```ts
async function getOwnedApp(ctx: ServiceCtx, id: string): Promise<AppRecord> {
  const a = await storage.getApp(id);
  if (!a) throw new NotFoundError(`app ${id}`);
  const w = await storage.getWorkspace(a.workspaceId);
  if (!w || w.ownerUserId !== ctx.actorUserId) throw new NotFoundError(`app ${id}`);
  return a;
}

const apps: Service['apps'] = {
  async create(ctx, input) {
    await getOwnedWorkspace(ctx, input.workspaceId);
    const appId = newId('app');
    const sealingKey = deriveSealingKey({ masterKey: input.masterKey, appId });
    const aad = Buffer.from(appId, 'utf8');
    const certEnc = encryptColumn({ key: sealingKey, plaintext: input.mtlsCert, aad });
    const keyEnc = encryptColumn({ key: sealingKey, plaintext: input.mtlsKey, aad });
    const clientId = `client_${appId.slice('app_'.length)}`;
    const clientSecret = generateClientSecret();
    const hash = await hashClientSecret(clientSecret);
    const ownership = computeInitialOwnership({ stage: input.stage, now: new Date() });
    const created = await storage.createApp({
      id: appId,
      workspaceId: input.workspaceId,
      appIdToss: input.appIdToss,
      displayTitle: input.displayTitle,
      clientId,
      clientSecretHashes: [hash],
      mtlsCertEnc: certEnc,
      mtlsKeyEnc: keyEnc,
      sealingKeyVersion: input.sealingKeyVersion,
      allowedOrigins: input.allowedOrigins,
      ownershipStatus: ownership.ownershipStatus,
      ownershipGraceUntil: ownership.ownershipGraceUntil,
      rawTokensEnabled: false,
    });
    await appendAudit({
      storage,
      actor: ctx.actorUserId,
      action: 'app.create',
      target: appId,
      details: { appIdToss: input.appIdToss, workspaceId: input.workspaceId },
    });
    return { app: created, clientId, clientSecret };
  },
  async list(ctx, workspaceId) {
    await getOwnedWorkspace(ctx, workspaceId);
    return storage.listAppsByWorkspace(workspaceId);
  },
  async get(ctx, id) {
    return getOwnedApp(ctx, id);
  },
  async update(ctx, id, patch) {
    await getOwnedApp(ctx, id);
    const updated = await storage.updateApp(id, patch);
    await appendAudit({
      storage,
      actor: ctx.actorUserId,
      action: 'app.update',
      target: id,
      details: patch,
    });
    return updated;
  },
  async delete(ctx, id) {
    await getOwnedApp(ctx, id);
    await storage.deleteApp(id);
    await appendAudit({ storage, actor: ctx.actorUserId, action: 'app.delete', target: id });
  },
  async rotateSecret(ctx, id) {
    const existing = await getOwnedApp(ctx, id);
    const clientSecret = generateClientSecret();
    const hash = await hashClientSecret(clientSecret);
    const updated = await storage.updateApp(id, {
      clientSecretHashes: [...existing.clientSecretHashes, hash],
    });
    await appendAudit({
      storage,
      actor: ctx.actorUserId,
      action: 'app.secret.rotate',
      target: id,
    });
    return { app: updated, clientSecret };
  },
  async toggleRawTokens(ctx, id, enabled) {
    await getOwnedApp(ctx, id);
    const updated = await storage.updateApp(id, { rawTokensEnabled: enabled });
    await appendAudit({
      storage,
      actor: ctx.actorUserId,
      action: 'app.raw_tokens.toggle',
      target: id,
      details: { enabled },
    });
    return updated;
  },
};

return {
  workspaces: { /* existing */ },
  apps,
};
```

(Replace the `return { workspaces: { ... } };` block at the end of the factory with `return { workspaces: { … }, apps };` — keep the existing workspace methods inline.)

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/apps/service.test.ts
```

Expected: PASS (12/12 across workspaces + apps).

- [ ] **Step 5: Commit**

```bash
git add src/apps/service.ts src/apps/service.test.ts
git commit -m "feat(apps): service layer for apps (create/get/list/update/delete/rotate/toggle)"
```

---

## Task 9: Service layer — api_tokens

`api_tokens.create` returns plaintext to the caller and stores the sha256 hash. `verify(token)` returns the `{ user, scopes }` tuple if valid.

**Files:**
- Modify: `src/apps/service.ts`
- Modify: `src/apps/service.test.ts`

- [ ] **Step 1: Append failing test**

Append to `src/apps/service.test.ts`:

```ts
describe('service: api_tokens', () => {
  it('creates a token and returns plaintext + hash row', async () => {
    const r = await svc.apiTokens.create(ctx, { name: 'cli', scopes: ['admin'] });
    expect(r.plaintext.startsWith('tok_')).toBe(true);
    expect(r.token.scopes).toEqual(['admin']);
  });

  it('verify returns user + scopes for valid token', async () => {
    const r = await svc.apiTokens.create(ctx, { name: 'cli', scopes: ['admin'] });
    const ok = await svc.apiTokens.verify(r.plaintext);
    expect(ok?.user.id).toBe('user_actor');
    expect(ok?.scopes).toEqual(['admin']);
  });

  it('verify returns null for unknown token', async () => {
    const out = await svc.apiTokens.verify('tok_unknown');
    expect(out).toBeNull();
  });

  it('lists tokens for the actor', async () => {
    await svc.apiTokens.create(ctx, { name: 'a', scopes: ['admin'] });
    await svc.apiTokens.create(ctx, { name: 'b', scopes: [] });
    const list = await svc.apiTokens.list(ctx);
    expect(list).toHaveLength(2);
  });

  it('deletes a token', async () => {
    const r = await svc.apiTokens.create(ctx, { name: 'cli', scopes: ['admin'] });
    await svc.apiTokens.delete(ctx, r.token.id);
    const list = await svc.apiTokens.list(ctx);
    expect(list).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Confirm fail**

- [ ] **Step 3: Extend `src/apps/service.ts`**

Add imports:

```ts
import { generateApiToken, hashApiToken } from './secrets.js';
import type { ApiToken, User } from '../storage/types.js';
```

Add to the `Service` interface:

```ts
  apiTokens: {
    create(
      ctx: ServiceCtx,
      input: { name: string; scopes: string[] },
    ): Promise<{ token: ApiToken; plaintext: string }>;
    list(ctx: ServiceCtx): Promise<ApiToken[]>;
    delete(ctx: ServiceCtx, id: string): Promise<void>;
    verify(plain: string): Promise<{ user: User; scopes: string[] } | null>;
  };
```

Inside the factory:

```ts
const apiTokens: Service['apiTokens'] = {
  async create(ctx, input) {
    const plaintext = generateApiToken();
    const tokenHash = hashApiToken(plaintext);
    const token = await storage.createApiToken({
      id: newId('api_token'),
      userId: ctx.actorUserId,
      name: input.name,
      tokenHash,
      scopes: input.scopes,
    });
    await appendAudit({
      storage,
      actor: ctx.actorUserId,
      action: 'api_token.create',
      target: token.id,
      details: { name: input.name, scopes: input.scopes },
    });
    return { token, plaintext };
  },
  async list(ctx) {
    return storage.listApiTokensByUser(ctx.actorUserId);
  },
  async delete(ctx, id) {
    const tokens = await storage.listApiTokensByUser(ctx.actorUserId);
    if (!tokens.some((t) => t.id === id)) {
      throw new NotFoundError(`api_token ${id}`);
    }
    await storage.deleteApiToken(id);
    await appendAudit({
      storage,
      actor: ctx.actorUserId,
      action: 'api_token.delete',
      target: id,
    });
  },
  async verify(plain) {
    if (!plain.startsWith('tok_')) return null;
    const hash = hashApiToken(plain);
    const row = await storage.getApiTokenByHash(hash);
    if (!row) return null;
    const user = await storage.getUserById(row.userId);
    if (!user) return null;
    await storage.touchApiTokenLastUsed(row.id, new Date());
    return { user, scopes: row.scopes };
  },
};

return { workspaces: { /* existing */ }, apps, apiTokens };
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/apps/service.test.ts
```

Expected: PASS (17/17).

- [ ] **Step 5: Commit**

```bash
git add src/apps/service.ts src/apps/service.test.ts
git commit -m "feat(apps): service layer for api_tokens (create/list/delete/verify)"
```

---

## Task 10: Auth middleware

Hono middleware that reads `Authorization: Bearer …`, calls `service.apiTokens.verify`, and stashes `(user, scopes)` on `c.var`. 401 on missing/invalid; 403 on missing scope.

**Files:**
- Create: `src/apps/auth.ts`
- Create: `src/apps/auth.test.ts`

- [ ] **Step 1: Write failing test**

`src/apps/auth.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSqliteStorage } from '../storage/sqlite.js';
import type { Storage } from '../storage/interface.js';
import { createService } from './service.js';
import { adminAuth } from './auth.js';

let dir: string;
let storage: Storage;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-auth-'));
  storage = createSqliteStorage({ path: join(dir, 'test.db') });
});

afterEach(async () => {
  await storage.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('adminAuth middleware', () => {
  async function bootstrap(): Promise<{ token: string; userId: string }> {
    await storage.createUser({ id: 'user_a', email: 'a@x.com' });
    const svc = createService({ storage });
    const r = await svc.apiTokens.create({ actorUserId: 'user_a' }, { name: 'cli', scopes: ['admin'] });
    return { token: r.plaintext, userId: 'user_a' };
  }

  function makeApp() {
    const svc = createService({ storage });
    const app = new Hono();
    app.use('/admin/*', adminAuth({ service: svc }));
    app.get('/admin/echo', (c) => {
      const user = c.get('user') as { id: string };
      return c.json({ id: user.id });
    });
    app.get('/admin/admin-only', adminAuth({ service: svc, requireScope: 'admin' }), (c) =>
      c.json({ ok: true }),
    );
    return app;
  }

  it('401 without Authorization header', async () => {
    const app = makeApp();
    const res = await app.request('/admin/echo');
    expect(res.status).toBe(401);
  });

  it('401 with malformed Authorization header', async () => {
    const app = makeApp();
    const res = await app.request('/admin/echo', { headers: { authorization: 'Basic xxx' } });
    expect(res.status).toBe(401);
  });

  it('401 with unknown bearer token', async () => {
    const app = makeApp();
    const res = await app.request('/admin/echo', { headers: { authorization: 'Bearer tok_unknown' } });
    expect(res.status).toBe(401);
  });

  it('200 with valid token; sets c.var.user', async () => {
    const { token } = await bootstrap();
    const app = makeApp();
    const res = await app.request('/admin/echo', { headers: { authorization: `Bearer ${token}` } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: 'user_a' });
  });

  it('403 when scope is required but not present', async () => {
    await storage.createUser({ id: 'user_b', email: 'b@x.com' });
    const svc = createService({ storage });
    const r = await svc.apiTokens.create({ actorUserId: 'user_b' }, { name: 'cli', scopes: [] });
    const app = makeApp();
    const res = await app.request('/admin/admin-only', {
      headers: { authorization: `Bearer ${r.plaintext}` },
    });
    expect(res.status).toBe(403);
  });
});
```

- [ ] **Step 2: Confirm fail**

- [ ] **Step 3: Implement `src/apps/auth.ts`**

```ts
import { createMiddleware } from 'hono/factory';
import type { User } from '../storage/types.js';
import type { Service } from './service.js';

export interface AdminAuthOptions {
  service: Service;
  requireScope?: string;
}

declare module 'hono' {
  interface ContextVariableMap {
    user: User;
    scopes: string[];
  }
}

function unauthorized() {
  return Response.json(
    { error: 'unauthorized', error_description: 'admin auth required' },
    { status: 401 },
  );
}

function forbidden() {
  return Response.json(
    { error: 'forbidden', error_description: 'insufficient scope' },
    { status: 403 },
  );
}

export function adminAuth(opts: AdminAuthOptions) {
  return createMiddleware(async (c, next) => {
    const header = c.req.header('authorization');
    if (!header || !header.toLowerCase().startsWith('bearer ')) {
      return unauthorized();
    }
    const plain = header.slice('bearer '.length).trim();
    const verified = await opts.service.apiTokens.verify(plain);
    if (!verified) return unauthorized();
    if (opts.requireScope && !verified.scopes.includes(opts.requireScope)) {
      return forbidden();
    }
    c.set('user', verified.user);
    c.set('scopes', verified.scopes);
    await next();
    return undefined;
  });
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/apps/auth.test.ts
```

Expected: PASS (5/5).

- [ ] **Step 5: Commit**

```bash
git add src/apps/auth.ts src/apps/auth.test.ts
git commit -m "feat(apps): admin Bearer api_token middleware with scope check"
```

---

## Task 11: Admin REST routes — workspaces + api_tokens

**Files:**
- Create: `src/apps/routes.ts`
- Create: `src/apps/routes.test.ts`

- [ ] **Step 1: Write failing test for workspace + api-token routes**

`src/apps/routes.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSqliteStorage } from '../storage/sqlite.js';
import type { Storage } from '../storage/interface.js';
import { createService } from './service.js';
import { mountAdminRoutes } from './routes.js';

let dir: string;
let storage: Storage;
let token: string;

async function makeApp() {
  const svc = createService({ storage });
  const app = new Hono();
  mountAdminRoutes(app, {
    service: svc,
    masterKeyProvider: {
      async getKeyBytes() {
        return Buffer.alloc(32, 0xab);
      },
      async listVersions() {
        return [1];
      },
    },
    activeMasterKeyVersion: () => 1,
    stage: () => 'alpha',
  });
  return app;
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-routes-'));
  storage = createSqliteStorage({ path: join(dir, 'test.db') });
  await storage.createUser({ id: 'user_a', email: 'a@x.com' });
  const svc = createService({ storage });
  const r = await svc.apiTokens.create({ actorUserId: 'user_a' }, { name: 'cli', scopes: ['admin'] });
  token = r.plaintext;
});

afterEach(async () => {
  await storage.close();
  rmSync(dir, { recursive: true, force: true });
});

const auth = () => ({ authorization: `Bearer ${token}` });

describe('admin routes — workspaces', () => {
  it('POST /admin/workspaces creates', async () => {
    const app = await makeApp();
    const res = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'first' }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.name).toBe('first');
  });

  it('GET /admin/workspaces lists', async () => {
    const app = await makeApp();
    await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'first' }),
    });
    const res = await app.request('/admin/workspaces', { headers: auth() });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toHaveLength(1);
  });

  it('PATCH /admin/workspaces/:id updates name', async () => {
    const app = await makeApp();
    const c = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'first' }),
    });
    const id = (await c.json()).id;
    const res = await app.request(`/admin/workspaces/${id}`, {
      method: 'PATCH',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'renamed' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.name).toBe('renamed');
  });

  it('DELETE /admin/workspaces/:id removes', async () => {
    const app = await makeApp();
    const c = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'first' }),
    });
    const id = (await c.json()).id;
    const res = await app.request(`/admin/workspaces/${id}`, {
      method: 'DELETE',
      headers: auth(),
    });
    expect(res.status).toBe(204);
  });

  it('POST /admin/workspaces validates body (zod)', async () => {
    const app = await makeApp();
    const res = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ wrong: 'field' }),
    });
    expect(res.status).toBe(400);
  });
});

describe('admin routes — api_tokens', () => {
  it('POST /admin/api-tokens returns plaintext exactly once', async () => {
    const app = await makeApp();
    const res = await app.request('/admin/api-tokens', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'second', scopes: ['admin'] }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.plaintext.startsWith('tok_')).toBe(true);
    expect(body.token.id).toMatch(/^tok_/);
  });

  it('GET /admin/api-tokens does not return token_hash', async () => {
    const app = await makeApp();
    const res = await app.request('/admin/api-tokens', { headers: auth() });
    const body = await res.json();
    for (const t of body) {
      expect(t.tokenHash).toBeUndefined();
      expect(t.token_hash).toBeUndefined();
    }
  });
});
```

- [ ] **Step 2: Confirm fail**

- [ ] **Step 3: Implement `src/apps/routes.ts`**

```ts
import type { Hono } from 'hono';
import { z } from 'zod';
import type { MasterKeyProvider } from '../master-keys/index.js';
import type { Stage } from './ownership.js';
import { adminAuth } from './auth.js';
import {
  ConflictError,
  NotFoundError,
  type Service,
  type ServiceCtx,
} from './service.js';
import type { ApiToken, AppRecord, Workspace } from '../storage/types.js';

export interface MountAdminRoutesOptions {
  service: Service;
  masterKeyProvider: MasterKeyProvider;
  activeMasterKeyVersion: () => number;
  stage: () => Stage;
}

const CreateWorkspaceSchema = z.object({ name: z.string().min(1) });
const UpdateWorkspaceSchema = z.object({ name: z.string().min(1).optional() });
const CreateAppSchema = z.object({
  workspaceId: z.string().min(1),
  appIdToss: z.string().min(1),
  displayTitle: z.string().min(1),
  mtlsCertPem: z.string().min(1),
  mtlsKeyPem: z.string().min(1),
  allowedOrigins: z.array(z.string().url()).default([]),
});
const UpdateAppSchema = z.object({
  displayTitle: z.string().min(1).optional(),
  allowedOrigins: z.array(z.string().url()).optional(),
});
const ToggleRawTokensSchema = z.object({ enabled: z.boolean() });
const CreateApiTokenSchema = z.object({
  name: z.string().min(1),
  scopes: z.array(z.string()).default([]),
});

function workspaceJson(w: Workspace) {
  return {
    id: w.id,
    ownerUserId: w.ownerUserId,
    name: w.name,
    createdAt: w.createdAt.toISOString(),
  };
}

function appJson(a: AppRecord) {
  return {
    id: a.id,
    workspaceId: a.workspaceId,
    appIdToss: a.appIdToss,
    displayTitle: a.displayTitle,
    clientId: a.clientId,
    allowedOrigins: a.allowedOrigins,
    ownershipStatus: a.ownershipStatus,
    ownershipGraceUntil: a.ownershipGraceUntil?.toISOString() ?? null,
    rawTokensEnabled: a.rawTokensEnabled,
    sealingKeyVersion: a.sealingKeyVersion,
    mtlsPresent: true,
    createdAt: a.createdAt.toISOString(),
    updatedAt: a.updatedAt.toISOString(),
  };
}

function apiTokenJson(t: ApiToken) {
  return {
    id: t.id,
    name: t.name,
    scopes: t.scopes,
    createdAt: t.createdAt.toISOString(),
    lastUsedAt: t.lastUsedAt?.toISOString() ?? null,
  };
}

function ctxFromHono(c: Parameters<Parameters<Hono['get']>[1]>[0]): ServiceCtx {
  const user = c.get('user');
  return { actorUserId: user.id };
}

function handleError(err: unknown) {
  if (err instanceof NotFoundError) {
    return Response.json({ error: 'not_found', error_description: err.message }, { status: 404 });
  }
  if (err instanceof ConflictError) {
    return Response.json({ error: 'conflict', error_description: err.message }, { status: 409 });
  }
  return Response.json(
    { error: 'server_error', error_description: 'unexpected error' },
    { status: 500 },
  );
}

export function mountAdminRoutes(app: Hono, opts: MountAdminRoutesOptions): void {
  const auth = adminAuth({ service: opts.service, requireScope: 'admin' });
  app.use('/admin/*', auth);

  // Workspaces
  app.post('/admin/workspaces', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = CreateWorkspaceSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const w = await opts.service.workspaces.create(ctxFromHono(c), parsed.data);
      return c.json(workspaceJson(w), 201);
    } catch (err) {
      return handleError(err);
    }
  });

  app.get('/admin/workspaces', async (c) => {
    const list = await opts.service.workspaces.list(ctxFromHono(c));
    return c.json(list.map(workspaceJson));
  });

  app.get('/admin/workspaces/:id', async (c) => {
    try {
      const w = await opts.service.workspaces.get(ctxFromHono(c), c.req.param('id'));
      return c.json(workspaceJson(w));
    } catch (err) {
      return handleError(err);
    }
  });

  app.patch('/admin/workspaces/:id', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = UpdateWorkspaceSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const w = await opts.service.workspaces.update(
        ctxFromHono(c),
        c.req.param('id'),
        parsed.data,
      );
      return c.json(workspaceJson(w));
    } catch (err) {
      return handleError(err);
    }
  });

  app.delete('/admin/workspaces/:id', async (c) => {
    try {
      await opts.service.workspaces.delete(ctxFromHono(c), c.req.param('id'));
      return c.body(null, 204);
    } catch (err) {
      return handleError(err);
    }
  });

  // Apps
  app.post('/admin/workspaces/:wsId/apps', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = CreateAppSchema.safeParse({ ...json, workspaceId: c.req.param('wsId') });
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const version = opts.activeMasterKeyVersion();
      const masterKey = await opts.masterKeyProvider.getKeyBytes(version);
      const result = await opts.service.apps.create(ctxFromHono(c), {
        workspaceId: parsed.data.workspaceId,
        appIdToss: parsed.data.appIdToss,
        displayTitle: parsed.data.displayTitle,
        mtlsCert: Buffer.from(parsed.data.mtlsCertPem, 'utf8'),
        mtlsKey: Buffer.from(parsed.data.mtlsKeyPem, 'utf8'),
        allowedOrigins: parsed.data.allowedOrigins,
        sealingKeyVersion: version,
        masterKey,
        stage: opts.stage(),
      });
      return c.json(
        {
          app: appJson(result.app),
          clientId: result.clientId,
          clientSecret: result.clientSecret,
        },
        201,
      );
    } catch (err) {
      return handleError(err);
    }
  });

  app.get('/admin/workspaces/:wsId/apps', async (c) => {
    try {
      const list = await opts.service.apps.list(ctxFromHono(c), c.req.param('wsId'));
      return c.json(list.map(appJson));
    } catch (err) {
      return handleError(err);
    }
  });

  app.get('/admin/apps/:id', async (c) => {
    try {
      const a = await opts.service.apps.get(ctxFromHono(c), c.req.param('id'));
      return c.json(appJson(a));
    } catch (err) {
      return handleError(err);
    }
  });

  app.patch('/admin/apps/:id', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = UpdateAppSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const a = await opts.service.apps.update(ctxFromHono(c), c.req.param('id'), parsed.data);
      return c.json(appJson(a));
    } catch (err) {
      return handleError(err);
    }
  });

  app.delete('/admin/apps/:id', async (c) => {
    try {
      await opts.service.apps.delete(ctxFromHono(c), c.req.param('id'));
      return c.body(null, 204);
    } catch (err) {
      return handleError(err);
    }
  });

  app.post('/admin/apps/:id/secrets/rotate', async (c) => {
    try {
      const r = await opts.service.apps.rotateSecret(ctxFromHono(c), c.req.param('id'));
      return c.json({ app: appJson(r.app), clientSecret: r.clientSecret });
    } catch (err) {
      return handleError(err);
    }
  });

  app.post('/admin/apps/:id/raw-tokens', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = ToggleRawTokensSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const a = await opts.service.apps.toggleRawTokens(
        ctxFromHono(c),
        c.req.param('id'),
        parsed.data.enabled,
      );
      return c.json(appJson(a));
    } catch (err) {
      return handleError(err);
    }
  });

  // Api tokens
  app.post('/admin/api-tokens', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = CreateApiTokenSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const r = await opts.service.apiTokens.create(ctxFromHono(c), parsed.data);
      return c.json({ token: apiTokenJson(r.token), plaintext: r.plaintext }, 201);
    } catch (err) {
      return handleError(err);
    }
  });

  app.get('/admin/api-tokens', async (c) => {
    const list = await opts.service.apiTokens.list(ctxFromHono(c));
    return c.json(list.map(apiTokenJson));
  });

  app.delete('/admin/api-tokens/:id', async (c) => {
    try {
      await opts.service.apiTokens.delete(ctxFromHono(c), c.req.param('id'));
      return c.body(null, 204);
    } catch (err) {
      return handleError(err);
    }
  });
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/apps/routes.test.ts
```

Expected: PASS (7/7 from this Task — apps tests come in Task 12).

- [ ] **Step 5: Commit**

```bash
git add src/apps/routes.ts src/apps/routes.test.ts
git commit -m "feat(apps): admin routes for workspaces + api_tokens"
```

---

## Task 12: Admin REST tests for apps

Append to `src/apps/routes.test.ts`. The cert/key are arbitrary placeholder strings — encryption is exercised, not real mTLS handshake.

**Files:**
- Modify: `src/apps/routes.test.ts`

- [ ] **Step 1: Append**

```ts
describe('admin routes — apps', () => {
  async function bootstrap(app: Awaited<ReturnType<typeof makeApp>>) {
    const wsRes = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'ws' }),
    });
    return (await wsRes.json()).id as string;
  }

  it('POST /admin/workspaces/:wsId/apps creates and returns plaintext secret once', async () => {
    const app = await makeApp();
    const wsId = await bootstrap(app);
    const res = await app.request(`/admin/workspaces/${wsId}/apps`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({
        appIdToss: 'mini-1',
        displayTitle: 'My App',
        mtlsCertPem: '-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----',
        mtlsKeyPem: '-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----',
        allowedOrigins: ['https://app.example.com'],
      }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.clientSecret).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(body.app.mtlsPresent).toBe(true);
    expect(body.app.ownershipStatus).toBe('verified');
  });

  it('GET /admin/apps/:id never returns mTLS bytes', async () => {
    const app = await makeApp();
    const wsId = await bootstrap(app);
    const create = await app.request(`/admin/workspaces/${wsId}/apps`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({
        appIdToss: 'mini-2',
        displayTitle: 'X',
        mtlsCertPem: 'cert',
        mtlsKeyPem: 'key',
        allowedOrigins: [],
      }),
    });
    const id = (await create.json()).app.id;
    const res = await app.request(`/admin/apps/${id}`, { headers: auth() });
    const body = await res.json();
    expect(body.mtlsPresent).toBe(true);
    expect(body.mtlsCertEnc).toBeUndefined();
    expect(body.mtlsKeyEnc).toBeUndefined();
    expect(body.mtls_cert_enc).toBeUndefined();
    expect(body.mtls_key_enc).toBeUndefined();
  });

  it('POST /admin/apps/:id/secrets/rotate returns a new plaintext', async () => {
    const app = await makeApp();
    const wsId = await bootstrap(app);
    const create = await app.request(`/admin/workspaces/${wsId}/apps`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({
        appIdToss: 'mini-3',
        displayTitle: 'X',
        mtlsCertPem: 'c',
        mtlsKeyPem: 'k',
        allowedOrigins: [],
      }),
    });
    const id = (await create.json()).app.id;
    const res = await app.request(`/admin/apps/${id}/secrets/rotate`, {
      method: 'POST',
      headers: auth(),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.clientSecret).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('POST /admin/apps/:id/raw-tokens flips the toggle', async () => {
    const app = await makeApp();
    const wsId = await bootstrap(app);
    const create = await app.request(`/admin/workspaces/${wsId}/apps`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({
        appIdToss: 'mini-4',
        displayTitle: 'X',
        mtlsCertPem: 'c',
        mtlsKeyPem: 'k',
        allowedOrigins: [],
      }),
    });
    const id = (await create.json()).app.id;
    const res = await app.request(`/admin/apps/${id}/raw-tokens`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ enabled: true }),
    });
    const body = await res.json();
    expect(body.rawTokensEnabled).toBe(true);
  });
});
```

- [ ] **Step 2: Confirm green**

```bash
pnpm test src/apps/routes.test.ts
```

Expected: PASS (11/11).

- [ ] **Step 3: Commit**

```bash
git add src/apps/routes.test.ts
git commit -m "test(apps): admin routes coverage for apps endpoints"
```

---

## Task 13: Wire admin routes into `app.ts`

`createApp` becomes parametrized: it accepts an optional `admin` block and mounts admin routes only when supplied. Tests in earlier phases (Phase 0's `/healthz` test) keep working because the parameter is optional.

**Files:**
- Modify: `src/app.ts`
- Modify: `src/app.test.ts`

- [ ] **Step 1: Update `src/app.ts`**

```ts
import { Hono } from 'hono';
import { mountAdminRoutes, type MountAdminRoutesOptions } from './apps/routes.js';

export interface CreateAppOptions {
  admin?: MountAdminRoutesOptions;
}

export function createApp(opts: CreateAppOptions = {}): Hono {
  const app = new Hono();
  app.get('/healthz', (c) => c.json({ status: 'ok' }));
  if (opts.admin) {
    mountAdminRoutes(app, opts.admin);
  }
  return app;
}
```

- [ ] **Step 2: Confirm existing app tests still pass**

```bash
pnpm test src/app.test.ts
```

Expected: PASS — no admin block was passed, so `/healthz` is the only mounted route, and the legacy-`/verify`-404 test still passes.

- [ ] **Step 3: Add an integration test that admin routes mount**

Append to `src/app.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach } from 'vitest';
import { createService } from './apps/service.js';
import { createSqliteStorage } from './storage/sqlite.js';
import type { Storage } from './storage/interface.js';

describe('createApp with admin', () => {
  let dir: string;
  let storage: Storage;
  let token: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-app-admin-'));
    storage = createSqliteStorage({ path: join(dir, 'test.db') });
    await storage.createUser({ id: 'user_a', email: 'a@x.com' });
    const svc = createService({ storage });
    token = (await svc.apiTokens.create({ actorUserId: 'user_a' }, { name: 'cli', scopes: ['admin'] }))
      .plaintext;
  });

  afterEach(async () => {
    await storage.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('mounts /admin/workspaces when admin opts are provided', async () => {
    const svc = createService({ storage });
    const app = createApp({
      admin: {
        service: svc,
        masterKeyProvider: {
          async getKeyBytes() {
            return Buffer.alloc(32, 0xab);
          },
          async listVersions() {
            return [1];
          },
        },
        activeMasterKeyVersion: () => 1,
        stage: () => 'alpha',
      },
    });
    const res = await app.request('/admin/workspaces', {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });

  it('does not mount /admin/* without admin opts', async () => {
    const app = createApp();
    const res = await app.request('/admin/workspaces');
    expect(res.status).toBe(404);
  });
});
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test
```

Expected: every previous test still passes, plus the two new ones.

- [ ] **Step 5: Commit**

```bash
git add src/app.ts src/app.test.ts
git commit -m "feat(app): mount admin routes when admin options are provided"
```

---

## Task 14: CLI shared options + commander entrypoint

The CLI runs in two modes:

- **Offline** (`--db-path …`): opens a SQLite DB directly via the service layer. Used during bootstrap and self-host first-time setup.
- **Online** (`--api-url …` + `--token …`): hits the REST API. Same surface, different transport.

Phase 7 will wire `bootstrap` and `doctor` end-to-end. This phase only adds the basic CRUD commands.

**Files:**
- Create: `cli/index.ts`
- Create: `cli/api-client.ts`
- Create: `cli/api-client.test.ts`
- Create: `cli/commands/_shared.ts`
- Create: `cli/commands/workspace.ts`
- Create: `cli/commands/app.ts`
- Create: `cli/commands/api-token.ts`

- [ ] **Step 1: Implement `cli/api-client.ts`**

```ts
export interface ApiClient {
  request<T>(method: string, path: string, body?: unknown): Promise<T>;
}

export interface ApiClientOptions {
  baseUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
}

export function createApiClient(opts: ApiClientOptions): ApiClient {
  const fetchImpl = opts.fetchImpl ?? fetch;
  return {
    async request(method, path, body) {
      const res = await fetchImpl(`${opts.baseUrl.replace(/\/$/, '')}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${opts.token}`,
          'content-type': 'application/json',
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
      if (!res.ok && res.status !== 204) {
        const text = await res.text().catch(() => '');
        throw new Error(`api ${method} ${path} → ${res.status}: ${text}`);
      }
      if (res.status === 204) return undefined as never;
      return (await res.json()) as never;
    },
  };
}
```

- [ ] **Step 2: Implement `cli/api-client.test.ts`**

```ts
import { describe, expect, it, vi } from 'vitest';
import { createApiClient } from './api-client.js';

describe('createApiClient', () => {
  it('sends bearer + content-type and parses JSON', async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const c = createApiClient({ baseUrl: 'http://x', token: 'tok_x', fetchImpl });
    const out = await c.request<{ ok: boolean }>('GET', '/admin/workspaces');
    expect(out).toEqual({ ok: true });
    const headers = fetchImpl.mock.calls[0]![1]?.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer tok_x');
    expect(headers['content-type']).toBe('application/json');
  });

  it('throws on non-2xx', async () => {
    const fetchImpl = vi.fn(async () =>
      new Response('err', { status: 404 }),
    );
    const c = createApiClient({ baseUrl: 'http://x', token: 't', fetchImpl });
    await expect(c.request('GET', '/x')).rejects.toThrow(/404/);
  });

  it('returns undefined on 204', async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(null, { status: 204 }),
    );
    const c = createApiClient({ baseUrl: 'http://x', token: 't', fetchImpl });
    expect(await c.request('DELETE', '/x')).toBeUndefined();
  });
});
```

- [ ] **Step 3: Implement `cli/commands/_shared.ts`**

```ts
import { createService, type Service, type ServiceCtx } from '../../src/apps/service.js';
import { createSqliteStorage } from '../../src/storage/sqlite.js';
import type { Storage } from '../../src/storage/interface.js';
import { createApiClient, type ApiClient } from '../api-client.js';

export interface ConnectionOptions {
  apiUrl?: string;
  token?: string;
  dbPath?: string;
  asUser?: string;
}

export interface OnlineConnection {
  mode: 'online';
  client: ApiClient;
}

export interface OfflineConnection {
  mode: 'offline';
  service: Service;
  storage: Storage;
  ctx: ServiceCtx;
}

export type Connection = OnlineConnection | OfflineConnection;

export function connect(opts: ConnectionOptions): Connection {
  if (opts.dbPath) {
    const storage = createSqliteStorage({ path: opts.dbPath });
    const service = createService({ storage });
    if (!opts.asUser) {
      throw new Error('offline mode requires --as-user (the user_… id to act as)');
    }
    return { mode: 'offline', storage, service, ctx: { actorUserId: opts.asUser } };
  }
  if (!opts.apiUrl || !opts.token) {
    throw new Error('online mode requires --api-url and --token (or set --db-path for offline)');
  }
  return { mode: 'online', client: createApiClient({ baseUrl: opts.apiUrl, token: opts.token }) };
}

export async function close(c: Connection): Promise<void> {
  if (c.mode === 'offline') await c.storage.close();
}
```

- [ ] **Step 4: Implement `cli/commands/workspace.ts`**

```ts
import { Command } from 'commander';
import { close, connect, type ConnectionOptions } from './_shared.js';

interface WorkspaceJson {
  id: string;
  name: string;
}

export function workspaceCommand(): Command {
  const cmd = new Command('workspace').description('manage workspaces');

  cmd
    .command('list')
    .description('list workspaces')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions) => {
      const c = connect(opts);
      try {
        const list =
          c.mode === 'offline'
            ? await c.service.workspaces.list(c.ctx)
            : await c.client.request<WorkspaceJson[]>('GET', '/admin/workspaces');
        for (const w of list) {
          console.log(`${w.id}\t${w.name}`);
        }
      } finally {
        await close(c);
      }
    });

  cmd
    .command('create')
    .description('create a workspace')
    .requiredOption('--name <name>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { name: string }) => {
      const c = connect(opts);
      try {
        const w =
          c.mode === 'offline'
            ? await c.service.workspaces.create(c.ctx, { name: opts.name })
            : await c.client.request<WorkspaceJson>('POST', '/admin/workspaces', {
                name: opts.name,
              });
        console.log(`${w.id}\t${w.name}`);
      } finally {
        await close(c);
      }
    });

  cmd
    .command('rename')
    .description('rename a workspace')
    .requiredOption('--id <id>')
    .requiredOption('--name <name>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string; name: string }) => {
      const c = connect(opts);
      try {
        const w =
          c.mode === 'offline'
            ? await c.service.workspaces.update(c.ctx, opts.id, { name: opts.name })
            : await c.client.request<WorkspaceJson>('PATCH', `/admin/workspaces/${opts.id}`, {
                name: opts.name,
              });
        console.log(`${w.id}\t${w.name}`);
      } finally {
        await close(c);
      }
    });

  cmd
    .command('delete')
    .description('delete a workspace')
    .requiredOption('--id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string }) => {
      const c = connect(opts);
      try {
        if (c.mode === 'offline') {
          await c.service.workspaces.delete(c.ctx, opts.id);
        } else {
          await c.client.request('DELETE', `/admin/workspaces/${opts.id}`);
        }
        console.log(`deleted ${opts.id}`);
      } finally {
        await close(c);
      }
    });

  return cmd;
}
```

- [ ] **Step 5: Implement `cli/commands/app.ts`**

```ts
import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import { close, connect, type ConnectionOptions } from './_shared.js';
import { createMasterKeyProvider } from '../../src/master-keys/index.js';

interface AppJson {
  id: string;
  appIdToss: string;
  displayTitle: string;
  clientId: string;
  ownershipStatus: string;
  rawTokensEnabled: boolean;
}
interface CreateAppResponse {
  app: AppJson;
  clientId: string;
  clientSecret: string;
}

export function appCommand(): Command {
  const cmd = new Command('app').description('manage apps');

  cmd
    .command('create')
    .description('create an app')
    .requiredOption('--workspace-id <id>')
    .requiredOption('--app-id-toss <id>', 'the Toss mini-app ID')
    .requiredOption('--title <title>')
    .requiredOption('--cert <path>', 'path to mTLS certificate PEM')
    .requiredOption('--key <path>', 'path to mTLS private key PEM')
    .option('--allowed-origin <url...>', 'allowed origin (repeatable)', [])
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .option('--master-key-version <n>', 'sealing key version for offline mode', '1')
    .option('--stage <stage>', 'alpha|beta|ga', 'alpha')
    .action(
      async (
        opts: ConnectionOptions & {
          workspaceId: string;
          appIdToss: string;
          title: string;
          cert: string;
          key: string;
          allowedOrigin: string[];
          masterKeyVersion: string;
          stage: string;
        },
      ) => {
        const certPem = readFileSync(opts.cert, 'utf8');
        const keyPem = readFileSync(opts.key, 'utf8');
        const c = connect(opts);
        try {
          if (c.mode === 'offline') {
            const provider = createMasterKeyProvider();
            const version = Number(opts.masterKeyVersion);
            const masterKey = await provider.getKeyBytes(version);
            const r = await c.service.apps.create(c.ctx, {
              workspaceId: opts.workspaceId,
              appIdToss: opts.appIdToss,
              displayTitle: opts.title,
              mtlsCert: Buffer.from(certPem, 'utf8'),
              mtlsKey: Buffer.from(keyPem, 'utf8'),
              allowedOrigins: opts.allowedOrigin,
              sealingKeyVersion: version,
              masterKey,
              stage: opts.stage as 'alpha' | 'beta' | 'ga',
            });
            console.log(`${r.app.id}\t${r.clientId}`);
            console.log(`client_secret: ${r.clientSecret}`);
            console.log('(this is the only time the plaintext secret will be shown)');
          } else {
            const r = await c.client.request<CreateAppResponse>(
              'POST',
              `/admin/workspaces/${opts.workspaceId}/apps`,
              {
                appIdToss: opts.appIdToss,
                displayTitle: opts.title,
                mtlsCertPem: certPem,
                mtlsKeyPem: keyPem,
                allowedOrigins: opts.allowedOrigin,
              },
            );
            console.log(`${r.app.id}\t${r.clientId}`);
            console.log(`client_secret: ${r.clientSecret}`);
            console.log('(this is the only time the plaintext secret will be shown)');
          }
        } finally {
          await close(c);
        }
      },
    );

  cmd
    .command('list')
    .description('list apps in a workspace')
    .requiredOption('--workspace-id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { workspaceId: string }) => {
      const c = connect(opts);
      try {
        const list =
          c.mode === 'offline'
            ? await c.service.apps.list(c.ctx, opts.workspaceId)
            : await c.client.request<AppJson[]>(
                'GET',
                `/admin/workspaces/${opts.workspaceId}/apps`,
              );
        for (const a of list) {
          console.log(`${a.id}\t${a.appIdToss}\t${a.displayTitle}\t${a.ownershipStatus}`);
        }
      } finally {
        await close(c);
      }
    });

  cmd
    .command('rotate-secret')
    .description("rotate an app's client_secret")
    .requiredOption('--id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string }) => {
      const c = connect(opts);
      try {
        const r =
          c.mode === 'offline'
            ? await c.service.apps.rotateSecret(c.ctx, opts.id)
            : await c.client.request<{ app: AppJson; clientSecret: string }>(
                'POST',
                `/admin/apps/${opts.id}/secrets/rotate`,
              );
        console.log(`client_secret: ${r.clientSecret}`);
        console.log('(this is the only time the plaintext secret will be shown)');
      } finally {
        await close(c);
      }
    });

  cmd
    .command('toggle-raw-tokens')
    .description('enable or disable raw-tokens endpoint for an app')
    .requiredOption('--id <id>')
    .requiredOption('--enabled <bool>', 'true|false')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string; enabled: string }) => {
      const enabled = opts.enabled === 'true';
      const c = connect(opts);
      try {
        const a =
          c.mode === 'offline'
            ? await c.service.apps.toggleRawTokens(c.ctx, opts.id, enabled)
            : await c.client.request<AppJson>('POST', `/admin/apps/${opts.id}/raw-tokens`, {
                enabled,
              });
        console.log(`raw_tokens_enabled = ${a.rawTokensEnabled}`);
      } finally {
        await close(c);
      }
    });

  cmd
    .command('delete')
    .description('delete an app')
    .requiredOption('--id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string }) => {
      const c = connect(opts);
      try {
        if (c.mode === 'offline') await c.service.apps.delete(c.ctx, opts.id);
        else await c.client.request('DELETE', `/admin/apps/${opts.id}`);
        console.log(`deleted ${opts.id}`);
      } finally {
        await close(c);
      }
    });

  return cmd;
}
```

- [ ] **Step 6: Implement `cli/commands/api-token.ts`**

```ts
import { Command } from 'commander';
import { close, connect, type ConnectionOptions } from './_shared.js';

interface ApiTokenJson {
  id: string;
  name: string;
  scopes: string[];
}

export function apiTokenCommand(): Command {
  const cmd = new Command('api-token').description('manage api tokens');

  cmd
    .command('create')
    .description('create an api token')
    .requiredOption('--name <name>')
    .option('--scope <scope...>', 'scope (repeatable)', [])
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(
      async (opts: ConnectionOptions & { name: string; scope: string[] }) => {
        const c = connect(opts);
        try {
          if (c.mode === 'offline') {
            const r = await c.service.apiTokens.create(c.ctx, {
              name: opts.name,
              scopes: opts.scope,
            });
            console.log(`${r.token.id}\t${r.token.name}`);
            console.log(`token: ${r.plaintext}`);
            console.log('(this is the only time the plaintext token will be shown)');
          } else {
            const r = await c.client.request<{ token: ApiTokenJson; plaintext: string }>(
              'POST',
              '/admin/api-tokens',
              { name: opts.name, scopes: opts.scope },
            );
            console.log(`${r.token.id}\t${r.token.name}`);
            console.log(`token: ${r.plaintext}`);
            console.log('(this is the only time the plaintext token will be shown)');
          }
        } finally {
          await close(c);
        }
      },
    );

  cmd
    .command('list')
    .description('list api tokens')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions) => {
      const c = connect(opts);
      try {
        const list =
          c.mode === 'offline'
            ? await c.service.apiTokens.list(c.ctx)
            : await c.client.request<ApiTokenJson[]>('GET', '/admin/api-tokens');
        for (const t of list) {
          console.log(`${t.id}\t${t.name}\t${t.scopes.join(',')}`);
        }
      } finally {
        await close(c);
      }
    });

  cmd
    .command('delete')
    .description('delete an api token')
    .requiredOption('--id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string }) => {
      const c = connect(opts);
      try {
        if (c.mode === 'offline') await c.service.apiTokens.delete(c.ctx, opts.id);
        else await c.client.request('DELETE', `/admin/api-tokens/${opts.id}`);
        console.log(`deleted ${opts.id}`);
      } finally {
        await close(c);
      }
    });

  return cmd;
}
```

- [ ] **Step 7: Implement `cli/index.ts`**

```ts
#!/usr/bin/env node
import { Command } from 'commander';
import { apiTokenCommand } from './commands/api-token.js';
import { appCommand } from './commands/app.js';
import { workspaceCommand } from './commands/workspace.js';

const program = new Command()
  .name('oidc-bridge')
  .description('oidc-bridge admin CLI')
  .version('0.0.0');

program.addCommand(workspaceCommand());
program.addCommand(appCommand());
program.addCommand(apiTokenCommand());

program.parseAsync(process.argv).catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
```

- [ ] **Step 8: Make CLI buildable**

Update `package.json` `scripts.build` to also bundle the CLI:

```json
"build": "tsdown src/server.ts cli/index.ts --format esm",
"build:server": "tsdown src/server.ts --format esm",
"build:cli": "tsdown cli/index.ts --format esm",
```

And add a `bin` entry so `pnpm link` exposes the binary:

```json
"bin": {
  "oidc-bridge": "./dist/index.mjs"
}
```

- [ ] **Step 9: Run lint + typecheck + build + test**

```bash
pnpm lint && pnpm typecheck && pnpm build && pnpm test
```

Expected: green. `dist/server.mjs` and `dist/index.mjs` both exist.

- [ ] **Step 10: Smoke-test `--help`**

```bash
node dist/index.mjs --help
node dist/index.mjs workspace --help
node dist/index.mjs app create --help
```

Expected: each prints usage.

- [ ] **Step 11: Commit**

```bash
git add cli/ package.json
git commit -m "feat(cli): commander CLI with workspace/app/api-token commands (offline + online modes)"
```

---

## Task 15: Final phase-end verification

- [ ] **Step 1: Full local pipeline**

```bash
pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm build && pnpm test
```

Expected: green. Test count grows by ~50.

- [ ] **Step 2: Manual end-to-end via offline CLI**

```bash
TMPDIR_E2E=$(mktemp -d)
TMPDIR_KEY=$(mktemp -d)
# Make a master key for offline mode.
node -e "require('node:fs').writeFileSync('$TMPDIR_KEY/v1.key', require('node:crypto').randomBytes(32), { mode: 0o600 })"
export MASTER_KEY_PROVIDER=file MASTER_KEY_DIR="$TMPDIR_KEY"

DB_PATH="$TMPDIR_E2E/zerocode.db"

# Bootstrap a user directly via Node, since the bootstrap CLI command lands in Phase 7.
node -e "
  const { createSqliteStorage } = require('./dist/index.mjs');
  // Phase 7 will replace this with a real bootstrap command.
" || echo "(skipped — wait for Phase 7 bootstrap command)"

# Cleanup
rm -rf "$TMPDIR_E2E" "$TMPDIR_KEY"
unset MASTER_KEY_PROVIDER MASTER_KEY_DIR
```

Note: Phase 7 introduces the `bootstrap` command that creates the first user + api token + workspace in one shot. Until then, full CLI E2E requires manually inserting a user via Node — exercised by the test suite, not by hand.

- [ ] **Step 3: Verify spec invariants**

```bash
git grep -nE 'mtlsCertEnc|mtlsKeyEnc' src/apps/routes.ts
```

Expected: only inside `appJson()` — no mtlsCertEnc or mtlsKeyEnc field is included in the JSON response. The test in Task 12 enforces this.

```bash
git grep -nE 'console\.log\(.*client_secret|console\.log\(.*plaintext' src/
```

Expected: empty output. Plaintext secrets are returned in the HTTP response body (or printed by the CLI to stdout, intentionally) but never logged via the structured logger.

---

## Phase 2 — done condition

After Task 15:

- `Storage` interface is fully implemented and tested for both pg + sqlite drivers.
- Service layer covers workspaces, apps, and api_tokens with audit log entries on every mutation.
- Admin REST surface mounts under `/admin/*` with API_TOKEN bearer auth.
- mTLS material is encrypted with per-app sealing key + AAD; never returned by GET.
- `client_secret` is bcrypt-hashed; rotation overlap supported; plaintext shown once.
- CLI offers offline + online modes; `--help` smoke passes.
- `pnpm lint && pnpm typecheck && pnpm build && pnpm test` is green.

That state is the foundation Phase 3 (OIDC token endpoint, public client only, against a mocked Toss adapter) builds on.
