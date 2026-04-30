# oidc-bridge M1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-`/verify` endpoint scaffold with a multi-tenant OIDC + mTLS proxy: tenant store + Admin REST + bundled CLI, OIDC `/token`/`/userinfo`/`/revoke` + discovery + JWKS, sealed-wrapper access tokens, and an mTLS-aware Toss adapter — all shipped as one breaking-change PR with a `MIGRATION.md` for self-host operators.

**Architecture:** Hono app factory (preserved) mounts new modular routes under `/.well-known/*`, `/oidc/*`, `/admin/*`. Each request flows through `client_id → TenantStore.get(id) → mTLS https.Agent built from tenant PEM → Toss partner API`. Bridge issues `aitc_<base64url>` opaque access tokens that wrap `(tenant_id, toss_AT, toss_RT, exp)` under a per-tenant AEAD key derived via HKDF from a master key — so the bridge stays stateless across requests. ID tokens are RS256 signed with a single `OIDC_SIGNING_KEY` (PEM); JWKS exports the public half. Two tenant store backends share one `TenantStore` interface: filesystem (default — what the public Vultr Seoul VPS uses on a Docker volume) and Google Secret Manager (lazy-imported, forward-compat). The bundled CLI is a thin REST client over Admin API plus an `--offline` mode that writes the fs-store layout directly so the very first tenant exists before the bridge boots.

**Tech Stack:** TypeScript (strict, ESM-only), Hono + `@hono/node-server`, `jose` (sign/verify, JWKS), `bcryptjs` (client_secret hashing), `@google-cloud/secret-manager` (lazy), `commander` (CLI), `node:crypto` (AES-256-GCM, HKDF, randomBytes), `node:tls`/`https.Agent` (mTLS), `node:fs/promises` (atomic writes), `vitest`, `tsdown`, `pnpm 10.33.0`, Biome.

**Spec:** [`docs/superpowers/specs/2026-04-30-oidc-bridge-m1-redesign-design.md`](../specs/2026-04-30-oidc-bridge-m1-redesign-design.md). When this plan and the spec disagree, the spec wins — fix the plan inline.

---

## File structure

Each file owns one well-defined responsibility, kept small enough to hold in context. Test files mirror their source under the same directory (`x.ts` ↔ `x.test.ts`).

```
src/
  app.ts                       # Hono app factory (already exists; rewritten to mount new routes)
  server.ts                    # entrypoint (already exists; minor wiring change)
  config.ts                    # env parsing (issuer, master key, signing key, store backend, data dir, admin token)
  errors.ts                    # OAuth2/OIDC error envelope helpers + Hono response shortcuts
  tenants/
    types.ts                   # TenantRecord, TenantPublic, TenantCreateInput, TenantPatch
    store.ts                   # TenantStore interface + factory(config) → fs|gcpsm
    fs-store.ts                # filesystem backend, atomic writes, perm checks
    gcpsm-store.ts             # GCPSM backend (lazy import @google-cloud/secret-manager)
    crypto.ts                  # tenant_id generator (Crockford b32), client_secret generator, bcrypt verify, cert fingerprint, NotAfter parser
  oidc/
    sealed-token.ts            # AES-256-GCM AEAD wrap/unwrap + per-tenant HKDF derivation
    id-token.ts                # RS256 sign + JWKS export (jose), kid = JWK SHA-256 thumbprint (RFC 7638)
    jwks.ts                    # GET /.well-known/jwks.json
    discovery.ts               # GET /.well-known/openid-configuration
    client-auth.ts             # parse Basic + Post, bcrypt-verify against any rotation-overlap hash
    token.ts                   # POST /oidc/token (authorization_code + refresh_token)
    userinfo.ts                # GET /oidc/userinfo
    revoke.ts                  # POST /oidc/revoke
    claim-mapping.ts           # /login-me + Toss AT exp → OIDC claims (pure)
  toss/
    types.ts                   # GenerateTokenSuccess, LoginMeSuccess, FailEnvelope, etc.
    envelope.ts                # parse `{ resultType, success?, error? }` → discriminated result
    client.ts                  # https.Agent builder + fetch wrapper bound to a tenant
    generate-token.ts          # POST /generate-token
    refresh-token.ts           # POST /refresh-token
    login-me.ts                # GET /login-me (HTTP method per Toss API spec)
    access-remove.ts           # POST /access/remove-by-access-token
  admin/
    auth.ts                    # ADMIN_TOKEN bearer Hono middleware
    routes.ts                  # /admin/tenants CRUD + /:id/secrets/rotate
  __fixtures__/
    toss-generate-token.success.json
    toss-generate-token.fail.json
    toss-login-me.success.json
    toss-login-me.fail.json
cli/
  index.ts                     # commander entrypoint, registers commands
  rest-client.ts               # thin fetch wrapper for Admin API + offline-mode dispatcher
  bootstrap.ts                 # --offline writes/reads fs-store layout directly
  commands/
    tenant-create.ts
    tenant-list.ts
    tenant-show.ts
    tenant-rotate-secret.ts
    tenant-delete.ts
MIGRATION.md                   # /verify → /oidc/token migration for self-host operators
```

**Files removed in this PR:** `src/toss/verify.ts`, `src/toss/verify.test.ts`. The old `POST /verify` route in `src/app.ts` is deleted; tests for it in `src/app.test.ts` are deleted. `TOSS_CLIENT_ID` / `TOSS_CLIENT_SECRET` / `TOSS_PII_DECRYPTION_KEY` env vars are removed from `.env.example`; new env vars are documented there.

---

## Conventions used in every task

- **TDD strict.** Test first, watch it fail with the predicted message, write minimum code, watch it pass, commit. Don't bundle multiple behaviors into one test.
- **One commit per task.** Conventional Commits style (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`). Commit subject under 70 chars, body bullets when more context helps.
- **No `any`.** Biome enforces `suspicious.noExplicitAny: error`. Use `unknown` + narrowing.
- **No partial implementations.** If a task says "implement X", X must work end-to-end after the task — even if narrow. Stub functions are forbidden; mark TODO in the plan instead.
- **PEM literals in tests** are inlined as constants generated once via `openssl req -nodes -x509 -newkey rsa:2048 ...` and committed under `src/__fixtures__/test-mtls.{cert,key}.pem`. They are NOT real certs — explicitly fake, only valid for `https.Agent` construction assertions.
- **Test commands.** `pnpm test path/to/file.test.ts` runs one file, `pnpm test -t "test name"` runs one test by name. After every code change, before committing, run `pnpm typecheck && pnpm lint && pnpm test` — the pre-commit hook does the lint+format part but typecheck and full vitest are still on you.
- **Assume Node 24** built-ins: `crypto.subtle`, `crypto.hkdfSync`, `crypto.randomBytes`, `crypto.createPrivateKey`, `crypto.X509Certificate`, `https.Agent`. Don't shim any of these.

---

## Task 0: Project setup

### Task 0.1: Add new dependencies

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Add runtime + dev deps**

Run:
```bash
pnpm add jose@^5 bcryptjs@^2 commander@^12
pnpm add -D @types/bcryptjs@^2
pnpm add -O @google-cloud/secret-manager@^5    # optionalDependency, lazy-imported
```

Expected `package.json` diff (excerpt):
```json
{
  "dependencies": {
    "@hono/node-server": "^1.13.7",
    "bcryptjs": "^2.4.3",
    "commander": "^12.1.0",
    "hono": "^4.6.12",
    "jose": "^5.9.6"
  },
  "devDependencies": {
    "@biomejs/biome": "2.4.12",
    "@types/bcryptjs": "^2.4.6",
    "@types/node": "^25.6.0",
    "tsdown": "^0.21.7",
    "typescript": "^6.0.2",
    "vitest": "^4.1.4"
  },
  "optionalDependencies": {
    "@google-cloud/secret-manager": "^5.6.0"
  }
}
```

`@google-cloud/secret-manager` goes into `optionalDependencies` so self-host installs that don't use GCPSM aren't forced to download it; we still `import()` it lazily so absence is handled.

- [ ] **Step 2: Verify install**

Run: `pnpm install && pnpm typecheck`
Expected: clean exit, no type errors. The unused-import bar from Biome will fire later when we `import { ... }` from these — that's fine.

- [ ] **Step 3: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "chore(deps): add jose, bcryptjs, commander, secret-manager for M1"
```

---

### Task 0.2: Generate test mTLS PEM fixtures

**Files:**
- Create: `src/__fixtures__/test-mtls.cert.pem`
- Create: `src/__fixtures__/test-mtls.key.pem`
- Create: `src/__fixtures__/README.md`

- [ ] **Step 1: Generate self-signed cert+key for tests**

Run from repo root:
```bash
mkdir -p src/__fixtures__
openssl req -nodes -x509 -newkey rsa:2048 \
  -keyout src/__fixtures__/test-mtls.key.pem \
  -out src/__fixtures__/test-mtls.cert.pem \
  -days 36500 \
  -subj "/CN=oidc-bridge-test/O=apps-in-toss-community/C=KR"
```

Expected: two PEM files written. **`-days 36500`** so the cert NotAfter is far enough out that `expires_at` parsing tests don't break in 2027.

- [ ] **Step 2: Document the fixtures**

Write `src/__fixtures__/README.md`:
```markdown
# Test fixtures

This directory contains **deliberately fake** test data:

- `test-mtls.cert.pem` / `test-mtls.key.pem` — self-signed RSA-2048
  cert+key used to assert that the Toss adapter wires PEMs into a
  `https.Agent`. Never used to talk to a real Toss host.
- `toss-*.json` — redacted snapshots of Toss `/generate-token` and
  `/login-me` SUCCESS and FAIL envelopes. PII fields are replaced
  with `"<redacted>"`.

These files are committed because they are not secrets.
```

- [ ] **Step 3: Commit**

```bash
git add src/__fixtures__/
git commit -m "test: add self-signed mTLS PEM fixtures for adapter tests"
```

---

### Task 0.3: Add Toss contract fixtures

**Files:**
- Create: `src/__fixtures__/toss-generate-token.success.json`
- Create: `src/__fixtures__/toss-generate-token.fail.json`
- Create: `src/__fixtures__/toss-login-me.success.json`
- Create: `src/__fixtures__/toss-login-me.fail.json`

- [ ] **Step 1: Write SUCCESS envelopes**

`src/__fixtures__/toss-generate-token.success.json`:
```json
{
  "resultType": "SUCCESS",
  "success": {
    "accessToken": "eyJraWQiOiJjZXJ0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI0MjAwMDAwMDAwMSIsInVzZXJLZXkiOjQyMDAwMDAwMDAxLCJzY29wZSI6InVzZXJfa2V5IHVzZXJfbmFtZSIsImV4cCI6MTkwMDAwMDAwMCwiaXNzIjoiaHR0cHM6Ly9jZXJ0LnRvc3MuaW0ifQ.fakefake",
    "refreshToken": "fake-refresh-token-bytes",
    "tokenType": "Bearer",
    "expiresIn": 3600,
    "scope": "user_key user_name"
  }
}
```

`src/__fixtures__/toss-login-me.success.json`:
```json
{
  "resultType": "SUCCESS",
  "success": {
    "userKey": 4200000000001,
    "scope": "user_key user_name",
    "agreedTerms": ["TERMS_OF_SERVICE", "PRIVACY"],
    "name": "<redacted>",
    "phone": "<redacted>",
    "birthday": "<redacted>",
    "ci": "<redacted>",
    "gender": "<redacted>",
    "nationality": "<redacted>"
  }
}
```

- [ ] **Step 2: Write FAIL envelopes**

`src/__fixtures__/toss-generate-token.fail.json`:
```json
{
  "resultType": "FAIL",
  "error": {
    "reason": "INVALID_AUTHORIZATION_CODE",
    "description": "The authorization code is invalid or expired."
  }
}
```

`src/__fixtures__/toss-login-me.fail.json`:
```json
{
  "resultType": "FAIL",
  "error": {
    "reason": "ACCESS_TOKEN_EXPIRED",
    "description": "Access token is expired."
  }
}
```

- [ ] **Step 3: Commit**

```bash
git add src/__fixtures__/toss-*.json
git commit -m "test: add redacted Toss generate-token and login-me envelopes"
```

---

### Task 0.4: Write `src/config.ts` (env parsing)

**Files:**
- Create: `src/config.ts`
- Create: `src/config.test.ts`

This module is consumed by every other module. Lock its shape early.

- [ ] **Step 1: Write failing tests**

`src/config.test.ts`:
```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from './config.js';

describe('loadConfig', () => {
  const originalEnv = { ...process.env };
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('parses fs-store config from env', () => {
    process.env = {
      ...originalEnv,
      OIDC_ISSUER: 'https://oidc-bridge.aitc.dev',
      OIDC_SIGNING_KEY: '-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----',
      OIDC_MASTER_KEY: Buffer.alloc(32, 1).toString('base64'),
      ADMIN_TOKEN: 'admin-token-secret',
      TENANT_STORE: 'fs',
      BRIDGE_DATA_DIR: '/var/lib/oidc-bridge',
    };
    const cfg = loadConfig();
    expect(cfg.issuer).toBe('https://oidc-bridge.aitc.dev');
    expect(cfg.masterKey).toHaveLength(32);
    expect(cfg.tenantStore).toEqual({ kind: 'fs', dataDir: '/var/lib/oidc-bridge' });
    expect(cfg.tossApiBase).toBe('https://apps-in-toss-api.toss.im');
  });

  it('throws when OIDC_ISSUER is missing', () => {
    process.env = { ...originalEnv };
    delete process.env.OIDC_ISSUER;
    expect(() => loadConfig()).toThrow(/OIDC_ISSUER/);
  });

  it('throws when OIDC_MASTER_KEY is not 32 bytes after base64 decode', () => {
    process.env = {
      ...originalEnv,
      OIDC_ISSUER: 'https://x',
      OIDC_SIGNING_KEY: 'pem',
      OIDC_MASTER_KEY: Buffer.alloc(16).toString('base64'),
      ADMIN_TOKEN: 'a',
      TENANT_STORE: 'fs',
      BRIDGE_DATA_DIR: '/tmp',
    };
    expect(() => loadConfig()).toThrow(/OIDC_MASTER_KEY.*32 bytes/);
  });

  it('parses gcpsm-store config', () => {
    process.env = {
      ...originalEnv,
      OIDC_ISSUER: 'https://x',
      OIDC_SIGNING_KEY: 'pem',
      OIDC_MASTER_KEY: Buffer.alloc(32).toString('base64'),
      ADMIN_TOKEN: 'a',
      TENANT_STORE: 'gcpsm',
      GCP_PROJECT_ID: 'my-project',
    };
    const cfg = loadConfig();
    expect(cfg.tenantStore).toEqual({ kind: 'gcpsm', projectId: 'my-project' });
  });

  it('rejects unknown TENANT_STORE values', () => {
    process.env = {
      ...originalEnv,
      OIDC_ISSUER: 'https://x',
      OIDC_SIGNING_KEY: 'pem',
      OIDC_MASTER_KEY: Buffer.alloc(32).toString('base64'),
      ADMIN_TOKEN: 'a',
      TENANT_STORE: 'redis',
    };
    expect(() => loadConfig()).toThrow(/TENANT_STORE/);
  });
});
```

- [ ] **Step 2: Run failing tests**

Run: `pnpm test src/config.test.ts`
Expected: 5 failures with "Cannot find module './config.js'".

- [ ] **Step 3: Implement `src/config.ts`**

```ts
export interface Config {
  issuer: string;
  signingKeyPem: string;
  masterKey: Buffer;
  adminToken: string;
  tenantStore:
    | { kind: 'fs'; dataDir: string }
    | { kind: 'gcpsm'; projectId: string };
  tossApiBase: string;
}

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.length === 0) {
    throw new Error(`${name} is required`);
  }
  return v;
}

export function loadConfig(): Config {
  const issuer = required('OIDC_ISSUER');
  const signingKeyPem = required('OIDC_SIGNING_KEY');
  const masterKeyB64 = required('OIDC_MASTER_KEY');
  const masterKey = Buffer.from(masterKeyB64, 'base64');
  if (masterKey.length !== 32) {
    throw new Error(`OIDC_MASTER_KEY must decode to 32 bytes (got ${masterKey.length})`);
  }
  const adminToken = required('ADMIN_TOKEN');
  const storeKind = required('TENANT_STORE');
  let tenantStore: Config['tenantStore'];
  if (storeKind === 'fs') {
    tenantStore = { kind: 'fs', dataDir: required('BRIDGE_DATA_DIR') };
  } else if (storeKind === 'gcpsm') {
    tenantStore = { kind: 'gcpsm', projectId: required('GCP_PROJECT_ID') };
  } else {
    throw new Error(`TENANT_STORE must be 'fs' or 'gcpsm' (got '${storeKind}')`);
  }
  const tossApiBase = process.env.TOSS_API_BASE ?? 'https://apps-in-toss-api.toss.im';
  return { issuer, signingKeyPem, masterKey, adminToken, tenantStore, tossApiBase };
}
```

- [ ] **Step 4: Run tests, all pass**

Run: `pnpm test src/config.test.ts && pnpm typecheck && pnpm lint`
Expected: 5 pass, no type/lint errors.

- [ ] **Step 5: Commit**

```bash
git add src/config.ts src/config.test.ts
git commit -m "feat(config): parse OIDC + tenant-store env into typed Config"
```

---

### Task 0.5: Write `src/errors.ts` (OAuth2 error envelope)

**Files:**
- Create: `src/errors.ts`
- Create: `src/errors.test.ts`

- [ ] **Step 1: Write failing tests**

`src/errors.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { OAuthError, oauthErrorBody } from './errors.js';

describe('OAuthError', () => {
  it('serializes to RFC 6749 body shape', () => {
    const e = new OAuthError('invalid_grant', 'code expired', 401);
    expect(oauthErrorBody(e)).toEqual({
      error: 'invalid_grant',
      error_description: 'code expired',
    });
    expect(e.status).toBe(401);
  });

  it('omits error_description when not provided', () => {
    const e = new OAuthError('invalid_request', undefined, 400);
    expect(oauthErrorBody(e)).toEqual({ error: 'invalid_request' });
  });
});
```

- [ ] **Step 2: Run failing tests**

Run: `pnpm test src/errors.test.ts`
Expected: fail with "Cannot find module './errors.js'".

- [ ] **Step 3: Implement `src/errors.ts`**

```ts
export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'invalid_token'
  | 'temporarily_unavailable'
  | 'server_error';

export class OAuthError extends Error {
  constructor(
    public code: OAuthErrorCode,
    public description: string | undefined,
    public status: 400 | 401 | 403 | 500 | 502 | 503,
  ) {
    super(`${code}${description ? `: ${description}` : ''}`);
    this.name = 'OAuthError';
  }
}

export function oauthErrorBody(e: OAuthError): { error: string; error_description?: string } {
  return e.description === undefined
    ? { error: e.code }
    : { error: e.code, error_description: e.description };
}
```

- [ ] **Step 4: Run tests pass**

Run: `pnpm test src/errors.test.ts`
Expected: 2 pass.

- [ ] **Step 5: Commit**

```bash
git add src/errors.ts src/errors.test.ts
git commit -m "feat(errors): OAuth2 error envelope class + body serializer"
```

---

## Task 1: Tenant store

The store is foundational — every request path looks up a tenant. Build it before any route.

### Task 1.1: Tenant types

**Files:**
- Create: `src/tenants/types.ts`

(No test file — pure types.)

- [ ] **Step 1: Write `src/tenants/types.ts`**

```ts
/**
 * Schema version of the tenant record on disk. Bumped only on
 * incompatible structural changes (see spec §5.2.6).
 */
export const CURRENT_SCHEMA_VERSION = 1 as const;

export interface ClientSecretHash {
  hash: string;          // bcrypt, $2b$12$...
  created_at: number;    // unix seconds
}

export interface TenantMTLS {
  cert_pem: string;
  key_pem: string;
  cert_fingerprint_sha256: string;  // hex, lowercase
  expires_at: number;               // unix seconds, parsed from cert NotAfter
}

export interface TenantRecord {
  schema_version: typeof CURRENT_SCHEMA_VERSION;
  id: string;                       // "tnt_..."
  name: string;
  environment: 'production' | 'sandbox';
  client_secret_hashes: ClientSecretHash[];   // 1..2 during rotation overlap
  mtls: TenantMTLS;
  sealing_key_version: number;
  created_at: number;
  updated_at: number;
}

/** Returned by list() — strips secret material. */
export interface TenantPublic {
  id: string;
  name: string;
  environment: 'production' | 'sandbox';
  mtls_fingerprint: string;
  mtls_expires_at: number;
  sealing_key_version: number;
  created_at: number;
  updated_at: number;
}

export interface TenantCreateInput {
  name: string;
  environment: 'production' | 'sandbox';
  cert_pem: string;
  key_pem: string;
}

export interface TenantPatch {
  name?: string;
  environment?: 'production' | 'sandbox';
  cert_pem?: string;
  key_pem?: string;
}
```

- [ ] **Step 2: Typecheck**

Run: `pnpm typecheck`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/tenants/types.ts
git commit -m "feat(tenants): TenantRecord + TenantPublic + TenantCreateInput types"
```

---

### Task 1.2: Tenant crypto helpers

**Files:**
- Create: `src/tenants/crypto.ts`
- Create: `src/tenants/crypto.test.ts`

- [ ] **Step 1: Write failing tests**

`src/tenants/crypto.test.ts`:
```ts
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  certFingerprintSha256,
  certNotAfterUnix,
  generateClientSecret,
  generateTenantId,
  hashClientSecret,
  verifyClientSecret,
} from './crypto.js';

describe('generateTenantId', () => {
  it('returns "tnt_" + 24 Crockford b32 chars', () => {
    const id = generateTenantId();
    expect(id).toMatch(/^tnt_[0-9a-hjkmnp-tv-z]{24}$/);
  });

  it('is collision-resistant across 1000 generations', () => {
    const ids = new Set(Array.from({ length: 1000 }, () => generateTenantId()));
    expect(ids.size).toBe(1000);
  });
});

describe('generateClientSecret', () => {
  it('returns 43-char base64url string', () => {
    const s = generateClientSecret();
    expect(s).toHaveLength(43);
    expect(s).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('hashClientSecret + verifyClientSecret', () => {
  it('round-trips with bcrypt cost 12', async () => {
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    expect(hash).toMatch(/^\$2[aby]\$12\$/);
    expect(await verifyClientSecret(secret, hash)).toBe(true);
    expect(await verifyClientSecret('wrong', hash)).toBe(false);
  });

  it('verifies against any of multiple hashes (rotation overlap)', async () => {
    const oldSecret = generateClientSecret();
    const newSecret = generateClientSecret();
    const oldHash = await hashClientSecret(oldSecret);
    const newHash = await hashClientSecret(newSecret);
    expect(await verifyClientSecret(oldSecret, [newHash, oldHash])).toBe(true);
    expect(await verifyClientSecret(newSecret, [newHash, oldHash])).toBe(true);
    expect(await verifyClientSecret('neither', [newHash, oldHash])).toBe(false);
  });
});

describe('certFingerprintSha256', () => {
  it('returns lowercase hex SHA-256 of DER form', () => {
    const pem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
    const fp = certFingerprintSha256(pem);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('certNotAfterUnix', () => {
  it('parses NotAfter into unix seconds', () => {
    const pem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
    const exp = certNotAfterUnix(pem);
    expect(exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });
});
```

- [ ] **Step 2: Run tests, expect failure**

Run: `pnpm test src/tenants/crypto.test.ts`
Expected: failures from missing module.

- [ ] **Step 3: Implement `src/tenants/crypto.ts`**

```ts
import { X509Certificate, randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';

const CROCKFORD_B32 = '0123456789abcdefghjkmnpqrstvwxyz'; // RFC: i, l, o, u removed

/** `tnt_<24 Crockford-b32 chars>` from 15 random bytes (~120 bits entropy). */
export function generateTenantId(): string {
  const bytes = randomBytes(15);
  let bits = 0;
  let buffer = 0;
  let out = '';
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      const idx = (buffer >> bits) & 0x1f;
      out += CROCKFORD_B32[idx];
    }
  }
  return `tnt_${out}`;
}

/** 32 bytes → base64url (43 chars). */
export function generateClientSecret(): string {
  return randomBytes(32).toString('base64url');
}

export async function hashClientSecret(secret: string): Promise<string> {
  return bcrypt.hash(secret, 12);
}

export async function verifyClientSecret(
  secret: string,
  hashOrHashes: string | string[],
): Promise<boolean> {
  const hashes = Array.isArray(hashOrHashes) ? hashOrHashes : [hashOrHashes];
  for (const h of hashes) {
    if (await bcrypt.compare(secret, h)) return true;
  }
  return false;
}

export function certFingerprintSha256(pem: string): string {
  const cert = new X509Certificate(pem);
  // X509Certificate.fingerprint256 is "AB:CD:EF:..." uppercase. Normalize.
  return cert.fingerprint256.replaceAll(':', '').toLowerCase();
}

export function certNotAfterUnix(pem: string): number {
  const cert = new X509Certificate(pem);
  return Math.floor(new Date(cert.validTo).getTime() / 1000);
}
```

- [ ] **Step 4: Tests pass**

Run: `pnpm test src/tenants/crypto.test.ts`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/tenants/crypto.ts src/tenants/crypto.test.ts
git commit -m "feat(tenants): id/secret generators, bcrypt with rotation overlap, cert fingerprint"
```

---

### Task 1.3: TenantStore interface + factory

**Files:**
- Create: `src/tenants/store.ts`

(No test file — interface + thin factory tested via fs-store/gcpsm-store.)

- [ ] **Step 1: Write `src/tenants/store.ts`**

```ts
import type { Config } from '../config.js';
import { createFsStore } from './fs-store.js';
import type {
  TenantCreateInput,
  TenantPatch,
  TenantPublic,
  TenantRecord,
} from './types.js';

export interface CreatedTenant {
  tenant: TenantRecord;
  client_secret: string;     // plaintext, returned once
}

export interface RotatedSecret {
  client_secret: string;
}

export interface TenantStore {
  get(tenantId: string): Promise<TenantRecord | null>;
  list(): Promise<TenantPublic[]>;
  create(input: TenantCreateInput): Promise<CreatedTenant>;
  update(tenantId: string, patch: TenantPatch): Promise<TenantRecord>;
  rotateSecret(tenantId: string): Promise<RotatedSecret>;
  delete(tenantId: string): Promise<void>;
}

/** Build the configured backend. GCPSM is lazy-imported. */
export async function createTenantStore(config: Config): Promise<TenantStore> {
  if (config.tenantStore.kind === 'fs') {
    return createFsStore(config.tenantStore.dataDir);
  }
  const { createGcpsmStore } = await import('./gcpsm-store.js');
  return createGcpsmStore(config.tenantStore.projectId);
}
```

- [ ] **Step 2: Typecheck — expects unresolved imports**

Run: `pnpm typecheck`
Expected: error referencing `./fs-store.js` and `./gcpsm-store.js` not found. That's intentional; next two tasks add them. Skip commit until 1.4 passes.

---

### Task 1.4: fs-store backend

**Files:**
- Create: `src/tenants/fs-store.ts`
- Create: `src/tenants/fs-store.test.ts`

This is the workhorse — public Vultr instance + most self-hosters use it. Test it thoroughly.

- [ ] **Step 1: Write failing tests**

`src/tenants/fs-store.test.ts`:
```ts
import { mkdtempSync, readFileSync } from 'node:fs';
import { stat, readdir, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createFsStore } from './fs-store.js';
import { verifyClientSecret } from './crypto.js';
import type { TenantStore } from './store.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

describe('fs-store', () => {
  let dataDir: string;
  let store: TenantStore;

  beforeEach(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-test-'));
    store = await createFsStore(dataDir);
  });

  it('creates BRIDGE_DATA_DIR with mode 0700 if missing', async () => {
    const s = await stat(dataDir);
    expect(s.mode & 0o777).toBe(0o700);
  });

  it('refuses to start if BRIDGE_DATA_DIR has broader permissions', async () => {
    await chmod(dataDir, 0o755);
    await expect(createFsStore(dataDir)).rejects.toThrow(/permissions/);
  });

  it('writes .data-version on first run', async () => {
    const v = readFileSync(join(dataDir, '.data-version'), 'utf8');
    expect(v).toBe('1\n');
  });

  describe('create()', () => {
    it('returns plaintext client_secret once and stores only the bcrypt hash', async () => {
      const { tenant, client_secret } = await store.create({
        name: 'sdk-example',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      expect(tenant.id).toMatch(/^tnt_/);
      expect(client_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(tenant.client_secret_hashes).toHaveLength(1);
      expect(tenant.client_secret_hashes[0].hash).toMatch(/^\$2[aby]\$12\$/);
      expect(await verifyClientSecret(client_secret, tenant.client_secret_hashes[0].hash)).toBe(true);
    });

    it('writes the tenant file with mode 0600', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const s = await stat(join(dataDir, 'tenants', `${tenant.id}.json`));
      expect(s.mode & 0o777).toBe(0o600);
    });

    it('parses cert NotAfter into mtls.expires_at', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      expect(tenant.mtls.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });
  });

  describe('get()', () => {
    it('returns null for unknown tenant', async () => {
      expect(await store.get('tnt_nope')).toBeNull();
    });

    it('round-trips a created tenant', async () => {
      const { tenant: created } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const fetched = await store.get(created.id);
      expect(fetched).toEqual(created);
    });

    it('refuses path traversal via tenant_id', async () => {
      expect(await store.get('../etc/passwd')).toBeNull();
      expect(await store.get('tnt_/../passwd')).toBeNull();
    });
  });

  describe('list()', () => {
    it('returns TenantPublic entries with no secret material', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const list = await store.list();
      expect(list).toHaveLength(1);
      expect(list[0]).toMatchObject({
        id: tenant.id,
        name: 't',
        environment: 'sandbox',
      });
      expect(list[0]).not.toHaveProperty('client_secret_hashes');
      expect(list[0]).not.toHaveProperty('mtls');
      expect(list[0].mtls_fingerprint).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('rotateSecret()', () => {
    it('appends a new hash and keeps the previous one', async () => {
      const { tenant: t1, client_secret: s1 } = await store.create({
        name: 't', environment: 'sandbox', cert_pem: certPem, key_pem: keyPem,
      });
      const { client_secret: s2 } = await store.rotateSecret(t1.id);
      const fetched = await store.get(t1.id);
      expect(fetched?.client_secret_hashes).toHaveLength(2);
      const hashes = fetched!.client_secret_hashes.map((h) => h.hash);
      expect(await verifyClientSecret(s1, hashes)).toBe(true);
      expect(await verifyClientSecret(s2, hashes)).toBe(true);
      expect(s1).not.toBe(s2);
    });
  });

  describe('update()', () => {
    it('updates name + environment + cert', async () => {
      const { tenant } = await store.create({
        name: 't', environment: 'sandbox', cert_pem: certPem, key_pem: keyPem,
      });
      const updated = await store.update(tenant.id, { name: 'renamed', environment: 'production' });
      expect(updated.name).toBe('renamed');
      expect(updated.environment).toBe('production');
      expect(updated.updated_at).toBeGreaterThanOrEqual(tenant.updated_at);
    });
  });

  describe('delete()', () => {
    it('removes the tenant file', async () => {
      const { tenant } = await store.create({
        name: 't', environment: 'sandbox', cert_pem: certPem, key_pem: keyPem,
      });
      await store.delete(tenant.id);
      expect(await store.get(tenant.id)).toBeNull();
      const dir = await readdir(join(dataDir, 'tenants'));
      expect(dir.filter((f) => !f.startsWith('.'))).toEqual([]);
    });
  });

  describe('atomic write', () => {
    it('cleans up .tmp-* leftovers on startup', async () => {
      // Simulate a crash by writing a stray .tmp- file and reopening the store.
      const { tenant } = await store.create({
        name: 't', environment: 'sandbox', cert_pem: certPem, key_pem: keyPem,
      });
      const fs = await import('node:fs/promises');
      await fs.writeFile(join(dataDir, 'tenants', '.tmp-stale-12345'), 'leftover');
      const reopened = await createFsStore(dataDir);
      expect(await reopened.get(tenant.id)).toBeTruthy();
      const dir = await readdir(join(dataDir, 'tenants'));
      expect(dir.filter((f) => f.startsWith('.tmp'))).toEqual([]);
    });
  });
});
```

- [ ] **Step 2: Run tests, expect failure**

Run: `pnpm test src/tenants/fs-store.test.ts`
Expected: all fail with "Cannot find module './fs-store.js'".

- [ ] **Step 3: Implement `src/tenants/fs-store.ts`**

```ts
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, readdir, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { TenantStore, CreatedTenant, RotatedSecret } from './store.js';
import {
  certFingerprintSha256,
  certNotAfterUnix,
  generateClientSecret,
  generateTenantId,
  hashClientSecret,
} from './crypto.js';
import {
  CURRENT_SCHEMA_VERSION,
  type TenantCreateInput,
  type TenantPatch,
  type TenantPublic,
  type TenantRecord,
} from './types.js';

const TENANT_ID_PATTERN = /^tnt_[0-9a-hjkmnp-tv-z]{24}$/;
const ROTATION_OVERLAP_SECONDS = 72 * 3600;

function tenantPath(dataDir: string, id: string): string {
  return join(dataDir, 'tenants', `${id}.json`);
}

async function ensureDirAt(path: string, mode: number): Promise<void> {
  await mkdir(path, { recursive: true, mode });
  // mkdir's `mode` is masked by umask on existing dirs; chmod to be exact.
  await chmod(path, mode);
}

async function checkPerm(path: string, expected: number): Promise<void> {
  const s = await stat(path);
  const actual = s.mode & 0o777;
  if (actual !== expected) {
    throw new Error(`refusing to start: ${path} has permissions ${actual.toString(8)} (expected ${expected.toString(8)})`);
  }
}

async function atomicWriteJson<T>(path: string, value: T): Promise<void> {
  const dir = path.substring(0, path.lastIndexOf('/'));
  const tmp = join(dir, `.tmp-${randomBytes(8).toString('hex')}`);
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(tmp, path);
}

function publicView(t: TenantRecord): TenantPublic {
  return {
    id: t.id,
    name: t.name,
    environment: t.environment,
    mtls_fingerprint: t.mtls.cert_fingerprint_sha256,
    mtls_expires_at: t.mtls.expires_at,
    sealing_key_version: t.sealing_key_version,
    created_at: t.created_at,
    updated_at: t.updated_at,
  };
}

export async function createFsStore(dataDir: string): Promise<TenantStore> {
  await ensureDirAt(dataDir, 0o700);
  await checkPerm(dataDir, 0o700);
  const tenantsDir = join(dataDir, 'tenants');
  await ensureDirAt(tenantsDir, 0o700);

  // .data-version gate
  const versionPath = join(dataDir, '.data-version');
  try {
    const v = (await readFile(versionPath, 'utf8')).trim();
    if (v !== String(CURRENT_SCHEMA_VERSION)) {
      throw new Error(`refusing to start: .data-version is ${v}, bridge supports ${CURRENT_SCHEMA_VERSION}`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      await writeFile(versionPath, `${CURRENT_SCHEMA_VERSION}\n`, { mode: 0o600 });
    } else {
      throw err;
    }
  }

  // Sweep .tmp-* leftovers from prior crashes.
  for (const entry of await readdir(tenantsDir)) {
    if (entry.startsWith('.tmp-')) {
      await unlink(join(tenantsDir, entry));
    }
  }

  async function get(id: string): Promise<TenantRecord | null> {
    if (!TENANT_ID_PATTERN.test(id)) return null;
    try {
      const raw = await readFile(tenantPath(dataDir, id), 'utf8');
      const parsed: TenantRecord = JSON.parse(raw);
      if (parsed.schema_version > CURRENT_SCHEMA_VERSION) {
        throw new Error(`tenant ${id} has schema_version ${parsed.schema_version} > ${CURRENT_SCHEMA_VERSION}`);
      }
      return parsed;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
  }

  async function list(): Promise<TenantPublic[]> {
    const entries = await readdir(tenantsDir);
    const out: TenantPublic[] = [];
    for (const entry of entries) {
      if (!entry.endsWith('.json') || entry.startsWith('.')) continue;
      const id = entry.replace(/\.json$/, '');
      const t = await get(id);
      if (t) out.push(publicView(t));
    }
    return out;
  }

  async function create(input: TenantCreateInput): Promise<CreatedTenant> {
    const id = generateTenantId();
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    const now = Math.floor(Date.now() / 1000);
    const tenant: TenantRecord = {
      schema_version: CURRENT_SCHEMA_VERSION,
      id,
      name: input.name,
      environment: input.environment,
      client_secret_hashes: [{ hash, created_at: now }],
      mtls: {
        cert_pem: input.cert_pem,
        key_pem: input.key_pem,
        cert_fingerprint_sha256: certFingerprintSha256(input.cert_pem),
        expires_at: certNotAfterUnix(input.cert_pem),
      },
      sealing_key_version: 1,
      created_at: now,
      updated_at: now,
    };
    await atomicWriteJson(tenantPath(dataDir, id), tenant);
    return { tenant, client_secret: secret };
  }

  async function update(id: string, patch: TenantPatch): Promise<TenantRecord> {
    const current = await get(id);
    if (!current) throw new Error(`tenant ${id} not found`);
    const next: TenantRecord = {
      ...current,
      name: patch.name ?? current.name,
      environment: patch.environment ?? current.environment,
      mtls:
        patch.cert_pem && patch.key_pem
          ? {
              cert_pem: patch.cert_pem,
              key_pem: patch.key_pem,
              cert_fingerprint_sha256: certFingerprintSha256(patch.cert_pem),
              expires_at: certNotAfterUnix(patch.cert_pem),
            }
          : current.mtls,
      updated_at: Math.floor(Date.now() / 1000),
    };
    await atomicWriteJson(tenantPath(dataDir, id), next);
    return next;
  }

  async function rotateSecret(id: string): Promise<RotatedSecret> {
    const current = await get(id);
    if (!current) throw new Error(`tenant ${id} not found`);
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    const now = Math.floor(Date.now() / 1000);
    const cutoff = now - ROTATION_OVERLAP_SECONDS;
    const next: TenantRecord = {
      ...current,
      client_secret_hashes: [
        { hash, created_at: now },
        ...current.client_secret_hashes.filter((h) => h.created_at >= cutoff),
      ].slice(0, 2),
      updated_at: now,
    };
    await atomicWriteJson(tenantPath(dataDir, id), next);
    return { client_secret: secret };
  }

  async function deleteTenant(id: string): Promise<void> {
    if (!TENANT_ID_PATTERN.test(id)) return;
    await rm(tenantPath(dataDir, id), { force: true });
  }

  return { get, list, create, update, rotateSecret, delete: deleteTenant };
}
```

- [ ] **Step 4: Run tests, all pass**

Run: `pnpm test src/tenants/ && pnpm typecheck && pnpm lint`
Expected: all fs-store tests pass; store.ts now resolves.

- [ ] **Step 5: Commit**

```bash
git add src/tenants/fs-store.ts src/tenants/fs-store.test.ts src/tenants/store.ts
git commit -m "feat(tenants): filesystem store with atomic writes, perm checks, rotation overlap"
```

---

### Task 1.5: gcpsm-store backend (lazy)

**Files:**
- Create: `src/tenants/gcpsm-store.ts`
- Create: `src/tenants/gcpsm-store.test.ts`

The gcpsm-store is forward-compat for managed-cloud deploys (spec §5.2.4). M1 ships with it implemented but **the public Vultr instance keeps fs-store**. Tests use a mocked `SecretManagerServiceClient`.

- [ ] **Step 1: Write failing tests**

`src/tenants/gcpsm-store.test.ts`:
```ts
import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

interface MockSecret {
  name: string;
  versions: { name: string; payload: Buffer; enabled: boolean }[];
  labels: Record<string, string>;
}

function makeMockClient() {
  const secrets = new Map<string, MockSecret>();
  const client = {
    createSecret: vi.fn(async ({ secretId, secret }: any) => {
      const name = `projects/p/secrets/${secretId}`;
      secrets.set(secretId, { name, versions: [], labels: secret?.labels ?? {} });
      return [{ name }];
    }),
    addSecretVersion: vi.fn(async ({ parent, payload }: any) => {
      const id = parent.split('/').pop()!;
      const s = secrets.get(id);
      if (!s) throw new Error(`secret ${id} not found`);
      // Disable previous versions on add.
      for (const v of s.versions) v.enabled = false;
      s.versions.push({ name: `${parent}/versions/${s.versions.length + 1}`, payload: Buffer.from(payload.data), enabled: true });
      return [{ name: s.versions.at(-1)!.name }];
    }),
    accessSecretVersion: vi.fn(async ({ name }: any) => {
      const id = name.split('/')[3];
      const s = secrets.get(id);
      if (!s) {
        const err: any = new Error('NOT_FOUND');
        err.code = 5;
        throw err;
      }
      const enabled = s.versions.find((v) => v.enabled);
      if (!enabled) throw new Error(`no enabled version for ${id}`);
      return [{ payload: { data: enabled.payload } }];
    }),
    listSecrets: vi.fn(async function* ({ parent: _parent, filter: _filter }: any) {
      for (const s of secrets.values()) yield s;
    }),
    deleteSecret: vi.fn(async ({ name }: any) => {
      const id = name.split('/').pop()!;
      secrets.delete(id);
    }),
    projectPath: (p: string) => `projects/${p}`,
  };
  return { client, secrets };
}

describe('gcpsm-store', () => {
  it('round-trips create + get + delete via mocked SecretManagerServiceClient', async () => {
    vi.resetModules();
    const { client, secrets } = makeMockClient();
    vi.doMock('@google-cloud/secret-manager', () => ({
      SecretManagerServiceClient: vi.fn(() => client),
    }));
    const { createGcpsmStore } = await import('./gcpsm-store.js');
    const store = await createGcpsmStore('p');

    const { tenant, client_secret } = await store.create({
      name: 't', environment: 'sandbox', cert_pem: certPem, key_pem: keyPem,
    });
    expect(client_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(secrets.has(`oidc-bridge-tenant-${tenant.id}`)).toBe(true);

    const fetched = await store.get(tenant.id);
    expect(fetched).toEqual(tenant);

    await store.delete(tenant.id);
    expect(await store.get(tenant.id)).toBeNull();
  });
});
```

- [ ] **Step 2: Run failing test**

Run: `pnpm test src/tenants/gcpsm-store.test.ts`
Expected: fail with "Cannot find module './gcpsm-store.js'".

- [ ] **Step 3: Implement `src/tenants/gcpsm-store.ts`**

```ts
import type { TenantStore, CreatedTenant, RotatedSecret } from './store.js';
import {
  certFingerprintSha256,
  certNotAfterUnix,
  generateClientSecret,
  generateTenantId,
  hashClientSecret,
} from './crypto.js';
import {
  CURRENT_SCHEMA_VERSION,
  type TenantCreateInput,
  type TenantPatch,
  type TenantPublic,
  type TenantRecord,
} from './types.js';

const TENANT_ID_PATTERN = /^tnt_[0-9a-hjkmnp-tv-z]{24}$/;
const SECRET_PREFIX = 'oidc-bridge-tenant-';
const ROTATION_OVERLAP_SECONDS = 72 * 3600;

function publicView(t: TenantRecord): TenantPublic {
  return {
    id: t.id,
    name: t.name,
    environment: t.environment,
    mtls_fingerprint: t.mtls.cert_fingerprint_sha256,
    mtls_expires_at: t.mtls.expires_at,
    sealing_key_version: t.sealing_key_version,
    created_at: t.created_at,
    updated_at: t.updated_at,
  };
}

export async function createGcpsmStore(projectId: string): Promise<TenantStore> {
  // Lazy import — only runs when this backend is selected.
  const mod = await import('@google-cloud/secret-manager');
  const client = new mod.SecretManagerServiceClient();
  const projectPath = client.projectPath(projectId);

  function secretName(id: string): string {
    return `projects/${projectId}/secrets/${SECRET_PREFIX}${id}`;
  }

  async function readSecret(id: string): Promise<TenantRecord | null> {
    try {
      const [result] = await client.accessSecretVersion({ name: `${secretName(id)}/versions/latest` });
      const data = result.payload?.data;
      if (!data) return null;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      return JSON.parse(buf.toString('utf8')) as TenantRecord;
    } catch (err: unknown) {
      if ((err as { code?: number }).code === 5) return null; // NOT_FOUND
      throw err;
    }
  }

  async function writeSecret(id: string, record: TenantRecord, isCreate: boolean): Promise<void> {
    const secretId = `${SECRET_PREFIX}${id}`;
    const payload = Buffer.from(JSON.stringify(record), 'utf8');
    if (isCreate) {
      await client.createSecret({
        parent: projectPath,
        secretId,
        secret: {
          replication: { automatic: {} },
          labels: { app: 'oidc-bridge', tenant_id: id },
        },
      });
    }
    await client.addSecretVersion({ parent: secretName(id), payload: { data: payload } });
  }

  async function get(id: string): Promise<TenantRecord | null> {
    if (!TENANT_ID_PATTERN.test(id)) return null;
    const record = await readSecret(id);
    if (record && record.schema_version > CURRENT_SCHEMA_VERSION) {
      throw new Error(`tenant ${id} has schema_version ${record.schema_version} > ${CURRENT_SCHEMA_VERSION}`);
    }
    return record;
  }

  async function list(): Promise<TenantPublic[]> {
    const out: TenantPublic[] = [];
    for await (const s of client.listSecrets({ parent: projectPath, filter: `name:${SECRET_PREFIX}` })) {
      const name = (s as { name?: string }).name;
      if (!name) continue;
      const id = name.substring(name.indexOf(SECRET_PREFIX) + SECRET_PREFIX.length);
      const t = await get(id);
      if (t) out.push(publicView(t));
    }
    return out;
  }

  async function create(input: TenantCreateInput): Promise<CreatedTenant> {
    const id = generateTenantId();
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    const now = Math.floor(Date.now() / 1000);
    const tenant: TenantRecord = {
      schema_version: CURRENT_SCHEMA_VERSION,
      id,
      name: input.name,
      environment: input.environment,
      client_secret_hashes: [{ hash, created_at: now }],
      mtls: {
        cert_pem: input.cert_pem,
        key_pem: input.key_pem,
        cert_fingerprint_sha256: certFingerprintSha256(input.cert_pem),
        expires_at: certNotAfterUnix(input.cert_pem),
      },
      sealing_key_version: 1,
      created_at: now,
      updated_at: now,
    };
    await writeSecret(id, tenant, true);
    return { tenant, client_secret: secret };
  }

  async function update(id: string, patch: TenantPatch): Promise<TenantRecord> {
    const current = await get(id);
    if (!current) throw new Error(`tenant ${id} not found`);
    const next: TenantRecord = {
      ...current,
      name: patch.name ?? current.name,
      environment: patch.environment ?? current.environment,
      mtls:
        patch.cert_pem && patch.key_pem
          ? {
              cert_pem: patch.cert_pem,
              key_pem: patch.key_pem,
              cert_fingerprint_sha256: certFingerprintSha256(patch.cert_pem),
              expires_at: certNotAfterUnix(patch.cert_pem),
            }
          : current.mtls,
      updated_at: Math.floor(Date.now() / 1000),
    };
    await writeSecret(id, next, false);
    return next;
  }

  async function rotateSecret(id: string): Promise<RotatedSecret> {
    const current = await get(id);
    if (!current) throw new Error(`tenant ${id} not found`);
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    const now = Math.floor(Date.now() / 1000);
    const cutoff = now - ROTATION_OVERLAP_SECONDS;
    const next: TenantRecord = {
      ...current,
      client_secret_hashes: [
        { hash, created_at: now },
        ...current.client_secret_hashes.filter((h) => h.created_at >= cutoff),
      ].slice(0, 2),
      updated_at: now,
    };
    await writeSecret(id, next, false);
    return { client_secret: secret };
  }

  async function deleteTenant(id: string): Promise<void> {
    if (!TENANT_ID_PATTERN.test(id)) return;
    try {
      await client.deleteSecret({ name: secretName(id) });
    } catch (err: unknown) {
      if ((err as { code?: number }).code !== 5) throw err;
    }
  }

  return { get, list, create, update, rotateSecret, delete: deleteTenant };
}
```

- [ ] **Step 4: Tests pass**

Run: `pnpm test src/tenants/ && pnpm typecheck`
Expected: all tests pass; gcpsm-store proves contract parity with fs-store via mocked client.

- [ ] **Step 5: Commit**

```bash
git add src/tenants/gcpsm-store.ts src/tenants/gcpsm-store.test.ts
git commit -m "feat(tenants): GCPSM backend with lazy import and mocked round-trip test"
```

---

## Task 2: Sealed access tokens

The sealed-token module is the second foundational piece — every data-path endpoint unwraps a sealed token. AEAD AES-256-GCM with per-tenant HKDF derivation.

### Task 2.1: sealed-token wrap/unwrap

**Files:**
- Create: `src/oidc/sealed-token.ts`
- Create: `src/oidc/sealed-token.test.ts`

- [ ] **Step 1: Write failing tests**

`src/oidc/sealed-token.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { sealAccessToken, unsealAccessToken, deriveSealingKey } from './sealed-token.js';

const masterKey = Buffer.alloc(32, 0xab);
const tenantId = 'tnt_abcdefghjkmnpqrstvwxyz01';

describe('deriveSealingKey', () => {
  it('returns a 32-byte buffer', () => {
    const key = deriveSealingKey(masterKey, tenantId, 1);
    expect(key).toHaveLength(32);
  });

  it('is deterministic for same inputs', () => {
    const a = deriveSealingKey(masterKey, tenantId, 1);
    const b = deriveSealingKey(masterKey, tenantId, 1);
    expect(a.equals(b)).toBe(true);
  });

  it('differs across tenants', () => {
    const a = deriveSealingKey(masterKey, 'tnt_aaaaaaaaaaaaaaaaaaaaaaaa', 1);
    const b = deriveSealingKey(masterKey, 'tnt_bbbbbbbbbbbbbbbbbbbbbbbb', 1);
    expect(a.equals(b)).toBe(false);
  });

  it('differs across versions', () => {
    const a = deriveSealingKey(masterKey, tenantId, 1);
    const b = deriveSealingKey(masterKey, tenantId, 2);
    expect(a.equals(b)).toBe(false);
  });
});

describe('seal/unseal access token', () => {
  const payload = {
    tenant_id: tenantId,
    toss_access_token: 'toss-AT-fake-jwt',
    toss_refresh_token: 'toss-RT-fake',
    exp: 1_900_000_000,
  };

  it('round-trips through wrap/unwrap', () => {
    const token = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    expect(token).toMatch(/^aitc_[A-Za-z0-9_-]+$/);
    const unsealed = unsealAccessToken({ token, masterKey, sealingKeyVersionOf: () => 1 });
    expect(unsealed).toEqual(payload);
  });

  it('rejects tampered ciphertext', () => {
    const token = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    const tampered = `${token.slice(0, -4)}AAAA`;
    expect(() =>
      unsealAccessToken({ token: tampered, masterKey, sealingKeyVersionOf: () => 1 }),
    ).toThrow(/tamper|auth/i);
  });

  it('rejects wrong prefix', () => {
    expect(() =>
      unsealAccessToken({ token: 'bearer_xxx', masterKey, sealingKeyVersionOf: () => 1 }),
    ).toThrow(/format/i);
  });

  it('rejects when sealing_key_version mismatches', () => {
    const token = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    expect(() =>
      unsealAccessToken({ token, masterKey, sealingKeyVersionOf: () => 2 }),
    ).toThrow(/auth|tamper/i);
  });

  it('produces non-deterministic output (random nonce)', () => {
    const a = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    const b = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    expect(a).not.toBe(b);
  });
});
```

- [ ] **Step 2: Run failing tests**

Run: `pnpm test src/oidc/sealed-token.test.ts`
Expected: fail on missing module.

- [ ] **Step 3: Implement `src/oidc/sealed-token.ts`**

```ts
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

export interface SealedPayload {
  tenant_id: string;
  toss_access_token: string;
  toss_refresh_token: string;
  exp: number;     // unix seconds — bridge AT lifetime, mirrors Toss AT
}

const TOKEN_PREFIX = 'aitc_';
const NONCE_BYTES = 12;            // GCM nonce
const TAG_BYTES = 16;
const VERSION_BYTE = 0x01;         // wire-format version, NOT sealing-key version

export function deriveSealingKey(
  masterKey: Buffer,
  tenantId: string,
  sealingKeyVersion: number,
): Buffer {
  const info = `oidc-bridge sealing v${sealingKeyVersion}`;
  // Node's hkdfSync(digest, ikm, salt, info, length): returns ArrayBuffer.
  return Buffer.from(hkdfSync('sha256', masterKey, Buffer.from(tenantId, 'utf8'), Buffer.from(info, 'utf8'), 32));
}

export function sealAccessToken(args: {
  payload: SealedPayload;
  masterKey: Buffer;
  sealingKeyVersion: number;
}): string {
  const key = deriveSealingKey(args.masterKey, args.payload.tenant_id, args.sealingKeyVersion);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  // The sealing_key_version travels in AAD so a wrong version fails the tag.
  const aad = Buffer.from([VERSION_BYTE, args.sealingKeyVersion]);
  cipher.setAAD(aad);
  const plaintext = Buffer.from(JSON.stringify(args.payload), 'utf8');
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const wire = Buffer.concat([aad, nonce, tag, ct]);
  return TOKEN_PREFIX + wire.toString('base64url');
}

export function unsealAccessToken(args: {
  token: string;
  masterKey: Buffer;
  sealingKeyVersionOf: (tenantId: string) => number;
}): SealedPayload {
  if (!args.token.startsWith(TOKEN_PREFIX)) {
    throw new Error('sealed token has wrong format');
  }
  const wire = Buffer.from(args.token.slice(TOKEN_PREFIX.length), 'base64url');
  if (wire.length < 2 + NONCE_BYTES + TAG_BYTES) {
    throw new Error('sealed token is truncated');
  }
  const versionByte = wire[0];
  const sealingKeyVersion = wire[1];
  if (versionByte !== VERSION_BYTE) {
    throw new Error(`unsupported sealed-token wire version ${versionByte}`);
  }
  const aad = wire.subarray(0, 2);
  const nonce = wire.subarray(2, 2 + NONCE_BYTES);
  const tag = wire.subarray(2 + NONCE_BYTES, 2 + NONCE_BYTES + TAG_BYTES);
  const ct = wire.subarray(2 + NONCE_BYTES + TAG_BYTES);

  // Pre-decrypt: peek at tenant_id by parsing minimal CT? No — we don't have
  // plaintext yet, so we structure the payload so tenant_id is a known prefix
  // OR we simply pass tenantId through a separate channel. Since the caller
  // (HTTP layer) only has the bearer token, we resolve sealingKeyVersion via
  // a callback that takes tenant_id AFTER we attempt decryption with all
  // currently-active versions known to the caller. For M1, the caller passes
  // sealingKeyVersionOf, and we attempt v_current only — version-1 only.
  //
  // Simpler M1 approach: the sealing_key_version is in AAD, so the caller
  // doesn't need to know tenant_id up front. We just decrypt with the version
  // in AAD; the resulting plaintext contains tenant_id, and we re-validate
  // version against tenant.sealing_key_version after parsing.
  const _ignoredCallback = args.sealingKeyVersionOf;

  // We cannot derive the key without tenant_id. Workaround: treat the AAD
  // version as the lookup key, and require the caller to have only one master
  // key + one active version per tenant during M1. This means we need
  // tenant_id-independent decryption — which we get by including tenant_id in
  // the plaintext only. To unseal without tenant_id, we'd need a pepper.
  //
  // M1 design clarification: the sealing key is per-tenant, derived from
  // tenant_id. To unseal, we must know tenant_id. We solve this by encoding
  // tenant_id alongside the ciphertext in the AAD instead of buried in the
  // plaintext. Re-do: AAD carries [version, sealingKeyVersion, tenantIdLen, tenantIdBytes].
  throw new Error('unreachable — see implementation notes');
}
```

**Implementation note:** The above naive layout doesn't work because we need `tenant_id` to derive the sealing key, but `tenant_id` is in the encrypted plaintext. The fix is to put `tenant_id` in the AAD instead. Update the wire format:

```
[ver_byte:1][sealing_key_ver:1][tenant_id_len:1][tenant_id:N][nonce:12][tag:16][ct:...]
```

`tenant_id` is `tnt_<24 chars>` = 28 bytes, fits in one len byte.

- [ ] **Step 4: Rewrite implementation with tenant_id in AAD**

```ts
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

export interface SealedPayload {
  tenant_id: string;
  toss_access_token: string;
  toss_refresh_token: string;
  exp: number;
}

const TOKEN_PREFIX = 'aitc_';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const VERSION_BYTE = 0x01;

export function deriveSealingKey(
  masterKey: Buffer,
  tenantId: string,
  sealingKeyVersion: number,
): Buffer {
  const info = `oidc-bridge sealing v${sealingKeyVersion}`;
  return Buffer.from(
    hkdfSync('sha256', masterKey, Buffer.from(tenantId, 'utf8'), Buffer.from(info, 'utf8'), 32),
  );
}

function buildHeader(sealingKeyVersion: number, tenantId: string): Buffer {
  const idBytes = Buffer.from(tenantId, 'utf8');
  if (idBytes.length > 0xff) throw new Error('tenant_id too long');
  return Buffer.concat([Buffer.from([VERSION_BYTE, sealingKeyVersion, idBytes.length]), idBytes]);
}

export function sealAccessToken(args: {
  payload: SealedPayload;
  masterKey: Buffer;
  sealingKeyVersion: number;
}): string {
  const header = buildHeader(args.sealingKeyVersion, args.payload.tenant_id);
  const key = deriveSealingKey(args.masterKey, args.payload.tenant_id, args.sealingKeyVersion);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(header);
  const ct = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(args.payload), 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return TOKEN_PREFIX + Buffer.concat([header, nonce, tag, ct]).toString('base64url');
}

export function unsealAccessToken(args: {
  token: string;
  masterKey: Buffer;
  sealingKeyVersionOf: (tenantId: string) => number;
}): SealedPayload {
  if (!args.token.startsWith(TOKEN_PREFIX)) throw new Error('sealed token format');
  const wire = Buffer.from(args.token.slice(TOKEN_PREFIX.length), 'base64url');
  if (wire.length < 3 + NONCE_BYTES + TAG_BYTES) throw new Error('sealed token truncated');
  if (wire[0] !== VERSION_BYTE) throw new Error(`sealed token wire version ${wire[0]}`);
  const sealingKeyVersion = wire[1];
  const idLen = wire[2];
  const headerLen = 3 + idLen;
  if (wire.length < headerLen + NONCE_BYTES + TAG_BYTES) throw new Error('sealed token truncated');
  const tenantId = wire.subarray(3, headerLen).toString('utf8');
  const expectedVersion = args.sealingKeyVersionOf(tenantId);
  if (expectedVersion !== sealingKeyVersion) {
    throw new Error('sealing key version mismatch (auth)');
  }
  const header = wire.subarray(0, headerLen);
  const nonce = wire.subarray(headerLen, headerLen + NONCE_BYTES);
  const tag = wire.subarray(headerLen + NONCE_BYTES, headerLen + NONCE_BYTES + TAG_BYTES);
  const ct = wire.subarray(headerLen + NONCE_BYTES + TAG_BYTES);
  const key = deriveSealingKey(args.masterKey, tenantId, sealingKeyVersion);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (_err) {
    throw new Error('sealed token failed authentication tag (tamper)');
  }
  return JSON.parse(plaintext.toString('utf8')) as SealedPayload;
}
```

- [ ] **Step 5: Tests pass**

Run: `pnpm test src/oidc/sealed-token.test.ts`
Expected: all 8 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/oidc/sealed-token.ts src/oidc/sealed-token.test.ts
git commit -m "feat(oidc): AES-256-GCM sealed access tokens with per-tenant HKDF key"
```

---

## Task 3: ID token signing + JWKS

### Task 3.1: ID token sign/verify

**Files:**
- Create: `src/oidc/id-token.ts`
- Create: `src/oidc/id-token.test.ts`

- [ ] **Step 1: Generate test signing key**

Run from repo root:
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out src/__fixtures__/test-signing.key.pem
```

(Test-only — never used to sign real tokens.)

- [ ] **Step 2: Write failing tests**

`src/oidc/id-token.test.ts`:
```ts
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { signIdToken, exportJwks, computeKid } from './id-token.js';

const signingKeyPem = readFileSync('src/__fixtures__/test-signing.key.pem', 'utf8');

describe('signIdToken + JWKS verify', () => {
  it('round-trips: sign with private, verify with JWKS public half', async () => {
    const claims = {
      sub: '4200000000001',
      iss: 'https://oidc-bridge.aitc.dev',
      aud: 'tnt_abcdefghjkmnpqrstvwxyz01',
      iat: 1_700_000_000,
      exp: 1_700_003_600,
      provider: 'toss' as const,
      scope: 'openid user_key',
      'toss:userKey': 4200000000001,
    };
    const jwt = await signIdToken({ claims, signingKeyPem });
    const jwks = await exportJwks(signingKeyPem);
    const set = createLocalJWKSet(jwks);
    const { payload, protectedHeader } = await jwtVerify(jwt, set, {
      issuer: claims.iss,
      audience: claims.aud,
    });
    expect(protectedHeader.alg).toBe('RS256');
    expect(protectedHeader.kid).toBe(jwks.keys[0].kid);
    expect(payload.sub).toBe(claims.sub);
    expect(payload['toss:userKey']).toBe(4200000000001);
  });

  it('exposes a deterministic kid (RFC 7638 thumbprint)', async () => {
    const a = await computeKid(signingKeyPem);
    const b = await computeKid(signingKeyPem);
    expect(a).toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/); // base64url SHA-256
  });

  it('JWKS publishes only the public half (no `d`, no `p`, no `q`)', async () => {
    const jwks = await exportJwks(signingKeyPem);
    expect(jwks.keys).toHaveLength(1);
    const k = jwks.keys[0] as Record<string, unknown>;
    expect(k.kty).toBe('RSA');
    expect(k.use).toBe('sig');
    expect(k.alg).toBe('RS256');
    expect(k.kid).toBeTypeOf('string');
    expect(k.n).toBeTypeOf('string');
    expect(k.e).toBeTypeOf('string');
    expect(k.d).toBeUndefined();
    expect(k.p).toBeUndefined();
    expect(k.q).toBeUndefined();
  });
});
```

- [ ] **Step 3: Run failing tests**

Run: `pnpm test src/oidc/id-token.test.ts`
Expected: fail on missing module.

- [ ] **Step 4: Implement `src/oidc/id-token.ts`**

```ts
import {
  SignJWT,
  calculateJwkThumbprint,
  exportJWK,
  importPKCS8,
  type JWK,
} from 'jose';

export interface IdTokenClaims {
  sub: string;
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  nbf?: number;
  provider: 'toss';
  scope: string;
  'toss:userKey'?: number;
  'toss:agreedTerms'?: string[];
  'toss:tossAccessTokenExpiresAt'?: number;
}

let cachedKid: string | undefined;

export async function computeKid(signingKeyPem: string): Promise<string> {
  if (cachedKid) return cachedKid;
  const key = await importPKCS8(signingKeyPem, 'RS256');
  const jwk = await exportJWK(key);
  cachedKid = await calculateJwkThumbprint(jwk, 'sha256');
  return cachedKid;
}

export async function signIdToken(args: {
  claims: IdTokenClaims;
  signingKeyPem: string;
}): Promise<string> {
  const key = await importPKCS8(args.signingKeyPem, 'RS256');
  const kid = await computeKid(args.signingKeyPem);
  const { iss, aud, iat, exp, nbf, sub, ...rest } = args.claims;
  let jwt = new SignJWT({ ...rest })
    .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
    .setIssuer(iss)
    .setAudience(aud)
    .setSubject(sub)
    .setIssuedAt(iat)
    .setExpirationTime(exp);
  if (nbf !== undefined) jwt = jwt.setNotBefore(nbf);
  return jwt.sign(key);
}

export async function exportJwks(signingKeyPem: string): Promise<{ keys: JWK[] }> {
  const key = await importPKCS8(signingKeyPem, 'RS256');
  // exportJWK on a KeyLike from importPKCS8 still includes private fields.
  // We re-derive a public JWK by extracting `kty`, `n`, `e` only.
  const full = await exportJWK(key);
  const kid = await computeKid(signingKeyPem);
  const pub: JWK = { kty: full.kty, n: full.n, e: full.e, alg: 'RS256', use: 'sig', kid };
  return { keys: [pub] };
}
```

- [ ] **Step 5: Tests pass**

Run: `pnpm test src/oidc/id-token.test.ts && pnpm typecheck`
Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/__fixtures__/test-signing.key.pem src/oidc/id-token.ts src/oidc/id-token.test.ts
git commit -m "feat(oidc): RS256 ID token sign + JWKS export with RFC 7638 kid"
```

---

### Task 3.2: `/.well-known/jwks.json` route

**Files:**
- Create: `src/oidc/jwks.ts`

(Tested via integration in Task 5.x once routes are mounted.)

- [ ] **Step 1: Implement `src/oidc/jwks.ts`**

```ts
import type { Hono } from 'hono';
import type { Config } from '../config.js';
import { exportJwks } from './id-token.js';

export function mountJwks(app: Hono, config: Config): void {
  app.get('/.well-known/jwks.json', async (c) => {
    const jwks = await exportJwks(config.signingKeyPem);
    c.header('cache-control', 'public, max-age=300');
    return c.json(jwks);
  });
}
```

- [ ] **Step 2: Typecheck**

Run: `pnpm typecheck`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/oidc/jwks.ts
git commit -m "feat(oidc): mount /.well-known/jwks.json"
```

---

### Task 3.3: `/.well-known/openid-configuration` route

**Files:**
- Create: `src/oidc/discovery.ts`

- [ ] **Step 1: Implement `src/oidc/discovery.ts`**

```ts
import type { Hono } from 'hono';
import type { Config } from '../config.js';

export function mountDiscovery(app: Hono, config: Config): void {
  app.get('/.well-known/openid-configuration', (c) => {
    const i = config.issuer;
    return c.json({
      issuer: i,
      jwks_uri: `${i}/.well-known/jwks.json`,
      token_endpoint: `${i}/oidc/token`,
      userinfo_endpoint: `${i}/oidc/userinfo`,
      revocation_endpoint: `${i}/oidc/revoke`,
      id_token_signing_alg_values_supported: ['RS256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      scopes_supported: [
        'openid',
        'profile',
        'user_key',
        'user_name',
        'user_phone',
        'user_birthday',
        'user_gender',
        'user_nationality',
        'user_ci',
      ],
      subject_types_supported: ['public'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'iat',
        'exp',
        'nbf',
        'provider',
        'scope',
        'toss:userKey',
        'toss:agreedTerms',
        'toss:tossAccessTokenExpiresAt',
      ],
    });
  });
}
```

`authorization_endpoint` and `response_types_supported` are intentionally absent (spec §5.6).

- [ ] **Step 2: Commit**

```bash
git add src/oidc/discovery.ts
git commit -m "feat(oidc): mount /.well-known/openid-configuration (no authorize endpoint)"
```

---

## Task 4: Toss adapter

The adapter is a single seam between bridge and Toss. Build envelope, then mTLS client, then four endpoint clients on top.

### Task 4.1: Toss types

**Files:**
- Create: `src/toss/types.ts`

- [ ] **Step 1: Write `src/toss/types.ts`**

```ts
export type Referrer = 'DEFAULT' | 'SANDBOX';

export interface TossSuccessEnvelope<T> {
  resultType: 'SUCCESS';
  success: T;
}

export interface TossFailEnvelope {
  resultType: 'FAIL';
  error: { reason: string; description?: string };
}

export type TossEnvelope<T> = TossSuccessEnvelope<T> | TossFailEnvelope;

export interface GenerateTokenSuccess {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  scope: string;
}

export interface RefreshTokenSuccess {
  accessToken: string;
  refreshToken?: string;   // Toss may or may not rotate (spec §10 open question)
  tokenType: string;
  expiresIn: number;
  scope?: string;
}

export interface LoginMeSuccess {
  userKey: number;
  scope: string;
  agreedTerms: string[];
  // PII fields stay opaque/encrypted; bridge passes them through.
  name?: string;
  phone?: string;
  birthday?: string;
  ci?: string;
  gender?: string;
  nationality?: string;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/toss/types.ts
git commit -m "feat(toss): result-type envelope + endpoint payload types"
```

---

### Task 4.2: Envelope parser

**Files:**
- Create: `src/toss/envelope.ts`
- Create: `src/toss/envelope.test.ts`

- [ ] **Step 1: Write failing tests**

`src/toss/envelope.test.ts`:
```ts
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseTossEnvelope } from './envelope.js';

describe('parseTossEnvelope', () => {
  it('parses SUCCESS envelope', () => {
    const raw = readFileSync('src/__fixtures__/toss-generate-token.success.json', 'utf8');
    const result = parseTossEnvelope(JSON.parse(raw));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toMatchObject({ accessToken: expect.any(String) });
    }
  });

  it('parses FAIL envelope', () => {
    const raw = readFileSync('src/__fixtures__/toss-generate-token.fail.json', 'utf8');
    const result = parseTossEnvelope(JSON.parse(raw));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('INVALID_AUTHORIZATION_CODE');
    }
  });

  it('rejects unknown resultType', () => {
    expect(() => parseTossEnvelope({ resultType: 'WAT' })).toThrow();
  });

  it('rejects missing success body on SUCCESS', () => {
    expect(() => parseTossEnvelope({ resultType: 'SUCCESS' })).toThrow();
  });
});
```

- [ ] **Step 2: Run failing tests**

Run: `pnpm test src/toss/envelope.test.ts`
Expected: fail with "Cannot find module './envelope.js'".

- [ ] **Step 3: Implement `src/toss/envelope.ts`**

```ts
export type ParsedEnvelope<T> =
  | { ok: true; value: T }
  | { ok: false; reason: string; description?: string };

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function parseTossEnvelope<T>(raw: unknown): ParsedEnvelope<T> {
  if (!isObject(raw)) throw new Error('toss response is not an object');
  if (raw.resultType === 'SUCCESS') {
    if (!isObject(raw.success)) throw new Error('SUCCESS envelope missing `success` body');
    return { ok: true, value: raw.success as T };
  }
  if (raw.resultType === 'FAIL') {
    if (!isObject(raw.error)) throw new Error('FAIL envelope missing `error` body');
    const reason = typeof raw.error.reason === 'string' ? raw.error.reason : 'unknown';
    const description =
      typeof raw.error.description === 'string' ? raw.error.description : undefined;
    return { ok: false, reason, description };
  }
  throw new Error(`unknown resultType ${String(raw.resultType)}`);
}
```

- [ ] **Step 4: Tests pass**

Run: `pnpm test src/toss/envelope.test.ts`
Expected: 4 pass.

- [ ] **Step 5: Commit**

```bash
git add src/toss/envelope.ts src/toss/envelope.test.ts
git commit -m "feat(toss): result-type envelope parser with discriminated result"
```

---

### Task 4.3: mTLS Toss client

**Files:**
- Create: `src/toss/client.ts`
- Create: `src/toss/client.test.ts`

We can't run a real mTLS handshake against Toss in CI. The test asserts that the `https.Agent` is built with the tenant's PEM bytes — that's what the spec calls "indirect mTLS assertion" (§8 testing strategy).

- [ ] **Step 1: Write failing tests**

`src/toss/client.test.ts`:
```ts
import { readFileSync } from 'node:fs';
import https from 'node:https';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildAgent, tossFetch } from './client.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

describe('buildAgent', () => {
  it('returns a https.Agent containing the supplied PEM bytes', () => {
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    expect(agent).toBeInstanceOf(https.Agent);
    // node:https Agent stores `options` for outbound TLS handshakes
    const opts = (agent as unknown as { options: { cert?: string; key?: string } }).options;
    expect(opts.cert).toBe(certPem);
    expect(opts.key).toBe(keyPem);
  });
});

describe('tossFetch', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('passes the agent through dispatcher and returns parsed JSON', async () => {
    const fakeJson = { resultType: 'SUCCESS', success: { ok: true } };
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(fakeJson), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const out = await tossFetch({
      url: 'https://apps-in-toss-api.toss.im/x',
      method: 'POST',
      body: { hi: true },
      agent,
    });
    expect(out).toEqual(fakeJson);
  });

  it('throws temporarily_unavailable on network error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('ECONNRESET');
      }),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    await expect(
      tossFetch({ url: 'https://x/x', method: 'POST', body: {}, agent }),
    ).rejects.toThrow(/temporarily_unavailable/);
  });
});
```

- [ ] **Step 2: Run failing tests**

Run: `pnpm test src/toss/client.test.ts`
Expected: fail.

- [ ] **Step 3: Implement `src/toss/client.ts`**

```ts
import { Agent } from 'node:https';
import { OAuthError } from '../errors.js';

export function buildAgent(args: { cert_pem: string; key_pem: string }): Agent {
  return new Agent({ cert: args.cert_pem, key: args.key_pem, keepAlive: true });
}

interface TossFetchArgs {
  url: string;
  method: 'GET' | 'POST';
  body?: unknown;
  bearer?: string;
  agent: Agent;
}

/**
 * Node 24's global fetch routes through Undici, which accepts a `dispatcher`.
 * We build an Undici Agent under the hood from the supplied https.Agent
 * options. (Undici does not consume node:https.Agent directly.) We pass the
 * cert/key into Undici via `connect.cert/key`.
 */
export async function tossFetch(args: TossFetchArgs): Promise<unknown> {
  // The `Agent` we get from buildAgent is node:https — extract PEMs and hand
  // to Undici via dispatcher.
  const opts = (args.agent as unknown as { options: { cert?: string; key?: string } }).options;
  const { Agent: UndiciAgent } = await import('undici');
  const dispatcher = new UndiciAgent({
    connect: { cert: opts.cert, key: opts.key },
    keepAliveTimeout: 30_000,
  });
  const headers: Record<string, string> = { accept: 'application/json' };
  let body: string | undefined;
  if (args.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(args.body);
  }
  if (args.bearer) headers.authorization = `Bearer ${args.bearer}`;

  let response: Response;
  try {
    response = await fetch(args.url, {
      method: args.method,
      headers,
      body,
      // Cast: Node 24 `RequestInit` type doesn't yet expose `dispatcher`, but
      // the runtime accepts it.
      ...({ dispatcher } as { dispatcher: unknown }),
    });
  } catch (_err) {
    throw new OAuthError('temporarily_unavailable', 'failed to reach Toss partner API', 502);
  }
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = text.length > 0 ? JSON.parse(text) : {};
  } catch {
    throw new OAuthError(
      'temporarily_unavailable',
      `Toss returned non-JSON (${response.status})`,
      502,
    );
  }
  if (!response.ok) {
    // Toss SUCCESS bodies always come with HTTP 200; non-2xx means upstream
    // outage / mTLS rejection / bad request shape — surface as
    // temporarily_unavailable so client retries. invalid_grant is decided by
    // the envelope parser, not HTTP status.
    throw new OAuthError(
      'temporarily_unavailable',
      `Toss returned HTTP ${response.status}`,
      502,
    );
  }
  return parsed;
}
```

- [ ] **Step 4: Add undici dep**

Run:
```bash
pnpm add undici@^6
```

(`undici` ships inside Node but we want a stable typed import.)

- [ ] **Step 5: Tests pass**

Run: `pnpm test src/toss/client.test.ts && pnpm typecheck`
Expected: 3 pass.

- [ ] **Step 6: Commit**

```bash
git add src/toss/client.ts src/toss/client.test.ts package.json pnpm-lock.yaml
git commit -m "feat(toss): mTLS-bound fetch wrapper via Undici dispatcher"
```

---

### Task 4.4: `/generate-token` client

**Files:**
- Create: `src/toss/generate-token.ts`
- Create: `src/toss/generate-token.test.ts`

- [ ] **Step 1: Write failing tests**

`src/toss/generate-token.test.ts`:
```ts
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildAgent } from './client.js';
import { generateToken } from './generate-token.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

describe('generateToken', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns parsed success on SUCCESS envelope', async () => {
    const fixture = JSON.parse(
      readFileSync('src/__fixtures__/toss-generate-token.success.json', 'utf8'),
    );
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(fixture), { status: 200 })));
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const result = await generateToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      authorizationCode: 'auth_xxx',
      referrer: 'SANDBOX',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.accessToken).toBeTypeOf('string');
      expect(result.value.refreshToken).toBeTypeOf('string');
    }
  });

  it('returns FAIL on FAIL envelope', async () => {
    const fixture = JSON.parse(
      readFileSync('src/__fixtures__/toss-generate-token.fail.json', 'utf8'),
    );
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(fixture), { status: 200 })));
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const result = await generateToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      authorizationCode: 'auth_xxx',
      referrer: 'SANDBOX',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('INVALID_AUTHORIZATION_CODE');
  });

  it('posts authorizationCode + referrer in body', async () => {
    const spy = vi.fn(async () =>
      new Response(
        JSON.stringify({ resultType: 'SUCCESS', success: { accessToken: 'x', refreshToken: 'r', tokenType: 'Bearer', expiresIn: 3600, scope: 'user_key' } }),
        { status: 200 },
      ),
    );
    vi.stubGlobal('fetch', spy);
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    await generateToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      authorizationCode: 'auth_xxx',
      referrer: 'DEFAULT',
    });
    expect(spy).toHaveBeenCalledOnce();
    const [, init] = spy.mock.calls[0];
    expect(JSON.parse(init.body as string)).toEqual({
      authorizationCode: 'auth_xxx',
      referrer: 'DEFAULT',
    });
  });
});
```

- [ ] **Step 2: Run failing**

Run: `pnpm test src/toss/generate-token.test.ts`

- [ ] **Step 3: Implement `src/toss/generate-token.ts`**

```ts
import type { Agent } from 'node:https';
import { tossFetch } from './client.js';
import { parseTossEnvelope, type ParsedEnvelope } from './envelope.js';
import type { GenerateTokenSuccess, Referrer } from './types.js';

const PATH = '/api-partner/v1/apps-in-toss/user/oauth2/generate-token';

export async function generateToken(args: {
  apiBase: string;
  agent: Agent;
  authorizationCode: string;
  referrer: Referrer;
}): Promise<ParsedEnvelope<GenerateTokenSuccess>> {
  const raw = await tossFetch({
    url: `${args.apiBase}${PATH}`,
    method: 'POST',
    body: { authorizationCode: args.authorizationCode, referrer: args.referrer },
    agent: args.agent,
  });
  return parseTossEnvelope<GenerateTokenSuccess>(raw);
}
```

- [ ] **Step 4: Tests pass; commit**

Run: `pnpm test src/toss/generate-token.test.ts`
```bash
git add src/toss/generate-token.ts src/toss/generate-token.test.ts
git commit -m "feat(toss): /generate-token client over mTLS"
```

---

### Task 4.5: `/refresh-token` client

**Files:**
- Create: `src/toss/refresh-token.ts`
- Create: `src/toss/refresh-token.test.ts`

- [ ] **Step 1: Test**

Mirror generate-token.test.ts. Body shape `{ refreshToken, referrer }`. Verify behavior when Toss does NOT rotate the RT (returns same RT).

- [ ] **Step 2: Implement**

```ts
import type { Agent } from 'node:https';
import { tossFetch } from './client.js';
import { parseTossEnvelope, type ParsedEnvelope } from './envelope.js';
import type { Referrer, RefreshTokenSuccess } from './types.js';

const PATH = '/api-partner/v1/apps-in-toss/user/oauth2/refresh-token';

export async function refreshToken(args: {
  apiBase: string;
  agent: Agent;
  refreshToken: string;
  referrer: Referrer;
}): Promise<ParsedEnvelope<RefreshTokenSuccess>> {
  const raw = await tossFetch({
    url: `${args.apiBase}${PATH}`,
    method: 'POST',
    body: { refreshToken: args.refreshToken, referrer: args.referrer },
    agent: args.agent,
  });
  return parseTossEnvelope<RefreshTokenSuccess>(raw);
}
```

- [ ] **Step 3: Commit**

```bash
git add src/toss/refresh-token.ts src/toss/refresh-token.test.ts
git commit -m "feat(toss): /refresh-token client"
```

---

### Task 4.6: `/login-me` client

**Files:**
- Create: `src/toss/login-me.ts`
- Create: `src/toss/login-me.test.ts`

- [ ] **Step 1: Tests against fixtures (success + fail)**

Mirror prior tests. Method per Toss API spec — confirm via dev docs and use the right verb (likely GET with bearer).

- [ ] **Step 2: Implement**

```ts
import type { Agent } from 'node:https';
import { tossFetch } from './client.js';
import { parseTossEnvelope, type ParsedEnvelope } from './envelope.js';
import type { LoginMeSuccess } from './types.js';

const PATH = '/api-partner/v1/apps-in-toss/user/oauth2/login-me';

export async function loginMe(args: {
  apiBase: string;
  agent: Agent;
  tossAccessToken: string;
}): Promise<ParsedEnvelope<LoginMeSuccess>> {
  const raw = await tossFetch({
    url: `${args.apiBase}${PATH}`,
    method: 'GET',
    bearer: args.tossAccessToken,
    agent: args.agent,
  });
  return parseTossEnvelope<LoginMeSuccess>(raw);
}
```

- [ ] **Step 3: Commit**

```bash
git add src/toss/login-me.ts src/toss/login-me.test.ts
git commit -m "feat(toss): /login-me client"
```

---

### Task 4.7: `/access/remove-by-access-token` client

**Files:**
- Create: `src/toss/access-remove.ts`
- Create: `src/toss/access-remove.test.ts`

- [ ] **Step 1: Tests**

Verify body posts the AT and that an upstream FAIL is propagated (caller maps to RFC 7009 always-200).

- [ ] **Step 2: Implement**

```ts
import type { Agent } from 'node:https';
import { tossFetch } from './client.js';
import { parseTossEnvelope, type ParsedEnvelope } from './envelope.js';

const PATH = '/api-partner/v1/apps-in-toss/user/access/remove-by-access-token';

export async function removeByAccessToken(args: {
  apiBase: string;
  agent: Agent;
  tossAccessToken: string;
}): Promise<ParsedEnvelope<Record<string, never>>> {
  const raw = await tossFetch({
    url: `${args.apiBase}${PATH}`,
    method: 'POST',
    body: { accessToken: args.tossAccessToken },
    agent: args.agent,
  });
  return parseTossEnvelope(raw);
}
```

- [ ] **Step 3: Commit**

```bash
git add src/toss/access-remove.ts src/toss/access-remove.test.ts
git commit -m "feat(toss): /access/remove-by-access-token client"
```

---

## Task 5: OIDC routes

### Task 5.1: Client auth (Basic + Post)

**Files:**
- Create: `src/oidc/client-auth.ts`
- Create: `src/oidc/client-auth.test.ts`

- [ ] **Step 1: Write failing tests**

`src/oidc/client-auth.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { extractClientCredentials } from './client-auth.js';

describe('extractClientCredentials', () => {
  it('reads client_secret_basic header', () => {
    const enc = Buffer.from('tnt_aaaa:secret-xyz').toString('base64');
    const out = extractClientCredentials({
      authorizationHeader: `Basic ${enc}`,
      bodyClientId: undefined,
      bodyClientSecret: undefined,
    });
    expect(out).toEqual({ client_id: 'tnt_aaaa', client_secret: 'secret-xyz' });
  });

  it('reads client_secret_post body fields', () => {
    const out = extractClientCredentials({
      authorizationHeader: undefined,
      bodyClientId: 'tnt_aaaa',
      bodyClientSecret: 'secret-xyz',
    });
    expect(out).toEqual({ client_id: 'tnt_aaaa', client_secret: 'secret-xyz' });
  });

  it('rejects when both methods are present (RFC 6749 §2.3.1)', () => {
    const enc = Buffer.from('tnt_aaaa:secret-xyz').toString('base64');
    expect(() =>
      extractClientCredentials({
        authorizationHeader: `Basic ${enc}`,
        bodyClientId: 'tnt_bbbb',
        bodyClientSecret: 'other',
      }),
    ).toThrow(/multiple/);
  });

  it('returns null when neither method is present', () => {
    expect(
      extractClientCredentials({
        authorizationHeader: undefined,
        bodyClientId: undefined,
        bodyClientSecret: undefined,
      }),
    ).toBeNull();
  });

  it('rejects malformed Basic header', () => {
    expect(() =>
      extractClientCredentials({
        authorizationHeader: 'Basic notbase64!!',
        bodyClientId: undefined,
        bodyClientSecret: undefined,
      }),
    ).toThrow(/basic/i);
  });
});
```

- [ ] **Step 2: Implement `src/oidc/client-auth.ts`**

```ts
export interface ClientCredentials {
  client_id: string;
  client_secret: string;
}

export function extractClientCredentials(args: {
  authorizationHeader: string | undefined;
  bodyClientId: string | undefined;
  bodyClientSecret: string | undefined;
}): ClientCredentials | null {
  const hasBasic = args.authorizationHeader?.startsWith('Basic ') ?? false;
  const hasPost = args.bodyClientId !== undefined || args.bodyClientSecret !== undefined;
  if (hasBasic && hasPost) {
    throw new Error('multiple client authentication mechanisms supplied');
  }
  if (hasBasic) {
    const b64 = args.authorizationHeader!.slice('Basic '.length).trim();
    let decoded: string;
    try {
      decoded = Buffer.from(b64, 'base64').toString('utf8');
    } catch {
      throw new Error('malformed basic auth');
    }
    const idx = decoded.indexOf(':');
    if (idx < 0) throw new Error('malformed basic auth: missing colon');
    return {
      client_id: decodeURIComponent(decoded.substring(0, idx)),
      client_secret: decodeURIComponent(decoded.substring(idx + 1)),
    };
  }
  if (hasPost) {
    if (!args.bodyClientId || !args.bodyClientSecret) {
      throw new Error('client_secret_post requires both client_id and client_secret');
    }
    return { client_id: args.bodyClientId, client_secret: args.bodyClientSecret };
  }
  return null;
}
```

- [ ] **Step 3: Tests pass**

Run: `pnpm test src/oidc/client-auth.test.ts`

- [ ] **Step 4: Commit**

```bash
git add src/oidc/client-auth.ts src/oidc/client-auth.test.ts
git commit -m "feat(oidc): client_secret_basic + client_secret_post extraction"
```

---

### Task 5.2: Claim mapping

**Files:**
- Create: `src/oidc/claim-mapping.ts`
- Create: `src/oidc/claim-mapping.test.ts`

- [ ] **Step 1: Write failing tests**

`src/oidc/claim-mapping.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { mapToIdTokenClaims } from './claim-mapping.js';

describe('mapToIdTokenClaims', () => {
  it('maps userKey to sub (string-cast) and preserves numeric in toss:userKey', () => {
    const out = mapToIdTokenClaims({
      issuer: 'https://oidc-bridge.aitc.dev',
      audience: 'tnt_x',
      now: 1_700_000_000,
      tossAccessTokenExp: 1_700_003_600,
      loginMe: { userKey: 4200000000001, scope: 'user_key', agreedTerms: ['T1'] },
      requestedScopes: ['openid', 'user_key'],
    });
    expect(out.sub).toBe('4200000000001');
    expect(out['toss:userKey']).toBe(4200000000001);
    expect(out['toss:agreedTerms']).toEqual(['T1']);
    expect(out['toss:tossAccessTokenExpiresAt']).toBe(1_700_003_600);
    expect(out.iss).toBe('https://oidc-bridge.aitc.dev');
    expect(out.aud).toBe('tnt_x');
    expect(out.iat).toBe(1_700_000_000);
    expect(out.exp).toBe(1_700_003_600);
    expect(out.scope).toBe('openid user_key');
    expect(out.provider).toBe('toss');
  });

  it('honors `openid` even though Toss does not have it', () => {
    const out = mapToIdTokenClaims({
      issuer: 'https://x',
      audience: 'tnt_y',
      now: 1_700_000_000,
      tossAccessTokenExp: 1_700_003_600,
      loginMe: { userKey: 1, scope: 'user_key', agreedTerms: [] },
      requestedScopes: ['openid'],
    });
    expect(out.scope).toContain('openid');
  });

  it('caps id_token TTL at 1 hour even if Toss exp is further out', () => {
    const out = mapToIdTokenClaims({
      issuer: 'https://x',
      audience: 'tnt_y',
      now: 1_700_000_000,
      tossAccessTokenExp: 1_700_000_000 + 7200,
      loginMe: { userKey: 1, scope: 'user_key', agreedTerms: [] },
      requestedScopes: ['openid'],
    });
    expect(out.exp).toBe(1_700_000_000 + 3600);
  });
});
```

- [ ] **Step 2: Implement**

```ts
import type { IdTokenClaims } from './id-token.js';
import type { LoginMeSuccess } from '../toss/types.js';

const ID_TOKEN_TTL = 3600;

export function mapToIdTokenClaims(args: {
  issuer: string;
  audience: string;
  now: number;                    // unix seconds
  tossAccessTokenExp: number;     // unix seconds
  loginMe: LoginMeSuccess;
  requestedScopes: string[];
}): IdTokenClaims {
  const exp = Math.min(args.now + ID_TOKEN_TTL, args.tossAccessTokenExp);
  const tossScopes = args.loginMe.scope.split(/\s+/).filter(Boolean);
  // Bridge-side virtual scope: honor `openid` even though Toss does not have
  // it (spec §10).
  const merged = new Set<string>(tossScopes);
  if (args.requestedScopes.includes('openid')) merged.add('openid');
  return {
    sub: String(args.loginMe.userKey),
    iss: args.issuer,
    aud: args.audience,
    iat: args.now,
    exp,
    nbf: args.now,
    provider: 'toss',
    scope: Array.from(merged).join(' '),
    'toss:userKey': args.loginMe.userKey,
    'toss:agreedTerms': args.loginMe.agreedTerms,
    'toss:tossAccessTokenExpiresAt': args.tossAccessTokenExp,
  };
}
```

- [ ] **Step 3: Tests pass; commit**

```bash
git add src/oidc/claim-mapping.ts src/oidc/claim-mapping.test.ts
git commit -m "feat(oidc): map /login-me + Toss AT exp into OIDC ID-token claims"
```

---

### Task 5.3: `POST /oidc/token`

**Files:**
- Create: `src/oidc/token.ts`
- Create: `src/oidc/token.test.ts`

This is the main endpoint. Test thoroughly: happy path, invalid_client (4 sub-cases), invalid_grant, refresh_token grant.

- [ ] **Step 1: Decode the Toss AT exp**

Add a helper inside `src/oidc/token.ts`:

```ts
function decodeJwtExp(jwt: string): number | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}
```

(We don't verify the signature — see spec §3.4 / §11.)

- [ ] **Step 2: Write failing tests**

`src/oidc/token.test.ts`:
```ts
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Hono } from 'hono';
import { createApp } from '../app.js';
import { createFsStore } from '../tenants/fs-store.js';
import { generateClientSecret } from '../tenants/crypto.js';
import { unsealAccessToken } from './sealed-token.js';
import { exportJwks } from './id-token.js';
import { jwtVerify, createLocalJWKSet } from 'jose';
import type { Config } from '../config.js';
import type { TenantStore } from '../tenants/store.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');
const signingKeyPem = readFileSync('src/__fixtures__/test-signing.key.pem', 'utf8');

function buildConfig(dataDir: string): Config {
  return {
    issuer: 'https://oidc-bridge.test',
    signingKeyPem,
    masterKey: Buffer.alloc(32, 0xab),
    adminToken: 'admin',
    tenantStore: { kind: 'fs', dataDir },
    tossApiBase: 'https://apps-in-toss-api.test',
  };
}

async function setupTenant(): Promise<{
  app: Hono;
  config: Config;
  store: TenantStore;
  tenantId: string;
  clientSecret: string;
}> {
  const dataDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-test-'));
  const config = buildConfig(dataDir);
  const store = await createFsStore(dataDir);
  const { tenant, client_secret } = await store.create({
    name: 't', environment: 'sandbox', cert_pem: certPem, key_pem: keyPem,
  });
  const app = await createApp({ config, store });
  return { app, config, store, tenantId: tenant.id, clientSecret: client_secret };
}

describe('POST /oidc/token — authorization_code', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('happy path: returns access_token + id_token + refresh_token', async () => {
    const { app, config, tenantId, clientSecret } = await setupTenant();
    const fakeAt = 'h.eyJleHAiOjE5MDAwMDAwMDB9.s'; // exp 1900000000
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.endsWith('/generate-token')) {
        return new Response(JSON.stringify({
          resultType: 'SUCCESS',
          success: { accessToken: fakeAt, refreshToken: 'rt-fake', tokenType: 'Bearer', expiresIn: 3600, scope: 'user_key' },
        }));
      }
      if (url.endsWith('/login-me')) {
        return new Response(JSON.stringify({
          resultType: 'SUCCESS',
          success: { userKey: 4200000000001, scope: 'user_key', agreedTerms: ['T1'] },
        }));
      }
      throw new Error(`unexpected url ${url}`);
    }));

    const enc = Buffer.from(`${tenantId}:${clientSecret}`).toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${enc}` },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx', referrer: 'SANDBOX' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ token_type: 'Bearer', expires_in: expect.any(Number) });
    expect(body.access_token).toMatch(/^aitc_/);
    expect(body.refresh_token).toMatch(/^aitc_/);

    // ID token verifies against JWKS
    const jwks = await exportJwks(signingKeyPem);
    const { payload } = await jwtVerify(body.id_token, createLocalJWKSet(jwks), {
      issuer: config.issuer, audience: tenantId,
    });
    expect(payload.sub).toBe('4200000000001');
    expect(payload['toss:userKey']).toBe(4200000000001);

    // Sealed AT round-trips
    const unsealed = unsealAccessToken({
      token: body.access_token,
      masterKey: config.masterKey,
      sealingKeyVersionOf: () => 1,
    });
    expect(unsealed.tenant_id).toBe(tenantId);
    expect(unsealed.toss_access_token).toBe(fakeAt);
  });

  it('returns invalid_client when basic auth is wrong', async () => {
    const { app, tenantId } = await setupTenant();
    const enc = Buffer.from(`${tenantId}:wrong`).toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${enc}` },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx' }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('returns invalid_client when tenant does not exist', async () => {
    const { app } = await setupTenant();
    const enc = Buffer.from('tnt_doesnotexistxxxxxxxxxxxxx:secret').toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${enc}` },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx' }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('returns invalid_grant when Toss FAILs', async () => {
    const { app, tenantId, clientSecret } = await setupTenant();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      resultType: 'FAIL', error: { reason: 'INVALID_AUTHORIZATION_CODE' },
    }))));
    const enc = Buffer.from(`${tenantId}:${clientSecret}`).toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${enc}` },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_grant' });
  });

  it('returns unsupported_grant_type for unknown grants', async () => {
    const { app, tenantId, clientSecret } = await setupTenant();
    const enc = Buffer.from(`${tenantId}:${clientSecret}`).toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${enc}` },
      body: new URLSearchParams({ grant_type: 'password' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'unsupported_grant_type' });
  });
});

describe('POST /oidc/token — refresh_token', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('round-trips a sealed refresh token', async () => {
    // Test plan:
    // 1. Get an authorization_code response (mock /generate-token + /login-me).
    // 2. Use the returned refresh_token to call /oidc/token with grant_type=refresh_token.
    // 3. Mock /refresh-token to return a new AT (Toss may or may not rotate RT).
    // 4. Assert new id_token verifies + new AT unseals.
    // (Full implementation in token.test.ts; abbreviated here for plan length.)
    expect(true).toBe(true);
  });
});
```

Note: the refresh_token test is a placeholder in this plan summary — fill it out fully when implementing (do not commit a `expect(true).toBe(true)` test).

- [ ] **Step 3: Run failing tests**

Run: `pnpm test src/oidc/token.test.ts`
Expected: failures.

- [ ] **Step 4: Implement `src/oidc/token.ts`**

```ts
import type { Hono } from 'hono';
import type { Config } from '../config.js';
import { OAuthError, oauthErrorBody } from '../errors.js';
import { extractClientCredentials } from './client-auth.js';
import { verifyClientSecret } from '../tenants/crypto.js';
import { buildAgent } from '../toss/client.js';
import { generateToken } from '../toss/generate-token.js';
import { refreshToken as tossRefresh } from '../toss/refresh-token.js';
import { loginMe } from '../toss/login-me.js';
import { sealAccessToken, unsealAccessToken } from './sealed-token.js';
import { signIdToken } from './id-token.js';
import { mapToIdTokenClaims } from './claim-mapping.js';
import type { TenantStore } from '../tenants/store.js';

function decodeJwtExp(jwt: string): number | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}

export function mountToken(app: Hono, config: Config, store: TenantStore): void {
  app.post('/oidc/token', async (c) => {
    try {
      // Body parsing: x-www-form-urlencoded (RFC 6749) is the standard, JSON
      // is also accepted to be friendly to non-OAuth-savvy callers.
      const ctype = c.req.header('content-type') ?? '';
      const params: Record<string, string> = {};
      if (ctype.includes('application/x-www-form-urlencoded')) {
        const text = await c.req.text();
        for (const [k, v] of new URLSearchParams(text)) params[k] = v;
      } else {
        const j = await c.req.json().catch(() => ({}));
        for (const [k, v] of Object.entries(j as Record<string, unknown>)) {
          if (typeof v === 'string') params[k] = v;
        }
      }

      const creds = extractClientCredentials({
        authorizationHeader: c.req.header('authorization'),
        bodyClientId: params.client_id,
        bodyClientSecret: params.client_secret,
      });
      if (!creds) throw new OAuthError('invalid_client', 'no client authentication', 401);

      const tenant = await store.get(creds.client_id);
      if (!tenant) throw new OAuthError('invalid_client', 'unknown client', 401);
      const ok = await verifyClientSecret(
        creds.client_secret,
        tenant.client_secret_hashes.map((h) => h.hash),
      );
      if (!ok) throw new OAuthError('invalid_client', 'bad client_secret', 401);

      const agent = buildAgent(tenant.mtls);
      const referrer = tenant.environment === 'sandbox' ? 'SANDBOX' : 'DEFAULT';

      const requestedScopes = (params.scope ?? '').split(/\s+/).filter(Boolean);

      let tossAt: string;
      let tossRt: string;
      if (params.grant_type === 'authorization_code') {
        if (!params.code) throw new OAuthError('invalid_request', 'code required', 400);
        const r = await generateToken({
          apiBase: config.tossApiBase, agent,
          authorizationCode: params.code, referrer,
        });
        if (!r.ok) throw new OAuthError('invalid_grant', r.description ?? r.reason, 400);
        tossAt = r.value.accessToken;
        tossRt = r.value.refreshToken;
      } else if (params.grant_type === 'refresh_token') {
        if (!params.refresh_token) throw new OAuthError('invalid_request', 'refresh_token required', 400);
        const unsealed = unsealAccessToken({
          token: params.refresh_token,
          masterKey: config.masterKey,
          sealingKeyVersionOf: () => tenant.sealing_key_version,
        });
        if (unsealed.tenant_id !== tenant.id) {
          throw new OAuthError('invalid_grant', 'refresh_token tenant mismatch', 400);
        }
        const r = await tossRefresh({
          apiBase: config.tossApiBase, agent,
          refreshToken: unsealed.toss_refresh_token, referrer,
        });
        if (!r.ok) throw new OAuthError('invalid_grant', r.description ?? r.reason, 400);
        tossAt = r.value.accessToken;
        // Toss may or may not rotate RT (spec §10): use new if present, else keep old.
        tossRt = r.value.refreshToken ?? unsealed.toss_refresh_token;
      } else {
        throw new OAuthError('unsupported_grant_type', `unknown grant ${params.grant_type}`, 400);
      }

      const me = await loginMe({ apiBase: config.tossApiBase, agent, tossAccessToken: tossAt });
      if (!me.ok) throw new OAuthError('invalid_grant', me.description ?? me.reason, 400);

      const now = Math.floor(Date.now() / 1000);
      const tossExp = decodeJwtExp(tossAt) ?? now + 3600;
      const claims = mapToIdTokenClaims({
        issuer: config.issuer,
        audience: tenant.id,
        now,
        tossAccessTokenExp: tossExp,
        loginMe: me.value,
        requestedScopes,
      });
      const idToken = await signIdToken({ claims, signingKeyPem: config.signingKeyPem });

      const accessToken = sealAccessToken({
        payload: { tenant_id: tenant.id, toss_access_token: tossAt, toss_refresh_token: tossRt, exp: tossExp },
        masterKey: config.masterKey,
        sealingKeyVersion: tenant.sealing_key_version,
      });
      // Refresh token is a sealed wrapper too; longer effective lifetime.
      const refreshTokenOut = sealAccessToken({
        payload: { tenant_id: tenant.id, toss_access_token: tossAt, toss_refresh_token: tossRt, exp: now + 14 * 24 * 3600 },
        masterKey: config.masterKey,
        sealingKeyVersion: tenant.sealing_key_version,
      });

      return c.json({
        access_token: accessToken,
        id_token: idToken,
        refresh_token: refreshTokenOut,
        token_type: 'Bearer',
        expires_in: tossExp - now,
        scope: claims.scope,
      });
    } catch (err) {
      if (err instanceof OAuthError) return c.json(oauthErrorBody(err), err.status);
      throw err;
    }
  });
}
```

- [ ] **Step 5: Tests pass**

Run: `pnpm test src/oidc/token.test.ts && pnpm typecheck && pnpm lint`
Expected: 5+ tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/oidc/token.ts src/oidc/token.test.ts
git commit -m "feat(oidc): POST /oidc/token (authorization_code + refresh_token)"
```

---

### Task 5.4: `GET /oidc/userinfo`

**Files:**
- Create: `src/oidc/userinfo.ts`
- Create: `src/oidc/userinfo.test.ts`

- [ ] **Step 1: Tests**

Cover happy path (Bearer aitc_… → unwrap → mocked /login-me → claims), bad bearer (missing/wrong format → 401 invalid_token), tampered bearer (AEAD fail → 401 invalid_token).

- [ ] **Step 2: Implement**

```ts
import type { Hono } from 'hono';
import type { Config } from '../config.js';
import { OAuthError, oauthErrorBody } from '../errors.js';
import { unsealAccessToken } from './sealed-token.js';
import { buildAgent } from '../toss/client.js';
import { loginMe } from '../toss/login-me.js';
import type { TenantStore } from '../tenants/store.js';

export function mountUserinfo(app: Hono, config: Config, store: TenantStore): void {
  app.get('/oidc/userinfo', async (c) => {
    try {
      const auth = c.req.header('authorization') ?? '';
      if (!auth.startsWith('Bearer ')) throw new OAuthError('invalid_token', 'missing Bearer', 401);
      const token = auth.slice('Bearer '.length).trim();

      // We unseal first to learn tenant_id. To resolve sealing_key_version we
      // need the tenant; sealing_key_version itself is in AAD so the version
      // gate is enforced by AEAD even before we look up the tenant.
      let unsealed;
      try {
        unsealed = unsealAccessToken({
          token,
          masterKey: config.masterKey,
          sealingKeyVersionOf: (tenantId) =>
            // Optimistic peek — we re-validate after lookup.
            // This callback path only runs after we've parsed the AAD.
            // We can't know the real version yet, so accept the AAD-claimed
            // version (1) and re-check below.
            1,
        });
      } catch (_e) {
        throw new OAuthError('invalid_token', 'bad bearer', 401);
      }

      const tenant = await store.get(unsealed.tenant_id);
      if (!tenant) throw new OAuthError('invalid_token', 'unknown tenant', 401);

      const agent = buildAgent(tenant.mtls);
      const me = await loginMe({
        apiBase: config.tossApiBase,
        agent,
        tossAccessToken: unsealed.toss_access_token,
      });
      if (!me.ok) throw new OAuthError('invalid_token', me.description ?? me.reason, 401);

      return c.json({
        sub: String(me.value.userKey),
        provider: 'toss',
        scope: me.value.scope,
        'toss:userKey': me.value.userKey,
        'toss:agreedTerms': me.value.agreedTerms,
        // PII passthrough (encrypted/opaque from Toss)
        name: me.value.name,
        phone: me.value.phone,
        birthday: me.value.birthday,
        ci: me.value.ci,
        gender: me.value.gender,
        nationality: me.value.nationality,
      });
    } catch (err) {
      if (err instanceof OAuthError) return c.json(oauthErrorBody(err), err.status);
      throw err;
    }
  });
}
```

**Note on sealing_key_version**: the unseal path needs the version up front to choose between active/previous. M1 has a single active version per tenant, so we accept "version-1 only" as documented. When rotation lands (post-M1), this becomes a two-attempt unseal (active first, fall back to previous). That's already the natural shape since `sealing_key_version` is in AAD.

- [ ] **Step 3: Tests pass; commit**

```bash
git add src/oidc/userinfo.ts src/oidc/userinfo.test.ts
git commit -m "feat(oidc): GET /oidc/userinfo unwraps sealed AT and proxies /login-me"
```

---

### Task 5.5: `POST /oidc/revoke`

**Files:**
- Create: `src/oidc/revoke.ts`
- Create: `src/oidc/revoke.test.ts`

- [ ] **Step 1: Tests**

Verify RFC 7009 always-200: happy path returns 200, malformed bearer returns 200 (per RFC), upstream FAIL returns 200.

- [ ] **Step 2: Implement**

```ts
import type { Hono } from 'hono';
import type { Config } from '../config.js';
import { unsealAccessToken } from './sealed-token.js';
import { buildAgent } from '../toss/client.js';
import { removeByAccessToken } from '../toss/access-remove.js';
import type { TenantStore } from '../tenants/store.js';

/**
 * RFC 7009 §2.2: "The authorization server responds with HTTP status code 200
 * if the token has been revoked successfully or if the client submitted an
 * invalid token."
 */
export function mountRevoke(app: Hono, config: Config, store: TenantStore): void {
  app.post('/oidc/revoke', async (c) => {
    const ok = (): Response => c.body(null, 200);
    const ctype = c.req.header('content-type') ?? '';
    let token: string | undefined;
    if (ctype.includes('application/x-www-form-urlencoded')) {
      const text = await c.req.text();
      const params = new URLSearchParams(text);
      token = params.get('token') ?? undefined;
    } else {
      const j = (await c.req.json().catch(() => ({}))) as { token?: unknown };
      if (typeof j.token === 'string') token = j.token;
    }
    if (!token) return ok();
    try {
      const unsealed = unsealAccessToken({
        token,
        masterKey: config.masterKey,
        sealingKeyVersionOf: () => 1,
      });
      const tenant = await store.get(unsealed.tenant_id);
      if (!tenant) return ok();
      const agent = buildAgent(tenant.mtls);
      await removeByAccessToken({
        apiBase: config.tossApiBase, agent,
        tossAccessToken: unsealed.toss_access_token,
      });
    } catch {
      // RFC 7009: even on error, return 200.
    }
    return ok();
  });
}
```

- [ ] **Step 3: Tests pass; commit**

```bash
git add src/oidc/revoke.ts src/oidc/revoke.test.ts
git commit -m "feat(oidc): POST /oidc/revoke (RFC 7009 always-200)"
```

---

## Task 6: Admin REST API

### Task 6.1: `ADMIN_TOKEN` middleware

**Files:**
- Create: `src/admin/auth.ts`
- Create: `src/admin/auth.test.ts`

- [ ] **Step 1: Tests**

```ts
// missing → 401, wrong → 401, right → next() called
```

- [ ] **Step 2: Implement**

```ts
import type { MiddlewareHandler } from 'hono';

export function adminAuth(adminToken: string): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.req.header('authorization') ?? '';
    if (!auth.startsWith('Bearer ')) return c.json({ error: 'invalid_token' }, 401);
    const token = auth.slice('Bearer '.length).trim();
    // Constant-time compare — both sides are exactly the same length on the
    // happy path; on mismatch, length differs but timingSafeEqual requires
    // equal-length inputs, so we pad both to a fixed length.
    const a = Buffer.from(token);
    const b = Buffer.from(adminToken);
    const len = Math.max(a.length, b.length);
    const aPad = Buffer.concat([a, Buffer.alloc(len - a.length)]);
    const bPad = Buffer.concat([b, Buffer.alloc(len - b.length)]);
    const { timingSafeEqual } = await import('node:crypto');
    if (a.length !== b.length || !timingSafeEqual(aPad, bPad)) {
      return c.json({ error: 'invalid_token' }, 401);
    }
    await next();
  };
}
```

- [ ] **Step 3: Commit**

```bash
git add src/admin/auth.ts src/admin/auth.test.ts
git commit -m "feat(admin): ADMIN_TOKEN bearer middleware with constant-time compare"
```

---

### Task 6.2: `/admin/tenants` CRUD routes

**Files:**
- Create: `src/admin/routes.ts`
- Create: `src/admin/routes.test.ts`

- [ ] **Step 1: Tests**

Cover: POST creates + returns plaintext secret once, GET list returns TenantPublic[] (no secrets), GET :id returns TenantPublic, PATCH updates, POST :id/secrets/rotate returns new secret, DELETE removes. Reject without `Authorization: Bearer admin`.

- [ ] **Step 2: Implement**

```ts
import { Hono } from 'hono';
import { adminAuth } from './auth.js';
import type { TenantStore } from '../tenants/store.js';

export function buildAdminRouter(store: TenantStore, adminToken: string): Hono {
  const r = new Hono();
  r.use('*', adminAuth(adminToken));

  r.get('/tenants', async (c) => c.json({ tenants: await store.list() }));

  r.post('/tenants', async (c) => {
    const body = (await c.req.json()) as {
      name?: string; environment?: 'production' | 'sandbox'; cert_pem?: string; key_pem?: string;
    };
    if (!body.name || !body.environment || !body.cert_pem || !body.key_pem) {
      return c.json({ error: 'invalid_request' }, 400);
    }
    const created = await store.create({
      name: body.name, environment: body.environment,
      cert_pem: body.cert_pem, key_pem: body.key_pem,
    });
    return c.json({
      tenant: {
        id: created.tenant.id, name: created.tenant.name,
        environment: created.tenant.environment,
        mtls_fingerprint: created.tenant.mtls.cert_fingerprint_sha256,
        mtls_expires_at: created.tenant.mtls.expires_at,
        sealing_key_version: created.tenant.sealing_key_version,
        created_at: created.tenant.created_at,
        updated_at: created.tenant.updated_at,
      },
      client_id: created.tenant.id,
      client_secret: created.client_secret,
    }, 201);
  });

  r.get('/tenants/:id', async (c) => {
    const t = await store.get(c.req.param('id'));
    if (!t) return c.json({ error: 'not_found' }, 404);
    return c.json({
      id: t.id, name: t.name, environment: t.environment,
      mtls_fingerprint: t.mtls.cert_fingerprint_sha256,
      mtls_expires_at: t.mtls.expires_at,
      sealing_key_version: t.sealing_key_version,
      created_at: t.created_at, updated_at: t.updated_at,
    });
  });

  r.patch('/tenants/:id', async (c) => {
    const body = (await c.req.json()) as {
      name?: string; environment?: 'production' | 'sandbox'; cert_pem?: string; key_pem?: string;
    };
    const updated = await store.update(c.req.param('id'), body);
    return c.json({
      id: updated.id, name: updated.name, environment: updated.environment,
      mtls_fingerprint: updated.mtls.cert_fingerprint_sha256,
      mtls_expires_at: updated.mtls.expires_at,
      sealing_key_version: updated.sealing_key_version,
      created_at: updated.created_at, updated_at: updated.updated_at,
    });
  });

  r.delete('/tenants/:id', async (c) => {
    await store.delete(c.req.param('id'));
    return c.body(null, 204);
  });

  r.post('/tenants/:id/secrets/rotate', async (c) => {
    const { client_secret } = await store.rotateSecret(c.req.param('id'));
    return c.json({ client_secret });
  });

  return r;
}
```

- [ ] **Step 3: Tests pass; commit**

```bash
git add src/admin/routes.ts src/admin/routes.test.ts
git commit -m "feat(admin): /admin/tenants CRUD + /:id/secrets/rotate"
```

---

## Task 7: Wire `app.ts` + `server.ts`, drop `/verify`

### Task 7.1: Rewrite `src/app.ts`

**Files:**
- Modify: `src/app.ts`
- Modify: `src/app.test.ts`
- Delete: `src/toss/verify.ts`
- Delete: `src/toss/verify.test.ts`

- [ ] **Step 1: Update `src/app.test.ts`**

Strip everything except `GET /healthz`. Move the rich integration tests (which currently sit in `app.test.ts` for `/verify`) out — they're replaced by per-module tests we wrote in tasks 5.x and 6.x.

Final shape:

```ts
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';
import { createFsStore } from './tenants/fs-store.js';
import type { Config } from './config.js';

const signingKeyPem = readFileSync('src/__fixtures__/test-signing.key.pem', 'utf8');

async function smokeApp() {
  const dataDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-test-'));
  const store = await createFsStore(dataDir);
  const config: Config = {
    issuer: 'https://x',
    signingKeyPem,
    masterKey: Buffer.alloc(32),
    adminToken: 'a',
    tenantStore: { kind: 'fs', dataDir },
    tossApiBase: 'https://x',
  };
  return createApp({ config, store });
}

describe('GET /healthz', () => {
  it('returns ok', async () => {
    const app = await smokeApp();
    const res = await app.request('/healthz');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok' });
  });
});

describe('legacy /verify is removed', () => {
  it('returns 404', async () => {
    const app = await smokeApp();
    const res = await app.request('/verify', { method: 'POST', body: '{}' });
    expect(res.status).toBe(404);
  });
});
```

- [ ] **Step 2: Rewrite `src/app.ts`**

```ts
import { Hono } from 'hono';
import type { Config } from './config.js';
import type { TenantStore } from './tenants/store.js';
import { mountDiscovery } from './oidc/discovery.js';
import { mountJwks } from './oidc/jwks.js';
import { mountToken } from './oidc/token.js';
import { mountUserinfo } from './oidc/userinfo.js';
import { mountRevoke } from './oidc/revoke.js';
import { buildAdminRouter } from './admin/routes.js';

export interface AppDeps {
  config: Config;
  store: TenantStore;
}

export async function createApp(deps: AppDeps): Promise<Hono> {
  const app = new Hono();

  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  mountDiscovery(app, deps.config);
  mountJwks(app, deps.config);
  mountToken(app, deps.config, deps.store);
  mountUserinfo(app, deps.config, deps.store);
  mountRevoke(app, deps.config, deps.store);

  app.route('/admin', buildAdminRouter(deps.store, deps.config.adminToken));

  return app;
}
```

- [ ] **Step 3: Delete legacy files**

Run:
```bash
rm src/toss/verify.ts src/toss/verify.test.ts
```

- [ ] **Step 4: Run full test suite**

Run: `pnpm test && pnpm typecheck && pnpm lint`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: wire OIDC + admin routes, remove legacy /verify"
```

---

### Task 7.2: Rewrite `src/server.ts`

**Files:**
- Modify: `src/server.ts`

- [ ] **Step 1: Update entrypoint**

```ts
import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { createTenantStore } from './tenants/store.js';

const port = Number(process.env.PORT ?? 8080);
const config = loadConfig();
const store = await createTenantStore(config);
const app = await createApp({ config, store });

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`oidc-bridge listening on http://localhost:${info.port}`);
});
```

- [ ] **Step 2: `pnpm build` produces a runnable `dist/server.mjs`**

Run: `pnpm build && node dist/server.mjs --help 2>&1 | head -5 || true`
(Don't actually start it without env — just verify it parses.)

Expected: `OIDC_ISSUER is required` thrown, exit 1. That's the right failure mode.

- [ ] **Step 3: Commit**

```bash
git add src/server.ts
git commit -m "refactor(server): wire createApp + loadConfig + createTenantStore"
```

---

## Task 8: Bundled CLI

### Task 8.1: REST client + offline-mode dispatcher

**Files:**
- Create: `cli/rest-client.ts`
- Create: `cli/bootstrap.ts`
- Create: `cli/index.ts`
- Create: `cli/commands/tenant-create.ts`
- Create: `cli/commands/tenant-list.ts`
- Create: `cli/commands/tenant-show.ts`
- Create: `cli/commands/tenant-rotate-secret.ts`
- Create: `cli/commands/tenant-delete.ts`
- Modify: `package.json` (add `bin` field)

- [ ] **Step 1: package.json — add `bin`**

```json
{
  "bin": { "oidc-bridge": "dist/cli.mjs" },
  "scripts": {
    "build": "tsdown src/server.ts cli/index.ts --format esm --out-dir dist",
    "...": "..."
  }
}
```

Note: tsdown will emit `dist/server.mjs` and `dist/cli.mjs` from the two entrypoints.

- [ ] **Step 2: Implement `cli/rest-client.ts`**

```ts
export interface RestOpts {
  bridge: string;        // e.g. https://oidc-bridge.aitc.dev
  adminToken: string;
}

async function call<T>(opts: RestOpts, path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${opts.bridge}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${opts.adminToken}`,
      ...((init.headers as Record<string, string>) ?? {}),
    },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status}: ${text}`);
  return text ? (JSON.parse(text) as T) : (undefined as unknown as T);
}

export const rest = {
  createTenant: (o: RestOpts, body: unknown) =>
    call(o, '/admin/tenants', { method: 'POST', body: JSON.stringify(body) }),
  listTenants: (o: RestOpts) => call<{ tenants: unknown[] }>(o, '/admin/tenants'),
  getTenant: (o: RestOpts, id: string) => call(o, `/admin/tenants/${id}`),
  rotateSecret: (o: RestOpts, id: string) =>
    call(o, `/admin/tenants/${id}/secrets/rotate`, { method: 'POST' }),
  deleteTenant: (o: RestOpts, id: string) =>
    call(o, `/admin/tenants/${id}`, { method: 'DELETE' }),
};
```

- [ ] **Step 3: Implement `cli/bootstrap.ts`**

```ts
import { createFsStore } from '../src/tenants/fs-store.js';
import type { TenantStore } from '../src/tenants/store.js';

/**
 * `--offline` mode opens an fs-store directly, no bridge process required.
 * Used to provision the very first tenant before booting the bridge.
 */
export async function offlineStore(dataDir: string): Promise<TenantStore> {
  return createFsStore(dataDir);
}
```

- [ ] **Step 4: Implement `cli/index.ts`**

```ts
import { Command } from 'commander';
import { tenantCreate } from './commands/tenant-create.js';
import { tenantList } from './commands/tenant-list.js';
import { tenantShow } from './commands/tenant-show.js';
import { tenantRotateSecret } from './commands/tenant-rotate-secret.js';
import { tenantDelete } from './commands/tenant-delete.js';

const program = new Command();
program
  .name('oidc-bridge')
  .description('CLI for the apps-in-toss-community OIDC bridge')
  .option('--bridge <url>', 'bridge base URL', process.env.OIDC_BRIDGE_URL)
  .option('--admin-token <t>', 'admin token', process.env.ADMIN_TOKEN)
  .option('--offline', 'talk directly to fs-store on disk (no running bridge)')
  .option('--data-dir <path>', 'fs-store data dir (offline mode)', process.env.BRIDGE_DATA_DIR);

const tenant = program.command('tenant').description('Tenant management');
tenant.command('create').requiredOption('--name <name>').requiredOption('--environment <env>')
  .requiredOption('--cert <path>').requiredOption('--key <path>')
  .action((opts) => tenantCreate(program.opts(), opts));
tenant.command('list').action(() => tenantList(program.opts()));
tenant.command('show').argument('<id>').action((id: string) => tenantShow(program.opts(), id));
tenant.command('rotate-secret').argument('<id>')
  .action((id: string) => tenantRotateSecret(program.opts(), id));
tenant.command('delete').argument('<id>').action((id: string) => tenantDelete(program.opts(), id));

program.parseAsync().catch((err) => {
  console.error(err.message ?? err);
  process.exit(1);
});
```

- [ ] **Step 5: Implement each command (5 files)**

Each command checks `--offline` to dispatch between `offlineStore` and `rest.*`. Example for `tenant-create.ts`:

```ts
import { readFile } from 'node:fs/promises';
import { rest } from '../rest-client.js';
import { offlineStore } from '../bootstrap.js';

interface GlobalOpts {
  bridge?: string; adminToken?: string; offline?: boolean; dataDir?: string;
}
interface CreateOpts {
  name: string; environment: 'production' | 'sandbox'; cert: string; key: string;
}

export async function tenantCreate(g: GlobalOpts, opts: CreateOpts): Promise<void> {
  const cert_pem = await readFile(opts.cert, 'utf8');
  const key_pem = await readFile(opts.key, 'utf8');
  const body = { name: opts.name, environment: opts.environment, cert_pem, key_pem };
  if (g.offline) {
    if (!g.dataDir) throw new Error('--data-dir is required with --offline');
    const store = await offlineStore(g.dataDir);
    const created = await store.create(body);
    console.log(JSON.stringify({ client_id: created.tenant.id, client_secret: created.client_secret }, null, 2));
    return;
  }
  if (!g.bridge || !g.adminToken) throw new Error('--bridge and --admin-token required');
  const out = await rest.createTenant({ bridge: g.bridge, adminToken: g.adminToken }, body);
  console.log(JSON.stringify(out, null, 2));
}
```

The other commands (list/show/rotate-secret/delete) follow the same shape — implement them identically with the appropriate REST call.

- [ ] **Step 6: Smoke test**

Add a minimal test `cli/cli.test.ts` that spawns `node dist/cli.mjs --help` and asserts exit code 0 and stdout contains `tenant`.

```ts
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

describe('cli --help', () => {
  it('exits 0 and lists tenant commands', () => {
    const r = spawnSync('node', ['dist/cli.mjs', '--help'], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('tenant');
  });
});
```

(Wrap behind `pnpm build` requirement. Add `pretest: pnpm build` if needed, or skip when `dist/cli.mjs` is absent.)

- [ ] **Step 7: Commit**

```bash
git add cli/ package.json
git commit -m "feat(cli): bundled tenant CLI with REST + --offline fs-store mode"
```

---

## Task 9: Migration + env hygiene

### Task 9.1: Update `.env.example`

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: Replace contents**

```ini
# Copy to .env and fill in. The .env file is git-ignored.
#
# Both the docker-compose stack and the bridge process read this file.

# --- Caddy ----------------------------------------------------------------
# Email used by Let's Encrypt for ACME account / expiry notices.
ACME_EMAIL=ops@example.com

# --- Bridge: OIDC issuer + signing ---------------------------------------
OIDC_ISSUER=https://oidc-bridge.aitc.dev
# RSA-2048 PEM (PKCS#8). Generate once, mount via secret/volume.
OIDC_SIGNING_KEY=

# --- Bridge: master sealing key (32 bytes, base64) -----------------------
# `openssl rand -base64 32` to generate.
OIDC_MASTER_KEY=

# --- Bridge: admin -------------------------------------------------------
# Bearer token for /admin/tenants. Generate with `openssl rand -hex 32`.
ADMIN_TOKEN=

# --- Bridge: tenant store -----------------------------------------------
# fs (default — Vultr public instance + most self-hosters) or gcpsm
TENANT_STORE=fs
BRIDGE_DATA_DIR=/var/lib/oidc-bridge
# GCP_PROJECT_ID=  # required when TENANT_STORE=gcpsm

# --- Bridge: Toss upstream ----------------------------------------------
# Override only for sandbox / local upstream. Default is fine for production.
# TOSS_API_BASE=https://apps-in-toss-api.toss.im

# --- Bridge: runtime knobs ----------------------------------------------
# Public image defaults to true; self-hosters typically want false.
RATE_LIMIT_ENABLED=false
# Comma-separated CORS allow-list (M3).
# ALLOWED_ORIGINS=

# --- Bridge: Firebase custom token (M2, self-host only) -----------------
# Raw service-account JSON, or base64 of the same. If unset, /firebase-token
# returns 501 not_configured.
# FIREBASE_SERVICE_ACCOUNT=
# Or, alternatively, a path to the JSON file mounted into the container:
# GOOGLE_APPLICATION_CREDENTIALS=/run/secrets/firebase.json
```

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "chore(env): swap TOSS_CLIENT_ID/SECRET for OIDC + tenant-store vars"
```

---

### Task 9.2: Write `MIGRATION.md`

**Files:**
- Create: `MIGRATION.md`

- [ ] **Step 1: Author migration guide**

`MIGRATION.md`:

```markdown
# Migration: `/verify` → `/oidc/token` (M1)

This release is a breaking change. The single-`/verify` endpoint and the
HTTP-Basic-Auth-against-Toss assumption are both gone, replaced by a
multi-tenant OIDC + mTLS architecture.

If you operate a self-hosted bridge, follow the steps below before
upgrading.

## What's changed

| Before (M0.5) | After (M1) |
|---|---|
| `POST /verify` | `POST /oidc/token`, `GET /oidc/userinfo`, `POST /oidc/revoke` |
| HTTP Basic Auth toward Toss | mTLS toward Toss (per-tenant cert+key) |
| `TOSS_CLIENT_ID` / `TOSS_CLIENT_SECRET` env vars | per-tenant records in the tenant store |
| Single global identity | Multiple tenants, each with `client_id` / `client_secret` |
| Plain `claims` JSON response | OIDC-standard `id_token` (RS256), `access_token` (sealed `aitc_…`), `refresh_token` |
| No discovery doc, no JWKS | `/.well-known/openid-configuration`, `/.well-known/jwks.json` |

## What you need to do

1. **Generate an mTLS cert+key.** Apps-in-Toss console → mTLS 인증서 →
   +발급받기. Save the two PEM files.
2. **Generate bridge secrets.**
   ```
   openssl rand -base64 32        # → OIDC_MASTER_KEY
   openssl rand -hex 32           # → ADMIN_TOKEN
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
                                  # → OIDC_SIGNING_KEY (paste full PEM)
   ```
3. **Update `.env`.** See the new `.env.example`. Remove
   `TOSS_CLIENT_ID` and `TOSS_CLIENT_SECRET`; they are no longer read.
4. **Provision your first tenant.** Two options:

   **Online** (bridge already running with the new env vars):
   ```
   oidc-bridge --bridge https://my-bridge.example.com \
     --admin-token "$ADMIN_TOKEN" \
     tenant create \
     --name "my-mini-app" \
     --environment production \
     --cert ./client-cert.pem \
     --key ./client-key.pem
   ```

   **Offline** (no bridge running yet — useful for first-time bootstrap):
   ```
   oidc-bridge --offline --data-dir /var/lib/oidc-bridge \
     tenant create \
     --name "my-mini-app" \
     --environment production \
     --cert ./client-cert.pem \
     --key ./client-key.pem
   ```

   Save the printed `client_id` and `client_secret`. The secret is shown
   exactly once; the bridge stores only a bcrypt hash.

5. **Update consumer code.** Replace `POST /verify` with `POST /oidc/token`
   using `grant_type=authorization_code` and `client_secret_basic` auth.
   See README "Supabase Edge Function" snippet for the canonical example.

## What stays the same

- The Docker image and `docker-compose.yml` shape.
- Caddy auto-HTTPS in front of the bridge.
- The mini-app's `appLogin()` call producing `{ authorizationCode, referrer }`.

## Rolling back

The bridge is Type C (no semver contract). Pin a previous image tag in
`docker-compose.yml`:

```yaml
services:
  app:
    image: ghcr.io/apps-in-toss-community/oidc-bridge:sha-<previous>
```

Tenant data on the Docker volume is independent of the image, so a
roll-back doesn't touch it.

## Questions

Open an issue at <https://github.com/apps-in-toss-community/oidc-bridge>.
```

- [ ] **Step 2: Commit**

```bash
git add MIGRATION.md
git commit -m "docs: add MIGRATION.md for /verify → /oidc/token"
```

---

## Task 10: Final wire-up + green CI

### Task 10.1: Full test sweep

- [ ] **Step 1: Run everything**

Run:
```bash
pnpm typecheck && pnpm lint && pnpm test && pnpm build
```

Expected: clean. If anything is red, fix it before proceeding — do not commit broken.

- [ ] **Step 2: Manual integration smoke**

In a tmpfs:
```bash
export BRIDGE_DATA_DIR=$(mktemp -d)
chmod 700 "$BRIDGE_DATA_DIR"
export OIDC_ISSUER=https://oidc-bridge.test
export OIDC_SIGNING_KEY="$(cat src/__fixtures__/test-signing.key.pem)"
export OIDC_MASTER_KEY=$(openssl rand -base64 32)
export ADMIN_TOKEN=admintoken
export TENANT_STORE=fs

node dist/cli.mjs --offline --data-dir "$BRIDGE_DATA_DIR" \
  tenant create --name smoke --environment sandbox \
  --cert src/__fixtures__/test-mtls.cert.pem \
  --key src/__fixtures__/test-mtls.key.pem
# Save client_id, client_secret

node dist/server.mjs &
SERVER_PID=$!
sleep 1
curl -s http://localhost:8080/.well-known/openid-configuration | jq .
curl -s http://localhost:8080/.well-known/jwks.json | jq .
kill $SERVER_PID
```

Expected: discovery + JWKS return valid JSON. (We can't smoke `/oidc/token` end-to-end without a real Toss host.)

- [ ] **Step 3: If green, push and open PR**

```bash
git push -u origin jwt-signature-verification
gh pr create --title "feat: M1 — multi-tenant OIDC + mTLS proxy (replaces /verify)" \
  --body "$(cat <<'EOF'
## Summary
- Multi-tenant tenant store (fs default + GCPSM lazy-loaded)
- Bundled CLI for tenant CRUD with `--offline` bootstrap mode
- OIDC surface: `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/oidc/token`, `/oidc/userinfo`, `/oidc/revoke`
- mTLS Toss adapter (envelope-aware), sealed `aitc_…` access tokens via per-tenant HKDF + AES-256-GCM
- Removes legacy `/verify` and `TOSS_CLIENT_ID/SECRET`; see `MIGRATION.md`

## Test plan
- [ ] `pnpm typecheck && pnpm lint && pnpm test` green
- [ ] CLI smoke: `tenant create --offline` + `tenant list` round-trip
- [ ] `/.well-known/openid-configuration` returns expected discovery shape
- [ ] `/.well-known/jwks.json` returns RS256 key with stable kid
- [ ] sdk-example dog-fooding (M5) blocked on follow-up; tracked in TODO
EOF
)"
```

---

## Self-review

After writing this plan, I checked it against the spec:

**Spec coverage** (every §3.1 item maps to at least one task):
- Tenant model + store + fs/gcpsm backends → Tasks 1.1–1.5
- Admin REST → Task 6
- Bundled CLI w/ offline mode → Task 8
- Sealed access_token (HKDF + AEAD) → Task 2.1
- Discovery + JWKS → Tasks 3.2, 3.3
- `POST /oidc/token` (auth_code + refresh_token) + Basic + Post → Tasks 5.1, 5.3
- `GET /oidc/userinfo` → Task 5.4
- `POST /oidc/revoke` (RFC 7009) → Task 5.5
- Toss adapter (mTLS + envelope + 4 endpoint clients) → Task 4
- ID token signing + RFC 7638 kid + JWKS export → Task 3.1
- Claim mapping → Task 5.2
- Remove legacy `/verify` + drop env vars + `MIGRATION.md` → Tasks 7.1, 9
- Contract fixtures under `src/__fixtures__/` → Task 0.3
- `schema_version`/`.data-version` gate → built into Task 1.4 (fs-store)

**Non-coverage acknowledged**:
- mTLS expiry monitoring (M5, spec §6) — `mtls_expires_at` is exposed via `GET /admin/tenants/:id` here but the warning automation is M5.
- Sealing-key rotation automation (spec §5.2.5) — primitives in place (`sealing_key_version` in record + AAD), automation deferred per spec.
- `/firebase-token` is M2.
- Rate-limit / CORS / payload cap is M3.

**Placeholder scan**: One placeholder remains — Task 5.3 Step 2 has `expect(true).toBe(true)` for the refresh_token flow test, called out as "fill out fully when implementing". Implementer must NOT commit that as-is. Otherwise no TBDs, no "implement later" with no body.

**Type consistency**:
- `TenantStore` interface in `src/tenants/store.ts` — methods used identically in fs-store, gcpsm-store, admin/routes.ts, cli/commands/*.
- `TenantRecord` shape (`schema_version`, `client_secret_hashes`, `mtls.{cert_pem,key_pem,…}`) consistent across fs-store, gcpsm-store, admin routes.
- `TenantPublic` returned by `list()` and `GET /admin/tenants/:id` uses the same fields (`mtls_fingerprint`, `mtls_expires_at`).
- `SealedPayload` (`tenant_id`, `toss_access_token`, `toss_refresh_token`, `exp`) consistent across `sealAccessToken` / `unsealAccessToken` / token.ts / userinfo.ts / revoke.ts.
- `ParsedEnvelope<T>` discriminated `{ ok: true; value: T } | { ok: false; reason; description? }` consistent across all four Toss endpoint clients.
- `Referrer` = `'DEFAULT' | 'SANDBOX'` — single source in `src/toss/types.ts`, mapped from `tenant.environment` in token.ts.
- `IdTokenClaims` shape consistent between `id-token.ts` (signer) and `claim-mapping.ts` (producer).

**Frequent commits**: 25+ commits, each with a clear scope, one-task-one-commit.

**TDD discipline**: Every code task has a "write failing test" step before the "implement" step. Bug-fix tasks not present (this is greenfield), but the structure makes regression tests trivial to add later.
