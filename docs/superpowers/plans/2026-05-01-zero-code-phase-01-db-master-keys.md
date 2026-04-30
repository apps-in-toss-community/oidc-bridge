# Phase 1 — DB + master keys

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the persistence layer (Postgres + SQLite) with the 7-table schema, and the `MasterKeyProvider` interface with env + file providers, HKDF-derived per-app sealing keys, and a 6-hour TTL cache. No HTTP surface yet — this phase is library code that subsequent phases call.

**Architecture:** A `Storage` interface covers the operations later phases need (insert/get/update/delete on each table). Postgres-default + SQLite-fallback drivers implement it. Migrations live as numbered SQL files under `src/storage/migrations/`. `MasterKeyProvider` is a tiny interface (`getKeyBytes(version): Promise<Buffer>`) with env/file implementations registered at startup; GCPSM is deferred to Phase 10. HKDF + sealing-key derivation are pure functions (no I/O) tested in isolation. The cache is a small TTL Map keyed by `version`.

**Tech stack:** TypeScript ESM strict, `pg`, `better-sqlite3`, `node:crypto` (HKDF, AES-GCM), vitest. No new HTTP / runtime deps.

---

## Universal invariants (apply to every task)

See [`2026-05-01-zero-code-mode-index.md`](./2026-05-01-zero-code-mode-index.md#universal-invariants). Phase 1 leans on:

- **TDD.** Every storage / crypto unit gets a red→green→commit cycle.
- **No PII / secrets in logs.** Master key bytes never appear in any error or test output.
- **Cloud-agnostic.** GCPSM is **not** added in this phase — only env + file providers.
- **Self-host first-class.** SQLite path passes the same conformance suite as Postgres.

## Files touched in this phase

**Created:**

- `src/storage/types.ts` — domain types (Workspace, App, etc.).
- `src/storage/interface.ts` — `Storage` interface.
- `src/storage/migrations/001_initial.sql` — Postgres schema.
- `src/storage/migrations/001_initial.sqlite.sql` — SQLite schema.
- `src/storage/migrate.ts` — migration runner (idempotent).
- `src/storage/migrate.test.ts`
- `src/storage/pg.ts` — Postgres driver.
- `src/storage/pg.test.ts` — gated on `PG_TEST_URL` env.
- `src/storage/sqlite.ts` — SQLite driver.
- `src/storage/sqlite.test.ts`
- `src/storage/conformance.ts` — driver-agnostic test suite.
- `src/master-keys/provider.ts` — `MasterKeyProvider` interface.
- `src/master-keys/env-provider.ts`
- `src/master-keys/env-provider.test.ts`
- `src/master-keys/file-provider.ts`
- `src/master-keys/file-provider.test.ts`
- `src/master-keys/cache.ts` — 6-hour TTL cache wrapper.
- `src/master-keys/cache.test.ts`
- `src/master-keys/hkdf.ts` — sealing-key derivation.
- `src/master-keys/hkdf.test.ts`
- `src/master-keys/index.ts` — `createMasterKeyProvider(env)` factory.
- `src/master-keys/index.test.ts`
- `vitest.config.ts` — test config (single project, isolation).

**Modified:**

- `package.json` — add `pg`, `@types/pg`, `better-sqlite3`, `@types/better-sqlite3`.
- `tsconfig.json` — no change.

---

## Pre-flight

```bash
pwd       # …/oidc-bridge-jwt-signature-verification
git branch --show-current   # zero-code-mode
git status                  # clean
```

If a Postgres-backed conformance run is desired locally:

```bash
docker run -d --name pg-zerocode-phase1 \
  -e POSTGRES_PASSWORD=test \
  -e POSTGRES_USER=test \
  -e POSTGRES_DB=zerocode_test \
  -p 127.0.0.1:55432:5432 \
  postgres:16-alpine
export PG_TEST_URL=postgresql://test:test@127.0.0.1:55432/zerocode_test
```

Cleanup: `docker rm -f pg-zerocode-phase1`. CI sets `PG_TEST_URL` itself in Phase 1's PR; without it set, the pg test suite is skipped (and the sqlite suite still runs).

---

## Task 1: Add `pg` and `better-sqlite3` deps

We pick `pg` because it is the canonical Node Postgres driver with first-class types and works against any Postgres-compatible service (Cloud SQL, Supabase, RDS, self-host). We pick `better-sqlite3` because its synchronous API maps cleanly to migration runners and CLI bootstrap, and it is the de-facto Node SQLite. The async `node:sqlite` standard module is too new for production reliance in May 2026.

**Files:**
- Modify: `package.json`
- Modify: `pnpm-lock.yaml`

- [ ] **Step 1: Install deps**

```bash
pnpm add pg@^8.13 better-sqlite3@^11
pnpm add -D @types/pg @types/better-sqlite3
```

- [ ] **Step 2: Verify**

```bash
pnpm list pg better-sqlite3 --depth=0
```

Expected: shows `pg 8.x` and `better-sqlite3 11.x` under dependencies.

- [ ] **Step 3: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "chore: add pg + better-sqlite3 for Phase 1 storage"
```

---

## Task 2: Lock `vitest.config.ts`

Vitest's defaults are mostly fine, but we need:
- Test isolation (each test file in its own process — DB-touching suites must not share connections).
- A clear timeout for slow Postgres tests.
- `globals: false` so we keep explicit imports.

**Files:**
- Create: `vitest.config.ts`

- [ ] **Step 1: Write the config**

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    isolate: true,
    pool: 'forks',
    poolOptions: { forks: { singleFork: false } },
    testTimeout: 15_000,
    include: ['src/**/*.test.ts', 'cli/**/*.test.ts'],
  },
});
```

- [ ] **Step 2: Verify it picks up existing tests**

```bash
pnpm test
```

Expected: existing tests (logger, app) pass. No regressions.

- [ ] **Step 3: Commit**

```bash
git add vitest.config.ts
git commit -m "chore(vitest): pin config; isolate tests across processes"
```

---

## Task 3: Domain types

These are the field-for-field shapes Phase 2+ will read/write. Defining them in one file keeps the storage interface readable.

**Files:**
- Create: `src/storage/types.ts`

- [ ] **Step 1: Write `src/storage/types.ts`**

```ts
export type AppOwnershipStatus = 'pending' | 'verified' | 'lapsed';

export interface User {
  id: string;
  email: string;
  createdAt: Date;
}

export interface ApiToken {
  id: string;
  userId: string;
  name: string;
  tokenHash: string;
  scopes: string[];
  createdAt: Date;
  lastUsedAt: Date | null;
}

export interface Workspace {
  id: string;
  ownerUserId: string;
  name: string;
  createdAt: Date;
}

export interface AppRecord {
  id: string;
  workspaceId: string;
  appIdToss: string;
  displayTitle: string;
  clientId: string;
  clientSecretHashes: string[];
  mtlsCertEnc: Buffer;
  mtlsKeyEnc: Buffer;
  sealingKeyVersion: number;
  allowedOrigins: string[];
  ownershipStatus: AppOwnershipStatus;
  ownershipGraceUntil: Date | null;
  rawTokensEnabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserSession {
  id: string;
  userId: string;
  expiresAt: Date;
  createdAt: Date;
}

export interface MasterKeyMeta {
  id: string;
  version: number;
  createdAt: Date;
  retiredAt: Date | null;
  providerRef: string | null;
}

export interface AuditLogEntry {
  id: string;
  ts: Date;
  actor: string;
  action: string;
  target: string;
  detailsJson: Record<string, unknown>;
}
```

- [ ] **Step 2: Run typecheck**

```bash
pnpm typecheck
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/storage/types.ts
git commit -m "feat(storage): domain types for the 7-table schema"
```

---

## Task 4: Postgres migration SQL

`001_initial.sql` is the canonical Postgres schema. Self-host SQLite gets a parallel file (Task 5) — the conformance test suite enforces that both are kept in sync semantically.

**Files:**
- Create: `src/storage/migrations/001_initial.sql`

- [ ] **Step 1: Write the SQL**

```sql
-- 001_initial.sql — zero-code mode Phase 1 schema for Postgres.
-- Idempotent: every CREATE uses IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_tokens_user_id_idx ON api_tokens(user_id);

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS workspaces_owner_idx ON workspaces(owner_user_id);

CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  app_id_toss TEXT NOT NULL,
  display_title TEXT NOT NULL,
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hashes TEXT[] NOT NULL DEFAULT '{}',
  mtls_cert_enc BYTEA NOT NULL,
  mtls_key_enc BYTEA NOT NULL,
  sealing_key_version INTEGER NOT NULL,
  allowed_origins TEXT[] NOT NULL DEFAULT '{}',
  ownership_status TEXT NOT NULL CHECK (ownership_status IN ('pending','verified','lapsed')),
  ownership_grace_until TIMESTAMPTZ,
  raw_tokens_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(workspace_id, app_id_toss)
);
CREATE INDEX IF NOT EXISTS apps_workspace_idx ON apps(workspace_id);

CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions(user_id);

CREATE TABLE IF NOT EXISTS master_keys (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at TIMESTAMPTZ,
  provider_ref TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  details_json JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log(ts DESC);

CREATE TABLE IF NOT EXISTS schema_migrations (
  filename TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

- [ ] **Step 2: Commit**

```bash
git add src/storage/migrations/001_initial.sql
git commit -m "feat(storage): Postgres initial migration (7 tables + schema_migrations)"
```

---

## Task 5: SQLite mirror migration

SQLite differences from Postgres that matter:
- No native array type → use JSON-encoded TEXT.
- No `BYTEA` → `BLOB`.
- No `JSONB` → `TEXT` (we serialize ourselves).
- `TIMESTAMPTZ` → `TEXT` storing ISO-8601 UTC. SQLite has no real timestamp type.

The SQLite driver's mapper layer (Task 8) handles serialization so the API surface in `Storage` is uniform.

**Files:**
- Create: `src/storage/migrations/001_initial.sqlite.sql`

- [ ] **Step 1: Write the SQL**

```sql
-- 001_initial.sqlite.sql — zero-code mode Phase 1 schema for SQLite.
-- TEXT[] → TEXT (JSON), BYTEA → BLOB, TIMESTAMPTZ → TEXT (ISO-8601 UTC).
-- The driver layer enforces the JSON shape and timestamp parsing.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS api_tokens_user_id_idx ON api_tokens(user_id);

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS workspaces_owner_idx ON workspaces(owner_user_id);

CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  app_id_toss TEXT NOT NULL,
  display_title TEXT NOT NULL,
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hashes TEXT NOT NULL DEFAULT '[]',
  mtls_cert_enc BLOB NOT NULL,
  mtls_key_enc BLOB NOT NULL,
  sealing_key_version INTEGER NOT NULL,
  allowed_origins TEXT NOT NULL DEFAULT '[]',
  ownership_status TEXT NOT NULL CHECK (ownership_status IN ('pending','verified','lapsed')),
  ownership_grace_until TEXT,
  raw_tokens_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, app_id_toss)
);
CREATE INDEX IF NOT EXISTS apps_workspace_idx ON apps(workspace_id);

CREATE TABLE IF NOT EXISTS user_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions(user_id);

CREATE TABLE IF NOT EXISTS master_keys (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  retired_at TEXT,
  provider_ref TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log(ts DESC);

CREATE TABLE IF NOT EXISTS schema_migrations (
  filename TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);
```

- [ ] **Step 2: Commit**

```bash
git add src/storage/migrations/001_initial.sqlite.sql
git commit -m "feat(storage): SQLite mirror migration"
```

---

## Task 6: `Storage` interface

The interface is the contract every later phase imports. Methods are scoped to the operations actually needed by other phases. We do not add a method until a concrete caller exists — but we do add the full set the spec implies (so subsequent phase plans can reference them).

**Files:**
- Create: `src/storage/interface.ts`

- [ ] **Step 1: Write the interface**

```ts
import type {
  ApiToken,
  AppOwnershipStatus,
  AppRecord,
  AuditLogEntry,
  MasterKeyMeta,
  User,
  UserSession,
  Workspace,
} from './types.js';

export interface Storage {
  // Users
  createUser(input: { id: string; email: string }): Promise<User>;
  getUserById(id: string): Promise<User | null>;
  getUserByEmail(email: string): Promise<User | null>;

  // API tokens
  createApiToken(input: {
    id: string;
    userId: string;
    name: string;
    tokenHash: string;
    scopes: string[];
  }): Promise<ApiToken>;
  getApiTokenByHash(tokenHash: string): Promise<ApiToken | null>;
  listApiTokensByUser(userId: string): Promise<ApiToken[]>;
  deleteApiToken(id: string): Promise<void>;
  touchApiTokenLastUsed(id: string, at: Date): Promise<void>;

  // Workspaces
  createWorkspace(input: { id: string; ownerUserId: string; name: string }): Promise<Workspace>;
  getWorkspace(id: string): Promise<Workspace | null>;
  listWorkspacesByOwner(ownerUserId: string): Promise<Workspace[]>;
  updateWorkspace(id: string, patch: { name?: string }): Promise<Workspace>;
  deleteWorkspace(id: string): Promise<void>;

  // Apps
  createApp(input: {
    id: string;
    workspaceId: string;
    appIdToss: string;
    displayTitle: string;
    clientId: string;
    clientSecretHashes: string[];
    mtlsCertEnc: Buffer;
    mtlsKeyEnc: Buffer;
    sealingKeyVersion: number;
    allowedOrigins: string[];
    ownershipStatus: AppOwnershipStatus;
    ownershipGraceUntil: Date | null;
    rawTokensEnabled: boolean;
  }): Promise<AppRecord>;
  getApp(id: string): Promise<AppRecord | null>;
  getAppByClientId(clientId: string): Promise<AppRecord | null>;
  listAppsByWorkspace(workspaceId: string): Promise<AppRecord[]>;
  updateApp(
    id: string,
    patch: Partial<{
      displayTitle: string;
      clientSecretHashes: string[];
      mtlsCertEnc: Buffer;
      mtlsKeyEnc: Buffer;
      sealingKeyVersion: number;
      allowedOrigins: string[];
      ownershipStatus: AppOwnershipStatus;
      ownershipGraceUntil: Date | null;
      rawTokensEnabled: boolean;
    }>,
  ): Promise<AppRecord>;
  deleteApp(id: string): Promise<void>;
  countApps(): Promise<number>;

  // User sessions (Phase 6 placeholder; Phase 1 only stubs CRUD)
  createUserSession(input: { id: string; userId: string; expiresAt: Date }): Promise<UserSession>;
  getUserSession(id: string): Promise<UserSession | null>;
  deleteUserSession(id: string): Promise<void>;

  // Master keys (metadata only; bytes live in the provider)
  createMasterKey(input: {
    id: string;
    version: number;
    providerRef: string | null;
  }): Promise<MasterKeyMeta>;
  getMasterKeyByVersion(version: number): Promise<MasterKeyMeta | null>;
  listMasterKeys(): Promise<MasterKeyMeta[]>;
  retireMasterKey(version: number, retiredAt: Date): Promise<MasterKeyMeta>;

  // Audit log
  appendAudit(entry: Omit<AuditLogEntry, 'id' | 'ts'> & { id: string; ts?: Date }): Promise<void>;
  listAudit(options?: { limit?: number }): Promise<AuditLogEntry[]>;

  // Lifecycle
  close(): Promise<void>;
}
```

- [ ] **Step 2: Run typecheck**

```bash
pnpm typecheck
```

Expected: green.

- [ ] **Step 3: Commit**

```bash
git add src/storage/interface.ts
git commit -m "feat(storage): Storage interface covering all 7 tables"
```

---

## Task 7: Migration runner

The runner reads SQL files from `migrations/` in lexicographic order, executes ones not in `schema_migrations`, and records them. Same file works for pg and sqlite — but the SQL filename rule is `<n>_<name>.sql` for pg and `<n>_<name>.sqlite.sql` for sqlite. The runner picks based on a flag.

**Files:**
- Create: `src/storage/migrate.ts`
- Create: `src/storage/migrate.test.ts`

- [ ] **Step 1: Write a failing test**

`src/storage/migrate.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runSqliteMigrations } from './migrate.js';

describe('runSqliteMigrations', () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-migrate-'));
    dbPath = join(dir, 'test.db');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('applies all migrations on a fresh DB', () => {
    const db = new Database(dbPath);
    runSqliteMigrations(db);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all() as { name: string }[];
    const names = tables.map((t) => t.name).filter((n) => !n.startsWith('sqlite_'));
    expect(names).toEqual([
      'api_tokens',
      'apps',
      'audit_log',
      'master_keys',
      'schema_migrations',
      'user_sessions',
      'users',
      'workspaces',
    ]);
    db.close();
  });

  it('is idempotent', () => {
    const db = new Database(dbPath);
    runSqliteMigrations(db);
    runSqliteMigrations(db);
    const applied = db.prepare('SELECT filename FROM schema_migrations').all() as { filename: string }[];
    expect(applied.map((r) => r.filename)).toEqual(['001_initial.sqlite.sql']);
    db.close();
  });
});
```

- [ ] **Step 2: Run tests; confirm fail**

```bash
pnpm test src/storage/migrate.test.ts
```

Expected: FAIL — `Cannot find module './migrate.js'`.

- [ ] **Step 3: Implement `src/storage/migrate.ts`**

```ts
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type Database from 'better-sqlite3';
import type { Pool } from 'pg';

const MIGRATIONS_DIR = fileURLToPath(new URL('./migrations/', import.meta.url));

function listMigrations(suffix: string): string[] {
  return readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(suffix))
    .sort();
}

function readMigration(filename: string): string {
  return readFileSync(join(MIGRATIONS_DIR, filename), 'utf8');
}

export function runSqliteMigrations(db: Database.Database): void {
  db.exec(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       filename TEXT PRIMARY KEY,
       applied_at TEXT NOT NULL
     )`,
  );
  const applied = new Set(
    (db.prepare('SELECT filename FROM schema_migrations').all() as { filename: string }[]).map(
      (r) => r.filename,
    ),
  );
  const files = listMigrations('.sqlite.sql');
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = readMigration(file);
    db.transaction(() => {
      db.exec(sql);
      db.prepare('INSERT INTO schema_migrations (filename, applied_at) VALUES (?, ?)').run(
        file,
        new Date().toISOString(),
      );
    })();
  }
}

export async function runPgMigrations(pool: Pool): Promise<void> {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       filename TEXT PRIMARY KEY,
       applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
     )`,
  );
  const { rows } = await pool.query<{ filename: string }>('SELECT filename FROM schema_migrations');
  const applied = new Set(rows.map((r) => r.filename));
  const files = listMigrations('.sql').filter((f) => !f.endsWith('.sqlite.sql'));
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = readMigration(file);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [file]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }
}
```

- [ ] **Step 4: Run tests; confirm green**

```bash
pnpm test src/storage/migrate.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/storage/migrate.ts src/storage/migrate.test.ts
git commit -m "feat(storage): migration runner for sqlite + pg"
```

---

## Task 8: SQLite driver

Single driver file. Synchronous `better-sqlite3` is wrapped in `async` returns to satisfy the `Storage` interface — there is no actual await needed, but the surface is uniform across drivers.

**Files:**
- Create: `src/storage/sqlite.ts`

- [ ] **Step 1: Write `src/storage/sqlite.ts`**

```ts
import Database from 'better-sqlite3';
import { runSqliteMigrations } from './migrate.js';
import type { Storage } from './interface.js';
import type {
  ApiToken,
  AppOwnershipStatus,
  AppRecord,
  AuditLogEntry,
  MasterKeyMeta,
  User,
  UserSession,
  Workspace,
} from './types.js';

interface UserRow {
  id: string;
  email: string;
  created_at: string;
}

interface ApiTokenRow {
  id: string;
  user_id: string;
  name: string;
  token_hash: string;
  scopes: string;
  created_at: string;
  last_used_at: string | null;
}

interface WorkspaceRow {
  id: string;
  owner_user_id: string;
  name: string;
  created_at: string;
}

interface AppRow {
  id: string;
  workspace_id: string;
  app_id_toss: string;
  display_title: string;
  client_id: string;
  client_secret_hashes: string;
  mtls_cert_enc: Buffer;
  mtls_key_enc: Buffer;
  sealing_key_version: number;
  allowed_origins: string;
  ownership_status: AppOwnershipStatus;
  ownership_grace_until: string | null;
  raw_tokens_enabled: number;
  created_at: string;
  updated_at: string;
}

interface UserSessionRow {
  id: string;
  user_id: string;
  expires_at: string;
  created_at: string;
}

interface MasterKeyRow {
  id: string;
  version: number;
  created_at: string;
  retired_at: string | null;
  provider_ref: string | null;
}

interface AuditRow {
  id: string;
  ts: string;
  actor: string;
  action: string;
  target: string;
  details_json: string;
}

const iso = (d: Date): string => d.toISOString();
const parseDate = (s: string): Date => new Date(s);
const parseDateOrNull = (s: string | null): Date | null => (s ? new Date(s) : null);
const toJson = (v: unknown): string => JSON.stringify(v);
const fromJsonArray = (s: string): string[] => JSON.parse(s);
const fromJsonObj = (s: string): Record<string, unknown> => JSON.parse(s);

function mapUser(r: UserRow): User {
  return { id: r.id, email: r.email, createdAt: parseDate(r.created_at) };
}

function mapApiToken(r: ApiTokenRow): ApiToken {
  return {
    id: r.id,
    userId: r.user_id,
    name: r.name,
    tokenHash: r.token_hash,
    scopes: fromJsonArray(r.scopes),
    createdAt: parseDate(r.created_at),
    lastUsedAt: parseDateOrNull(r.last_used_at),
  };
}

function mapWorkspace(r: WorkspaceRow): Workspace {
  return {
    id: r.id,
    ownerUserId: r.owner_user_id,
    name: r.name,
    createdAt: parseDate(r.created_at),
  };
}

function mapApp(r: AppRow): AppRecord {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    appIdToss: r.app_id_toss,
    displayTitle: r.display_title,
    clientId: r.client_id,
    clientSecretHashes: fromJsonArray(r.client_secret_hashes),
    mtlsCertEnc: r.mtls_cert_enc,
    mtlsKeyEnc: r.mtls_key_enc,
    sealingKeyVersion: r.sealing_key_version,
    allowedOrigins: fromJsonArray(r.allowed_origins),
    ownershipStatus: r.ownership_status,
    ownershipGraceUntil: parseDateOrNull(r.ownership_grace_until),
    rawTokensEnabled: r.raw_tokens_enabled !== 0,
    createdAt: parseDate(r.created_at),
    updatedAt: parseDate(r.updated_at),
  };
}

function mapSession(r: UserSessionRow): UserSession {
  return {
    id: r.id,
    userId: r.user_id,
    expiresAt: parseDate(r.expires_at),
    createdAt: parseDate(r.created_at),
  };
}

function mapMasterKey(r: MasterKeyRow): MasterKeyMeta {
  return {
    id: r.id,
    version: r.version,
    createdAt: parseDate(r.created_at),
    retiredAt: parseDateOrNull(r.retired_at),
    providerRef: r.provider_ref,
  };
}

function mapAudit(r: AuditRow): AuditLogEntry {
  return {
    id: r.id,
    ts: parseDate(r.ts),
    actor: r.actor,
    action: r.action,
    target: r.target,
    detailsJson: fromJsonObj(r.details_json),
  };
}

export function createSqliteStorage(opts: { path: string }): Storage {
  const db = new Database(opts.path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  runSqliteMigrations(db);

  const storage: Storage = {
    async createUser(input) {
      const now = iso(new Date());
      db.prepare('INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)').run(
        input.id,
        input.email,
        now,
      );
      return { id: input.id, email: input.email, createdAt: parseDate(now) };
    },
    async getUserById(id) {
      const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
      return row ? mapUser(row) : null;
    },
    async getUserByEmail(email) {
      const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;
      return row ? mapUser(row) : null;
    },

    async createApiToken(input) {
      const now = iso(new Date());
      db.prepare(
        'INSERT INTO api_tokens (id, user_id, name, token_hash, scopes, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, NULL)',
      ).run(input.id, input.userId, input.name, input.tokenHash, toJson(input.scopes), now);
      return {
        id: input.id,
        userId: input.userId,
        name: input.name,
        tokenHash: input.tokenHash,
        scopes: input.scopes,
        createdAt: parseDate(now),
        lastUsedAt: null,
      };
    },
    async getApiTokenByHash(tokenHash) {
      const row = db.prepare('SELECT * FROM api_tokens WHERE token_hash = ?').get(tokenHash) as
        | ApiTokenRow
        | undefined;
      return row ? mapApiToken(row) : null;
    },
    async listApiTokensByUser(userId) {
      const rows = db.prepare('SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at').all(
        userId,
      ) as ApiTokenRow[];
      return rows.map(mapApiToken);
    },
    async deleteApiToken(id) {
      db.prepare('DELETE FROM api_tokens WHERE id = ?').run(id);
    },
    async touchApiTokenLastUsed(id, at) {
      db.prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?').run(iso(at), id);
    },

    async createWorkspace(input) {
      const now = iso(new Date());
      db.prepare(
        'INSERT INTO workspaces (id, owner_user_id, name, created_at) VALUES (?, ?, ?, ?)',
      ).run(input.id, input.ownerUserId, input.name, now);
      return {
        id: input.id,
        ownerUserId: input.ownerUserId,
        name: input.name,
        createdAt: parseDate(now),
      };
    },
    async getWorkspace(id) {
      const row = db.prepare('SELECT * FROM workspaces WHERE id = ?').get(id) as WorkspaceRow | undefined;
      return row ? mapWorkspace(row) : null;
    },
    async listWorkspacesByOwner(ownerUserId) {
      const rows = db
        .prepare('SELECT * FROM workspaces WHERE owner_user_id = ? ORDER BY created_at')
        .all(ownerUserId) as WorkspaceRow[];
      return rows.map(mapWorkspace);
    },
    async updateWorkspace(id, patch) {
      const existing = (await storage.getWorkspace(id)) ?? null;
      if (!existing) throw new Error(`workspace ${id} not found`);
      const name = patch.name ?? existing.name;
      db.prepare('UPDATE workspaces SET name = ? WHERE id = ?').run(name, id);
      return { ...existing, name };
    },
    async deleteWorkspace(id) {
      db.prepare('DELETE FROM workspaces WHERE id = ?').run(id);
    },

    async createApp(input) {
      const now = iso(new Date());
      db.prepare(
        `INSERT INTO apps (
          id, workspace_id, app_id_toss, display_title, client_id,
          client_secret_hashes, mtls_cert_enc, mtls_key_enc, sealing_key_version,
          allowed_origins, ownership_status, ownership_grace_until,
          raw_tokens_enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        input.id,
        input.workspaceId,
        input.appIdToss,
        input.displayTitle,
        input.clientId,
        toJson(input.clientSecretHashes),
        input.mtlsCertEnc,
        input.mtlsKeyEnc,
        input.sealingKeyVersion,
        toJson(input.allowedOrigins),
        input.ownershipStatus,
        input.ownershipGraceUntil ? iso(input.ownershipGraceUntil) : null,
        input.rawTokensEnabled ? 1 : 0,
        now,
        now,
      );
      const row = db.prepare('SELECT * FROM apps WHERE id = ?').get(input.id) as AppRow;
      return mapApp(row);
    },
    async getApp(id) {
      const row = db.prepare('SELECT * FROM apps WHERE id = ?').get(id) as AppRow | undefined;
      return row ? mapApp(row) : null;
    },
    async getAppByClientId(clientId) {
      const row = db.prepare('SELECT * FROM apps WHERE client_id = ?').get(clientId) as
        | AppRow
        | undefined;
      return row ? mapApp(row) : null;
    },
    async listAppsByWorkspace(workspaceId) {
      const rows = db
        .prepare('SELECT * FROM apps WHERE workspace_id = ? ORDER BY created_at')
        .all(workspaceId) as AppRow[];
      return rows.map(mapApp);
    },
    async updateApp(id, patch) {
      const existing = await storage.getApp(id);
      if (!existing) throw new Error(`app ${id} not found`);
      const next: AppRecord = {
        ...existing,
        ...(patch.displayTitle !== undefined ? { displayTitle: patch.displayTitle } : {}),
        ...(patch.clientSecretHashes !== undefined
          ? { clientSecretHashes: patch.clientSecretHashes }
          : {}),
        ...(patch.mtlsCertEnc !== undefined ? { mtlsCertEnc: patch.mtlsCertEnc } : {}),
        ...(patch.mtlsKeyEnc !== undefined ? { mtlsKeyEnc: patch.mtlsKeyEnc } : {}),
        ...(patch.sealingKeyVersion !== undefined
          ? { sealingKeyVersion: patch.sealingKeyVersion }
          : {}),
        ...(patch.allowedOrigins !== undefined ? { allowedOrigins: patch.allowedOrigins } : {}),
        ...(patch.ownershipStatus !== undefined ? { ownershipStatus: patch.ownershipStatus } : {}),
        ...(patch.ownershipGraceUntil !== undefined
          ? { ownershipGraceUntil: patch.ownershipGraceUntil }
          : {}),
        ...(patch.rawTokensEnabled !== undefined
          ? { rawTokensEnabled: patch.rawTokensEnabled }
          : {}),
        updatedAt: new Date(),
      };
      db.prepare(
        `UPDATE apps SET
          display_title = ?, client_secret_hashes = ?, mtls_cert_enc = ?, mtls_key_enc = ?,
          sealing_key_version = ?, allowed_origins = ?, ownership_status = ?,
          ownership_grace_until = ?, raw_tokens_enabled = ?, updated_at = ?
         WHERE id = ?`,
      ).run(
        next.displayTitle,
        toJson(next.clientSecretHashes),
        next.mtlsCertEnc,
        next.mtlsKeyEnc,
        next.sealingKeyVersion,
        toJson(next.allowedOrigins),
        next.ownershipStatus,
        next.ownershipGraceUntil ? iso(next.ownershipGraceUntil) : null,
        next.rawTokensEnabled ? 1 : 0,
        iso(next.updatedAt),
        id,
      );
      return next;
    },
    async deleteApp(id) {
      db.prepare('DELETE FROM apps WHERE id = ?').run(id);
    },
    async countApps() {
      const row = db.prepare('SELECT COUNT(*) AS c FROM apps').get() as { c: number };
      return row.c;
    },

    async createUserSession(input) {
      const now = iso(new Date());
      db.prepare(
        'INSERT INTO user_sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)',
      ).run(input.id, input.userId, iso(input.expiresAt), now);
      return {
        id: input.id,
        userId: input.userId,
        expiresAt: input.expiresAt,
        createdAt: parseDate(now),
      };
    },
    async getUserSession(id) {
      const row = db.prepare('SELECT * FROM user_sessions WHERE id = ?').get(id) as
        | UserSessionRow
        | undefined;
      return row ? mapSession(row) : null;
    },
    async deleteUserSession(id) {
      db.prepare('DELETE FROM user_sessions WHERE id = ?').run(id);
    },

    async createMasterKey(input) {
      const now = iso(new Date());
      db.prepare(
        'INSERT INTO master_keys (id, version, created_at, retired_at, provider_ref) VALUES (?, ?, ?, NULL, ?)',
      ).run(input.id, input.version, now, input.providerRef);
      const row = db.prepare('SELECT * FROM master_keys WHERE id = ?').get(input.id) as MasterKeyRow;
      return mapMasterKey(row);
    },
    async getMasterKeyByVersion(version) {
      const row = db.prepare('SELECT * FROM master_keys WHERE version = ?').get(version) as
        | MasterKeyRow
        | undefined;
      return row ? mapMasterKey(row) : null;
    },
    async listMasterKeys() {
      const rows = db.prepare('SELECT * FROM master_keys ORDER BY version').all() as MasterKeyRow[];
      return rows.map(mapMasterKey);
    },
    async retireMasterKey(version, retiredAt) {
      db.prepare('UPDATE master_keys SET retired_at = ? WHERE version = ?').run(
        iso(retiredAt),
        version,
      );
      const row = db.prepare('SELECT * FROM master_keys WHERE version = ?').get(version) as MasterKeyRow;
      if (!row) throw new Error(`master_key version ${version} not found`);
      return mapMasterKey(row);
    },

    async appendAudit(entry) {
      const ts = iso(entry.ts ?? new Date());
      db.prepare(
        'INSERT INTO audit_log (id, ts, actor, action, target, details_json) VALUES (?, ?, ?, ?, ?, ?)',
      ).run(entry.id, ts, entry.actor, entry.action, entry.target, toJson(entry.detailsJson));
    },
    async listAudit(options) {
      const limit = options?.limit ?? 100;
      const rows = db.prepare('SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?').all(limit) as AuditRow[];
      return rows.map(mapAudit);
    },

    async close() {
      db.close();
    },
  };

  return storage;
}
```

- [ ] **Step 2: Run typecheck + lint**

```bash
pnpm typecheck && pnpm lint
```

Expected: green.

- [ ] **Step 3: Commit**

```bash
git add src/storage/sqlite.ts
git commit -m "feat(storage): SQLite driver implementing Storage interface"
```

---

## Task 9: Storage conformance test suite

A single test factory takes a `() => Promise<Storage>` and runs the full CRUD matrix. Both pg and sqlite drivers reuse it. Phase 1 only invokes it from the sqlite test file; pg test file (Task 11) reuses the same factory.

**Files:**
- Create: `src/storage/conformance.ts`
- Create: `src/storage/sqlite.test.ts`

- [ ] **Step 1: Write the conformance suite**

`src/storage/conformance.ts`:

```ts
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Storage } from './interface.js';

export interface ConformanceFactory {
  /** Returns a fresh Storage backed by an empty DB. */
  open(): Promise<Storage>;
  /** Cleans up DB after each test. */
  cleanup(s: Storage): Promise<void>;
}

export function runStorageConformance(name: string, factory: ConformanceFactory): void {
  describe(`Storage conformance — ${name}`, () => {
    let storage: Storage;

    beforeEach(async () => {
      storage = await factory.open();
    });

    afterEach(async () => {
      await factory.cleanup(storage);
    });

    it('users: create + getById + getByEmail', async () => {
      const u = await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      expect(u.email).toBe('a@b.c');
      expect(await storage.getUserById('u_1')).toMatchObject({ email: 'a@b.c' });
      expect(await storage.getUserByEmail('a@b.c')).toMatchObject({ id: 'u_1' });
      expect(await storage.getUserById('nope')).toBeNull();
    });

    it('api tokens: full lifecycle + scopes roundtrip + last-used', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      const t = await storage.createApiToken({
        id: 't_1',
        userId: 'u_1',
        name: 'cli',
        tokenHash: 'h1',
        scopes: ['admin', 'read'],
      });
      expect(t.scopes).toEqual(['admin', 'read']);
      expect(t.lastUsedAt).toBeNull();
      const fetched = await storage.getApiTokenByHash('h1');
      expect(fetched?.scopes).toEqual(['admin', 'read']);
      const at = new Date('2026-05-01T12:00:00Z');
      await storage.touchApiTokenLastUsed('t_1', at);
      const after = await storage.getApiTokenByHash('h1');
      expect(after?.lastUsedAt?.toISOString()).toBe(at.toISOString());
      const list = await storage.listApiTokensByUser('u_1');
      expect(list).toHaveLength(1);
      await storage.deleteApiToken('t_1');
      expect(await storage.getApiTokenByHash('h1')).toBeNull();
    });

    it('workspaces: create, update name, list by owner, delete', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      const w = await storage.createWorkspace({ id: 'w_1', ownerUserId: 'u_1', name: 'first' });
      expect(w.name).toBe('first');
      const updated = await storage.updateWorkspace('w_1', { name: 'renamed' });
      expect(updated.name).toBe('renamed');
      const list = await storage.listWorkspacesByOwner('u_1');
      expect(list).toHaveLength(1);
      await storage.deleteWorkspace('w_1');
      expect(await storage.getWorkspace('w_1')).toBeNull();
    });

    it('apps: full lifecycle, partial update, count', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      await storage.createWorkspace({ id: 'w_1', ownerUserId: 'u_1', name: 'first' });
      const a = await storage.createApp({
        id: 'a_1',
        workspaceId: 'w_1',
        appIdToss: 'mini-app-123',
        displayTitle: 'My App',
        clientId: 'client_xyz',
        clientSecretHashes: ['$2a$12$abc'],
        mtlsCertEnc: Buffer.from('cert-bytes'),
        mtlsKeyEnc: Buffer.from('key-bytes'),
        sealingKeyVersion: 1,
        allowedOrigins: ['https://app.example.com'],
        ownershipStatus: 'pending',
        ownershipGraceUntil: new Date('2026-05-04T00:00:00Z'),
        rawTokensEnabled: false,
      });
      expect(a.allowedOrigins).toEqual(['https://app.example.com']);
      expect(a.mtlsCertEnc.toString()).toBe('cert-bytes');
      expect(a.rawTokensEnabled).toBe(false);

      const byClient = await storage.getAppByClientId('client_xyz');
      expect(byClient?.id).toBe('a_1');

      const updated = await storage.updateApp('a_1', {
        displayTitle: 'Renamed',
        ownershipStatus: 'verified',
        ownershipGraceUntil: null,
        rawTokensEnabled: true,
      });
      expect(updated.displayTitle).toBe('Renamed');
      expect(updated.ownershipStatus).toBe('verified');
      expect(updated.ownershipGraceUntil).toBeNull();
      expect(updated.rawTokensEnabled).toBe(true);

      expect(await storage.countApps()).toBe(1);

      await storage.deleteApp('a_1');
      expect(await storage.getApp('a_1')).toBeNull();
    });

    it('user sessions: create, get, delete', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      const s = await storage.createUserSession({
        id: 's_1',
        userId: 'u_1',
        expiresAt: new Date('2026-05-02T00:00:00Z'),
      });
      expect(s.userId).toBe('u_1');
      const f = await storage.getUserSession('s_1');
      expect(f?.expiresAt.toISOString()).toBe('2026-05-02T00:00:00.000Z');
      await storage.deleteUserSession('s_1');
      expect(await storage.getUserSession('s_1')).toBeNull();
    });

    it('master keys: create, list ordering, retire', async () => {
      const m1 = await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
      expect(m1.retiredAt).toBeNull();
      await storage.createMasterKey({ id: 'mk_2', version: 2, providerRef: 'env:2' });
      const list = await storage.listMasterKeys();
      expect(list.map((m) => m.version)).toEqual([1, 2]);
      const retired = await storage.retireMasterKey(1, new Date('2026-05-01T00:00:00Z'));
      expect(retired.retiredAt?.toISOString()).toBe('2026-05-01T00:00:00.000Z');
      const fetched = await storage.getMasterKeyByVersion(1);
      expect(fetched?.retiredAt).not.toBeNull();
    });

    it('audit log: append + list-newest-first + limit', async () => {
      const ts1 = new Date('2026-05-01T10:00:00Z');
      const ts2 = new Date('2026-05-01T11:00:00Z');
      await storage.appendAudit({
        id: 'au_1',
        ts: ts1,
        actor: 'u_1',
        action: 'app.create',
        target: 'a_1',
        detailsJson: { foo: 'bar' },
      });
      await storage.appendAudit({
        id: 'au_2',
        ts: ts2,
        actor: 'u_1',
        action: 'app.delete',
        target: 'a_1',
        detailsJson: { reason: 'cleanup' },
      });
      const all = await storage.listAudit();
      expect(all.map((e) => e.id)).toEqual(['au_2', 'au_1']);
      expect(all[0]!.detailsJson).toEqual({ reason: 'cleanup' });
      const limited = await storage.listAudit({ limit: 1 });
      expect(limited).toHaveLength(1);
      expect(limited[0]!.id).toBe('au_2');
    });
  });
}
```

- [ ] **Step 2: Write the SQLite-specific test entrypoint**

`src/storage/sqlite.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSqliteStorage } from './sqlite.js';
import { runStorageConformance } from './conformance.js';

let dir: string | null = null;

runStorageConformance('sqlite', {
  async open() {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-sqlite-'));
    return createSqliteStorage({ path: join(dir, 'test.db') });
  },
  async cleanup(s) {
    await s.close();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
      dir = null;
    }
  },
});
```

- [ ] **Step 3: Run the suite**

```bash
pnpm test src/storage/sqlite.test.ts
```

Expected: 8 tests pass under `Storage conformance — sqlite`.

- [ ] **Step 4: Commit**

```bash
git add src/storage/conformance.ts src/storage/sqlite.test.ts
git commit -m "feat(storage): conformance suite + SQLite driver passes it"
```

---

## Task 10: Postgres driver

Same surface as the SQLite driver, using `pg.Pool` for connections. Postgres handles arrays and timestamps natively, so the mapping layer is thinner.

**Files:**
- Create: `src/storage/pg.ts`

- [ ] **Step 1: Write `src/storage/pg.ts`**

```ts
import { Pool, type PoolConfig } from 'pg';
import { runPgMigrations } from './migrate.js';
import type { Storage } from './interface.js';
import type {
  ApiToken,
  AppOwnershipStatus,
  AppRecord,
  AuditLogEntry,
  MasterKeyMeta,
  User,
  UserSession,
  Workspace,
} from './types.js';

interface UserRow {
  id: string;
  email: string;
  created_at: Date;
}

interface ApiTokenRow {
  id: string;
  user_id: string;
  name: string;
  token_hash: string;
  scopes: string[];
  created_at: Date;
  last_used_at: Date | null;
}

interface WorkspaceRow {
  id: string;
  owner_user_id: string;
  name: string;
  created_at: Date;
}

interface AppRow {
  id: string;
  workspace_id: string;
  app_id_toss: string;
  display_title: string;
  client_id: string;
  client_secret_hashes: string[];
  mtls_cert_enc: Buffer;
  mtls_key_enc: Buffer;
  sealing_key_version: number;
  allowed_origins: string[];
  ownership_status: AppOwnershipStatus;
  ownership_grace_until: Date | null;
  raw_tokens_enabled: boolean;
  created_at: Date;
  updated_at: Date;
}

interface UserSessionRow {
  id: string;
  user_id: string;
  expires_at: Date;
  created_at: Date;
}

interface MasterKeyRow {
  id: string;
  version: number;
  created_at: Date;
  retired_at: Date | null;
  provider_ref: string | null;
}

interface AuditRow {
  id: string;
  ts: Date;
  actor: string;
  action: string;
  target: string;
  details_json: Record<string, unknown>;
}

function mapUser(r: UserRow): User {
  return { id: r.id, email: r.email, createdAt: r.created_at };
}
function mapApiToken(r: ApiTokenRow): ApiToken {
  return {
    id: r.id,
    userId: r.user_id,
    name: r.name,
    tokenHash: r.token_hash,
    scopes: r.scopes,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
  };
}
function mapWorkspace(r: WorkspaceRow): Workspace {
  return { id: r.id, ownerUserId: r.owner_user_id, name: r.name, createdAt: r.created_at };
}
function mapApp(r: AppRow): AppRecord {
  return {
    id: r.id,
    workspaceId: r.workspace_id,
    appIdToss: r.app_id_toss,
    displayTitle: r.display_title,
    clientId: r.client_id,
    clientSecretHashes: r.client_secret_hashes,
    mtlsCertEnc: r.mtls_cert_enc,
    mtlsKeyEnc: r.mtls_key_enc,
    sealingKeyVersion: r.sealing_key_version,
    allowedOrigins: r.allowed_origins,
    ownershipStatus: r.ownership_status,
    ownershipGraceUntil: r.ownership_grace_until,
    rawTokensEnabled: r.raw_tokens_enabled,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}
function mapSession(r: UserSessionRow): UserSession {
  return {
    id: r.id,
    userId: r.user_id,
    expiresAt: r.expires_at,
    createdAt: r.created_at,
  };
}
function mapMasterKey(r: MasterKeyRow): MasterKeyMeta {
  return {
    id: r.id,
    version: r.version,
    createdAt: r.created_at,
    retiredAt: r.retired_at,
    providerRef: r.provider_ref,
  };
}
function mapAudit(r: AuditRow): AuditLogEntry {
  return {
    id: r.id,
    ts: r.ts,
    actor: r.actor,
    action: r.action,
    target: r.target,
    detailsJson: r.details_json,
  };
}

export interface PgStorageOptions {
  connectionString: string;
  poolConfig?: Omit<PoolConfig, 'connectionString'>;
}

export async function createPgStorage(opts: PgStorageOptions): Promise<Storage> {
  const pool = new Pool({ connectionString: opts.connectionString, ...opts.poolConfig });
  await runPgMigrations(pool);

  const storage: Storage = {
    async createUser(input) {
      await pool.query('INSERT INTO users (id, email) VALUES ($1, $2)', [input.id, input.email]);
      const row = (await pool.query<UserRow>('SELECT * FROM users WHERE id = $1', [input.id])).rows[0];
      if (!row) throw new Error('createUser: insert succeeded but row missing');
      return mapUser(row);
    },
    async getUserById(id) {
      const row = (await pool.query<UserRow>('SELECT * FROM users WHERE id = $1', [id])).rows[0];
      return row ? mapUser(row) : null;
    },
    async getUserByEmail(email) {
      const row = (await pool.query<UserRow>('SELECT * FROM users WHERE email = $1', [email])).rows[0];
      return row ? mapUser(row) : null;
    },

    async createApiToken(input) {
      await pool.query(
        'INSERT INTO api_tokens (id, user_id, name, token_hash, scopes) VALUES ($1, $2, $3, $4, $5)',
        [input.id, input.userId, input.name, input.tokenHash, input.scopes],
      );
      const row = (
        await pool.query<ApiTokenRow>('SELECT * FROM api_tokens WHERE id = $1', [input.id])
      ).rows[0];
      if (!row) throw new Error('createApiToken: insert succeeded but row missing');
      return mapApiToken(row);
    },
    async getApiTokenByHash(tokenHash) {
      const row = (
        await pool.query<ApiTokenRow>('SELECT * FROM api_tokens WHERE token_hash = $1', [tokenHash])
      ).rows[0];
      return row ? mapApiToken(row) : null;
    },
    async listApiTokensByUser(userId) {
      const rows = (
        await pool.query<ApiTokenRow>(
          'SELECT * FROM api_tokens WHERE user_id = $1 ORDER BY created_at',
          [userId],
        )
      ).rows;
      return rows.map(mapApiToken);
    },
    async deleteApiToken(id) {
      await pool.query('DELETE FROM api_tokens WHERE id = $1', [id]);
    },
    async touchApiTokenLastUsed(id, at) {
      await pool.query('UPDATE api_tokens SET last_used_at = $1 WHERE id = $2', [at, id]);
    },

    async createWorkspace(input) {
      await pool.query(
        'INSERT INTO workspaces (id, owner_user_id, name) VALUES ($1, $2, $3)',
        [input.id, input.ownerUserId, input.name],
      );
      const row = (
        await pool.query<WorkspaceRow>('SELECT * FROM workspaces WHERE id = $1', [input.id])
      ).rows[0];
      if (!row) throw new Error('createWorkspace: insert succeeded but row missing');
      return mapWorkspace(row);
    },
    async getWorkspace(id) {
      const row = (await pool.query<WorkspaceRow>('SELECT * FROM workspaces WHERE id = $1', [id]))
        .rows[0];
      return row ? mapWorkspace(row) : null;
    },
    async listWorkspacesByOwner(ownerUserId) {
      const rows = (
        await pool.query<WorkspaceRow>(
          'SELECT * FROM workspaces WHERE owner_user_id = $1 ORDER BY created_at',
          [ownerUserId],
        )
      ).rows;
      return rows.map(mapWorkspace);
    },
    async updateWorkspace(id, patch) {
      const existing = await storage.getWorkspace(id);
      if (!existing) throw new Error(`workspace ${id} not found`);
      const name = patch.name ?? existing.name;
      await pool.query('UPDATE workspaces SET name = $1 WHERE id = $2', [name, id]);
      return { ...existing, name };
    },
    async deleteWorkspace(id) {
      await pool.query('DELETE FROM workspaces WHERE id = $1', [id]);
    },

    async createApp(input) {
      await pool.query(
        `INSERT INTO apps (
          id, workspace_id, app_id_toss, display_title, client_id,
          client_secret_hashes, mtls_cert_enc, mtls_key_enc, sealing_key_version,
          allowed_origins, ownership_status, ownership_grace_until, raw_tokens_enabled
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [
          input.id,
          input.workspaceId,
          input.appIdToss,
          input.displayTitle,
          input.clientId,
          input.clientSecretHashes,
          input.mtlsCertEnc,
          input.mtlsKeyEnc,
          input.sealingKeyVersion,
          input.allowedOrigins,
          input.ownershipStatus,
          input.ownershipGraceUntil,
          input.rawTokensEnabled,
        ],
      );
      const row = (await pool.query<AppRow>('SELECT * FROM apps WHERE id = $1', [input.id])).rows[0];
      if (!row) throw new Error('createApp: insert succeeded but row missing');
      return mapApp(row);
    },
    async getApp(id) {
      const row = (await pool.query<AppRow>('SELECT * FROM apps WHERE id = $1', [id])).rows[0];
      return row ? mapApp(row) : null;
    },
    async getAppByClientId(clientId) {
      const row = (await pool.query<AppRow>('SELECT * FROM apps WHERE client_id = $1', [clientId]))
        .rows[0];
      return row ? mapApp(row) : null;
    },
    async listAppsByWorkspace(workspaceId) {
      const rows = (
        await pool.query<AppRow>(
          'SELECT * FROM apps WHERE workspace_id = $1 ORDER BY created_at',
          [workspaceId],
        )
      ).rows;
      return rows.map(mapApp);
    },
    async updateApp(id, patch) {
      const existing = await storage.getApp(id);
      if (!existing) throw new Error(`app ${id} not found`);
      const next: AppRecord = {
        ...existing,
        ...(patch.displayTitle !== undefined ? { displayTitle: patch.displayTitle } : {}),
        ...(patch.clientSecretHashes !== undefined
          ? { clientSecretHashes: patch.clientSecretHashes }
          : {}),
        ...(patch.mtlsCertEnc !== undefined ? { mtlsCertEnc: patch.mtlsCertEnc } : {}),
        ...(patch.mtlsKeyEnc !== undefined ? { mtlsKeyEnc: patch.mtlsKeyEnc } : {}),
        ...(patch.sealingKeyVersion !== undefined
          ? { sealingKeyVersion: patch.sealingKeyVersion }
          : {}),
        ...(patch.allowedOrigins !== undefined ? { allowedOrigins: patch.allowedOrigins } : {}),
        ...(patch.ownershipStatus !== undefined ? { ownershipStatus: patch.ownershipStatus } : {}),
        ...(patch.ownershipGraceUntil !== undefined
          ? { ownershipGraceUntil: patch.ownershipGraceUntil }
          : {}),
        ...(patch.rawTokensEnabled !== undefined
          ? { rawTokensEnabled: patch.rawTokensEnabled }
          : {}),
        updatedAt: new Date(),
      };
      await pool.query(
        `UPDATE apps SET
           display_title = $1, client_secret_hashes = $2, mtls_cert_enc = $3, mtls_key_enc = $4,
           sealing_key_version = $5, allowed_origins = $6, ownership_status = $7,
           ownership_grace_until = $8, raw_tokens_enabled = $9, updated_at = $10
         WHERE id = $11`,
        [
          next.displayTitle,
          next.clientSecretHashes,
          next.mtlsCertEnc,
          next.mtlsKeyEnc,
          next.sealingKeyVersion,
          next.allowedOrigins,
          next.ownershipStatus,
          next.ownershipGraceUntil,
          next.rawTokensEnabled,
          next.updatedAt,
          id,
        ],
      );
      return next;
    },
    async deleteApp(id) {
      await pool.query('DELETE FROM apps WHERE id = $1', [id]);
    },
    async countApps() {
      const row = (await pool.query<{ c: string }>('SELECT COUNT(*)::text AS c FROM apps')).rows[0];
      return Number(row?.c ?? 0);
    },

    async createUserSession(input) {
      await pool.query(
        'INSERT INTO user_sessions (id, user_id, expires_at) VALUES ($1, $2, $3)',
        [input.id, input.userId, input.expiresAt],
      );
      const row = (
        await pool.query<UserSessionRow>('SELECT * FROM user_sessions WHERE id = $1', [input.id])
      ).rows[0];
      if (!row) throw new Error('createUserSession: insert succeeded but row missing');
      return mapSession(row);
    },
    async getUserSession(id) {
      const row = (
        await pool.query<UserSessionRow>('SELECT * FROM user_sessions WHERE id = $1', [id])
      ).rows[0];
      return row ? mapSession(row) : null;
    },
    async deleteUserSession(id) {
      await pool.query('DELETE FROM user_sessions WHERE id = $1', [id]);
    },

    async createMasterKey(input) {
      await pool.query(
        'INSERT INTO master_keys (id, version, provider_ref) VALUES ($1, $2, $3)',
        [input.id, input.version, input.providerRef],
      );
      const row = (
        await pool.query<MasterKeyRow>('SELECT * FROM master_keys WHERE id = $1', [input.id])
      ).rows[0];
      if (!row) throw new Error('createMasterKey: insert succeeded but row missing');
      return mapMasterKey(row);
    },
    async getMasterKeyByVersion(version) {
      const row = (
        await pool.query<MasterKeyRow>('SELECT * FROM master_keys WHERE version = $1', [version])
      ).rows[0];
      return row ? mapMasterKey(row) : null;
    },
    async listMasterKeys() {
      const rows = (await pool.query<MasterKeyRow>('SELECT * FROM master_keys ORDER BY version')).rows;
      return rows.map(mapMasterKey);
    },
    async retireMasterKey(version, retiredAt) {
      await pool.query('UPDATE master_keys SET retired_at = $1 WHERE version = $2', [
        retiredAt,
        version,
      ]);
      const row = (
        await pool.query<MasterKeyRow>('SELECT * FROM master_keys WHERE version = $1', [version])
      ).rows[0];
      if (!row) throw new Error(`master_key version ${version} not found`);
      return mapMasterKey(row);
    },

    async appendAudit(entry) {
      const ts = entry.ts ?? new Date();
      await pool.query(
        'INSERT INTO audit_log (id, ts, actor, action, target, details_json) VALUES ($1,$2,$3,$4,$5,$6)',
        [entry.id, ts, entry.actor, entry.action, entry.target, entry.detailsJson],
      );
    },
    async listAudit(options) {
      const limit = options?.limit ?? 100;
      const rows = (
        await pool.query<AuditRow>('SELECT * FROM audit_log ORDER BY ts DESC LIMIT $1', [limit])
      ).rows;
      return rows.map(mapAudit);
    },

    async close() {
      await pool.end();
    },
  };

  return storage;
}
```

- [ ] **Step 2: Run typecheck + lint**

```bash
pnpm typecheck && pnpm lint
```

Expected: green.

- [ ] **Step 3: Commit**

```bash
git add src/storage/pg.ts
git commit -m "feat(storage): Postgres driver implementing Storage interface"
```

---

## Task 11: Postgres conformance test (gated on `PG_TEST_URL`)

The pg test file imports the same `runStorageConformance` factory and `describe.skip`s the suite when `PG_TEST_URL` is unset (so local CI without Docker still passes). When set, each test gets its own schema namespace via `pg_temp` is not enough — schemas don't auto-clean — so we wipe the tables between tests instead.

**Files:**
- Create: `src/storage/pg.test.ts`

- [ ] **Step 1: Write the test**

```ts
import { describe } from 'vitest';
import { createPgStorage } from './pg.js';
import { runStorageConformance } from './conformance.js';
import type { Storage } from './interface.js';

const url = process.env.PG_TEST_URL;

if (!url) {
  describe.skip('Storage conformance — pg (PG_TEST_URL not set)', () => {});
} else {
  let openedStorage: Storage | null = null;
  runStorageConformance('pg', {
    async open() {
      const s = await createPgStorage({ connectionString: url });
      openedStorage = s;
      return s;
    },
    async cleanup(s) {
      const truncate = async (table: string): Promise<void> => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const anyS = s as any;
        await anyS._pool?.query?.(`TRUNCATE TABLE ${table} CASCADE`);
      };
      // We did not expose _pool — fallback: open a one-off pg client for cleanup.
      const { Pool } = await import('pg');
      const pool = new Pool({ connectionString: url });
      await pool.query(
        'TRUNCATE TABLE audit_log, master_keys, user_sessions, apps, workspaces, api_tokens, users RESTART IDENTITY CASCADE',
      );
      await pool.end();
      await s.close();
      openedStorage = null;
      void truncate;
    },
  });
}
```

The test uses a per-suite truncate against the same DB, so the conformance suite's "fresh DB per test" expectation holds.

- [ ] **Step 2: Run the suite locally if Docker is available**

If Postgres is up at `PG_TEST_URL`:

```bash
PG_TEST_URL=postgresql://test:test@127.0.0.1:55432/zerocode_test pnpm test src/storage/pg.test.ts
```

Expected: 8 tests pass under `Storage conformance — pg`.

If no Postgres:

```bash
pnpm test src/storage/pg.test.ts
```

Expected: 1 test "skipped" entry, suite green.

- [ ] **Step 3: Update CI to bring up a Postgres service**

Edit `.github/workflows/ci.yml` — under `build-and-test`, add a service container:

```yaml
  build-and-test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: zerocode_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U test -d zerocode_test"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    env:
      PG_TEST_URL: postgresql://test:test@127.0.0.1:5432/zerocode_test
    steps:
```

(Place `services` and `env` keys at the job level, before `steps`. The rest of `steps` is unchanged.)

- [ ] **Step 4: Lint + typecheck**

```bash
pnpm lint && pnpm typecheck
```

Expected: green.

- [ ] **Step 5: Commit**

```bash
git add src/storage/pg.test.ts .github/workflows/ci.yml
git commit -m "feat(storage): Postgres conformance test + CI postgres service"
```

---

## Task 12: HKDF + sealing-key derivation

Pure function. Given `masterKeyBytes` and `appId`, produce a 32-byte sealing key. We use Node's built-in HKDF (`crypto.hkdfSync`) — no extra dep.

**Files:**
- Create: `src/master-keys/hkdf.ts`
- Create: `src/master-keys/hkdf.test.ts`

- [ ] **Step 1: Write the failing test**

`src/master-keys/hkdf.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { deriveSealingKey } from './hkdf.js';

describe('deriveSealingKey', () => {
  it('is deterministic for the same inputs', () => {
    const master = Buffer.alloc(32, 0xab);
    const k1 = deriveSealingKey({ masterKey: master, appId: 'a_1' });
    const k2 = deriveSealingKey({ masterKey: master, appId: 'a_1' });
    expect(k1.equals(k2)).toBe(true);
    expect(k1).toHaveLength(32);
  });

  it('differs by appId', () => {
    const master = Buffer.alloc(32, 0xab);
    const k1 = deriveSealingKey({ masterKey: master, appId: 'a_1' });
    const k2 = deriveSealingKey({ masterKey: master, appId: 'a_2' });
    expect(k1.equals(k2)).toBe(false);
  });

  it('differs by masterKey', () => {
    const k1 = deriveSealingKey({ masterKey: Buffer.alloc(32, 0xab), appId: 'a_1' });
    const k2 = deriveSealingKey({ masterKey: Buffer.alloc(32, 0xcd), appId: 'a_1' });
    expect(k1.equals(k2)).toBe(false);
  });

  it('rejects master keys shorter than 32 bytes', () => {
    expect(() => deriveSealingKey({ masterKey: Buffer.alloc(16), appId: 'a_1' })).toThrow(
      /master key must be at least 32 bytes/,
    );
  });

  it('rejects empty appId', () => {
    expect(() => deriveSealingKey({ masterKey: Buffer.alloc(32), appId: '' })).toThrow(
      /appId required/,
    );
  });
});
```

- [ ] **Step 2: Run test; confirm fail**

```bash
pnpm test src/master-keys/hkdf.test.ts
```

Expected: FAIL — `Cannot find module './hkdf.js'`.

- [ ] **Step 3: Implement `src/master-keys/hkdf.ts`**

```ts
import { hkdfSync } from 'node:crypto';

export interface DeriveSealingKeyInput {
  masterKey: Buffer;
  appId: string;
}

const SEALING_KEY_BYTES = 32;
const HKDF_INFO = 'ait/seal/v1';
const HKDF_HASH = 'sha256';

export function deriveSealingKey(input: DeriveSealingKeyInput): Buffer {
  if (!input.appId || input.appId.length === 0) {
    throw new Error('deriveSealingKey: appId required');
  }
  if (input.masterKey.length < 32) {
    throw new Error('deriveSealingKey: master key must be at least 32 bytes');
  }
  const salt = Buffer.from(input.appId, 'utf8');
  const info = Buffer.from(HKDF_INFO, 'utf8');
  const derived = hkdfSync(HKDF_HASH, input.masterKey, salt, info, SEALING_KEY_BYTES);
  return Buffer.from(derived);
}
```

- [ ] **Step 4: Run test; confirm green**

```bash
pnpm test src/master-keys/hkdf.test.ts
```

Expected: PASS (5/5).

- [ ] **Step 5: Commit**

```bash
git add src/master-keys/hkdf.ts src/master-keys/hkdf.test.ts
git commit -m "feat(master-keys): HKDF-based per-app sealing key derivation"
```

---

## Task 13: `MasterKeyProvider` interface

The interface is two methods: `getKeyBytes(version)` and `listVersions()`. Implementations are env, file, gcpsm (later). The interface lives in `provider.ts`.

**Files:**
- Create: `src/master-keys/provider.ts`

- [ ] **Step 1: Write the interface**

```ts
export interface MasterKeyProvider {
  /** Returns raw key bytes (≥32) for the given version. Throws if missing. */
  getKeyBytes(version: number): Promise<Buffer>;
  /** Returns all known versions, sorted ascending. */
  listVersions(): Promise<number[]>;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/master-keys/provider.ts
git commit -m "feat(master-keys): MasterKeyProvider interface"
```

---

## Task 14: Env provider

Reads `MASTER_KEY_<version>_HEX` env vars at startup. Versions are discovered by scanning env keys matching the pattern.

**Files:**
- Create: `src/master-keys/env-provider.ts`
- Create: `src/master-keys/env-provider.test.ts`

- [ ] **Step 1: Write failing test**

`src/master-keys/env-provider.test.ts`:

```ts
import { afterEach, describe, expect, it } from 'vitest';
import { createEnvMasterKeyProvider } from './env-provider.js';

describe('createEnvMasterKeyProvider', () => {
  afterEach(() => {
    for (const k of Object.keys(process.env)) {
      if (k.startsWith('MASTER_KEY_TEST_')) delete process.env[k];
    }
  });

  it('returns key bytes for a version present in env', async () => {
    const hex = 'aa'.repeat(32);
    process.env.MASTER_KEY_TEST_1_HEX = hex;
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    const bytes = await p.getKeyBytes(1);
    expect(bytes).toHaveLength(32);
    expect(bytes.toString('hex')).toBe(hex);
  });

  it('lists discovered versions sorted', async () => {
    process.env.MASTER_KEY_TEST_2_HEX = 'bb'.repeat(32);
    process.env.MASTER_KEY_TEST_1_HEX = 'aa'.repeat(32);
    process.env.MASTER_KEY_TEST_5_HEX = 'cc'.repeat(32);
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    expect(await p.listVersions()).toEqual([1, 2, 5]);
  });

  it('throws when version is missing', async () => {
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    await expect(p.getKeyBytes(7)).rejects.toThrow(/version 7/);
  });

  it('rejects keys shorter than 32 bytes', async () => {
    process.env.MASTER_KEY_TEST_1_HEX = 'aa'.repeat(16);
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/at least 32 bytes/);
  });

  it('rejects non-hex content', async () => {
    process.env.MASTER_KEY_TEST_1_HEX = 'not-hex';
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/hex/);
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/master-keys/env-provider.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/master-keys/env-provider.ts`**

```ts
import type { MasterKeyProvider } from './provider.js';

export interface EnvProviderOptions {
  /** Env-var prefix. Default: "MASTER_KEY_". Pattern: `${prefix}<version>_HEX`. */
  prefix?: string;
}

const HEX_RE = /^[0-9a-fA-F]+$/;

export function createEnvMasterKeyProvider(opts: EnvProviderOptions = {}): MasterKeyProvider {
  const prefix = opts.prefix ?? 'MASTER_KEY_';
  const versionRe = new RegExp(`^${escapeRegExp(prefix)}(\\d+)_HEX$`);

  function readHex(version: number): string | undefined {
    return process.env[`${prefix}${version}_HEX`];
  }

  return {
    async getKeyBytes(version: number): Promise<Buffer> {
      const hex = readHex(version);
      if (!hex) throw new Error(`MasterKeyProvider(env): version ${version} not present`);
      if (!HEX_RE.test(hex)) {
        throw new Error(`MasterKeyProvider(env): version ${version} is not valid hex`);
      }
      const bytes = Buffer.from(hex, 'hex');
      if (bytes.length < 32) {
        throw new Error(
          `MasterKeyProvider(env): version ${version} must be at least 32 bytes (got ${bytes.length})`,
        );
      }
      return bytes;
    },
    async listVersions(): Promise<number[]> {
      const versions = new Set<number>();
      for (const k of Object.keys(process.env)) {
        const m = versionRe.exec(k);
        if (m && m[1]) versions.add(Number(m[1]));
      }
      return [...versions].sort((a, b) => a - b);
    },
  };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/master-keys/env-provider.test.ts
```

Expected: PASS (5/5).

- [ ] **Step 5: Commit**

```bash
git add src/master-keys/env-provider.ts src/master-keys/env-provider.test.ts
git commit -m "feat(master-keys): env-backed MasterKeyProvider"
```

---

## Task 15: File provider

Reads `${dir}/v<version>.key` files. Files contain raw bytes (not hex). Permissions warning if file is world-readable.

**Files:**
- Create: `src/master-keys/file-provider.ts`
- Create: `src/master-keys/file-provider.test.ts`

- [ ] **Step 1: Write failing test**

`src/master-keys/file-provider.test.ts`:

```ts
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createFileMasterKeyProvider } from './file-provider.js';

describe('createFileMasterKeyProvider', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-mkfile-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns key bytes for a version present', async () => {
    const bytes = Buffer.alloc(32, 0x55);
    writeFileSync(join(dir, 'v1.key'), bytes, { mode: 0o600 });
    const p = createFileMasterKeyProvider({ dir });
    const out = await p.getKeyBytes(1);
    expect(out.equals(bytes)).toBe(true);
  });

  it('lists discovered versions sorted', async () => {
    writeFileSync(join(dir, 'v3.key'), Buffer.alloc(32, 0x33), { mode: 0o600 });
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(32, 0x11), { mode: 0o600 });
    writeFileSync(join(dir, 'README.txt'), 'ignore me');
    const p = createFileMasterKeyProvider({ dir });
    expect(await p.listVersions()).toEqual([1, 3]);
  });

  it('throws when version is missing', async () => {
    const p = createFileMasterKeyProvider({ dir });
    await expect(p.getKeyBytes(99)).rejects.toThrow(/version 99/);
  });

  it('rejects key files shorter than 32 bytes', async () => {
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(16, 0x11), { mode: 0o600 });
    const p = createFileMasterKeyProvider({ dir });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/at least 32 bytes/);
  });

  it('warns (does not throw) when key file is world-readable', async () => {
    const path = join(dir, 'v1.key');
    writeFileSync(path, Buffer.alloc(32, 0x11));
    chmodSync(path, 0o644);
    const warnings: string[] = [];
    const p = createFileMasterKeyProvider({
      dir,
      onWarning: (m) => warnings.push(m),
    });
    await p.getKeyBytes(1);
    expect(warnings.some((w) => /permissions/.test(w))).toBe(true);
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/master-keys/file-provider.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/master-keys/file-provider.ts`**

```ts
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { MasterKeyProvider } from './provider.js';

export interface FileProviderOptions {
  dir: string;
  onWarning?: (msg: string) => void;
}

const FILE_RE = /^v(\d+)\.key$/;

export function createFileMasterKeyProvider(opts: FileProviderOptions): MasterKeyProvider {
  const dir = opts.dir;
  const warn = opts.onWarning ?? ((m: string) => console.warn(m));

  function pathFor(version: number): string {
    return join(dir, `v${version}.key`);
  }

  return {
    async getKeyBytes(version: number): Promise<Buffer> {
      const path = pathFor(version);
      let stat: ReturnType<typeof statSync>;
      try {
        stat = statSync(path);
      } catch {
        throw new Error(`MasterKeyProvider(file): version ${version} not present at ${path}`);
      }
      // POSIX-only check; on Windows the mode bits are not meaningful for "world".
      if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
        warn(
          `MasterKeyProvider(file): ${path} permissions are too open (${(stat.mode & 0o777).toString(8)}); chmod 600 recommended`,
        );
      }
      const bytes = readFileSync(path);
      if (bytes.length < 32) {
        throw new Error(
          `MasterKeyProvider(file): ${path} must be at least 32 bytes (got ${bytes.length})`,
        );
      }
      return bytes;
    },
    async listVersions(): Promise<number[]> {
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return [];
      }
      const out: number[] = [];
      for (const e of entries) {
        const m = FILE_RE.exec(e);
        if (m && m[1]) out.push(Number(m[1]));
      }
      return out.sort((a, b) => a - b);
    },
  };
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/master-keys/file-provider.test.ts
```

Expected: PASS (5/5).

- [ ] **Step 5: Commit**

```bash
git add src/master-keys/file-provider.ts src/master-keys/file-provider.test.ts
git commit -m "feat(master-keys): file-backed MasterKeyProvider with perm warning"
```

---

## Task 16: 6-hour TTL cache wrapper

Wraps any `MasterKeyProvider` and memoizes `getKeyBytes(version)` for `ttlMs` (default 6h). `listVersions` is **not** cached — version discovery is rare and we want freshness when ops add a key.

**Files:**
- Create: `src/master-keys/cache.ts`
- Create: `src/master-keys/cache.test.ts`

- [ ] **Step 1: Write failing test**

`src/master-keys/cache.test.ts`:

```ts
import { describe, expect, it, vi } from 'vitest';
import { withTtlCache } from './cache.js';
import type { MasterKeyProvider } from './provider.js';

function makeMockProvider(): { provider: MasterKeyProvider; calls: number } {
  let calls = 0;
  const provider: MasterKeyProvider = {
    async getKeyBytes(v) {
      calls += 1;
      return Buffer.alloc(32, v);
    },
    async listVersions() {
      return [1, 2, 3];
    },
  };
  return {
    provider,
    get calls() {
      return calls;
    },
  };
}

describe('withTtlCache', () => {
  it('memoizes getKeyBytes within the TTL', async () => {
    const m = makeMockProvider();
    const cached = withTtlCache(m.provider, { ttlMs: 1000 });
    const a = await cached.getKeyBytes(1);
    const b = await cached.getKeyBytes(1);
    expect(a.equals(b)).toBe(true);
    expect(m.calls).toBe(1);
  });

  it('refetches after TTL expiry', async () => {
    vi.useFakeTimers();
    try {
      const m = makeMockProvider();
      const cached = withTtlCache(m.provider, { ttlMs: 60_000 });
      await cached.getKeyBytes(1);
      vi.advanceTimersByTime(60_001);
      await cached.getKeyBytes(1);
      expect(m.calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not cache listVersions', async () => {
    const m = makeMockProvider();
    let listCalls = 0;
    const counted: MasterKeyProvider = {
      getKeyBytes: m.provider.getKeyBytes,
      async listVersions() {
        listCalls += 1;
        return m.provider.listVersions();
      },
    };
    const cached = withTtlCache(counted, { ttlMs: 60_000 });
    await cached.listVersions();
    await cached.listVersions();
    expect(listCalls).toBe(2);
  });

  it('caches different versions independently', async () => {
    const m = makeMockProvider();
    const cached = withTtlCache(m.provider, { ttlMs: 60_000 });
    await cached.getKeyBytes(1);
    await cached.getKeyBytes(2);
    await cached.getKeyBytes(1);
    expect(m.calls).toBe(2);
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/master-keys/cache.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/master-keys/cache.ts`**

```ts
import type { MasterKeyProvider } from './provider.js';

export interface TtlCacheOptions {
  /** Default 6 hours. */
  ttlMs?: number;
  /** Override clock for testing. */
  now?: () => number;
}

const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

interface Entry {
  bytes: Buffer;
  expiresAt: number;
}

export function withTtlCache(
  inner: MasterKeyProvider,
  opts: TtlCacheOptions = {},
): MasterKeyProvider {
  const ttl = opts.ttlMs ?? SIX_HOURS_MS;
  const now = opts.now ?? Date.now;
  const cache = new Map<number, Entry>();

  return {
    async getKeyBytes(version: number): Promise<Buffer> {
      const t = now();
      const entry = cache.get(version);
      if (entry && entry.expiresAt > t) {
        return entry.bytes;
      }
      const bytes = await inner.getKeyBytes(version);
      cache.set(version, { bytes, expiresAt: t + ttl });
      return bytes;
    },
    async listVersions(): Promise<number[]> {
      return inner.listVersions();
    },
  };
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/master-keys/cache.test.ts
```

Expected: PASS (4/4).

- [ ] **Step 5: Commit**

```bash
git add src/master-keys/cache.ts src/master-keys/cache.test.ts
git commit -m "feat(master-keys): 6h TTL cache wrapper for MasterKeyProvider"
```

---

## Task 17: Provider factory + index

The factory picks a provider based on `MASTER_KEY_PROVIDER` env (`env|file`). GCPSM is added in Phase 10. The factory wraps the inner provider in the TTL cache.

**Files:**
- Create: `src/master-keys/index.ts`
- Create: `src/master-keys/index.test.ts`

- [ ] **Step 1: Write failing test**

`src/master-keys/index.test.ts`:

```ts
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createMasterKeyProvider } from './index.js';

describe('createMasterKeyProvider', () => {
  const origEnv = { ...process.env };
  let dir: string | null = null;

  beforeEach(() => {
    dir = null;
  });

  afterEach(() => {
    process.env = { ...origEnv };
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('builds an env-backed provider', async () => {
    process.env.MASTER_KEY_PROVIDER = 'env';
    process.env.MASTER_KEY_1_HEX = 'aa'.repeat(32);
    const p = createMasterKeyProvider();
    expect(await p.listVersions()).toEqual([1]);
    expect((await p.getKeyBytes(1)).toString('hex')).toBe('aa'.repeat(32));
  });

  it('builds a file-backed provider', async () => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-mkfactory-'));
    process.env.MASTER_KEY_PROVIDER = 'file';
    process.env.MASTER_KEY_DIR = dir;
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(32, 0x42), { mode: 0o600 });
    const p = createMasterKeyProvider();
    expect(await p.listVersions()).toEqual([1]);
    expect((await p.getKeyBytes(1)).length).toBe(32);
  });

  it('throws on unknown provider', () => {
    process.env.MASTER_KEY_PROVIDER = 'wat';
    expect(() => createMasterKeyProvider()).toThrow(/MASTER_KEY_PROVIDER/);
  });

  it('defaults to env provider when MASTER_KEY_PROVIDER is unset', async () => {
    delete process.env.MASTER_KEY_PROVIDER;
    process.env.MASTER_KEY_1_HEX = 'cc'.repeat(32);
    const p = createMasterKeyProvider();
    expect(await p.listVersions()).toEqual([1]);
  });

  it('rejects file provider without MASTER_KEY_DIR', () => {
    process.env.MASTER_KEY_PROVIDER = 'file';
    delete process.env.MASTER_KEY_DIR;
    expect(() => createMasterKeyProvider()).toThrow(/MASTER_KEY_DIR/);
  });
});
```

- [ ] **Step 2: Confirm fail**

```bash
pnpm test src/master-keys/index.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 3: Implement `src/master-keys/index.ts`**

```ts
import { withTtlCache } from './cache.js';
import { createEnvMasterKeyProvider } from './env-provider.js';
import { createFileMasterKeyProvider } from './file-provider.js';
import type { MasterKeyProvider } from './provider.js';

export type { MasterKeyProvider } from './provider.js';
export { deriveSealingKey } from './hkdf.js';

export interface CreateMasterKeyProviderOptions {
  /** Override env-var lookup for tests; defaults to process.env. */
  env?: NodeJS.ProcessEnv;
  ttlMs?: number;
}

export function createMasterKeyProvider(
  opts: CreateMasterKeyProviderOptions = {},
): MasterKeyProvider {
  const env = opts.env ?? process.env;
  const kind = (env.MASTER_KEY_PROVIDER ?? 'env').toLowerCase();

  let inner: MasterKeyProvider;
  if (kind === 'env') {
    inner = createEnvMasterKeyProvider();
  } else if (kind === 'file') {
    const dir = env.MASTER_KEY_DIR;
    if (!dir) {
      throw new Error('createMasterKeyProvider(file): MASTER_KEY_DIR env required');
    }
    inner = createFileMasterKeyProvider({ dir });
  } else {
    throw new Error(`createMasterKeyProvider: unknown MASTER_KEY_PROVIDER=${kind}`);
  }

  const cacheOpts = opts.ttlMs !== undefined ? { ttlMs: opts.ttlMs } : {};
  return withTtlCache(inner, cacheOpts);
}
```

- [ ] **Step 4: Confirm green**

```bash
pnpm test src/master-keys/index.test.ts
```

Expected: PASS (5/5).

- [ ] **Step 5: Lint + typecheck + full suite**

```bash
pnpm lint && pnpm typecheck && pnpm test
```

Expected: green. Test count should now include all sqlite + master-keys tests; pg suite is `describe.skip` if `PG_TEST_URL` isn't set.

- [ ] **Step 6: Commit**

```bash
git add src/master-keys/index.ts src/master-keys/index.test.ts
git commit -m "feat(master-keys): factory dispatching env|file providers + TTL cache"
```

---

## Task 18: Final phase-end verification

- [ ] **Step 1: Full local pipeline**

```bash
pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm build && pnpm test
```

Expected: green.

- [ ] **Step 2: Optional: pg conformance**

If Postgres is up at `PG_TEST_URL`:

```bash
PG_TEST_URL=postgresql://test:test@127.0.0.1:55432/zerocode_test pnpm test src/storage/pg.test.ts
```

Expected: 8 conformance tests pass.

- [ ] **Step 3: Confirm import paths**

```bash
git grep -nE "from '\\./storage/'" src/ | head -5
git grep -nE "from '\\./master-keys/'" src/ | head -5
```

Expected: no top-level imports yet from outside the storage/master-keys modules — only their own internal imports. (Phase 2 is the first consumer.)

- [ ] **Step 4: Confirm spec invariants are not violated**

```bash
git grep -nE 'master_key|sealing_key' src/master-keys/ | head
git grep -nE 'console.log' src/master-keys/ src/storage/
```

Expected:
- First grep shows no master key bytes printed in any error (only "version N", "at least 32 bytes" — no payloads).
- Second grep is empty: no `console.log` in the new modules.

---

## Phase 1 — done condition

After Task 18 passes:

- 7 tables exist in both pg and sqlite migrations and are tested by the same conformance suite.
- The migration runner is idempotent on both backends.
- `MasterKeyProvider` has env + file implementations, an HKDF-based per-app sealing key derivation, and a 6-hour TTL cache.
- The factory dispatches by `MASTER_KEY_PROVIDER` env.
- No HTTP route, no CLI, no Toss adapter has been touched yet — Phase 1 is library code only.
- `pnpm lint && pnpm typecheck && pnpm build && pnpm test` is green.
- (Optional) `PG_TEST_URL`-gated conformance is green.

That state is the foundation Phase 2 (workspaces / apps / API_TOKEN admin) builds on.
