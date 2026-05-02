# Phase 1 — DB + master keys

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the persistence layer (Postgres + SQLite) using **Drizzle ORM** with the 7-table schema, and the `MasterKeyProvider` interface with env + file providers, HKDF-derived per-app sealing keys, and a 6-hour TTL cache. No HTTP surface yet — this phase is library code that subsequent phases call.

**Architecture:** A `Storage` interface covers the operations later phases need (insert/get/update/delete on each table). Two **hand-mirrored Drizzle schema files** (`schema.pg.ts` using `pgTable`, `schema.sqlite.ts` using `sqliteTable`) define the 7 tables once per dialect — Drizzle has no cross-dialect helper, so the storage-conformance test is what guarantees the mirror cannot drift silently. `drizzle-kit generate` produces per-dialect migration SQL that lives under `drizzle/pg/` and `drizzle/sqlite/` (committed to the repo). Postgres and SQLite drivers wrap Drizzle's per-dialect query builder — no hand-written SQL strings, no per-driver query duplication beyond the schema file. Domain types are **derived from the schema** via Drizzle's `$inferSelect`, so the interface, the schema, and the implementation cannot disagree about column shape. `MasterKeyProvider` is a tiny interface (`getKeyBytes(version): Promise<Buffer>`) with env/file implementations registered at startup; GCPSM is deferred to Phase 10. HKDF + sealing-key derivation are pure functions (no I/O) tested in isolation. The cache is a small TTL Map keyed by `version`.

**Bytes-at-the-boundary decision:** the `Storage` interface uses **`Uint8Array`** for byte columns (`mtlsCertEnc`, `mtlsKeyEnc`). Drizzle returns `Buffer` from both `bytea` (PG) and `blob({mode:'buffer'})` (SQLite); both drivers normalize the inferred row to `Uint8Array` at the mapping boundary. `Buffer` is a `Uint8Array` subclass, so `Buffer`-producing callers in later phases (`crypto.randomBytes()`, `fs.readFileSync()`) pass through unchanged. Picking `Uint8Array` keeps the interface portable across runtimes (Bun, Deno, browsers, Workers) and matches the spec §5.3 column-type table.

**Tech stack:** TypeScript ESM strict, **`drizzle-orm`** + **`drizzle-kit`** (Drizzle ORM, current stable May 2026: `drizzle-orm@^0.45` / `drizzle-kit@^0.30`), `pg` (node-postgres adapter for Drizzle — chosen over `postgres-js` because the project already declares `pg`, the lock-file resolution stays small, and `pg.Pool` semantics are well-understood for connection management on Cloud Run), `better-sqlite3` (Drizzle's underlying SQLite driver), `node:crypto` (HKDF, AES-GCM), vitest. No new HTTP / runtime deps.

---

## Universal invariants (apply to every task)

See [`2026-05-01-zero-code-mode-index.md`](./2026-05-01-zero-code-mode-index.md#universal-invariants). Phase 1 leans on:

- **TDD.** Every storage / crypto unit gets a red→green→commit cycle.
- **No PII / secrets in logs.** Master key bytes never appear in any error or test output.
- **Cloud-agnostic.** GCPSM is **not** added in this phase — only env + file providers.
- **Self-host first-class.** SQLite path passes the same conformance suite as Postgres.
- **Schema is the source of truth.** Domain types are inferred from `schema.pg.ts` via `$inferSelect`; no hand-maintained type duplication.

## Files touched in this phase

**Created:**

- `src/storage/schema.pg.ts` — Drizzle `pgTable` definitions for all 7 tables.
- `src/storage/schema.sqlite.ts` — Drizzle `sqliteTable` mirror.
- `src/storage/types.ts` — thin re-exports of `$inferSelect` types from `schema.pg.ts` (PG is canonical) plus the `AppOwnershipStatus` literal union and the storage-boundary normalized `AppRecord` type that uses `Uint8Array` for byte columns.
- `src/storage/interface.ts` — `Storage` interface.
- `src/storage/migrate.ts` — wraps `drizzle-orm/node-postgres/migrator` + `drizzle-orm/better-sqlite3/migrator`.
- `src/storage/migrate.test.ts`
- `src/storage/pg.ts` — Postgres driver (Drizzle + `pg.Pool`).
- `src/storage/pg.test.ts` — gated on `PG_TEST_URL` env.
- `src/storage/sqlite.ts` — SQLite driver (Drizzle + `better-sqlite3`).
- `src/storage/sqlite.test.ts`
- `src/storage/conformance.ts` — driver-agnostic test suite.
- `drizzle.config.pg.ts` — drizzle-kit config for the PG dialect.
- `drizzle.config.sqlite.ts` — drizzle-kit config for the SQLite dialect.
- `drizzle/pg/0000_*.sql` + `drizzle/pg/meta/*` — generated PG migration artifacts.
- `drizzle/sqlite/0000_*.sql` + `drizzle/sqlite/meta/*` — generated SQLite migration artifacts.
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

- `package.json` — add `drizzle-orm`, `drizzle-kit`, ensure `pg` + `@types/pg` + `better-sqlite3` + `@types/better-sqlite3` resolve to current stable; add `db:generate:pg`, `db:generate:sqlite`, `db:migrate:pg`, `db:migrate:sqlite` scripts.
- `tsconfig.json` — no change (drizzle.config files live at the project root and are picked up by the existing `include: ["src/**/*", "cli/**/*"]` only if used by tests; the configs themselves are run via `pnpm exec drizzle-kit`, which type-checks them in-process).
- `.gitignore` — confirm `drizzle/` is **not** ignored (committed migration SQL is the source of record).

---

## Pre-flight

```bash
pwd       # …/oidc-bridge-jwt-signature-verification
git branch --show-current   # zero-code-mode
git status                  # clean
git log --oneline -3        # most recent should be the spec adoption + raw-driver squash marker
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

## Task 1: Add Drizzle ORM + driver deps

Drizzle ORM gives us per-dialect query builders without hand-mirrored SQL strings. We pick `drizzle-orm`'s **node-postgres** adapter (over `postgres-js`) because the project already standardized on `pg`, `pg.Pool` semantics are well-understood for Cloud Run, and there is no measurable throughput gap at our load. We pick `better-sqlite3` because its synchronous API maps cleanly to migration runners and CLI bootstrap, and Drizzle treats it as a first-class adapter. The async `node:sqlite` standard module is too new for production reliance in May 2026.

**Files:**
- Modify: `package.json`
- Modify: `pnpm-lock.yaml`

- [ ] **Step 1: Install runtime deps**

```bash
pnpm add drizzle-orm@^0.45 pg@^8.20 better-sqlite3@^11
```

- [ ] **Step 2: Install dev deps**

```bash
pnpm add -D drizzle-kit@^0.30 @types/pg@^8.20 @types/better-sqlite3@^7.6
```

- [ ] **Step 3: Add npm scripts to `package.json`**

Inside the `"scripts"` block add:

```json
    "db:generate:pg": "drizzle-kit generate --config=drizzle.config.pg.ts",
    "db:generate:sqlite": "drizzle-kit generate --config=drizzle.config.sqlite.ts",
    "db:migrate:pg": "drizzle-kit migrate --config=drizzle.config.pg.ts",
    "db:migrate:sqlite": "drizzle-kit migrate --config=drizzle.config.sqlite.ts"
```

- [ ] **Step 4: Verify**

```bash
pnpm list drizzle-orm drizzle-kit pg better-sqlite3 --depth=0
```

Expected: shows `drizzle-orm 0.45.x`, `drizzle-kit 0.30.x`, `pg 8.x`, `better-sqlite3 11.x`.

- [ ] **Step 5: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "chore: add drizzle-orm + drizzle-kit + pg + better-sqlite3 for Phase 1 storage"
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
    forks: { singleFork: false },
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

## Task 3: Drizzle Postgres schema (`schema.pg.ts`)

Postgres is the canonical dialect. Drizzle's `pgTable` builder produces schema objects that double as runtime query targets and TypeScript types. The schema is the source of truth — domain types in Task 5 are inferred from this file via `$inferSelect`.

**Files:**
- Create: `src/storage/schema.pg.ts`

- [ ] **Step 1: Write the schema**

```ts
import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  customType,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core';

// `bytea` is not a top-level export from `drizzle-orm/pg-core` (verified
// against 0.45.2). Define it via customType — Drizzle returns Buffer on
// SELECT and accepts Buffer on INSERT, matching the spec §5.3 boundary
// (drivers normalize to Uint8Array at the storage interface).
const bytea = customType<{ data: Buffer; default: false }>({
  dataType: () => 'bytea',
});

const tsCol = (name: string) =>
  timestamp(name, { withTimezone: true, mode: 'date' });

export const users = pgTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  createdAt: tsCol('created_at').notNull().defaultNow(),
});

export const apiTokens = pgTable(
  'api_tokens',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    tokenHash: text('token_hash').notNull().unique(),
    scopes: text('scopes').array().notNull().default(sql`'{}'::text[]`),
    createdAt: tsCol('created_at').notNull().defaultNow(),
    lastUsedAt: tsCol('last_used_at'),
  },
  (t) => ({
    userIdIdx: index('api_tokens_user_id_idx').on(t.userId),
  }),
);

export const workspaces = pgTable(
  'workspaces',
  {
    id: text('id').primaryKey(),
    ownerUserId: text('owner_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    createdAt: tsCol('created_at').notNull().defaultNow(),
  },
  (t) => ({
    ownerIdx: index('workspaces_owner_idx').on(t.ownerUserId),
  }),
);

export const apps = pgTable(
  'apps',
  {
    id: text('id').primaryKey(),
    workspaceId: text('workspace_id')
      .notNull()
      .references(() => workspaces.id, { onDelete: 'cascade' }),
    appIdToss: text('app_id_toss').notNull(),
    displayTitle: text('display_title').notNull(),
    clientId: text('client_id').notNull().unique(),
    clientSecretHashes: text('client_secret_hashes')
      .array()
      .notNull()
      .default(sql`'{}'::text[]`),
    mtlsCertEnc: bytea('mtls_cert_enc').notNull(),
    mtlsKeyEnc: bytea('mtls_key_enc').notNull(),
    sealingKeyVersion: integer('sealing_key_version').notNull(),
    allowedOrigins: text('allowed_origins')
      .array()
      .notNull()
      .default(sql`'{}'::text[]`),
    ownershipStatus: text('ownership_status').notNull(),
    ownershipGraceUntil: tsCol('ownership_grace_until'),
    rawTokensEnabled: boolean('raw_tokens_enabled').notNull().default(false),
    createdAt: tsCol('created_at').notNull().defaultNow(),
    updatedAt: tsCol('updated_at')
      .notNull()
      .defaultNow()
      .$onUpdateFn(() => new Date()),
  },
  (t) => ({
    workspaceIdx: index('apps_workspace_idx').on(t.workspaceId),
    workspaceAppIdTossUq: uniqueIndex('apps_workspace_app_id_toss_uq').on(
      t.workspaceId,
      t.appIdToss,
    ),
    ownershipChk: check(
      'apps_ownership_status_chk',
      sql`${t.ownershipStatus} IN ('pending','verified','lapsed')`,
    ),
  }),
);

export const userSessions = pgTable(
  'user_sessions',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: tsCol('expires_at').notNull(),
    createdAt: tsCol('created_at').notNull().defaultNow(),
  },
  (t) => ({
    userIdx: index('user_sessions_user_idx').on(t.userId),
  }),
);

export const masterKeys = pgTable('master_keys', {
  id: text('id').primaryKey(),
  version: integer('version').notNull().unique(),
  createdAt: tsCol('created_at').notNull().defaultNow(),
  retiredAt: tsCol('retired_at'),
  providerRef: text('provider_ref'),
});

export const auditLog = pgTable(
  'audit_log',
  {
    id: text('id').primaryKey(),
    ts: tsCol('ts').notNull().defaultNow(),
    actor: text('actor').notNull(),
    action: text('action').notNull(),
    target: text('target').notNull(),
    detailsJson: jsonb('details_json')
      .$type<Record<string, unknown>>()
      .notNull()
      .default(sql`'{}'::jsonb`),
  },
  (t) => ({
    tsIdx: index('audit_log_ts_idx').on(sql`${t.ts} DESC`),
  }),
);
```

- [ ] **Step 2: Run typecheck**

```bash
pnpm typecheck
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/storage/schema.pg.ts
git commit -m "feat(storage): Drizzle pgTable schema for the 7-table model"
```

---

## Task 4: Drizzle SQLite schema (`schema.sqlite.ts`)

SQLite mirror. Per spec §5.3:
- timestamps → `integer({mode:'timestamp_ms'})` (Drizzle returns `Date`, matches PG `timestamp({mode:'date'})`).
- boolean → `integer({mode:'boolean'})`.
- bytes → `blob({mode:'buffer'})`.
- string array → `text({mode:'json'}).$type<string[]>()`.
- jsonb → `text({mode:'json'}).$type<Record<string,unknown>>()`.

**Files:**
- Create: `src/storage/schema.sqlite.ts`

- [ ] **Step 1: Write the schema**

```ts
import { sql } from 'drizzle-orm';
import {
  blob,
  check,
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core';

const tsCol = (name: string) =>
  integer(name, { mode: 'timestamp_ms' });

export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  createdAt: tsCol('created_at').notNull().default(sql`(unixepoch() * 1000)`),
});

export const apiTokens = sqliteTable(
  'api_tokens',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    tokenHash: text('token_hash').notNull().unique(),
    scopes: text('scopes', { mode: 'json' })
      .$type<string[]>()
      .notNull()
      .default(sql`'[]'`),
    createdAt: tsCol('created_at').notNull().default(sql`(unixepoch() * 1000)`),
    lastUsedAt: tsCol('last_used_at'),
  },
  (t) => ({
    userIdIdx: index('api_tokens_user_id_idx').on(t.userId),
  }),
);

export const workspaces = sqliteTable(
  'workspaces',
  {
    id: text('id').primaryKey(),
    ownerUserId: text('owner_user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    createdAt: tsCol('created_at').notNull().default(sql`(unixepoch() * 1000)`),
  },
  (t) => ({
    ownerIdx: index('workspaces_owner_idx').on(t.ownerUserId),
  }),
);

export const apps = sqliteTable(
  'apps',
  {
    id: text('id').primaryKey(),
    workspaceId: text('workspace_id')
      .notNull()
      .references(() => workspaces.id, { onDelete: 'cascade' }),
    appIdToss: text('app_id_toss').notNull(),
    displayTitle: text('display_title').notNull(),
    clientId: text('client_id').notNull().unique(),
    clientSecretHashes: text('client_secret_hashes', { mode: 'json' })
      .$type<string[]>()
      .notNull()
      .default(sql`'[]'`),
    mtlsCertEnc: blob('mtls_cert_enc', { mode: 'buffer' }).notNull(),
    mtlsKeyEnc: blob('mtls_key_enc', { mode: 'buffer' }).notNull(),
    sealingKeyVersion: integer('sealing_key_version').notNull(),
    allowedOrigins: text('allowed_origins', { mode: 'json' })
      .$type<string[]>()
      .notNull()
      .default(sql`'[]'`),
    ownershipStatus: text('ownership_status').notNull(),
    ownershipGraceUntil: tsCol('ownership_grace_until'),
    rawTokensEnabled: integer('raw_tokens_enabled', { mode: 'boolean' })
      .notNull()
      .default(false),
    createdAt: tsCol('created_at').notNull().default(sql`(unixepoch() * 1000)`),
    updatedAt: tsCol('updated_at').notNull().default(sql`(unixepoch() * 1000)`),
  },
  (t) => ({
    workspaceIdx: index('apps_workspace_idx').on(t.workspaceId),
    workspaceAppIdTossUq: uniqueIndex('apps_workspace_app_id_toss_uq').on(
      t.workspaceId,
      t.appIdToss,
    ),
    ownershipChk: check(
      'apps_ownership_status_chk',
      sql`${t.ownershipStatus} IN ('pending','verified','lapsed')`,
    ),
  }),
);

export const userSessions = sqliteTable(
  'user_sessions',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: tsCol('expires_at').notNull(),
    createdAt: tsCol('created_at').notNull().default(sql`(unixepoch() * 1000)`),
  },
  (t) => ({
    userIdx: index('user_sessions_user_idx').on(t.userId),
  }),
);

export const masterKeys = sqliteTable('master_keys', {
  id: text('id').primaryKey(),
  version: integer('version').notNull().unique(),
  createdAt: tsCol('created_at').notNull().default(sql`(unixepoch() * 1000)`),
  retiredAt: tsCol('retired_at'),
  providerRef: text('provider_ref'),
});

export const auditLog = sqliteTable(
  'audit_log',
  {
    id: text('id').primaryKey(),
    ts: tsCol('ts').notNull().default(sql`(unixepoch() * 1000)`),
    actor: text('actor').notNull(),
    action: text('action').notNull(),
    target: text('target').notNull(),
    detailsJson: text('details_json', { mode: 'json' })
      .$type<Record<string, unknown>>()
      .notNull()
      .default(sql`'{}'`),
  },
  (t) => ({
    tsIdx: index('audit_log_ts_idx').on(sql`${t.ts} DESC`),
  }),
);
```

- [ ] **Step 2: Run typecheck**

```bash
pnpm typecheck
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/storage/schema.sqlite.ts
git commit -m "feat(storage): Drizzle sqliteTable schema mirroring schema.pg.ts"
```

---

## Task 5: Domain types from `$inferSelect`

The schema is the source of truth. PG is canonical (it stores native bytes / arrays / jsonb), so we infer types from `schema.pg.ts`. The one transformation: `mtlsCertEnc` / `mtlsKeyEnc` come back from Drizzle as `Buffer`; the `Storage` interface boundary normalizes them to `Uint8Array` (see Architecture above). We define the boundary type `AppRecord` here.

**Files:**
- Create: `src/storage/types.ts`

- [ ] **Step 1: Write the types**

```ts
import type {
  apiTokens,
  apps,
  auditLog,
  masterKeys,
  userSessions,
  users,
  workspaces,
} from './schema.pg.js';

export type AppOwnershipStatus = 'pending' | 'verified' | 'lapsed';

export type User = typeof users.$inferSelect;
export type ApiToken = typeof apiTokens.$inferSelect;
export type Workspace = typeof workspaces.$inferSelect;
export type UserSession = typeof userSessions.$inferSelect;
export type MasterKeyMeta = typeof masterKeys.$inferSelect;
export type AuditLogEntry = typeof auditLog.$inferSelect;

// Drizzle infers `mtls_cert_enc: Buffer` from `bytea`. We expose Uint8Array
// at the Storage interface boundary (drivers normalize on the way out, accept
// either Buffer or Uint8Array on the way in — Buffer extends Uint8Array, so
// callers that pass Buffer work without a copy).
type RawApp = typeof apps.$inferSelect;
export type AppRecord = Omit<
  RawApp,
  'mtlsCertEnc' | 'mtlsKeyEnc' | 'ownershipStatus'
> & {
  mtlsCertEnc: Uint8Array;
  mtlsKeyEnc: Uint8Array;
  ownershipStatus: AppOwnershipStatus;
};
```

- [ ] **Step 2: Run typecheck**

```bash
pnpm typecheck
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add src/storage/types.ts
git commit -m "feat(storage): domain types derived from Drizzle \$inferSelect"
```

---

## Task 6: drizzle-kit configs + generated migrations

Two configs (one per dialect). Each emits its migrations under `drizzle/<dialect>/`. The output is committed: it is the source of record for what was applied.

**Files:**
- Create: `drizzle.config.pg.ts`
- Create: `drizzle.config.sqlite.ts`
- Create: `drizzle/pg/0000_*.sql` + `drizzle/pg/meta/_journal.json` + `drizzle/pg/meta/0000_snapshot.json` (generated)
- Create: `drizzle/sqlite/0000_*.sql` + `drizzle/sqlite/meta/_journal.json` + `drizzle/sqlite/meta/0000_snapshot.json` (generated)

- [ ] **Step 1: Write `drizzle.config.pg.ts`**

```ts
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/storage/schema.pg.ts',
  out: './drizzle/pg',
  // Connection is only needed for `drizzle-kit migrate`. Generation is offline.
  dbCredentials: {
    url: process.env.PG_DATABASE_URL ?? 'postgresql://localhost:5432/oidc_bridge',
  },
  strict: true,
  verbose: true,
});
```

- [ ] **Step 2: Write `drizzle.config.sqlite.ts`**

```ts
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'sqlite',
  schema: './src/storage/schema.sqlite.ts',
  out: './drizzle/sqlite',
  dbCredentials: {
    url: process.env.SQLITE_PATH ?? './oidc-bridge.sqlite',
  },
  strict: true,
  verbose: true,
});
```

- [ ] **Step 3: Generate the PG migration**

```bash
pnpm exec drizzle-kit generate --config=drizzle.config.pg.ts
```

Expected: writes `drizzle/pg/0000_<adjective>_<noun>.sql` plus `drizzle/pg/meta/_journal.json` and `drizzle/pg/meta/0000_snapshot.json`. Inspect the SQL: should contain `CREATE TABLE "users"`, `"api_tokens"`, ..., the `apps_ownership_status_chk` CHECK constraint, the unique index `apps_workspace_app_id_toss_uq`, and the four named indexes.

- [ ] **Step 4: Generate the SQLite migration**

```bash
pnpm exec drizzle-kit generate --config=drizzle.config.sqlite.ts
```

Expected: writes `drizzle/sqlite/0000_<adjective>_<noun>.sql` plus matching `meta/` files.

- [ ] **Step 5: Confirm `.gitignore` does NOT exclude `drizzle/`**

```bash
git check-ignore -v drizzle/pg/meta/_journal.json
```

Expected: nothing matched (exit code 1). If `drizzle/` is ignored, remove the rule from `.gitignore` before committing.

- [ ] **Step 6: Commit**

```bash
git add drizzle.config.pg.ts drizzle.config.sqlite.ts drizzle/
git commit -m "feat(storage): drizzle-kit configs + generated 0000 migrations (pg + sqlite)"
```

---

## Task 7: `Storage` interface

The interface is the contract every later phase imports. Methods are scoped to the operations actually needed by other phases. We do not add a method until a concrete caller exists — but we do add the full set the spec implies (so subsequent phase plans can reference them). Both drivers implement this interface via their per-dialect Drizzle query builder.

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
    mtlsCertEnc: Uint8Array;
    mtlsKeyEnc: Uint8Array;
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
      mtlsCertEnc: Uint8Array;
      mtlsKeyEnc: Uint8Array;
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
git commit -m "feat(storage): Storage interface; bytes are Uint8Array at the boundary"
```

---

## Task 8: Migration runner

We delegate to Drizzle's per-dialect `migrate()` helpers. They read `meta/_journal.json` and apply only the migrations not already in `__drizzle_migrations` (Drizzle's bookkeeping table — replaces the prior `schema_migrations`).

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
import { drizzle } from 'drizzle-orm/better-sqlite3';
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
    const sqlite = new Database(dbPath);
    const db = drizzle(sqlite);
    runSqliteMigrations(db);
    const tables = sqlite
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as { name: string }[];
    const names = tables.map((t) => t.name).filter((n) => !n.startsWith('sqlite_'));
    expect(names).toContain('users');
    expect(names).toContain('api_tokens');
    expect(names).toContain('workspaces');
    expect(names).toContain('apps');
    expect(names).toContain('user_sessions');
    expect(names).toContain('master_keys');
    expect(names).toContain('audit_log');
    expect(names).toContain('__drizzle_migrations');
    sqlite.close();
  });

  it('is idempotent', () => {
    const sqlite = new Database(dbPath);
    const db = drizzle(sqlite);
    runSqliteMigrations(db);
    runSqliteMigrations(db);
    const applied = sqlite
      .prepare('SELECT hash FROM __drizzle_migrations ORDER BY id')
      .all() as { hash: string }[];
    expect(applied).toHaveLength(1);
    sqlite.close();
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
import { fileURLToPath } from 'node:url';
import type { BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import { migrate as migrateSqlite } from 'drizzle-orm/better-sqlite3/migrator';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { migrate as migratePg } from 'drizzle-orm/node-postgres/migrator';

// drizzle-kit emits to drizzle/<dialect>/ at the project root (a sibling of src/).
const PG_FOLDER = fileURLToPath(new URL('../../drizzle/pg/', import.meta.url));
const SQLITE_FOLDER = fileURLToPath(new URL('../../drizzle/sqlite/', import.meta.url));

export async function runPgMigrations(db: NodePgDatabase): Promise<void> {
  await migratePg(db, { migrationsFolder: PG_FOLDER });
}

export function runSqliteMigrations(db: BetterSQLite3Database): void {
  migrateSqlite(db, { migrationsFolder: SQLITE_FOLDER });
}
```

- [ ] **Step 4: Run tests; confirm green**

```bash
pnpm test src/storage/migrate.test.ts
```

Expected: PASS (2/2).

- [ ] **Step 5: Commit**

```bash
git add src/storage/migrate.ts src/storage/migrate.test.ts
git commit -m "feat(storage): migration runner wrapping Drizzle migrators (pg + sqlite)"
```

---

## Task 9: SQLite driver

Single driver file. Drizzle's `better-sqlite3` adapter is synchronous under the hood; we wrap operations in `async` to satisfy the `Storage` interface — uniform across drivers.

Critical implementation rules (carry-forward from prior plan):
- `retireMasterKey`: use `.returning()` + check the returned array; throw if empty. **Atomic in a single statement.**
- All `create*` methods: use `.returning()` and return the row directly; no post-INSERT redundant SELECT.
- Enforce `apps` count ≤ 1 at insert (spec §5.3 SQLite-only constraint): check `countApps()` before insert and throw if >= 1.
- Buffer/Uint8Array normalization: Drizzle returns `Buffer` from `blob({mode:'buffer'})`; pass through directly (Buffer is a Uint8Array subclass).

**Files:**
- Create: `src/storage/sqlite.ts`

- [ ] **Step 1: Write `src/storage/sqlite.ts`**

```ts
import Database from 'better-sqlite3';
import { and, asc, count, desc, eq } from 'drizzle-orm';
import { type BetterSQLite3Database, drizzle } from 'drizzle-orm/better-sqlite3';
import type { Storage } from './interface.js';
import { runSqliteMigrations } from './migrate.js';
import * as s from './schema.sqlite.js';
import type {
  AppOwnershipStatus,
  AppRecord,
} from './types.js';

function toAppRecord(row: typeof s.apps.$inferSelect): AppRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    appIdToss: row.appIdToss,
    displayTitle: row.displayTitle,
    clientId: row.clientId,
    clientSecretHashes: row.clientSecretHashes,
    mtlsCertEnc: new Uint8Array(row.mtlsCertEnc.buffer, row.mtlsCertEnc.byteOffset, row.mtlsCertEnc.byteLength),
    mtlsKeyEnc: new Uint8Array(row.mtlsKeyEnc.buffer, row.mtlsKeyEnc.byteOffset, row.mtlsKeyEnc.byteLength),
    sealingKeyVersion: row.sealingKeyVersion,
    allowedOrigins: row.allowedOrigins,
    ownershipStatus: row.ownershipStatus as AppOwnershipStatus,
    ownershipGraceUntil: row.ownershipGraceUntil,
    rawTokensEnabled: row.rawTokensEnabled,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function asBuffer(u: Uint8Array): Buffer {
  return Buffer.isBuffer(u) ? u : Buffer.from(u.buffer, u.byteOffset, u.byteLength);
}

export interface SqliteStorageOptions {
  path: string;
}

export function createSqliteStorage(opts: SqliteStorageOptions): Storage {
  const sqlite = new Database(opts.path);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  const db: BetterSQLite3Database = drizzle(sqlite);
  runSqliteMigrations(db);

  const storage: Storage = {
    async createUser(input) {
      const [row] = await db
        .insert(s.users)
        .values({ id: input.id, email: input.email })
        .returning();
      if (!row) throw new Error('createUser: insert returned no row');
      return row;
    },
    async getUserById(id) {
      const [row] = await db.select().from(s.users).where(eq(s.users.id, id));
      return row ?? null;
    },
    async getUserByEmail(email) {
      const [row] = await db.select().from(s.users).where(eq(s.users.email, email));
      return row ?? null;
    },

    async createApiToken(input) {
      const [row] = await db
        .insert(s.apiTokens)
        .values({
          id: input.id,
          userId: input.userId,
          name: input.name,
          tokenHash: input.tokenHash,
          scopes: input.scopes,
        })
        .returning();
      if (!row) throw new Error('createApiToken: insert returned no row');
      return row;
    },
    async getApiTokenByHash(tokenHash) {
      const [row] = await db
        .select()
        .from(s.apiTokens)
        .where(eq(s.apiTokens.tokenHash, tokenHash));
      return row ?? null;
    },
    async listApiTokensByUser(userId) {
      return db
        .select()
        .from(s.apiTokens)
        .where(eq(s.apiTokens.userId, userId))
        .orderBy(asc(s.apiTokens.createdAt));
    },
    async deleteApiToken(id) {
      await db.delete(s.apiTokens).where(eq(s.apiTokens.id, id));
    },
    async touchApiTokenLastUsed(id, at) {
      await db.update(s.apiTokens).set({ lastUsedAt: at }).where(eq(s.apiTokens.id, id));
    },

    async createWorkspace(input) {
      const [row] = await db
        .insert(s.workspaces)
        .values({ id: input.id, ownerUserId: input.ownerUserId, name: input.name })
        .returning();
      if (!row) throw new Error('createWorkspace: insert returned no row');
      return row;
    },
    async getWorkspace(id) {
      const [row] = await db.select().from(s.workspaces).where(eq(s.workspaces.id, id));
      return row ?? null;
    },
    async listWorkspacesByOwner(ownerUserId) {
      return db
        .select()
        .from(s.workspaces)
        .where(eq(s.workspaces.ownerUserId, ownerUserId))
        .orderBy(asc(s.workspaces.createdAt));
    },
    async updateWorkspace(id, patch) {
      const set: { name?: string } = {};
      if (patch.name !== undefined) set.name = patch.name;
      const [row] = await db
        .update(s.workspaces)
        .set(set)
        .where(eq(s.workspaces.id, id))
        .returning();
      if (!row) throw new Error(`workspace ${id} not found`);
      return row;
    },
    async deleteWorkspace(id) {
      await db.delete(s.workspaces).where(eq(s.workspaces.id, id));
    },

    async createApp(input) {
      // SQLite is the ≤1-app-row dialect (spec §5.3).
      const existing = await storage.countApps();
      if (existing >= 1) {
        throw new Error('SQLite storage allows at most 1 app row (spec §5.3)');
      }
      const now = new Date();
      const [row] = await db
        .insert(s.apps)
        .values({
          id: input.id,
          workspaceId: input.workspaceId,
          appIdToss: input.appIdToss,
          displayTitle: input.displayTitle,
          clientId: input.clientId,
          clientSecretHashes: input.clientSecretHashes,
          mtlsCertEnc: asBuffer(input.mtlsCertEnc),
          mtlsKeyEnc: asBuffer(input.mtlsKeyEnc),
          sealingKeyVersion: input.sealingKeyVersion,
          allowedOrigins: input.allowedOrigins,
          ownershipStatus: input.ownershipStatus,
          ownershipGraceUntil: input.ownershipGraceUntil,
          rawTokensEnabled: input.rawTokensEnabled,
          createdAt: now,
          updatedAt: now,
        })
        .returning();
      if (!row) throw new Error('createApp: insert returned no row');
      return toAppRecord(row);
    },
    async getApp(id) {
      const [row] = await db.select().from(s.apps).where(eq(s.apps.id, id));
      return row ? toAppRecord(row) : null;
    },
    async getAppByClientId(clientId) {
      const [row] = await db.select().from(s.apps).where(eq(s.apps.clientId, clientId));
      return row ? toAppRecord(row) : null;
    },
    async listAppsByWorkspace(workspaceId) {
      const rows = await db
        .select()
        .from(s.apps)
        .where(eq(s.apps.workspaceId, workspaceId))
        .orderBy(asc(s.apps.createdAt));
      return rows.map(toAppRecord);
    },
    async updateApp(id, patch) {
      const set: Partial<typeof s.apps.$inferInsert> = { updatedAt: new Date() };
      if (patch.displayTitle !== undefined) set.displayTitle = patch.displayTitle;
      if (patch.clientSecretHashes !== undefined) set.clientSecretHashes = patch.clientSecretHashes;
      if (patch.mtlsCertEnc !== undefined) set.mtlsCertEnc = asBuffer(patch.mtlsCertEnc);
      if (patch.mtlsKeyEnc !== undefined) set.mtlsKeyEnc = asBuffer(patch.mtlsKeyEnc);
      if (patch.sealingKeyVersion !== undefined) set.sealingKeyVersion = patch.sealingKeyVersion;
      if (patch.allowedOrigins !== undefined) set.allowedOrigins = patch.allowedOrigins;
      if (patch.ownershipStatus !== undefined) set.ownershipStatus = patch.ownershipStatus;
      if (patch.ownershipGraceUntil !== undefined) set.ownershipGraceUntil = patch.ownershipGraceUntil;
      if (patch.rawTokensEnabled !== undefined) set.rawTokensEnabled = patch.rawTokensEnabled;

      const [row] = await db
        .update(s.apps)
        .set(set)
        .where(eq(s.apps.id, id))
        .returning();
      if (!row) throw new Error(`app ${id} not found`);
      return toAppRecord(row);
    },
    async deleteApp(id) {
      await db.delete(s.apps).where(eq(s.apps.id, id));
    },
    async countApps() {
      const [r] = await db.select({ c: count() }).from(s.apps);
      return r?.c ?? 0;
    },

    async createUserSession(input) {
      const [row] = await db
        .insert(s.userSessions)
        .values({ id: input.id, userId: input.userId, expiresAt: input.expiresAt })
        .returning();
      if (!row) throw new Error('createUserSession: insert returned no row');
      return row;
    },
    async getUserSession(id) {
      const [row] = await db.select().from(s.userSessions).where(eq(s.userSessions.id, id));
      return row ?? null;
    },
    async deleteUserSession(id) {
      await db.delete(s.userSessions).where(eq(s.userSessions.id, id));
    },

    async createMasterKey(input) {
      const [row] = await db
        .insert(s.masterKeys)
        .values({ id: input.id, version: input.version, providerRef: input.providerRef })
        .returning();
      if (!row) throw new Error('createMasterKey: insert returned no row');
      return row;
    },
    async getMasterKeyByVersion(version) {
      const [row] = await db
        .select()
        .from(s.masterKeys)
        .where(eq(s.masterKeys.version, version));
      return row ?? null;
    },
    async listMasterKeys() {
      return db.select().from(s.masterKeys).orderBy(asc(s.masterKeys.version));
    },
    async retireMasterKey(version, retiredAt) {
      // Atomic single-statement update + return; throw if no row matched.
      const [row] = await db
        .update(s.masterKeys)
        .set({ retiredAt })
        .where(eq(s.masterKeys.version, version))
        .returning();
      if (!row) throw new Error(`master_key version ${version} not found`);
      return row;
    },

    async appendAudit(entry) {
      await db.insert(s.auditLog).values({
        id: entry.id,
        ts: entry.ts ?? new Date(),
        actor: entry.actor,
        action: entry.action,
        target: entry.target,
        detailsJson: entry.detailsJson,
      });
    },
    async listAudit(options) {
      const limit = options?.limit ?? 100;
      return db.select().from(s.auditLog).orderBy(desc(s.auditLog.ts)).limit(limit);
    },

    async close() {
      sqlite.close();
    },
  };

  return storage;

  // Suppress "and" import unused-var false positive: the symbol is reserved
  // for upcoming compound predicates in later phases.
  void and;
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
git commit -m "feat(storage): SQLite driver via Drizzle implementing Storage"
```

---

## Task 10: Storage conformance test suite

A single test factory takes a `() => Promise<Storage>` and runs the full CRUD matrix, exercising every method with assertions sensitive to type round-trip: `Date` in/out, byte arrays in/out, string-array round-trip, JSON object round-trip, boolean round-trip. This is the load-bearing schema-drift detector.

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

    it('users: create + getById + getByEmail; Date round-trips', async () => {
      const u = await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      expect(u.email).toBe('a@b.c');
      expect(u.createdAt).toBeInstanceOf(Date);
      expect(await storage.getUserById('u_1')).toMatchObject({ email: 'a@b.c' });
      expect(await storage.getUserByEmail('a@b.c')).toMatchObject({ id: 'u_1' });
      expect(await storage.getUserById('nope')).toBeNull();
    });

    it('api tokens: scopes round-trip + last-used Date precision', async () => {
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

      const at = new Date('2026-05-01T12:00:00.000Z');
      await storage.touchApiTokenLastUsed('t_1', at);
      const after = await storage.getApiTokenByHash('h1');
      expect(after?.lastUsedAt).toBeInstanceOf(Date);
      expect(after?.lastUsedAt?.toISOString()).toBe(at.toISOString());

      const list = await storage.listApiTokensByUser('u_1');
      expect(list).toHaveLength(1);
      await storage.deleteApiToken('t_1');
      expect(await storage.getApiTokenByHash('h1')).toBeNull();
    });

    it('workspaces: create, update name, list, delete', async () => {
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

    it('apps: bytes / arrays / boolean / Date all round-trip', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      await storage.createWorkspace({ id: 'w_1', ownerUserId: 'u_1', name: 'first' });

      const certBytes = new Uint8Array([1, 2, 3, 4, 0xff, 0x00, 0xab]);
      const keyBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const grace = new Date('2026-05-04T00:00:00.000Z');

      const a = await storage.createApp({
        id: 'a_1',
        workspaceId: 'w_1',
        appIdToss: 'mini-app-123',
        displayTitle: 'My App',
        clientId: 'client_xyz',
        clientSecretHashes: ['$2a$12$abc', '$2a$12$def'],
        mtlsCertEnc: certBytes,
        mtlsKeyEnc: keyBytes,
        sealingKeyVersion: 1,
        allowedOrigins: ['https://app.example.com', 'https://www.example.com'],
        ownershipStatus: 'pending',
        ownershipGraceUntil: grace,
        rawTokensEnabled: false,
      });
      expect(a.allowedOrigins).toEqual(['https://app.example.com', 'https://www.example.com']);
      expect(a.clientSecretHashes).toEqual(['$2a$12$abc', '$2a$12$def']);
      expect(Array.from(a.mtlsCertEnc)).toEqual(Array.from(certBytes));
      expect(Array.from(a.mtlsKeyEnc)).toEqual(Array.from(keyBytes));
      expect(a.rawTokensEnabled).toBe(false);
      expect(a.ownershipGraceUntil).toBeInstanceOf(Date);
      expect(a.ownershipGraceUntil?.toISOString()).toBe(grace.toISOString());
      expect(a.createdAt).toBeInstanceOf(Date);

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

    it('user sessions: Date round-trip preserves millisecond precision', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      const exp = new Date('2026-05-02T01:23:45.678Z');
      const s = await storage.createUserSession({
        id: 's_1',
        userId: 'u_1',
        expiresAt: exp,
      });
      expect(s.userId).toBe('u_1');
      const f = await storage.getUserSession('s_1');
      expect(f?.expiresAt).toBeInstanceOf(Date);
      expect(f?.expiresAt.toISOString()).toBe(exp.toISOString());
      await storage.deleteUserSession('s_1');
      expect(await storage.getUserSession('s_1')).toBeNull();
    });

    it('master keys: create, list ordering, retire is atomic + throws on missing', async () => {
      const m1 = await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
      expect(m1.retiredAt).toBeNull();
      await storage.createMasterKey({ id: 'mk_2', version: 2, providerRef: 'env:2' });
      const list = await storage.listMasterKeys();
      expect(list.map((m) => m.version)).toEqual([1, 2]);

      const retiredAt = new Date('2026-05-01T00:00:00.000Z');
      const retired = await storage.retireMasterKey(1, retiredAt);
      expect(retired.retiredAt).toBeInstanceOf(Date);
      expect(retired.retiredAt?.toISOString()).toBe(retiredAt.toISOString());

      const fetched = await storage.getMasterKeyByVersion(1);
      expect(fetched?.retiredAt).not.toBeNull();

      await expect(storage.retireMasterKey(99, retiredAt)).rejects.toThrow(/version 99/);
    });

    it('audit log: JSON object round-trip + newest-first ordering + limit', async () => {
      const ts1 = new Date('2026-05-01T10:00:00.000Z');
      const ts2 = new Date('2026-05-01T11:00:00.000Z');
      await storage.appendAudit({
        id: 'au_1',
        ts: ts1,
        actor: 'u_1',
        action: 'app.create',
        target: 'a_1',
        detailsJson: { foo: 'bar', count: 7, nested: { ok: true } },
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
      expect(all[1]!.detailsJson).toEqual({ foo: 'bar', count: 7, nested: { ok: true } });
      expect(all[0]!.detailsJson).toEqual({ reason: 'cleanup' });
      const limited = await storage.listAudit({ limit: 1 });
      expect(limited).toHaveLength(1);
      expect(limited[0]!.id).toBe('au_2');
    });

    it('cross-dialect Date precision: persisted Date equals input Date by ISO string', async () => {
      await storage.createUser({ id: 'u_dt', email: 'dt@x.y' });
      // Choose a non-rounded ms boundary.
      const exp = new Date('2026-12-31T23:59:59.123Z');
      await storage.createUserSession({ id: 's_dt', userId: 'u_dt', expiresAt: exp });
      const back = await storage.getUserSession('s_dt');
      expect(back?.expiresAt.toISOString()).toBe(exp.toISOString());
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

## Task 11: Postgres driver

Same surface as the SQLite driver, using `pg.Pool` wrapped by Drizzle's `node-postgres` adapter. Postgres handles arrays / timestamps / jsonb / bytea natively, so the only normalization is `Buffer → Uint8Array` at the boundary (matching the spec §5.3 column-type table).

**Files:**
- Create: `src/storage/pg.ts`

- [ ] **Step 1: Write `src/storage/pg.ts`**

```ts
import { asc, count, desc, eq } from 'drizzle-orm';
import { type NodePgDatabase, drizzle } from 'drizzle-orm/node-postgres';
import { Pool, type PoolConfig } from 'pg';
import type { Storage } from './interface.js';
import { runPgMigrations } from './migrate.js';
import * as s from './schema.pg.js';
import type {
  AppOwnershipStatus,
  AppRecord,
} from './types.js';

function toAppRecord(row: typeof s.apps.$inferSelect): AppRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    appIdToss: row.appIdToss,
    displayTitle: row.displayTitle,
    clientId: row.clientId,
    clientSecretHashes: row.clientSecretHashes,
    mtlsCertEnc: new Uint8Array(row.mtlsCertEnc.buffer, row.mtlsCertEnc.byteOffset, row.mtlsCertEnc.byteLength),
    mtlsKeyEnc: new Uint8Array(row.mtlsKeyEnc.buffer, row.mtlsKeyEnc.byteOffset, row.mtlsKeyEnc.byteLength),
    sealingKeyVersion: row.sealingKeyVersion,
    allowedOrigins: row.allowedOrigins,
    ownershipStatus: row.ownershipStatus as AppOwnershipStatus,
    ownershipGraceUntil: row.ownershipGraceUntil,
    rawTokensEnabled: row.rawTokensEnabled,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function asBuffer(u: Uint8Array): Buffer {
  return Buffer.isBuffer(u) ? u : Buffer.from(u.buffer, u.byteOffset, u.byteLength);
}

export interface PgStorageOptions {
  connectionString: string;
  poolConfig?: Omit<PoolConfig, 'connectionString'>;
}

export async function createPgStorage(opts: PgStorageOptions): Promise<Storage> {
  const pool = new Pool({ connectionString: opts.connectionString, ...opts.poolConfig });
  const db: NodePgDatabase = drizzle(pool);
  await runPgMigrations(db);

  const storage: Storage = {
    async createUser(input) {
      const [row] = await db
        .insert(s.users)
        .values({ id: input.id, email: input.email })
        .returning();
      if (!row) throw new Error('createUser: insert returned no row');
      return row;
    },
    async getUserById(id) {
      const [row] = await db.select().from(s.users).where(eq(s.users.id, id));
      return row ?? null;
    },
    async getUserByEmail(email) {
      const [row] = await db.select().from(s.users).where(eq(s.users.email, email));
      return row ?? null;
    },

    async createApiToken(input) {
      const [row] = await db
        .insert(s.apiTokens)
        .values({
          id: input.id,
          userId: input.userId,
          name: input.name,
          tokenHash: input.tokenHash,
          scopes: input.scopes,
        })
        .returning();
      if (!row) throw new Error('createApiToken: insert returned no row');
      return row;
    },
    async getApiTokenByHash(tokenHash) {
      const [row] = await db
        .select()
        .from(s.apiTokens)
        .where(eq(s.apiTokens.tokenHash, tokenHash));
      return row ?? null;
    },
    async listApiTokensByUser(userId) {
      return db
        .select()
        .from(s.apiTokens)
        .where(eq(s.apiTokens.userId, userId))
        .orderBy(asc(s.apiTokens.createdAt));
    },
    async deleteApiToken(id) {
      await db.delete(s.apiTokens).where(eq(s.apiTokens.id, id));
    },
    async touchApiTokenLastUsed(id, at) {
      await db.update(s.apiTokens).set({ lastUsedAt: at }).where(eq(s.apiTokens.id, id));
    },

    async createWorkspace(input) {
      const [row] = await db
        .insert(s.workspaces)
        .values({ id: input.id, ownerUserId: input.ownerUserId, name: input.name })
        .returning();
      if (!row) throw new Error('createWorkspace: insert returned no row');
      return row;
    },
    async getWorkspace(id) {
      const [row] = await db.select().from(s.workspaces).where(eq(s.workspaces.id, id));
      return row ?? null;
    },
    async listWorkspacesByOwner(ownerUserId) {
      return db
        .select()
        .from(s.workspaces)
        .where(eq(s.workspaces.ownerUserId, ownerUserId))
        .orderBy(asc(s.workspaces.createdAt));
    },
    async updateWorkspace(id, patch) {
      const set: { name?: string } = {};
      if (patch.name !== undefined) set.name = patch.name;
      const [row] = await db
        .update(s.workspaces)
        .set(set)
        .where(eq(s.workspaces.id, id))
        .returning();
      if (!row) throw new Error(`workspace ${id} not found`);
      return row;
    },
    async deleteWorkspace(id) {
      await db.delete(s.workspaces).where(eq(s.workspaces.id, id));
    },

    async createApp(input) {
      const now = new Date();
      const [row] = await db
        .insert(s.apps)
        .values({
          id: input.id,
          workspaceId: input.workspaceId,
          appIdToss: input.appIdToss,
          displayTitle: input.displayTitle,
          clientId: input.clientId,
          clientSecretHashes: input.clientSecretHashes,
          mtlsCertEnc: asBuffer(input.mtlsCertEnc),
          mtlsKeyEnc: asBuffer(input.mtlsKeyEnc),
          sealingKeyVersion: input.sealingKeyVersion,
          allowedOrigins: input.allowedOrigins,
          ownershipStatus: input.ownershipStatus,
          ownershipGraceUntil: input.ownershipGraceUntil,
          rawTokensEnabled: input.rawTokensEnabled,
          createdAt: now,
          updatedAt: now,
        })
        .returning();
      if (!row) throw new Error('createApp: insert returned no row');
      return toAppRecord(row);
    },
    async getApp(id) {
      const [row] = await db.select().from(s.apps).where(eq(s.apps.id, id));
      return row ? toAppRecord(row) : null;
    },
    async getAppByClientId(clientId) {
      const [row] = await db.select().from(s.apps).where(eq(s.apps.clientId, clientId));
      return row ? toAppRecord(row) : null;
    },
    async listAppsByWorkspace(workspaceId) {
      const rows = await db
        .select()
        .from(s.apps)
        .where(eq(s.apps.workspaceId, workspaceId))
        .orderBy(asc(s.apps.createdAt));
      return rows.map(toAppRecord);
    },
    async updateApp(id, patch) {
      const set: Partial<typeof s.apps.$inferInsert> = { updatedAt: new Date() };
      if (patch.displayTitle !== undefined) set.displayTitle = patch.displayTitle;
      if (patch.clientSecretHashes !== undefined) set.clientSecretHashes = patch.clientSecretHashes;
      if (patch.mtlsCertEnc !== undefined) set.mtlsCertEnc = asBuffer(patch.mtlsCertEnc);
      if (patch.mtlsKeyEnc !== undefined) set.mtlsKeyEnc = asBuffer(patch.mtlsKeyEnc);
      if (patch.sealingKeyVersion !== undefined) set.sealingKeyVersion = patch.sealingKeyVersion;
      if (patch.allowedOrigins !== undefined) set.allowedOrigins = patch.allowedOrigins;
      if (patch.ownershipStatus !== undefined) set.ownershipStatus = patch.ownershipStatus;
      if (patch.ownershipGraceUntil !== undefined) set.ownershipGraceUntil = patch.ownershipGraceUntil;
      if (patch.rawTokensEnabled !== undefined) set.rawTokensEnabled = patch.rawTokensEnabled;

      const [row] = await db
        .update(s.apps)
        .set(set)
        .where(eq(s.apps.id, id))
        .returning();
      if (!row) throw new Error(`app ${id} not found`);
      return toAppRecord(row);
    },
    async deleteApp(id) {
      await db.delete(s.apps).where(eq(s.apps.id, id));
    },
    async countApps() {
      const [r] = await db.select({ c: count() }).from(s.apps);
      return Number(r?.c ?? 0);
    },

    async createUserSession(input) {
      const [row] = await db
        .insert(s.userSessions)
        .values({ id: input.id, userId: input.userId, expiresAt: input.expiresAt })
        .returning();
      if (!row) throw new Error('createUserSession: insert returned no row');
      return row;
    },
    async getUserSession(id) {
      const [row] = await db.select().from(s.userSessions).where(eq(s.userSessions.id, id));
      return row ?? null;
    },
    async deleteUserSession(id) {
      await db.delete(s.userSessions).where(eq(s.userSessions.id, id));
    },

    async createMasterKey(input) {
      const [row] = await db
        .insert(s.masterKeys)
        .values({ id: input.id, version: input.version, providerRef: input.providerRef })
        .returning();
      if (!row) throw new Error('createMasterKey: insert returned no row');
      return row;
    },
    async getMasterKeyByVersion(version) {
      const [row] = await db
        .select()
        .from(s.masterKeys)
        .where(eq(s.masterKeys.version, version));
      return row ?? null;
    },
    async listMasterKeys() {
      return db.select().from(s.masterKeys).orderBy(asc(s.masterKeys.version));
    },
    async retireMasterKey(version, retiredAt) {
      // Atomic single-statement update + return; throw if no row matched.
      const [row] = await db
        .update(s.masterKeys)
        .set({ retiredAt })
        .where(eq(s.masterKeys.version, version))
        .returning();
      if (!row) throw new Error(`master_key version ${version} not found`);
      return row;
    },

    async appendAudit(entry) {
      await db.insert(s.auditLog).values({
        id: entry.id,
        ts: entry.ts ?? new Date(),
        actor: entry.actor,
        action: entry.action,
        target: entry.target,
        detailsJson: entry.detailsJson,
      });
    },
    async listAudit(options) {
      const limit = options?.limit ?? 100;
      return db.select().from(s.auditLog).orderBy(desc(s.auditLog.ts)).limit(limit);
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
git commit -m "feat(storage): Postgres driver via Drizzle implementing Storage"
```

---

## Task 12: Postgres conformance test (gated on `PG_TEST_URL`)

The pg test file imports the same `runStorageConformance` factory and `describe.skip`s the suite when `PG_TEST_URL` is unset (so local CI without Docker still passes). When set, each test gets a freshly-truncated DB.

**Files:**
- Create: `src/storage/pg.test.ts`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the test**

```ts
import { Pool } from 'pg';
import { describe } from 'vitest';
import { runStorageConformance } from './conformance.js';
import { createPgStorage } from './pg.js';

const url = process.env.PG_TEST_URL;

if (!url) {
  describe.skip('Storage conformance — pg (PG_TEST_URL not set)', () => {});
} else {
  runStorageConformance('pg', {
    async open() {
      // Truncate before each open to give the conformance suite an empty DB.
      const pool = new Pool({ connectionString: url });
      try {
        // Apply migrations once so the tables exist; the driver will re-run idempotently.
        const { drizzle } = await import('drizzle-orm/node-postgres');
        const { runPgMigrations } = await import('./migrate.js');
        await runPgMigrations(drizzle(pool));
        await pool.query(
          'TRUNCATE TABLE audit_log, master_keys, user_sessions, apps, workspaces, api_tokens, users RESTART IDENTITY CASCADE',
        );
      } finally {
        await pool.end();
      }
      return createPgStorage({ connectionString: url });
    },
    async cleanup(s) {
      await s.close();
    },
  });
}
```

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

## Task 13: HKDF + sealing-key derivation

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

## Task 14: `MasterKeyProvider` interface

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

## Task 15: Env provider

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

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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

## Task 16: File provider

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

## Task 17: 6-hour TTL cache wrapper

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

function makeMockProvider(): { provider: MasterKeyProvider; calls: () => number } {
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
  return { provider, calls: () => calls };
}

describe('withTtlCache', () => {
  it('memoizes getKeyBytes within the TTL', async () => {
    const m = makeMockProvider();
    const cached = withTtlCache(m.provider, { ttlMs: 1000 });
    const a = await cached.getKeyBytes(1);
    const b = await cached.getKeyBytes(1);
    expect(a.equals(b)).toBe(true);
    expect(m.calls()).toBe(1);
  });

  it('refetches after TTL expiry', async () => {
    vi.useFakeTimers();
    try {
      const m = makeMockProvider();
      const cached = withTtlCache(m.provider, { ttlMs: 60_000 });
      await cached.getKeyBytes(1);
      vi.advanceTimersByTime(60_001);
      await cached.getKeyBytes(1);
      expect(m.calls()).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not cache listVersions', async () => {
    let listCalls = 0;
    const counted: MasterKeyProvider = {
      async getKeyBytes(v) {
        return Buffer.alloc(32, v);
      },
      async listVersions() {
        listCalls += 1;
        return [1, 2, 3];
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
    expect(m.calls()).toBe(2);
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

## Task 18: Provider factory + index

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

## Task 19: Final phase-end verification

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

- [ ] **Step 3: Smoke-test the Drizzle-backed storage manually**

```bash
node --input-type=module -e "
  import { mkdtempSync } from 'node:fs';
  import { tmpdir } from 'node:os';
  import { join } from 'node:path';
  import { createSqliteStorage } from './dist/storage/sqlite.mjs';
  // (run via ts-node or after build; confirms migration runs cleanly on a fresh path)
  const dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-smoke-'));
  const s = createSqliteStorage({ path: join(dir, 'smoke.db') });
  await s.createUser({ id: 'u_smoke', email: 'smoke@x.y' });
  console.log(await s.getUserByEmail('smoke@x.y'));
  await s.close();
" || echo "smoke skipped (build artifact path may differ); skip step 3 if build target differs"
```

The smoke step is informational — green CI test runs are the real gate.

- [ ] **Step 4: Confirm import paths**

```bash
git grep -nE "from '\\./storage/'" src/ | head -5
git grep -nE "from '\\./master-keys/'" src/ | head -5
```

Expected: no top-level imports yet from outside the storage/master-keys modules — only their own internal imports. (Phase 2 is the first consumer.)

- [ ] **Step 5: Confirm spec invariants are not violated**

```bash
git grep -nE 'master_key|sealing_key' src/master-keys/ | head
git grep -nE 'console.log' src/master-keys/ src/storage/
```

Expected:
- First grep shows no master key bytes printed in any error (only "version N", "at least 32 bytes" — no payloads).
- Second grep is empty: no `console.log` in the new modules.

- [ ] **Step 6: Confirm Drizzle artifacts are committed**

```bash
ls drizzle/pg/ drizzle/sqlite/
ls drizzle/pg/meta/ drizzle/sqlite/meta/
```

Expected: each dialect has `0000_*.sql` and `meta/_journal.json` + `meta/0000_snapshot.json`. Phase 1 should land with exactly one migration per dialect.

---

## Phase 1 — done condition

After Task 19 passes:

- 7 tables exist in both pg and sqlite Drizzle schemas, both passing the same conformance suite. Schema drift between `schema.pg.ts` and `schema.sqlite.ts` is caught by the conformance test (`mtlsCertEnc` bytes round-trip, `Date` round-trip at ms precision, `string[]` round-trip, `Record<string,unknown>` JSON round-trip, `boolean` round-trip).
- Drizzle-generated migrations under `drizzle/pg/` and `drizzle/sqlite/` are committed.
- The migration runner is idempotent on both backends (Drizzle's `__drizzle_migrations` table tracks applied SQL).
- `MasterKeyProvider` has env + file implementations, an HKDF-based per-app sealing key derivation, and a 6-hour TTL cache.
- The factory dispatches by `MASTER_KEY_PROVIDER` env.
- No HTTP route, no CLI, no Toss adapter has been touched yet — Phase 1 is library code only.
- `pnpm lint && pnpm typecheck && pnpm build && pnpm test` is green.
- (Optional) `PG_TEST_URL`-gated conformance is green.

That state is the foundation Phase 2 (workspaces / apps / API_TOKEN admin) builds on.
