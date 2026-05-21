import type { D1Database } from '@cloudflare/workers-types';
import { asc, count, desc, eq, lte, sql } from 'drizzle-orm';
import { type DrizzleD1Database, drizzle } from 'drizzle-orm/d1';
import type { Storage } from './interface.js';
import * as s from './schema.d1.js';
import type { AppOwnershipStatus, AppRecord } from './types.js';

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

/**
 * Inline DDL migration for D1. drizzle-kit generates file-based migrations
 * that drizzle-orm/d1/migrator reads from disk — not available in Workers or
 * test environments. We apply the same DDL as drizzle/sqlite/ inline via the
 * D1 API's batch() method.
 *
 * Every CREATE TABLE and CREATE [UNIQUE] INDEX uses IF NOT EXISTS so that
 * runD1Migrations is idempotent — safe to call against an already-migrated
 * database without throwing "table/index already exists". ALTER TABLE
 * statements are not idempotent by nature; they are append-only migrations
 * and must only run once (deploy-time guarantee, same as before).
 */
const MIGRATION_DDL = [
  // 0000 — initial schema
  `CREATE TABLE IF NOT EXISTS "users" (
    "id" text PRIMARY KEY NOT NULL,
    "email" text NOT NULL,
    "created_at" integer DEFAULT (unixepoch() * 1000) NOT NULL
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "users_email_unique" ON "users" ("email")`,

  `CREATE TABLE IF NOT EXISTS "api_tokens" (
    "id" text PRIMARY KEY NOT NULL,
    "user_id" text NOT NULL,
    "name" text NOT NULL,
    "token_hash" text NOT NULL,
    "scopes" text DEFAULT '[]' NOT NULL,
    "created_at" integer DEFAULT (unixepoch() * 1000) NOT NULL,
    "last_used_at" integer,
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE cascade
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "api_tokens_token_hash_unique" ON "api_tokens" ("token_hash")`,
  `CREATE INDEX IF NOT EXISTS "api_tokens_user_id_idx" ON "api_tokens" ("user_id")`,

  `CREATE TABLE IF NOT EXISTS "workspaces" (
    "id" text PRIMARY KEY NOT NULL,
    "owner_user_id" text NOT NULL,
    "name" text NOT NULL,
    "created_at" integer DEFAULT (unixepoch() * 1000) NOT NULL,
    FOREIGN KEY ("owner_user_id") REFERENCES "users"("id") ON DELETE cascade
  )`,
  `CREATE INDEX IF NOT EXISTS "workspaces_owner_idx" ON "workspaces" ("owner_user_id")`,

  `CREATE TABLE IF NOT EXISTS "apps" (
    "id" text PRIMARY KEY NOT NULL,
    "workspace_id" text NOT NULL,
    "app_id_toss" text NOT NULL,
    "display_title" text NOT NULL,
    "client_id" text NOT NULL,
    "client_secret_hashes" text DEFAULT '[]' NOT NULL,
    "mtls_cert_enc" blob NOT NULL,
    "mtls_key_enc" blob NOT NULL,
    "sealing_key_version" integer NOT NULL,
    "allowed_origins" text DEFAULT '[]' NOT NULL,
    "ownership_status" text NOT NULL,
    "ownership_grace_until" integer,
    "raw_tokens_enabled" integer DEFAULT false NOT NULL,
    "created_at" integer DEFAULT (unixepoch() * 1000) NOT NULL,
    "updated_at" integer DEFAULT (unixepoch() * 1000) NOT NULL,
    FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE cascade,
    CONSTRAINT "apps_ownership_status_chk" CHECK("ownership_status" IN ('pending','verified','lapsed'))
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "apps_client_id_unique" ON "apps" ("client_id")`,
  `CREATE INDEX IF NOT EXISTS "apps_workspace_idx" ON "apps" ("workspace_id")`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "apps_workspace_app_id_toss_uq" ON "apps" ("workspace_id","app_id_toss")`,

  `CREATE TABLE IF NOT EXISTS "audit_log" (
    "id" text PRIMARY KEY NOT NULL,
    "ts" integer DEFAULT (unixepoch() * 1000) NOT NULL,
    "actor" text NOT NULL,
    "action" text NOT NULL,
    "target" text NOT NULL,
    "details_json" text DEFAULT '{}' NOT NULL
  )`,
  // Note: D1/workerd does not support DESC in expression indexes; use plain index.
  `CREATE INDEX IF NOT EXISTS "audit_log_ts_idx" ON "audit_log" ("ts")`,

  `CREATE TABLE IF NOT EXISTS "master_keys" (
    "id" text PRIMARY KEY NOT NULL,
    "version" integer NOT NULL,
    "created_at" integer DEFAULT (unixepoch() * 1000) NOT NULL,
    "retired_at" integer,
    "provider_ref" text
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "master_keys_version_unique" ON "master_keys" ("version")`,

  `CREATE TABLE IF NOT EXISTS "user_sessions" (
    "id" text PRIMARY KEY NOT NULL,
    "user_id" text NOT NULL,
    "expires_at" integer NOT NULL,
    "created_at" integer DEFAULT (unixepoch() * 1000) NOT NULL,
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE cascade
  )`,
  `CREATE INDEX IF NOT EXISTS "user_sessions_user_idx" ON "user_sessions" ("user_id")`,

  // 0001 — add password_hash column
  `ALTER TABLE "users" ADD COLUMN "password_hash" text`,
];

export async function runD1Migrations(db: D1Database): Promise<void> {
  // D1 does not support multi-statement batches via the REST API for DDL
  // directly, but workerd (used by miniflare) executes them sequentially.
  // We run each statement independently to maximise compatibility.
  //
  // CREATE TABLE / INDEX statements use IF NOT EXISTS and are inherently
  // idempotent. ALTER TABLE ADD COLUMN has no IF NOT EXISTS syntax in SQLite;
  // we swallow "duplicate column" errors so the function is safe to call
  // against an already-migrated database.
  for (const stmt of MIGRATION_DDL) {
    try {
      await db.prepare(stmt).run();
    } catch (err) {
      const isAlterAddColumn = /^\s*ALTER\s+TABLE\b/i.test(stmt);
      const isDuplicateColumn = err instanceof Error && /duplicate column/i.test(err.message);
      if (isAlterAddColumn && isDuplicateColumn) continue;
      throw err;
    }
  }
}

// ---------------------------------------------------------------------------
// Type helpers
// ---------------------------------------------------------------------------

const OWNERSHIP_STATUSES = new Set<AppOwnershipStatus>(['pending', 'verified', 'lapsed']);

function toOwnershipStatus(raw: string): AppOwnershipStatus {
  if (!OWNERSHIP_STATUSES.has(raw as AppOwnershipStatus)) {
    throw new Error(`Unknown ownershipStatus from DB: "${raw}"`);
  }
  return raw as AppOwnershipStatus;
}

/** D1 returns BLOB columns as ArrayBuffer; normalize to Uint8Array. */
function toUint8Array(value: Buffer | Uint8Array | ArrayBuffer): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  // Buffer extends Uint8Array — same branch handles both.
  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}

function toAppRecord(row: typeof s.apps.$inferSelect): AppRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    appIdToss: row.appIdToss,
    displayTitle: row.displayTitle,
    clientId: row.clientId,
    clientSecretHashes: row.clientSecretHashes,
    mtlsCertEnc: toUint8Array(row.mtlsCertEnc),
    mtlsKeyEnc: toUint8Array(row.mtlsKeyEnc),
    sealingKeyVersion: row.sealingKeyVersion,
    allowedOrigins: row.allowedOrigins,
    ownershipStatus: toOwnershipStatus(row.ownershipStatus),
    ownershipGraceUntil: row.ownershipGraceUntil,
    rawTokensEnabled: row.rawTokensEnabled,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

// ---------------------------------------------------------------------------
// D1Storage factory
// ---------------------------------------------------------------------------

export interface CreateD1StorageDeps {
  db: D1Database;
  /** Optional dispose callback invoked by `close()`. Useful in tests to shut down Miniflare. */
  onClose?: () => Promise<void>;
}

/**
 * drizzle-orm/sqlite-core types blob({ mode: 'buffer' }) as `Buffer` for insertion,
 * but D1 accepts Uint8Array at runtime. This helper satisfies TypeScript without
 * allocating a copy when the value is already appropriately backed.
 */
function toInsertBlob(u: Uint8Array): Buffer {
  return Buffer.isBuffer(u) ? u : Buffer.from(u.buffer, u.byteOffset, u.byteLength);
}

export function createD1Storage(deps: CreateD1StorageDeps): Storage {
  // DrizzleD1Database accepts both the real D1Database and miniflare's
  // D1Database (same interface, different runtime). The cast avoids the
  // AnyD1Database union that differs between the two type declarations.
  const db: DrizzleD1Database = drizzle(deps.db as unknown as Parameters<typeof drizzle>[0]);

  const storage: Storage = {
    // -----------------------------------------------------------------------
    // Users
    // -----------------------------------------------------------------------
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
    async setUserPassword(userId, passwordHash) {
      const result = await db
        .update(s.users)
        .set({ passwordHash })
        .where(eq(s.users.id, userId))
        .returning({ id: s.users.id });
      if (result.length === 0) throw new Error(`setUserPassword: unknown user "${userId}"`);
    },

    // -----------------------------------------------------------------------
    // API tokens
    // -----------------------------------------------------------------------
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
      const [row] = await db.select().from(s.apiTokens).where(eq(s.apiTokens.tokenHash, tokenHash));
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

    // -----------------------------------------------------------------------
    // Workspaces
    // -----------------------------------------------------------------------
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
      if (Object.keys(set).length === 0) {
        const existing = await storage.getWorkspace(id);
        if (!existing) throw new Error(`workspace ${id} not found`);
        return existing;
      }
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

    // -----------------------------------------------------------------------
    // Apps
    // -----------------------------------------------------------------------
    async createApp(input) {
      // D1 is the multi-tenant driver (public instance). No 1-app limit.
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
          mtlsCertEnc: toInsertBlob(input.mtlsCertEnc),
          mtlsKeyEnc: toInsertBlob(input.mtlsKeyEnc),
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
      if (patch.mtlsCertEnc !== undefined) set.mtlsCertEnc = toInsertBlob(patch.mtlsCertEnc);
      if (patch.mtlsKeyEnc !== undefined) set.mtlsKeyEnc = toInsertBlob(patch.mtlsKeyEnc);
      if (patch.sealingKeyVersion !== undefined) set.sealingKeyVersion = patch.sealingKeyVersion;
      if (patch.allowedOrigins !== undefined) set.allowedOrigins = patch.allowedOrigins;
      if (patch.ownershipStatus !== undefined) set.ownershipStatus = patch.ownershipStatus;
      if (patch.ownershipGraceUntil !== undefined)
        set.ownershipGraceUntil = patch.ownershipGraceUntil;
      if (patch.rawTokensEnabled !== undefined) set.rawTokensEnabled = patch.rawTokensEnabled;
      const [row] = await db.update(s.apps).set(set).where(eq(s.apps.id, id)).returning();
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

    // -----------------------------------------------------------------------
    // User sessions
    // -----------------------------------------------------------------------
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
    async deleteUserSessionsByUser(userId) {
      await db.delete(s.userSessions).where(eq(s.userSessions.userId, userId));
    },
    async purgeExpiredUserSessions(now) {
      const result = await db
        .delete(s.userSessions)
        .where(lte(s.userSessions.expiresAt, now))
        .returning({ id: s.userSessions.id });
      return result.length;
    },

    // -----------------------------------------------------------------------
    // Master keys
    // -----------------------------------------------------------------------
    async createMasterKey(input) {
      const [row] = await db
        .insert(s.masterKeys)
        .values({ id: input.id, version: input.version, providerRef: input.providerRef })
        .returning();
      if (!row) throw new Error('createMasterKey: insert returned no row');
      return row;
    },
    async getMasterKeyByVersion(version) {
      const [row] = await db.select().from(s.masterKeys).where(eq(s.masterKeys.version, version));
      return row ?? null;
    },
    async listMasterKeys() {
      return db.select().from(s.masterKeys).orderBy(asc(s.masterKeys.version));
    },
    async retireMasterKey(version, retiredAt) {
      const [row] = await db
        .update(s.masterKeys)
        .set({ retiredAt })
        .where(eq(s.masterKeys.version, version))
        .returning();
      if (!row) throw new Error(`master_key version ${version} not found`);
      return row;
    },

    // -----------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------
    async close() {
      if (deps.onClose) await deps.onClose();
    },
  };

  return storage;
}

// Re-export sql for inline use in migration helpers if needed.
export { sql };
