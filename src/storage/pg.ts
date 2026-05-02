import { asc, count, desc, eq } from 'drizzle-orm';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool, type PoolConfig } from 'pg';
import type { Storage } from './interface.js';
import { runPgMigrations } from './migrate.js';
import * as s from './schema.pg.js';
import type { AppOwnershipStatus, AppRecord } from './types.js';

const OWNERSHIP_STATUSES = new Set<AppOwnershipStatus>(['pending', 'verified', 'lapsed']);
function toOwnershipStatus(raw: string): AppOwnershipStatus {
  if (!OWNERSHIP_STATUSES.has(raw as AppOwnershipStatus)) {
    throw new Error(`Unknown ownershipStatus from DB: "${raw}"`);
  }
  return raw as AppOwnershipStatus;
}

function toAppRecord(row: typeof s.apps.$inferSelect): AppRecord {
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    appIdToss: row.appIdToss,
    displayTitle: row.displayTitle,
    clientId: row.clientId,
    clientSecretHashes: row.clientSecretHashes,
    mtlsCertEnc: new Uint8Array(
      row.mtlsCertEnc.buffer,
      row.mtlsCertEnc.byteOffset,
      row.mtlsCertEnc.byteLength,
    ),
    mtlsKeyEnc: new Uint8Array(
      row.mtlsKeyEnc.buffer,
      row.mtlsKeyEnc.byteOffset,
      row.mtlsKeyEnc.byteLength,
    ),
    sealingKeyVersion: row.sealingKeyVersion,
    allowedOrigins: row.allowedOrigins,
    ownershipStatus: toOwnershipStatus(row.ownershipStatus),
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
      const [row] = await db.select().from(s.masterKeys).where(eq(s.masterKeys.version, version));
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
