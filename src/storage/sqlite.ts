import Database from 'better-sqlite3';
import type { Storage } from './interface.js';
import { runSqliteMigrations } from './migrate.js';
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
      const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as
        | UserRow
        | undefined;
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
      const rows = db
        .prepare('SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at')
        .all(userId) as ApiTokenRow[];
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
      const row = db.prepare('SELECT * FROM workspaces WHERE id = ?').get(id) as
        | WorkspaceRow
        | undefined;
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
      const nowDate = new Date();
      const now = iso(nowDate);
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
      return {
        id: input.id,
        workspaceId: input.workspaceId,
        appIdToss: input.appIdToss,
        displayTitle: input.displayTitle,
        clientId: input.clientId,
        clientSecretHashes: input.clientSecretHashes,
        mtlsCertEnc: input.mtlsCertEnc,
        mtlsKeyEnc: input.mtlsKeyEnc,
        sealingKeyVersion: input.sealingKeyVersion,
        allowedOrigins: input.allowedOrigins,
        ownershipStatus: input.ownershipStatus,
        ownershipGraceUntil: input.ownershipGraceUntil,
        rawTokensEnabled: input.rawTokensEnabled,
        createdAt: nowDate,
        updatedAt: nowDate,
      };
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
      const nowDate = new Date();
      const now = iso(nowDate);
      db.prepare(
        'INSERT INTO master_keys (id, version, created_at, retired_at, provider_ref) VALUES (?, ?, ?, NULL, ?)',
      ).run(input.id, input.version, now, input.providerRef);
      return {
        id: input.id,
        version: input.version,
        createdAt: nowDate,
        retiredAt: null,
        providerRef: input.providerRef,
      };
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
      const existing = db.prepare('SELECT * FROM master_keys WHERE version = ?').get(version) as
        | MasterKeyRow
        | undefined;
      if (!existing) throw new Error(`master_key version ${version} not found`);
      const retiredIso = iso(retiredAt);
      db.prepare('UPDATE master_keys SET retired_at = ? WHERE version = ?').run(
        retiredIso,
        version,
      );
      return mapMasterKey({ ...existing, retired_at: retiredIso });
    },

    async appendAudit(entry) {
      const ts = iso(entry.ts ?? new Date());
      db.prepare(
        'INSERT INTO audit_log (id, ts, actor, action, target, details_json) VALUES (?, ?, ?, ?, ?, ?)',
      ).run(entry.id, ts, entry.actor, entry.action, entry.target, toJson(entry.detailsJson));
    },
    async listAudit(options) {
      const limit = options?.limit ?? 100;
      const rows = db
        .prepare('SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?')
        .all(limit) as AuditRow[];
      return rows.map(mapAudit);
    },

    async close() {
      db.close();
    },
  };

  return storage;
}
