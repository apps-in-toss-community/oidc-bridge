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
