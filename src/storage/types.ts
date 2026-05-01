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
