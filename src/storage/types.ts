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
export type AppRecord = Omit<RawApp, 'mtlsCertEnc' | 'mtlsKeyEnc' | 'ownershipStatus'> & {
  mtlsCertEnc: Uint8Array;
  mtlsKeyEnc: Uint8Array;
  ownershipStatus: AppOwnershipStatus;
};
