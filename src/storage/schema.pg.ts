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

const tsCol = (name: string) => timestamp(name, { withTimezone: true, mode: 'date' });

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
    clientSecretHashes: text('client_secret_hashes').array().notNull().default(sql`'{}'::text[]`),
    mtlsCertEnc: bytea('mtls_cert_enc').notNull(),
    mtlsKeyEnc: bytea('mtls_key_enc').notNull(),
    sealingKeyVersion: integer('sealing_key_version').notNull(),
    allowedOrigins: text('allowed_origins').array().notNull().default(sql`'{}'::text[]`),
    ownershipStatus: text('ownership_status').notNull(),
    ownershipGraceUntil: tsCol('ownership_grace_until'),
    rawTokensEnabled: boolean('raw_tokens_enabled').notNull().default(false),
    createdAt: tsCol('created_at').notNull().defaultNow(),
    updatedAt: tsCol('updated_at').notNull().defaultNow(),
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
