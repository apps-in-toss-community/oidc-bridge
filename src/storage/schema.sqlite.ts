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

const tsCol = (name: string) => integer(name, { mode: 'timestamp_ms' });

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
    scopes: text('scopes', { mode: 'json' }).$type<string[]>().notNull().default(sql`'[]'`),
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
    rawTokensEnabled: integer('raw_tokens_enabled', { mode: 'boolean' }).notNull().default(false),
    createdAt: tsCol('created_at').notNull().default(sql`(unixepoch() * 1000)`),
    updatedAt: tsCol('updated_at')
      .notNull()
      .default(sql`(unixepoch() * 1000)`)
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
