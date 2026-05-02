import { newId } from '../ids.js';
import { deriveSealingKey } from '../master-keys/index.js';
import type { Storage } from '../storage/interface.js';
import type { ApiToken, AppRecord, User, Workspace } from '../storage/types.js';
import { appendAudit } from './audit.js';
import { encryptColumn } from './encryption.js';
import { computeInitialOwnership, type Stage } from './ownership.js';
import {
  generateApiToken,
  generateClientSecret,
  hashApiToken,
  hashClientSecret,
} from './secrets.js';

export interface ServiceCtx {
  actorUserId: string;
}

export interface CreateWorkspaceInput {
  name: string;
}

export interface UpdateWorkspaceInput {
  name?: string;
}

export interface CreateAppInput {
  workspaceId: string;
  appIdToss: string;
  displayTitle: string;
  mtlsCert: Buffer;
  mtlsKey: Buffer;
  allowedOrigins: string[];
  sealingKeyVersion: number;
  masterKey: Buffer;
  stage: Stage;
}

export interface CreateAppResult {
  app: AppRecord;
  clientId: string;
  clientSecret: string;
}

export interface RotateSecretResult {
  app: AppRecord;
  clientSecret: string;
}

export interface UpdateAppInput {
  displayTitle?: string;
  allowedOrigins?: string[];
}

export interface Service {
  workspaces: {
    create(ctx: ServiceCtx, input: CreateWorkspaceInput): Promise<Workspace>;
    list(ctx: ServiceCtx): Promise<Workspace[]>;
    get(ctx: ServiceCtx, id: string): Promise<Workspace>;
    update(ctx: ServiceCtx, id: string, input: UpdateWorkspaceInput): Promise<Workspace>;
    delete(ctx: ServiceCtx, id: string): Promise<void>;
  };
  apps: {
    create(ctx: ServiceCtx, input: CreateAppInput): Promise<CreateAppResult>;
    list(ctx: ServiceCtx, workspaceId: string): Promise<AppRecord[]>;
    get(ctx: ServiceCtx, id: string): Promise<AppRecord>;
    update(ctx: ServiceCtx, id: string, patch: UpdateAppInput): Promise<AppRecord>;
    delete(ctx: ServiceCtx, id: string): Promise<void>;
    rotateSecret(ctx: ServiceCtx, id: string): Promise<RotateSecretResult>;
    toggleRawTokens(ctx: ServiceCtx, id: string, enabled: boolean): Promise<AppRecord>;
  };
  apiTokens: {
    create(
      ctx: ServiceCtx,
      input: { name: string; scopes: string[] },
    ): Promise<{ token: ApiToken; plaintext: string }>;
    list(ctx: ServiceCtx): Promise<ApiToken[]>;
    delete(ctx: ServiceCtx, id: string): Promise<void>;
    verify(plain: string): Promise<{ user: User; scopes: string[] } | null>;
  };
}

export interface CreateServiceOptions {
  storage: Storage;
}

export class NotFoundError extends Error {
  constructor(public resource: string) {
    super(`not_found: ${resource}`);
  }
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(`conflict: ${message}`);
  }
}

export function createService(opts: CreateServiceOptions): Service {
  const storage = opts.storage;

  async function getOwnedWorkspace(ctx: ServiceCtx, id: string): Promise<Workspace> {
    const w = await storage.getWorkspace(id);
    if (!w || w.ownerUserId !== ctx.actorUserId) {
      throw new NotFoundError(`workspace ${id}`);
    }
    return w;
  }

  async function getOwnedApp(ctx: ServiceCtx, id: string): Promise<AppRecord> {
    const a = await storage.getApp(id);
    if (!a) throw new NotFoundError(`app ${id}`);
    const w = await storage.getWorkspace(a.workspaceId);
    if (!w || w.ownerUserId !== ctx.actorUserId) throw new NotFoundError(`app ${id}`);
    return a;
  }

  const workspaces: Service['workspaces'] = {
    async create(ctx, input) {
      const w = await storage.createWorkspace({
        id: newId('workspace'),
        ownerUserId: ctx.actorUserId,
        name: input.name,
      });
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'workspace.create',
        target: w.id,
        details: { name: input.name },
      });
      return w;
    },
    async list(ctx) {
      return storage.listWorkspacesByOwner(ctx.actorUserId);
    },
    async get(ctx, id) {
      return getOwnedWorkspace(ctx, id);
    },
    async update(ctx, id, input) {
      await getOwnedWorkspace(ctx, id);
      const updated = await storage.updateWorkspace(id, input);
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'workspace.update',
        target: id,
        details: input,
      });
      return updated;
    },
    async delete(ctx, id) {
      await getOwnedWorkspace(ctx, id);
      await storage.deleteWorkspace(id);
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'workspace.delete',
        target: id,
      });
    },
  };

  const apps: Service['apps'] = {
    async create(ctx, input) {
      await getOwnedWorkspace(ctx, input.workspaceId);
      const appId = newId('app');
      const sealingKey = deriveSealingKey({ masterKey: input.masterKey, appId });
      const aad = Buffer.from(appId, 'utf8');
      const certEnc = encryptColumn({ key: sealingKey, plaintext: input.mtlsCert, aad });
      const keyEnc = encryptColumn({ key: sealingKey, plaintext: input.mtlsKey, aad });
      const clientId = `client_${appId.slice('app_'.length)}`;
      const clientSecret = generateClientSecret();
      const hash = await hashClientSecret(clientSecret);
      const ownership = computeInitialOwnership({ stage: input.stage, now: new Date() });
      const created = await storage.createApp({
        id: appId,
        workspaceId: input.workspaceId,
        appIdToss: input.appIdToss,
        displayTitle: input.displayTitle,
        clientId,
        clientSecretHashes: [hash],
        mtlsCertEnc: certEnc,
        mtlsKeyEnc: keyEnc,
        sealingKeyVersion: input.sealingKeyVersion,
        allowedOrigins: input.allowedOrigins,
        ownershipStatus: ownership.ownershipStatus,
        ownershipGraceUntil: ownership.ownershipGraceUntil,
        rawTokensEnabled: false,
      });
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'app.create',
        target: appId,
        details: { appIdToss: input.appIdToss, workspaceId: input.workspaceId },
      });
      return { app: created, clientId, clientSecret };
    },
    async list(ctx, workspaceId) {
      await getOwnedWorkspace(ctx, workspaceId);
      return storage.listAppsByWorkspace(workspaceId);
    },
    async get(ctx, id) {
      return getOwnedApp(ctx, id);
    },
    async update(ctx, id, patch) {
      await getOwnedApp(ctx, id);
      const updated = await storage.updateApp(id, patch);
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'app.update',
        target: id,
        details: patch,
      });
      return updated;
    },
    async delete(ctx, id) {
      await getOwnedApp(ctx, id);
      await storage.deleteApp(id);
      await appendAudit({ storage, actor: ctx.actorUserId, action: 'app.delete', target: id });
    },
    async rotateSecret(ctx, id) {
      const existing = await getOwnedApp(ctx, id);
      const clientSecret = generateClientSecret();
      const hash = await hashClientSecret(clientSecret);
      const updated = await storage.updateApp(id, {
        clientSecretHashes: [...existing.clientSecretHashes, hash],
      });
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'app.secret.rotate',
        target: id,
      });
      return { app: updated, clientSecret };
    },
    async toggleRawTokens(ctx, id, enabled) {
      await getOwnedApp(ctx, id);
      const updated = await storage.updateApp(id, { rawTokensEnabled: enabled });
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'app.raw_tokens.toggle',
        target: id,
        details: { enabled },
      });
      return updated;
    },
  };

  const apiTokens: Service['apiTokens'] = {
    async create(ctx, input) {
      const plaintext = generateApiToken();
      const tokenHash = hashApiToken(plaintext);
      const token = await storage.createApiToken({
        id: newId('api_token'),
        userId: ctx.actorUserId,
        name: input.name,
        tokenHash,
        scopes: input.scopes,
      });
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'api_token.create',
        target: token.id,
        details: { name: input.name, scopes: input.scopes },
      });
      return { token, plaintext };
    },
    async list(ctx) {
      return storage.listApiTokensByUser(ctx.actorUserId);
    },
    async delete(ctx, id) {
      const tokens = await storage.listApiTokensByUser(ctx.actorUserId);
      if (!tokens.some((t) => t.id === id)) {
        throw new NotFoundError(`api_token ${id}`);
      }
      await storage.deleteApiToken(id);
      await appendAudit({
        storage,
        actor: ctx.actorUserId,
        action: 'api_token.delete',
        target: id,
      });
    },
    async verify(plain) {
      if (!plain.startsWith('tok_')) return null;
      const hash = hashApiToken(plain);
      const row = await storage.getApiTokenByHash(hash);
      if (!row) return null;
      const user = await storage.getUserById(row.userId);
      if (!user) return null;
      await storage.touchApiTokenLastUsed(row.id, new Date());
      return { user, scopes: row.scopes };
    },
  };

  return { workspaces, apps, apiTokens };
}
