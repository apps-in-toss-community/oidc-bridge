import { newId } from '../ids.js';
import type { Storage } from '../storage/interface.js';
import type { Workspace } from '../storage/types.js';
import { appendAudit } from './audit.js';

export interface ServiceCtx {
  actorUserId: string;
}

export interface CreateWorkspaceInput {
  name: string;
}

export interface UpdateWorkspaceInput {
  name?: string;
}

export interface Service {
  workspaces: {
    create(ctx: ServiceCtx, input: CreateWorkspaceInput): Promise<Workspace>;
    list(ctx: ServiceCtx): Promise<Workspace[]>;
    get(ctx: ServiceCtx, id: string): Promise<Workspace>;
    update(ctx: ServiceCtx, id: string, input: UpdateWorkspaceInput): Promise<Workspace>;
    delete(ctx: ServiceCtx, id: string): Promise<void>;
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

  return {
    workspaces: {
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
    },
  };
}
