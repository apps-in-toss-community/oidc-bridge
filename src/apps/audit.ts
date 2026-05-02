import { newId } from '../ids.js';
import type { Storage } from '../storage/interface.js';

export type AuditAction =
  | 'user.create'
  | 'workspace.create'
  | 'workspace.update'
  | 'workspace.delete'
  | 'app.create'
  | 'app.update'
  | 'app.delete'
  | 'app.secret.rotate'
  | 'app.raw_tokens.toggle'
  | 'app.ownership.verify'
  | 'app.ownership.lapse'
  | 'api_token.create'
  | 'api_token.delete'
  | 'master_key.rotate'
  | 'oidc.token.issue'
  | 'oidc.token.refresh';

export interface AppendAuditInput {
  storage: Storage;
  actor: string;
  action: AuditAction;
  target: string;
  details?: Record<string, unknown>;
}

export async function appendAudit(input: AppendAuditInput): Promise<void> {
  await input.storage.appendAudit({
    id: newId('audit'),
    actor: input.actor,
    action: input.action,
    target: input.target,
    detailsJson: input.details ?? {},
  });
}
