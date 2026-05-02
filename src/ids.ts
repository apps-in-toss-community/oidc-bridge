import { customAlphabet } from 'nanoid';

export type IdKind =
  | 'user'
  | 'workspace'
  | 'app'
  | 'api_token'
  | 'user_session'
  | 'master_key'
  | 'audit';

const PREFIX: Record<IdKind, string> = {
  user: 'user_',
  workspace: 'ws_',
  app: 'app_',
  api_token: 'tok_',
  user_session: 'ses_',
  master_key: 'mk_',
  audit: 'au_',
};

// 64-char alphabet with `-_` to avoid base64 padding issues; 21 chars ≈ 125 bits.
const nano = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_', 21);

export function newId(kind: IdKind): string {
  return `${PREFIX[kind]}${nano()}`;
}
