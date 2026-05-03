import bcrypt from 'bcryptjs';
import type { Session, SessionStore } from './types.js';

export type LoginResult =
  | { kind: 'ok'; session: Session }
  | { kind: 'invalid_credentials' }
  | { kind: 'no_password_set' };

export interface SessionServiceDeps {
  store: SessionStore;
  ttlMs: number;
  lookupUser: (email: string) => Promise<{ id: string; passwordHash: string | null } | null>;
}

export interface SessionService {
  login(email: string, password: string): Promise<LoginResult>;
  logout(id: string): Promise<void>;
  validate(id: string): Promise<Session | null>;
}

// Disposable hash used only when no user matches; keeps the bcrypt branch
// running so timing does not leak whether the email exists. Cost matches
// `client_secret` hashing (BCRYPT_ROUNDS = 12 in src/apps/secrets.ts).
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing-equalization', 12);

export function createSessionService(deps: SessionServiceDeps): SessionService {
  return {
    async login(email, password) {
      const u = await deps.lookupUser(email);
      const hash = u?.passwordHash ?? DUMMY_HASH;
      const compareOk = await bcrypt.compare(password, hash);
      if (!u) return { kind: 'invalid_credentials' };
      if (u.passwordHash === null) return { kind: 'no_password_set' };
      if (!compareOk) return { kind: 'invalid_credentials' };
      const session = await deps.store.create(u.id, deps.ttlMs);
      return { kind: 'ok', session };
    },

    async logout(id) {
      await deps.store.revoke(id);
    },

    async validate(id) {
      return deps.store.get(id);
    },
  };
}
