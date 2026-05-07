import { toHex } from '../core/bytes.js';
import type { Random } from '../core/random.js';
import { nodeRandom } from '../runtime/node-random.js';
import type { Storage } from '../storage/interface.js';
import type { Session, SessionStore } from './types.js';

export function createSessionStore(storage: Storage, opts: { random?: Random } = {}): SessionStore {
  const random = opts.random ?? nodeRandom;
  return {
    async create(userId, ttlMs) {
      const id = toHex(random.bytes(16));
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttlMs);
      const row = await storage.createUserSession({ id, userId, expiresAt });
      const session: Session = {
        id: row.id,
        userId: row.userId,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
      };
      return session;
    },

    async get(id) {
      const row = await storage.getUserSession(id);
      if (!row) return null;
      // Treat expired as gone, even before purge.
      if (row.expiresAt.getTime() <= Date.now()) return null;
      return {
        id: row.id,
        userId: row.userId,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
      };
    },

    async revoke(id) {
      await storage.deleteUserSession(id);
    },

    async revokeForUser(userId) {
      await storage.deleteUserSessionsByUser(userId);
    },

    async purgeExpired(now) {
      return storage.purgeExpiredUserSessions(now);
    },
  };
}
