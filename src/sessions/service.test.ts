import bcrypt from 'bcryptjs';
import { describe, expect, it } from 'vitest';
import { createSessionService } from './service.js';
import type { Session, SessionStore } from './types.js';

function fakeStore(): SessionStore & { rows: Map<string, Session> } {
  const rows = new Map<string, Session>();
  return {
    rows,
    async create(userId, ttlMs) {
      const id = `sid_${rows.size + 1}`;
      const r: Session = {
        id,
        userId,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + ttlMs),
      };
      rows.set(id, r);
      return r;
    },
    async get(id) {
      return rows.get(id) ?? null;
    },
    async revoke(id) {
      rows.delete(id);
    },
    async revokeForUser(userId) {
      for (const [k, v] of rows) if (v.userId === userId) rows.delete(k);
    },
    async purgeExpired() {
      return 0;
    },
  };
}

describe('createSessionService', () => {
  it('login returns ok session for correct password', async () => {
    const store = fakeStore();
    const hash = bcrypt.hashSync('secret123', 4);
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async (email) => (email === 'a@b' ? { id: 'u_1', passwordHash: hash } : null),
    });
    const r = await svc.login('a@b', 'secret123');
    expect(r.kind).toBe('ok');
    if (r.kind === 'ok') expect(r.session.userId).toBe('u_1');
  });

  it('login returns invalid_credentials for wrong password', async () => {
    const store = fakeStore();
    const hash = bcrypt.hashSync('secret123', 4);
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => ({ id: 'u_1', passwordHash: hash }),
    });
    const r = await svc.login('a@b', 'wrong');
    expect(r.kind).toBe('invalid_credentials');
  });

  it('login returns invalid_credentials for unknown email (no enumeration)', async () => {
    const store = fakeStore();
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => null,
    });
    const r = await svc.login('nobody@b', 'whatever');
    expect(r.kind).toBe('invalid_credentials');
  });

  it('login returns no_password_set when user has no hash', async () => {
    const store = fakeStore();
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => ({ id: 'u_1', passwordHash: null }),
    });
    const r = await svc.login('a@b', 'whatever');
    expect(r.kind).toBe('no_password_set');
  });

  it('logout deletes the session', async () => {
    const store = fakeStore();
    const hash = bcrypt.hashSync('secret123', 4);
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => ({ id: 'u_1', passwordHash: hash }),
    });
    const r = await svc.login('a@b', 'secret123');
    if (r.kind !== 'ok') throw new Error('expected login ok');
    await svc.logout(r.session.id);
    expect(await store.get(r.session.id)).toBeNull();
  });

  it('validate returns null for unknown id', async () => {
    const store = fakeStore();
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => null,
    });
    expect(await svc.validate('does-not-exist')).toBeNull();
  });

  it('validate returns the session for known id', async () => {
    const store = fakeStore();
    const hash = bcrypt.hashSync('secret123', 4);
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => ({ id: 'u_1', passwordHash: hash }),
    });
    const r = await svc.login('a@b', 'secret123');
    if (r.kind !== 'ok') throw new Error('expected login ok');
    const v = await svc.validate(r.session.id);
    expect(v?.userId).toBe('u_1');
  });
});
