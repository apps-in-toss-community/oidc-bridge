import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Storage } from './interface.js';

export interface ConformanceFactory {
  /** Returns a fresh Storage backed by an empty DB. */
  open(): Promise<Storage>;
  /** Cleans up DB after each test. */
  cleanup(s: Storage): Promise<void>;
}

export function runStorageConformance(name: string, factory: ConformanceFactory): void {
  describe(`Storage conformance — ${name}`, () => {
    let storage: Storage;

    beforeEach(async () => {
      storage = await factory.open();
    });

    afterEach(async () => {
      await factory.cleanup(storage);
    });

    it('users: create + getById + getByEmail; Date round-trips', async () => {
      const u = await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      expect(u.email).toBe('a@b.c');
      expect(u.createdAt).toBeInstanceOf(Date);
      expect(await storage.getUserById('u_1')).toMatchObject({ email: 'a@b.c' });
      expect(await storage.getUserByEmail('a@b.c')).toMatchObject({ id: 'u_1' });
      expect(await storage.getUserById('nope')).toBeNull();
    });

    it('api tokens: scopes round-trip + last-used Date precision', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      const t = await storage.createApiToken({
        id: 't_1',
        userId: 'u_1',
        name: 'cli',
        tokenHash: 'h1',
        scopes: ['admin', 'read'],
      });
      expect(t.scopes).toEqual(['admin', 'read']);
      expect(t.lastUsedAt).toBeNull();
      const fetched = await storage.getApiTokenByHash('h1');
      expect(fetched?.scopes).toEqual(['admin', 'read']);

      const at = new Date('2026-05-01T12:00:00.000Z');
      await storage.touchApiTokenLastUsed('t_1', at);
      const after = await storage.getApiTokenByHash('h1');
      expect(after?.lastUsedAt).toBeInstanceOf(Date);
      expect(after?.lastUsedAt?.toISOString()).toBe(at.toISOString());

      const list = await storage.listApiTokensByUser('u_1');
      expect(list).toHaveLength(1);
      await storage.deleteApiToken('t_1');
      expect(await storage.getApiTokenByHash('h1')).toBeNull();
    });

    it('workspaces: create, update name, list, delete', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      const w = await storage.createWorkspace({ id: 'w_1', ownerUserId: 'u_1', name: 'first' });
      expect(w.name).toBe('first');
      const updated = await storage.updateWorkspace('w_1', { name: 'renamed' });
      expect(updated.name).toBe('renamed');
      const list = await storage.listWorkspacesByOwner('u_1');
      expect(list).toHaveLength(1);
      await storage.deleteWorkspace('w_1');
      expect(await storage.getWorkspace('w_1')).toBeNull();
    });

    it('apps: bytes / arrays / boolean / Date all round-trip', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      await storage.createWorkspace({ id: 'w_1', ownerUserId: 'u_1', name: 'first' });

      const certBytes = new Uint8Array([1, 2, 3, 4, 0xff, 0x00, 0xab]);
      const keyBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const grace = new Date('2026-05-04T00:00:00.000Z');

      const a = await storage.createApp({
        id: 'a_1',
        workspaceId: 'w_1',
        appIdToss: 'mini-app-123',
        displayTitle: 'My App',
        clientId: 'client_xyz',
        clientSecretHashes: ['$2a$12$abc', '$2a$12$def'],
        mtlsCertEnc: certBytes,
        mtlsKeyEnc: keyBytes,
        sealingKeyVersion: 1,
        allowedOrigins: ['https://app.example.com', 'https://www.example.com'],
        ownershipStatus: 'pending',
        ownershipGraceUntil: grace,
        rawTokensEnabled: false,
      });
      expect(a.allowedOrigins).toEqual(['https://app.example.com', 'https://www.example.com']);
      expect(a.clientSecretHashes).toEqual(['$2a$12$abc', '$2a$12$def']);
      expect(Array.from(a.mtlsCertEnc)).toEqual(Array.from(certBytes));
      expect(Array.from(a.mtlsKeyEnc)).toEqual(Array.from(keyBytes));
      expect(a.rawTokensEnabled).toBe(false);
      expect(a.ownershipGraceUntil).toBeInstanceOf(Date);
      expect(a.ownershipGraceUntil?.toISOString()).toBe(grace.toISOString());
      expect(a.createdAt).toBeInstanceOf(Date);

      const byClient = await storage.getAppByClientId('client_xyz');
      expect(byClient?.id).toBe('a_1');

      const updated = await storage.updateApp('a_1', {
        displayTitle: 'Renamed',
        ownershipStatus: 'verified',
        ownershipGraceUntil: null,
        rawTokensEnabled: true,
      });
      expect(updated.displayTitle).toBe('Renamed');
      expect(updated.ownershipStatus).toBe('verified');
      expect(updated.ownershipGraceUntil).toBeNull();
      expect(updated.rawTokensEnabled).toBe(true);

      expect(await storage.countApps()).toBe(1);

      await storage.deleteApp('a_1');
      expect(await storage.getApp('a_1')).toBeNull();
    });

    it('user sessions: Date round-trip preserves millisecond precision', async () => {
      await storage.createUser({ id: 'u_1', email: 'a@b.c' });
      const exp = new Date('2026-05-02T01:23:45.678Z');
      const s = await storage.createUserSession({
        id: 's_1',
        userId: 'u_1',
        expiresAt: exp,
      });
      expect(s.userId).toBe('u_1');
      const f = await storage.getUserSession('s_1');
      expect(f?.expiresAt).toBeInstanceOf(Date);
      expect(f?.expiresAt.toISOString()).toBe(exp.toISOString());
      await storage.deleteUserSession('s_1');
      expect(await storage.getUserSession('s_1')).toBeNull();
    });

    it('user sessions: deleteUserSessionsByUser scopes by user_id', async () => {
      await storage.createUser({ id: 'u_a', email: 'a@x.y' });
      await storage.createUser({ id: 'u_b', email: 'b@x.y' });
      const future = new Date(Date.now() + 60_000);
      await storage.createUserSession({ id: 'sa1', userId: 'u_a', expiresAt: future });
      await storage.createUserSession({ id: 'sa2', userId: 'u_a', expiresAt: future });
      await storage.createUserSession({ id: 'sb1', userId: 'u_b', expiresAt: future });
      await storage.deleteUserSessionsByUser('u_a');
      expect(await storage.getUserSession('sa1')).toBeNull();
      expect(await storage.getUserSession('sa2')).toBeNull();
      expect(await storage.getUserSession('sb1')).not.toBeNull();
    });

    it('user sessions: purgeExpiredUserSessions deletes only expired and returns count', async () => {
      await storage.createUser({ id: 'u_p', email: 'p@x.y' });
      const past = new Date(Date.now() - 1_000);
      const future = new Date(Date.now() + 60_000);
      await storage.createUserSession({ id: 'p1', userId: 'u_p', expiresAt: past });
      await storage.createUserSession({ id: 'p2', userId: 'u_p', expiresAt: past });
      await storage.createUserSession({ id: 'f1', userId: 'u_p', expiresAt: future });
      const purged = await storage.purgeExpiredUserSessions(new Date());
      expect(purged).toBe(2);
      expect(await storage.getUserSession('p1')).toBeNull();
      expect(await storage.getUserSession('p2')).toBeNull();
      expect(await storage.getUserSession('f1')).not.toBeNull();
    });

    it('users: password_hash round-trips (null default; can be set via direct write)', async () => {
      const u = await storage.createUser({ id: 'u_pw', email: 'pw@x.y' });
      expect(u.passwordHash).toBeNull();
    });

    it('users: setUserPassword writes hash; throws on unknown user', async () => {
      await storage.createUser({ id: 'u_setpw', email: 'setpw@x.y' });
      await storage.setUserPassword('u_setpw', '$2a$12$abcdefghijklmnopqrstuv');
      const u = await storage.getUserById('u_setpw');
      expect(u?.passwordHash).toBe('$2a$12$abcdefghijklmnopqrstuv');
      await expect(storage.setUserPassword('u_missing', 'h')).rejects.toThrow(/u_missing/);
    });

    it('master keys: create, list ordering, retire is atomic + throws on missing', async () => {
      const m1 = await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
      expect(m1.retiredAt).toBeNull();
      await storage.createMasterKey({ id: 'mk_2', version: 2, providerRef: 'env:2' });
      const list = await storage.listMasterKeys();
      expect(list.map((m) => m.version)).toEqual([1, 2]);

      const retiredAt = new Date('2026-05-01T00:00:00.000Z');
      const retired = await storage.retireMasterKey(1, retiredAt);
      expect(retired.retiredAt).toBeInstanceOf(Date);
      expect(retired.retiredAt?.toISOString()).toBe(retiredAt.toISOString());

      const fetched = await storage.getMasterKeyByVersion(1);
      expect(fetched?.retiredAt).not.toBeNull();

      await expect(storage.retireMasterKey(99, retiredAt)).rejects.toThrow(/version 99/);
    });

    it('audit log: JSON object round-trip + newest-first ordering + limit', async () => {
      const ts1 = new Date('2026-05-01T10:00:00.000Z');
      const ts2 = new Date('2026-05-01T11:00:00.000Z');
      await storage.appendAudit({
        id: 'au_1',
        ts: ts1,
        actor: 'u_1',
        action: 'app.create',
        target: 'a_1',
        detailsJson: { foo: 'bar', count: 7, nested: { ok: true } },
      });
      await storage.appendAudit({
        id: 'au_2',
        ts: ts2,
        actor: 'u_1',
        action: 'app.delete',
        target: 'a_1',
        detailsJson: { reason: 'cleanup' },
      });
      const all = await storage.listAudit();
      expect(all.map((e) => e.id)).toEqual(['au_2', 'au_1']);
      expect(all[1]!.detailsJson).toEqual({ foo: 'bar', count: 7, nested: { ok: true } });
      expect(all[0]!.detailsJson).toEqual({ reason: 'cleanup' });
      const limited = await storage.listAudit({ limit: 1 });
      expect(limited).toHaveLength(1);
      expect(limited[0]!.id).toBe('au_2');
    });

    it('cross-dialect Date precision: persisted Date equals input Date by ISO string', async () => {
      await storage.createUser({ id: 'u_dt', email: 'dt@x.y' });
      // Choose a non-rounded ms boundary.
      const exp = new Date('2026-12-31T23:59:59.123Z');
      await storage.createUserSession({ id: 's_dt', userId: 'u_dt', expiresAt: exp });
      const back = await storage.getUserSession('s_dt');
      expect(back?.expiresAt.toISOString()).toBe(exp.toISOString());
    });
  });
}
