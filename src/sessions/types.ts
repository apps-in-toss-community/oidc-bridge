export type SessionId = string;

export interface Session {
  id: SessionId;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface SessionStore {
  create(userId: string, ttlMs: number): Promise<Session>;
  get(id: SessionId): Promise<Session | null>;
  revoke(id: SessionId): Promise<void>;
  revokeForUser(userId: string): Promise<void>;
  purgeExpired(now: Date): Promise<number>;
}
