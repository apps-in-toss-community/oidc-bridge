// src/toss/adapter.ts
export interface GenerateTokenInput {
  authorizationCode: string;
  referrer?: string;
}

export interface TossTokenSet {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string[];
}

export interface LoginMeOutput {
  userKey: number;
  scope: string[];
  agreedTerms: string[];
  encryptedPii?: Record<string, string>;
}

export interface RefreshTokenInput {
  refreshToken: string;
}

export interface TossAdapterContext {
  appId: string;
}

export interface TossAdapter {
  generateToken(ctx: TossAdapterContext, input: GenerateTokenInput): Promise<TossTokenSet>;
  refreshToken(ctx: TossAdapterContext, input: RefreshTokenInput): Promise<TossTokenSet>;
  loginMe(ctx: TossAdapterContext, input: { accessToken: string }): Promise<LoginMeOutput>;
}

export class TossUpstreamError extends Error {
  constructor(
    public readonly code: 'invalid_grant' | 'upstream_error',
    message: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'TossUpstreamError';
  }
}
