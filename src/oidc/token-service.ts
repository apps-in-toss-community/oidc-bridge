import type { LoginMeOutput, TossAdapter, TossTokenSet } from '../toss/adapter.js';
import { mintIdToken } from './id-token.js';
import { wrapSealedToken } from './sealed-token.js';
import type { SigningKeyRegistry } from './signing-keys.js';

export interface AppForTokenService {
  id: string;
  clientId: string;
  sealingKeyVersion: number;
}

export interface AuthorizationCodeInput {
  app: AppForTokenService;
  authorizationCode: string;
  referrer?: string;
}

export interface RefreshTokenInput {
  app: AppForTokenService;
  unwrappedRt: { tossRt: string; tossUserKey: string };
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  id_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
}

export interface TokenServiceDeps {
  adapter: TossAdapter;
  registry: SigningKeyRegistry;
  issuer: string;
  idTokenTtlSeconds: number;
  resolveAppSealingKey: (input: {
    appId: string;
    sealingKeyVersion: number;
  }) => Promise<Uint8Array>;
  now: () => number;
}

export interface TokenService {
  authorizationCode(input: AuthorizationCodeInput): Promise<TokenResponse>;
  refresh(input: RefreshTokenInput): Promise<TokenResponse>;
}

export function createTokenService(deps: TokenServiceDeps): TokenService {
  return {
    authorizationCode: async (input) => {
      const generateInput =
        input.referrer !== undefined
          ? { authorizationCode: input.authorizationCode, referrer: input.referrer }
          : { authorizationCode: input.authorizationCode };
      const ts = await deps.adapter.generateToken({ appId: input.app.id }, generateInput);
      const me = await deps.adapter.loginMe(
        { appId: input.app.id },
        { accessToken: ts.accessToken },
      );
      return finalize(deps, input.app, ts, me);
    },
    refresh: async (input) => {
      const ts = await deps.adapter.refreshToken(
        { appId: input.app.id },
        { refreshToken: input.unwrappedRt.tossRt },
      );
      const me = await deps.adapter.loginMe(
        { appId: input.app.id },
        { accessToken: ts.accessToken },
      );
      return finalize(deps, input.app, ts, me);
    },
  };
}

async function finalize(
  deps: TokenServiceDeps,
  app: AppForTokenService,
  ts: TossTokenSet,
  me: LoginMeOutput,
): Promise<TokenResponse> {
  const now = deps.now();
  const tossAtExp = now + ts.expiresIn;
  const sealingKey = await deps.resolveAppSealingKey({
    appId: app.id,
    sealingKeyVersion: app.sealingKeyVersion,
  });
  const sealCommon = {
    sealingKey,
    sealingKeyVersion: app.sealingKeyVersion,
    payload: {
      appId: app.id,
      tossUserKey: String(me.userKey),
      tossAt: ts.accessToken,
      tossRt: ts.refreshToken,
      tossAtExp,
      issuedAt: now,
    },
  };
  const accessToken = await wrapSealedToken(sealCommon);
  const refreshToken = await wrapSealedToken(sealCommon);
  const idToken = await mintIdToken({
    issuer: deps.issuer,
    ttlSeconds: deps.idTokenTtlSeconds,
    registry: deps.registry,
    app: { clientId: app.clientId },
    tossClaims: {
      userKey: me.userKey,
      scope: ts.scope,
      agreedTerms: me.agreedTerms,
      tossAtExp,
    },
    now,
  });
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    id_token: idToken,
    token_type: 'Bearer',
    expires_in: ts.expiresIn,
    scope: ts.scope.join(' '),
  };
}
