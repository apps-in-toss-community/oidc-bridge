import {
  type GenerateTokenInput,
  type LoginMeOutput,
  type RefreshTokenInput,
  type TossAdapter,
  type TossAdapterContext,
  type TossTokenSet,
  TossUpstreamError,
} from './adapter.js';
import gtSuccess from './fixtures/generate-token-success.json' with { type: 'json' };
import meSuccess from './fixtures/login-me-success.json' with { type: 'json' };
import rtSuccess from './fixtures/refresh-token-success.json' with { type: 'json' };

interface SuccessGenerate {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
}
interface SuccessLoginMe {
  userKey: number;
  scope: string;
  agreedTerms: string[];
}

export class MockTossAdapter implements TossAdapter {
  readonly accessRemoveCalls: { appId: string; userKey: string }[] = [];

  async generateToken(_ctx: TossAdapterContext, input: GenerateTokenInput): Promise<TossTokenSet> {
    if (input.authorizationCode === 'fail-code') {
      throw new TossUpstreamError('invalid_grant', 'mock fail-code');
    }
    if (input.authorizationCode === 'network-error-code') {
      throw new TossUpstreamError('upstream_error', 'mock network-error-code');
    }
    const s = (gtSuccess as { success: SuccessGenerate }).success;
    return {
      accessToken: s.accessToken,
      refreshToken: s.refreshToken,
      expiresIn: s.expiresIn,
      scope: s.scope.split(' '),
    };
  }

  async refreshToken(_ctx: TossAdapterContext, input: RefreshTokenInput): Promise<TossTokenSet> {
    if (input.refreshToken === 'fail-rt') {
      throw new TossUpstreamError('invalid_grant', 'mock fail-rt');
    }
    const s = (rtSuccess as { success: SuccessGenerate }).success;
    return {
      accessToken: s.accessToken,
      refreshToken: s.refreshToken,
      expiresIn: s.expiresIn,
      scope: s.scope.split(' '),
    };
  }

  async loginMe(_ctx: TossAdapterContext, input: { accessToken: string }): Promise<LoginMeOutput> {
    if (input.accessToken === 'fail-at') {
      throw new TossUpstreamError('upstream_error', 'mock fail-at');
    }
    const s = (meSuccess as { success: SuccessLoginMe }).success;
    return { userKey: s.userKey, scope: s.scope.split(' '), agreedTerms: s.agreedTerms };
  }

  async accessRemove(ctx: TossAdapterContext, input: { userKey: string }): Promise<void> {
    if (input.userKey === 'fail-userkey') {
      throw new TossUpstreamError('upstream_error', 'mock fail-userkey');
    }
    this.accessRemoveCalls.push({ appId: ctx.appId, userKey: input.userKey });
  }
}
