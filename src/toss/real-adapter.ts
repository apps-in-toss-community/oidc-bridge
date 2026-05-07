import type { MtlsClientFactory } from '../core/mtls.js';
import {
  type GenerateTokenInput,
  type LoginMeOutput,
  type RefreshTokenInput,
  type TossAdapter,
  type TossAdapterContext,
  type TossTokenSet,
  TossUpstreamError,
} from './adapter.js';
import { mapEnvelopeError, parseEnvelope } from './envelope.js';

export interface RealTossAdapterDeps {
  apiBase: string;
  mtlsFactory: MtlsClientFactory;
}

interface TossSuccessTokenBody {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
}

const PATH_GENERATE_TOKEN = '/api-partner/v1/apps-in-toss/user/oauth2/generate-token';
const PATH_REFRESH_TOKEN = '/api-partner/v1/apps-in-toss/user/oauth2/refresh-token';
const PATH_LOGIN_ME = '/api-partner/v1/apps-in-toss/user/oauth2/login-me';
const PATH_ACCESS_REMOVE = '/api-partner/v1/apps-in-toss/user/oauth2/access-remove';

interface TossLoginMeBody {
  userKey: number;
  scope: string;
  agreedTerms: string[];
  encryptedPii?: Record<string, string>;
}

export class RealTossAdapter implements TossAdapter {
  constructor(private readonly deps: RealTossAdapterDeps) {}

  async generateToken(ctx: TossAdapterContext, input: GenerateTokenInput): Promise<TossTokenSet> {
    const client = await this.clientFor(ctx.appId);
    const body = await this.callJson<TossSuccessTokenBody>(PATH_GENERATE_TOKEN, client, {
      authorizationCode: input.authorizationCode,
      referrer: input.referrer,
    });
    return this.toTokenSet(body);
  }

  async refreshToken(ctx: TossAdapterContext, input: RefreshTokenInput): Promise<TossTokenSet> {
    const client = await this.clientFor(ctx.appId);
    const body = await this.callJson<TossSuccessTokenBody>(PATH_REFRESH_TOKEN, client, {
      refreshToken: input.refreshToken,
    });
    return this.toTokenSet(body);
  }

  async loginMe(ctx: TossAdapterContext, input: { accessToken: string }): Promise<LoginMeOutput> {
    const client = await this.clientFor(ctx.appId);
    const body = await this.callJson<TossLoginMeBody>(
      PATH_LOGIN_ME,
      client,
      {},
      { authorization: `Bearer ${input.accessToken}` },
    );
    return {
      userKey: body.userKey,
      scope: body.scope.split(' ').filter(Boolean),
      agreedTerms: body.agreedTerms,
      ...(body.encryptedPii !== undefined ? { encryptedPii: body.encryptedPii } : {}),
    };
  }

  async accessRemove(ctx: TossAdapterContext, input: { userKey: string }): Promise<void> {
    const client = await this.clientFor(ctx.appId);
    await this.callJson<unknown>(PATH_ACCESS_REMOVE, client, { userKey: input.userKey });
  }

  // The factory is responsible for caching; missing-material throws a plain Error
  // which we convert here to TossUpstreamError for caller consistency.
  private async clientFor(appId: string) {
    try {
      return await this.deps.mtlsFactory.forApp(appId);
    } catch (err) {
      throw new TossUpstreamError(
        'upstream_error',
        err instanceof Error ? err.message : `no mtls material for app=${appId}`,
      );
    }
  }

  private async callJson<T>(
    path: string,
    client: { request(url: string, init: RequestInit): Promise<Response> },
    payload: unknown,
    extraHeaders: Record<string, string> = {},
  ): Promise<T> {
    let response: Response;
    try {
      response = await client.request(`${this.deps.apiBase}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...extraHeaders },
        body: JSON.stringify(payload),
      });
    } catch (err) {
      throw mapEnvelopeError(err);
    }
    if (response.status >= 500) {
      throw new TossUpstreamError('upstream_error', `Toss HTTP ${response.status}`);
    }
    let json: unknown;
    try {
      json = await response.json();
    } catch (err) {
      throw new TossUpstreamError(
        'upstream_error',
        `Toss returned non-JSON (status=${response.status})`,
        err,
      );
    }
    try {
      return parseEnvelope<T>(json);
    } catch (err) {
      throw mapEnvelopeError(err);
    }
  }

  private toTokenSet(body: TossSuccessTokenBody): TossTokenSet {
    return {
      accessToken: body.accessToken,
      refreshToken: body.refreshToken,
      expiresIn: body.expiresIn,
      scope: body.scope.split(' ').filter(Boolean),
    };
  }
}
