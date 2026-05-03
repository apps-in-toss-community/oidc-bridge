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
  getMtlsMaterial: (appId: string) => Promise<{ certPem: string; keyPem: string } | null>;
  fetchImpl?: typeof fetch;
  buildDispatcher?: (opts: { certPem: string; keyPem: string }) => unknown;
}

interface TossSuccessTokenBody {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
}

const PATH_GENERATE_TOKEN = '/api-partner/v1/apps-in-toss/user/oauth2/generate-token';

export class RealTossAdapter implements TossAdapter {
  private readonly dispatchers = new Map<string, unknown>();
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly deps: RealTossAdapterDeps) {
    this.fetchImpl = deps.fetchImpl ?? fetch;
  }

  async generateToken(ctx: TossAdapterContext, input: GenerateTokenInput): Promise<TossTokenSet> {
    const dispatcher = await this.dispatcherFor(ctx.appId);
    const body = await this.callJson<TossSuccessTokenBody>(PATH_GENERATE_TOKEN, dispatcher, {
      authorizationCode: input.authorizationCode,
      referrer: input.referrer,
    });
    return this.toTokenSet(body);
  }

  async refreshToken(_ctx: TossAdapterContext, _input: RefreshTokenInput): Promise<TossTokenSet> {
    throw new TossUpstreamError('upstream_error', 'refreshToken: not implemented yet');
  }

  async loginMe(_ctx: TossAdapterContext, _input: { accessToken: string }): Promise<LoginMeOutput> {
    throw new TossUpstreamError('upstream_error', 'loginMe: not implemented yet');
  }

  async accessRemove(_ctx: TossAdapterContext, _input: { userKey: string }): Promise<void> {
    throw new TossUpstreamError('upstream_error', 'accessRemove: not implemented yet');
  }

  private async dispatcherFor(appId: string): Promise<unknown> {
    const cached = this.dispatchers.get(appId);
    if (cached !== undefined) return cached;
    const mtls = await this.deps.getMtlsMaterial(appId);
    if (!mtls) {
      throw new TossUpstreamError('upstream_error', `no mtls material for app=${appId}`);
    }
    const builder = this.deps.buildDispatcher ?? defaultBuildDispatcher;
    const fresh = builder({ certPem: mtls.certPem, keyPem: mtls.keyPem });
    this.dispatchers.set(appId, fresh);
    return fresh;
  }

  private async callJson<T>(path: string, dispatcher: unknown, payload: unknown): Promise<T> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.deps.apiBase}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        ...((dispatcher !== undefined ? { dispatcher } : {}) as Record<string, unknown>),
      } as RequestInit);
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

function defaultBuildDispatcher(_opts: { certPem: string; keyPem: string }): unknown {
  // Real implementation lands in Task 7 (undici Pool). The throwing stub
  // ensures any prod path requires the lazy import to be wired before use.
  throw new Error('defaultBuildDispatcher not yet wired (Task 7 wires undici)');
}
