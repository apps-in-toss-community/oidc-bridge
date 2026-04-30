import type { Agent } from 'node:https';
import { tossFetch } from './client.js';
import { type ParsedEnvelope, parseTossEnvelope } from './envelope.js';
import type { Referrer, RefreshTokenSuccess } from './types.js';

const PATH = '/api-partner/v1/apps-in-toss/user/oauth2/refresh-token';

export async function refreshToken(args: {
  apiBase: string;
  agent: Agent;
  refreshToken: string;
  referrer: Referrer;
}): Promise<ParsedEnvelope<RefreshTokenSuccess>> {
  const raw = await tossFetch({
    url: `${args.apiBase}${PATH}`,
    method: 'POST',
    body: { refreshToken: args.refreshToken, referrer: args.referrer },
    agent: args.agent,
  });
  return parseTossEnvelope<RefreshTokenSuccess>(raw);
}
