import type { Agent } from 'node:https';
import { tossFetch } from './client.js';
import { type ParsedEnvelope, parseTossEnvelope } from './envelope.js';
import type { GenerateTokenSuccess, Referrer } from './types.js';

const PATH = '/api-partner/v1/apps-in-toss/user/oauth2/generate-token';

export async function generateToken(args: {
  apiBase: string;
  agent: Agent;
  authorizationCode: string;
  referrer: Referrer;
}): Promise<ParsedEnvelope<GenerateTokenSuccess>> {
  const raw = await tossFetch({
    url: `${args.apiBase}${PATH}`,
    method: 'POST',
    body: { authorizationCode: args.authorizationCode, referrer: args.referrer },
    agent: args.agent,
  });
  return parseTossEnvelope<GenerateTokenSuccess>(raw);
}
