import type { Agent } from 'node:https';
import { tossFetch } from './client.js';
import { type ParsedEnvelope, parseTossEnvelope } from './envelope.js';
import type { LoginMeSuccess } from './types.js';

const PATH = '/api-partner/v1/apps-in-toss/user/oauth2/login-me';

export async function loginMe(args: {
  apiBase: string;
  agent: Agent;
  accessToken: string;
}): Promise<ParsedEnvelope<LoginMeSuccess>> {
  const raw = await tossFetch({
    url: `${args.apiBase}${PATH}`,
    method: 'GET',
    bearer: args.accessToken,
    agent: args.agent,
  });
  return parseTossEnvelope<LoginMeSuccess>(raw);
}
