import type { Agent } from 'node:https';
import { tossFetch } from './client.js';
import { type ParsedEnvelope, parseTossEnvelope } from './envelope.js';

const PATH = '/api-partner/v1/apps-in-toss/user/access/remove-by-access-token';

export async function removeByAccessToken(args: {
  apiBase: string;
  agent: Agent;
  tossAccessToken: string;
}): Promise<ParsedEnvelope<Record<string, never>>> {
  const raw = await tossFetch({
    url: `${args.apiBase}${PATH}`,
    method: 'POST',
    body: { accessToken: args.tossAccessToken },
    agent: args.agent,
  });
  return parseTossEnvelope(raw);
}
