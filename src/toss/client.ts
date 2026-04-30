import { Agent } from 'node:https';
import { OAuthError } from '../errors.js';

export function buildAgent(args: { cert_pem: string; key_pem: string }): Agent {
  return new Agent({ cert: args.cert_pem, key: args.key_pem, keepAlive: true });
}

interface TossFetchArgs {
  url: string;
  method: 'GET' | 'POST';
  body?: unknown;
  bearer?: string;
  agent: Agent;
}

export async function tossFetch(args: TossFetchArgs): Promise<unknown> {
  const opts = (args.agent as unknown as { options: { cert?: string; key?: string } }).options;
  const { Agent: UndiciAgent } = await import('undici');
  const dispatcher = new UndiciAgent({
    connect: { cert: opts.cert, key: opts.key },
    keepAliveTimeout: 30_000,
  });
  const headers: Record<string, string> = { accept: 'application/json' };
  let body: string | undefined;
  if (args.body !== undefined) {
    headers['content-type'] = 'application/json';
    body = JSON.stringify(args.body);
  }
  if (args.bearer) headers.authorization = `Bearer ${args.bearer}`;

  // biome-ignore lint/suspicious/noExplicitAny: undici dispatcher has a different type shape than the global RequestInit Dispatcher
  const fetchInit: any = { method: args.method, headers, dispatcher };
  if (body !== undefined) fetchInit.body = body;

  let response: Response;
  try {
    response = await fetch(args.url, fetchInit as RequestInit);
  } catch (_err) {
    throw new OAuthError('temporarily_unavailable', 'failed to reach Toss partner API', 502);
  }
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = text.length > 0 ? JSON.parse(text) : {};
  } catch {
    throw new OAuthError(
      'temporarily_unavailable',
      `Toss returned non-JSON (${response.status})`,
      502,
    );
  }
  if (!response.ok) {
    throw new OAuthError('temporarily_unavailable', `Toss returned HTTP ${response.status}`, 502);
  }
  return parsed;
}
