export interface ClientCredentials {
  client_id: string;
  client_secret: string;
}

export function extractClientCredentials(args: {
  authorizationHeader: string | undefined;
  bodyClientId: string | undefined;
  bodyClientSecret: string | undefined;
}): ClientCredentials | null {
  const hasBasic = args.authorizationHeader?.startsWith('Basic ') ?? false;
  const hasPost = args.bodyClientId !== undefined || args.bodyClientSecret !== undefined;
  if (hasBasic && hasPost) {
    throw new Error('multiple client authentication mechanisms supplied');
  }
  if (hasBasic) {
    const b64 = args.authorizationHeader!.slice('Basic '.length).trim();
    let decoded: string;
    try {
      decoded = Buffer.from(b64, 'base64').toString('utf8');
    } catch {
      throw new Error('malformed basic auth');
    }
    const idx = decoded.indexOf(':');
    if (idx < 0) throw new Error('malformed basic auth: missing colon');
    return {
      client_id: decodeURIComponent(decoded.substring(0, idx)),
      client_secret: decodeURIComponent(decoded.substring(idx + 1)),
    };
  }
  if (hasPost) {
    if (!args.bodyClientId || !args.bodyClientSecret) {
      throw new Error('client_secret_post requires both client_id and client_secret');
    }
    return { client_id: args.bodyClientId, client_secret: args.bodyClientSecret };
  }
  return null;
}
