export type ClientAuthResult =
  | { kind: 'public' }
  | { kind: 'confidential'; clientId: string; plainSecret: string }
  | { kind: 'invalid'; reason: string };

export interface ClientAuthInput {
  authorization: string | undefined;
  bodyClientId: string | undefined;
  bodyClientSecret: string | undefined;
}

export function resolveClientAuth(input: ClientAuthInput): ClientAuthResult {
  const basic = parseBasic(input.authorization);
  const hasBasic = basic !== null;
  const hasBodySecret =
    typeof input.bodyClientSecret === 'string' && input.bodyClientSecret.length > 0;

  if (hasBasic && hasBodySecret) {
    return { kind: 'invalid', reason: 'multiple authentication methods' };
  }

  if (hasBasic) {
    if (basic.malformed) return { kind: 'invalid', reason: 'malformed Basic credentials' };
    if (input.bodyClientId !== undefined && basic.clientId !== input.bodyClientId) {
      return { kind: 'invalid', reason: 'client_id mismatch between Basic and body' };
    }
    return { kind: 'confidential', clientId: basic.clientId, plainSecret: basic.secret };
  }

  if (hasBodySecret) {
    if (!input.bodyClientId) {
      return { kind: 'invalid', reason: 'client_secret_post requires client_id' };
    }
    return {
      kind: 'confidential',
      clientId: input.bodyClientId,
      plainSecret: input.bodyClientSecret as string,
    };
  }

  return { kind: 'public' };
}

interface ParsedBasic {
  malformed: boolean;
  clientId: string;
  secret: string;
}

function parseBasic(authorization: string | undefined): ParsedBasic | null {
  if (!authorization) return null;
  const m = /^Basic\s+(\S+)\s*$/i.exec(authorization);
  if (!m) return null;
  const b64 = m[1] as string;
  if (!/^[A-Za-z0-9+/]+=*$/.test(b64)) {
    return { malformed: true, clientId: '', secret: '' };
  }
  let decoded: string;
  try {
    decoded = Buffer.from(b64, 'base64').toString('utf8');
  } catch {
    return { malformed: true, clientId: '', secret: '' };
  }
  if (!/^[\x20-\x7e]+$/.test(decoded)) {
    return { malformed: true, clientId: '', secret: '' };
  }
  const idx = decoded.indexOf(':');
  if (idx < 0) return { malformed: true, clientId: '', secret: '' };
  return {
    malformed: false,
    clientId: decoded.slice(0, idx),
    secret: decoded.slice(idx + 1),
  };
}
