// __Host- prefix forces Secure + Path=/ + no Domain. RFC 6265bis closes a
// subdomain-takeover vector by binding the cookie to the exact origin.
const COOKIE_NAME = '__Host-bridge_session';

export function setSessionCookie(id: string, expiresAt: Date): string {
  return `${COOKIE_NAME}=${id}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expiresAt.toUTCString()}`;
}

export function clearSessionCookie(): string {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function readSessionCookie(headerValue: string | null | undefined): string | null {
  if (!headerValue) return null;
  for (const piece of headerValue.split(';')) {
    const trimmed = piece.trim();
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const k = trimmed.slice(0, eq);
    if (k !== COOKIE_NAME) continue;
    const v = trimmed.slice(eq + 1);
    return v.length > 0 ? v : null;
  }
  return null;
}
