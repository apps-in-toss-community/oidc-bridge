const FORBIDDEN_VALUES = new Set(['null', '']);

export function originIsAllowed(origin: string | undefined, allowed: string[]): boolean {
  if (!origin) return false;
  if (origin !== origin.trim()) return false;
  if (FORBIDDEN_VALUES.has(origin)) return false;
  if (allowed.length === 0) return false;
  for (const a of allowed) {
    if (FORBIDDEN_VALUES.has(a)) continue;
    if (a === origin) return true;
  }
  return false;
}
