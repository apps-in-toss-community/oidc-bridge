export function originIsAllowed(origin: string | undefined, allowed: string[]): boolean {
  if (!origin) return false;
  if (allowed.length === 0) return false;
  return allowed.includes(origin);
}
