let last: Date | null = null;

export function recordHealthz(at: Date = new Date()): void {
  last = at;
}

export function getLastHealthz(): Date | null {
  return last;
}

export function resetLastHealthz(): void {
  last = null;
}
