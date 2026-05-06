export interface SlidingWindowOpts {
  limit: number;
  windowMs: number;
  now?: () => number;
}

interface Bucket {
  current: number;
  previous: number;
  windowStart: number;
}

/**
 * Cloudflare-style sliding-window approximation: tracks the count for the
 * current window plus the count for the previous window; the effective count
 * is a weighted blend of (previous * remaining-fraction) + current.
 *
 * Memory is one entry per active key; a sweep runs every 1000 admit calls
 * to evict keys whose buckets are older than two windows.
 */
export class SlidingWindow {
  private readonly buckets = new Map<string, Bucket>();
  private readonly now: () => number;
  private opCount = 0;

  constructor(private readonly opts: SlidingWindowOpts) {
    this.now = opts.now ?? Date.now;
  }

  admit(key: string): boolean {
    this.maybeSweep();
    const t = this.now();
    const wstart = Math.floor(t / this.opts.windowMs) * this.opts.windowMs;
    let b = this.buckets.get(key);
    if (!b) {
      b = { current: 0, previous: 0, windowStart: wstart };
      this.buckets.set(key, b);
    } else if (b.windowStart !== wstart) {
      const gap = (wstart - b.windowStart) / this.opts.windowMs;
      if (gap === 1) {
        b.previous = b.current;
        b.current = 0;
      } else {
        b.previous = 0;
        b.current = 0;
      }
      b.windowStart = wstart;
    }
    const intoWindow = (t - wstart) / this.opts.windowMs;
    const effective = b.previous * (1 - intoWindow) + b.current;
    if (effective >= this.opts.limit) return false;
    b.current += 1;
    return true;
  }

  size(): number {
    return this.buckets.size;
  }

  private maybeSweep(): void {
    this.opCount += 1;
    if (this.opCount % 1000 !== 0) return;
    const t = this.now();
    const cutoff = t - 2 * this.opts.windowMs;
    for (const [k, b] of this.buckets) {
      if (b.windowStart < cutoff) this.buckets.delete(k);
    }
  }
}
