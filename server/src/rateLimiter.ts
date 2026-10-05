/**
 * Per-device rate limits, applied after a request is authenticated (SPEC.md §13).
 *
 * Per-IP limits run before authentication in `@fastify/rate-limit`. These can't: keying a limit
 * on an unauthenticated device header would let anyone who knows a phone's fingerprint use up
 * that phone's budget. Memory only, like the bus: one process (PLAN.md §10), and a restart that
 * forgets the counters only makes limits briefly looser.
 */

interface Bucket {
  tokens: number;
  updatedAt: number;
  readonly limit: number;
  readonly windowMillis: number;
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  /**
   * Takes `cost` tokens from the bucket `key`, which holds `limit` tokens and refills completely
   * over `windowMillis`.
   *
   * @returns 0 when allowed, otherwise the seconds until enough tokens are back.
   */
  take(key: string, cost: number, limit: number, windowMillis: number): number {
    const bucket = this.buckets.get(key) ?? { tokens: limit, updatedAt: this.now(), limit, windowMillis };
    this.refill(bucket);
    this.buckets.set(key, bucket);
    if (cost > limit) return Math.ceil(windowMillis / 1000);
    if (bucket.tokens >= cost) {
      bucket.tokens -= cost;
      return 0;
    }
    return Math.max(1, Math.ceil(((cost - bucket.tokens) * windowMillis) / limit / 1000));
  }

  /** Drops buckets that have refilled completely; they carry no state worth keeping. */
  sweep(): void {
    for (const [key, bucket] of this.buckets) {
      this.refill(bucket);
      if (bucket.tokens >= bucket.limit) this.buckets.delete(key);
    }
  }

  /** How many buckets are held; for tests. */
  get size(): number {
    return this.buckets.size;
  }

  private refill(bucket: Bucket): void {
    const now = this.now();
    bucket.tokens = Math.min(bucket.limit, bucket.tokens + ((now - bucket.updatedAt) * bucket.limit) / bucket.windowMillis);
    bucket.updatedAt = now;
  }
}
