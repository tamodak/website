/**
 * What every route plugin receives, and the long-poll helper they share.
 */
import type { Kysely } from 'kysely';
import type { WakeBus } from '../bus.ts';
import type { Config } from '../config.ts';
import type { Database } from '../db/schema.ts';
import type { RateLimiter } from '../rateLimiter.ts';

/** Asks for a push to a phone (SPEC.md §9); `PushDispatcher` in production. */
export interface PushScheduler {
  schedule(deviceId: string): void;
}

export interface RouteDeps {
  readonly db: Kysely<Database>;
  readonly config: Config;
  readonly bus: WakeBus;
  readonly limiter: RateLimiter;
  readonly push: PushScheduler;
  readonly now: () => number;
}

/**
 * Reads, and if the result isn't what the caller is waiting for, waits for a wake-up on `channel`
 * (or the timeout, or the client leaving) and reads once more.
 *
 * The waiter is registered before the first read, so a change that lands between that read and
 * the wait still wakes it.
 */
export async function longPoll<T>(options: {
  readonly bus: WakeBus;
  readonly channel: string;
  readonly waitMillis: number;
  readonly clientGone: AbortSignal;
  readonly read: () => Promise<T>;
  readonly ready: (value: T) => boolean;
}): Promise<T> {
  if (options.waitMillis <= 0) return options.read();
  const done = new AbortController();
  const woken = options.bus.wait(options.channel, options.waitMillis, AbortSignal.any([done.signal, options.clientGone]));
  const first = await options.read();
  if (options.ready(first) || options.clientGone.aborted) {
    done.abort();
    return first;
  }
  await woken;
  return options.read();
}

/** One hour, the window of the hourly rate limits. */
export const HOUR_MILLIS = 60 * 60 * 1000;
