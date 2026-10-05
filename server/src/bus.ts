/**
 * Wake-ups for long polls (SPEC.md §6.2 and §8): a request waiting for news is woken as soon as
 * something it cares about changes, instead of polling the database.
 *
 * The server runs as a single process on one small machine (PLAN.md §10), so an in-process
 * emitter is enough. Running several processes would need Postgres LISTEN/NOTIFY here instead;
 * nothing else would change, because waiters always re-read the database after waking.
 */
import { EventEmitter } from 'node:events';

/** Channel names: one per device for its mailbox, one per invite for both participants. */
export const deviceChannel = (deviceId: string): string => `device:${deviceId}`;
export const inviteChannel = (inviteId: string): string => `invite:${inviteId}`;

export class WakeBus {
  private readonly emitter = new EventEmitter();

  constructor() {
    // Each waiting request is one listener; a phone may legitimately have a few at once.
    this.emitter.setMaxListeners(0);
  }

  /** Wakes everything waiting on `channel`. */
  notify(channel: string): void {
    this.emitter.emit(channel);
  }

  /**
   * Resolves when `channel` is notified, after `timeoutMillis`, or when `signal` aborts (the
   * client went away), whichever is first. Never rejects: the caller re-reads either way.
   */
  wait(channel: string, timeoutMillis: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
      if (signal?.aborted) {
        resolve();
        return;
      }
      const done = (): void => {
        clearTimeout(timer);
        this.emitter.off(channel, done);
        signal?.removeEventListener('abort', done);
        resolve();
      };
      const timer = setTimeout(done, timeoutMillis);
      this.emitter.on(channel, done);
      signal?.addEventListener('abort', done, { once: true });
    });
  }

  /** How many requests are waiting on `channel`; for tests. */
  waiting(channel: string): number {
    return this.emitter.listenerCount(channel);
  }
}
