/**
 * Decides when to push (SPEC.md §9): at most one "sync" every 10 seconds per phone, retries with
 * backoff when FCM asks for it, and forgets tokens FCM says are dead.
 *
 * Push is only a wake-up. Everything it signals is already safe in the mailbox, so a push that
 * never arrives costs a delay until the next app open or WorkManager poll, never a message.
 */
import type { Kysely } from 'kysely';
import type { Database } from '../db/schema.ts';
import type { SendResult } from './fcm.ts';

/** What the dispatcher needs from an FCM client; tests substitute a fake. */
export interface PushSender {
  send(registrationToken: string): Promise<SendResult>;
}

export interface PushLog {
  info(message: string): void;
  warn(message: string): void;
}

export interface DispatcherOptions {
  readonly db: Kysely<Database>;
  /** Null when no FCM credentials are configured: pushes are then skipped. */
  readonly sender: PushSender | null;
  readonly log: PushLog;
  readonly minIntervalMillis?: number;
  readonly maxAttempts?: number;
  /** The first retry's delay; each later one doubles it. FCM asks for at least a minute. */
  readonly retryBaseMillis?: number;
  readonly now?: () => number;
}

interface DeviceState {
  lastSentAt: number;
  timer: NodeJS.Timeout | null;
  inFlight: boolean;
  /** A push was asked for while one was being sent: send once more afterwards. */
  again: boolean;
  attempt: number;
}

export class PushDispatcher {
  private readonly devices = new Map<string, DeviceState>();
  private readonly options: Required<Omit<DispatcherOptions, 'sender'>> & Pick<DispatcherOptions, 'sender'>;
  private stopped = false;

  constructor(options: DispatcherOptions) {
    this.options = { minIntervalMillis: 10_000, maxAttempts: 5, retryBaseMillis: 60_000, now: Date.now, ...options };
  }

  /** Asks for a push to `deviceId` soon. Calls close together become one push. */
  schedule(deviceId: string): void {
    if (this.options.sender === null || this.stopped) return;
    const state = this.state(deviceId);
    if (state.inFlight) {
      state.again = true;
      return;
    }
    if (state.timer !== null) return;
    const wait = Math.max(0, state.lastSentAt + this.options.minIntervalMillis - this.options.now());
    this.arm(deviceId, state, wait);
  }

  /** Cancels every pending push; used on shutdown. */
  stop(): void {
    this.stopped = true;
    for (const state of this.devices.values()) if (state.timer !== null) clearTimeout(state.timer);
    this.devices.clear();
  }

  /** Phones with a push pending or in flight; for tests. */
  get pending(): number {
    return [...this.devices.values()].filter((state) => state.timer !== null || state.inFlight).length;
  }

  private state(deviceId: string): DeviceState {
    let state = this.devices.get(deviceId);
    if (state === undefined) {
      state = { lastSentAt: -Infinity, timer: null, inFlight: false, again: false, attempt: 0 };
      this.devices.set(deviceId, state);
    }
    return state;
  }

  private arm(deviceId: string, state: DeviceState, delayMillis: number): void {
    state.timer = setTimeout(() => {
      state.timer = null;
      void this.deliver(deviceId, state);
    }, delayMillis);
    state.timer.unref();
  }

  private async deliver(deviceId: string, state: DeviceState): Promise<void> {
    state.inFlight = true;
    state.again = false;
    let result: SendResult | 'no_token';
    try {
      const row = await this.options.db.selectFrom('devices').select('fcm_token').where('id', '=', deviceId).executeTakeFirst();
      const token = row?.fcm_token ?? null;
      result = token === null ? 'no_token' : await this.options.sender!.send(token);
      if (result !== 'no_token' && !result.ok && result.kind === 'token_invalid' && token !== null) {
        // Only the token that failed: the phone may have registered a new one meanwhile.
        await this.options.db.updateTable('devices').set({ fcm_token: null }).where('id', '=', deviceId).where('fcm_token', '=', token).execute();
        this.options.log.info('push: forgot a token FCM reported as invalid');
      }
    } catch (error) {
      result = { ok: false, kind: 'retry', retryAfterSeconds: null };
      this.options.log.warn(`push: send failed (${(error as Error).name})`);
    }
    state.inFlight = false;
    state.lastSentAt = this.options.now();

    if (result !== 'no_token' && !result.ok && result.kind === 'retry' && !this.stopped) {
      state.attempt++;
      if (state.attempt < this.options.maxAttempts) {
        // FCM asks for exponential backoff; quota errors want at least a minute.
        const backoff = Math.min(15 * 60_000, this.options.retryBaseMillis * 2 ** (state.attempt - 1));
        const delay = result.retryAfterSeconds !== null ? Math.max(result.retryAfterSeconds * 1000, backoff) : backoff;
        this.arm(deviceId, state, delay);
        return;
      }
      this.options.log.warn('push: giving up after repeated FCM errors; the mailbox still holds the message');
    } else if (result !== 'no_token' && !result.ok && result.kind === 'error') {
      this.options.log.warn(`push: FCM refused a send (HTTP ${result.status}, ${result.code ?? 'no code'})`);
    }
    state.attempt = 0;
    if (this.stopped) return;
    if (state.again) {
      this.arm(deviceId, state, this.options.minIntervalMillis);
      return;
    }
    // Keep lastSentAt for one interval, so a schedule() right after this still waits its turn;
    // then forget the phone, unless something was scheduled meanwhile.
    setTimeout(() => {
      if (state.timer === null && !state.inFlight && this.devices.get(deviceId) === state) this.devices.delete(deviceId);
    }, this.options.minIntervalMillis).unref();
  }
}
