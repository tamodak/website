/**
 * The small pieces: the wake-up bus, the per-device rate limiter and the purge job.
 */
import { sql } from 'kysely';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { WakeBus } from '../src/bus.ts';
import { purge } from '../src/jobs/purge.ts';
import { RateLimiter } from '../src/rateLimiter.ts';
import { registeredPhone } from './support/client.ts';
import { startServer, type TestServer } from './support/server.ts';

describe('WakeBus', () => {
  it('wakes waiters on their channel only', async () => {
    const bus = new WakeBus();
    let woken = false;
    const waiting = bus.wait('a', 5000).then(() => (woken = true));
    bus.notify('b');
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(woken).toBe(false);
    bus.notify('a');
    await waiting;
    expect(bus.waiting('a')).toBe(0);
  });

  it('gives up after the timeout or when aborted, leaving no listener behind', async () => {
    const bus = new WakeBus();
    await bus.wait('a', 10);
    const controller = new AbortController();
    const waiting = bus.wait('a', 5000, controller.signal);
    expect(bus.waiting('a')).toBe(1);
    controller.abort();
    await waiting;
    expect(bus.waiting('a')).toBe(0);
  });
});

describe('RateLimiter', () => {
  it('refills over its window and says how long to wait', () => {
    let now = 0;
    const limiter = new RateLimiter(() => now);
    expect(limiter.take('k', 2, 2, 60_000)).toBe(0);
    expect(limiter.take('k', 1, 2, 60_000)).toBe(30);
    now += 30_000;
    expect(limiter.take('k', 1, 2, 60_000)).toBe(0);
    expect(limiter.take('k', 5, 2, 60_000)).toBe(60);
  });

  it('forgets buckets that have refilled', () => {
    let now = 0;
    const limiter = new RateLimiter(() => now);
    limiter.take('a', 1, 10, 1000);
    limiter.take('b', 1, 10, 1000);
    limiter.sweep();
    expect(limiter.size).toBe(2);
    now += 1000;
    limiter.sweep();
    expect(limiter.size).toBe(0);
  });
});

describe('purge', () => {
  let server: TestServer;

  beforeAll(async () => {
    server = await startServer();
  });

  afterAll(async () => {
    await server.close();
  });

  it('removes expired challenges, nonces and old invites, and keeps the rest', async () => {
    const phone = await registeredPhone(server);
    await phone.call('POST', '/v1/register/challenge');
    const finished = (await phone.call('POST', '/v1/invites')).body.id;
    const fresh = (await phone.call('POST', '/v1/invites')).body.id;
    await server.db.updateTable('attestation_challenges').set({ expires_at: sql<Date>`now() - interval '1 minute'` }).execute();
    await server.db.updateTable('seen_nonces').set({ expires_at: sql<Date>`now() - interval '1 minute'` }).execute();
    await server.db.updateTable('invites').set({ finished_at: sql<Date>`now() - interval '61 minutes'` }).where('id', '=', finished).execute();

    const result = await purge(server.db, server.limiter);
    expect(result.challenges).toBeGreaterThan(0);
    expect(result.nonces).toBeGreaterThan(0);
    expect(result.invites).toBe(1);
    const left = await server.db.selectFrom('invites').select('id').execute();
    expect(left.map((row) => row.id)).toEqual([fresh]);
  });
});
