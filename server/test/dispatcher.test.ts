/**
 * When pushes go out (SPEC.md §9): coalesced per phone, retried when FCM asks, and dead tokens
 * forgotten.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PushDispatcher, type PushSender } from '../src/push/dispatcher.ts';
import type { SendResult } from '../src/push/fcm.ts';
import { registeredPhone, type PhoneClient } from './support/client.ts';
import { startServer, type TestServer } from './support/server.ts';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});

afterAll(async () => {
  await server.close();
});

class FakeSender implements PushSender {
  readonly sent: string[] = [];
  results: SendResult[] = [];
  /** Runs while a send is in flight, e.g. to change the token underneath it. */
  during: (() => Promise<void>) | null = null;
  async send(token: string): Promise<SendResult> {
    this.sent.push(token);
    await this.during?.();
    return this.results.shift() ?? { ok: true };
  }
}

const quiet = { info: () => {}, warn: () => {} };
const sleep = (millis: number) => new Promise((resolve) => setTimeout(resolve, millis));

async function phoneWithToken(token: string): Promise<{ client: PhoneClient; id: string }> {
  const client = await registeredPhone(server);
  await client.call('PUT', '/v1/devices/me/push', { fcmToken: token });
  const row = await server.db.selectFrom('devices').select('id').where('fingerprint', '=', Buffer.from(client.phone.fp)).executeTakeFirstOrThrow();
  return { client, id: row.id };
}

async function tokenOf(id: string): Promise<string | null> {
  return (await server.db.selectFrom('devices').select('fcm_token').where('id', '=', id).executeTakeFirstOrThrow()).fcm_token;
}

async function until(condition: () => boolean, timeoutMillis = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMillis;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('condition not met in time');
    await sleep(10);
  }
}

describe('PushDispatcher', () => {
  it('turns a burst of requests into one push, then waits its interval before the next', async () => {
    const sender = new FakeSender();
    const dispatcher = new PushDispatcher({ db: server.db, sender, log: quiet, minIntervalMillis: 300 });
    const { id } = await phoneWithToken('token-burst');
    for (let i = 0; i < 5; i++) dispatcher.schedule(id);
    await until(() => sender.sent.length === 1);
    dispatcher.schedule(id);
    await sleep(100);
    expect(sender.sent).toHaveLength(1);
    await until(() => sender.sent.length === 2);
    dispatcher.stop();
  });

  it('forgets a token FCM says is dead', async () => {
    const sender = new FakeSender();
    const dispatcher = new PushDispatcher({ db: server.db, sender, log: quiet, minIntervalMillis: 10 });
    const { id } = await phoneWithToken('token-dead');
    sender.results.push({ ok: false, kind: 'token_invalid' });
    dispatcher.schedule(id);
    await until(() => sender.sent.length === 1 && dispatcher.pending === 0);
    expect(await tokenOf(id)).toBeNull();
    dispatcher.stop();
  });

  it('keeps a token the phone registered while the dead one was being tried', async () => {
    const sender = new FakeSender();
    const dispatcher = new PushDispatcher({ db: server.db, sender, log: quiet, minIntervalMillis: 10 });
    const { client, id } = await phoneWithToken('token-old');
    sender.results.push({ ok: false, kind: 'token_invalid' });
    sender.during = async () => {
      await client.call('PUT', '/v1/devices/me/push', { fcmToken: 'token-new' });
    };
    dispatcher.schedule(id);
    await until(() => sender.sent.length === 1 && dispatcher.pending === 0);
    expect(await tokenOf(id)).toBe('token-new');
    dispatcher.stop();
  });

  it('retries when FCM asks, then gives up', async () => {
    const sender = new FakeSender();
    const dispatcher = new PushDispatcher({ db: server.db, sender, log: quiet, minIntervalMillis: 10, retryBaseMillis: 20, maxAttempts: 3 });
    const { id } = await phoneWithToken('token-retry');
    sender.results.push(
      { ok: false, kind: 'retry', retryAfterSeconds: null },
      { ok: false, kind: 'retry', retryAfterSeconds: null },
      { ok: false, kind: 'retry', retryAfterSeconds: null },
    );
    dispatcher.schedule(id);
    await until(() => sender.sent.length === 3);
    await sleep(200);
    expect(sender.sent).toHaveLength(3);
    dispatcher.stop();
  });

  it('skips phones without a token', async () => {
    const sender = new FakeSender();
    const dispatcher = new PushDispatcher({ db: server.db, sender, log: quiet, minIntervalMillis: 10 });
    const client = await registeredPhone(server);
    const row = await server.db.selectFrom('devices').select('id').where('fingerprint', '=', Buffer.from(client.phone.fp)).executeTakeFirstOrThrow();
    dispatcher.schedule(row.id);
    await sleep(100);
    expect(sender.sent).toEqual([]);
    dispatcher.stop();
  });

  it('does nothing without FCM credentials', () => {
    const dispatcher = new PushDispatcher({ db: server.db, sender: null, log: quiet });
    dispatcher.schedule('00000000-0000-0000-0000-000000000000');
    expect(dispatcher.pending).toBe(0);
  });
});
