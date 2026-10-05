/**
 * The mailbox (SPEC.md §8): routing only between linked phones, exact sizes, caps, long polls,
 * acknowledgement, and the push it triggers.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ENVELOPE_BYTES, randomBytes, toBase64Url } from '@tamodak/protocol/api';
import { pair } from './support/ceremony.ts';
import { registeredPhone, type PhoneClient } from './support/client.ts';
import { startServer, type TestServer } from './support/server.ts';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});

afterAll(async () => {
  await server.close();
});

/** Opaque bytes of the right size; the server can't tell them from a real envelope. */
const envelope = () => toBase64Url(randomBytes(ENVELOPE_BYTES));

async function linkedPair(): Promise<[PhoneClient, PhoneClient]> {
  const a = await registeredPhone(server);
  const b = await registeredPhone(server);
  await pair(a, b);
  return [a, b];
}

const deviceRowId = async (client: PhoneClient) =>
  (await server.db.selectFrom('devices').select('id').where('fingerprint', '=', Buffer.from(client.phone.fp)).executeTakeFirstOrThrow()).id;

describe('sending', () => {
  it('delivers to a linked phone, byte for byte, and asks for a push', async () => {
    const [a, b] = await linkedPair();
    const sent = envelope();
    expect(await a.call('POST', '/v1/messages', { messages: [{ to: b.deviceId, envelope: sent }] })).toMatchObject({
      status: 202,
      body: { accepted: 1 },
    });
    const inbox = await b.call('GET', '/v1/messages');
    expect(inbox.body.messages).toHaveLength(1);
    expect(inbox.body.messages[0]).toMatchObject({ from: a.deviceId, envelope: sent });
    expect(server.push.scheduled).toContain(await deviceRowId(b));
  });

  it('refuses the whole batch if any recipient isn\'t linked', async () => {
    const [a, b] = await linkedPair();
    const stranger = await registeredPhone(server);
    const unknown = toBase64Url(randomBytes(32));
    const response = await a.call('POST', '/v1/messages', {
      messages: [
        { to: b.deviceId, envelope: envelope() },
        { to: stranger.deviceId, envelope: envelope() },
        { to: unknown, envelope: envelope() },
      ],
    });
    expect(response.status).toBe(403);
    expect(response.body.error).toBe('not_linked');
    expect(new Set(response.body.peers)).toEqual(new Set([stranger.deviceId, unknown]));
    expect((await b.call('GET', '/v1/messages')).body.messages).toEqual([]);
  });

  it('refuses a message to itself', async () => {
    const [a] = await linkedPair();
    expect((await a.call('POST', '/v1/messages', { messages: [{ to: a.deviceId, envelope: envelope() }] })).status).toBe(403);
  });

  it('accepts only the exact envelope size', async () => {
    const [a, b] = await linkedPair();
    for (const size of [ENVELOPE_BYTES - 1, ENVELOPE_BYTES + 1, 0]) {
      const response = await a.call('POST', '/v1/messages', { messages: [{ to: b.deviceId, envelope: toBase64Url(randomBytes(size)) }] });
      expect(response.status).toBe(400);
    }
  });

  it('accepts at most 50 envelopes in one request', async () => {
    const [a, b] = await linkedPair();
    const messages = Array.from({ length: 51 }, () => ({ to: b.deviceId, envelope: envelope() }));
    expect((await a.call('POST', '/v1/messages', { messages })).status).toBe(400);
  });

  it('stops routing once a link is removed', async () => {
    const [a, b] = await linkedPair();
    await a.call('DELETE', `/v1/links/${b.deviceId}`);
    expect((await a.call('POST', '/v1/messages', { messages: [{ to: b.deviceId, envelope: envelope() }] })).status).toBe(403);
  });
});

describe('mailbox caps', () => {
  it('cap one sender, and the whole mailbox', async () => {
    const capped = await startServer({ MAILBOX_PER_SENDER: '2', MAILBOX_PER_RECIPIENT: '3' });
    try {
      const [a, b, c] = [await registeredPhone(capped), await registeredPhone(capped), await registeredPhone(capped)];
      await pair(a, b);
      await pair(c, b);
      const send = (from: PhoneClient, count: number) =>
        from.call('POST', '/v1/messages', { messages: Array.from({ length: count }, () => ({ to: b.deviceId, envelope: envelope() })) });
      expect((await send(a, 2)).status).toBe(202);
      expect(await send(a, 1)).toMatchObject({ status: 429, body: { error: 'mailbox_full' } });
      expect((await send(c, 1)).status).toBe(202);
      expect((await send(c, 1)).status).toBe(429);
      const inbox = await b.call('GET', '/v1/messages');
      await b.call('POST', '/v1/messages/ack', { ids: inbox.body.messages.map((m: { id: string }) => m.id) });
      expect((await send(a, 2)).status).toBe(202);
    } finally {
      await capped.close();
    }
  });
});

describe('receiving', () => {
  it('returns the oldest first, 32 at a time, until acknowledged', async () => {
    const [a, b] = await linkedPair();
    const sent: string[] = [];
    for (let batch = 0; batch < 2; batch++) {
      const messages = Array.from({ length: 20 }, () => ({ to: b.deviceId, envelope: envelope() }));
      sent.push(...messages.map((m) => m.envelope));
      await a.call('POST', '/v1/messages', { messages });
    }
    const first = await b.call('GET', '/v1/messages');
    expect(first.body.messages).toHaveLength(32);
    expect(new Set(first.body.messages.map((m: { envelope: string }) => m.envelope))).toEqual(new Set(sent.slice(0, 32)));
    // Unacknowledged messages come back.
    expect((await b.call('GET', '/v1/messages')).body.messages).toHaveLength(32);
    await b.call('POST', '/v1/messages/ack', { ids: first.body.messages.map((m: { id: string }) => m.id) });
    const rest = await b.call('GET', '/v1/messages');
    expect(rest.body.messages).toHaveLength(8);
  });

  it('lets only the recipient acknowledge', async () => {
    const [a, b] = await linkedPair();
    await a.call('POST', '/v1/messages', { messages: [{ to: b.deviceId, envelope: envelope() }] });
    const id = (await b.call('GET', '/v1/messages')).body.messages[0].id;
    expect((await a.call('POST', '/v1/messages/ack', { ids: [id] })).status).toBe(204);
    expect((await b.call('GET', '/v1/messages')).body.messages).toHaveLength(1);
  });

  it('wakes a long poll as soon as a message arrives', async () => {
    const [a, b] = await linkedPair();
    const started = Date.now();
    const poll = b.call('GET', '/v1/messages?wait=20');
    await new Promise((resolve) => setTimeout(resolve, 200));
    await a.call('POST', '/v1/messages', { messages: [{ to: b.deviceId, envelope: envelope() }] });
    expect((await poll).body.messages).toHaveLength(1);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('ends a long poll empty when nothing comes', async () => {
    const [, b] = await linkedPair();
    const started = Date.now();
    const response = await b.call('GET', '/v1/messages?wait=1');
    expect(response.body.messages).toEqual([]);
    expect(Date.now() - started).toBeGreaterThanOrEqual(900);
  });

  it('stops waiting for a client that left', async () => {
    const [, b] = await linkedPair();
    const channel = `device:${await deviceRowId(b)}`;
    const controller = new AbortController();
    const headers = await (async () => {
      const { signRequest } = await import('@tamodak/protocol/api');
      return signRequest(b.phone.signKey, b.phone.fp, {
        audience: 'api.killit.test',
        method: 'GET',
        target: '/v1/messages?wait=30',
        timestamp: server.clock.now(),
        nonce: randomBytes(16),
        body: new Uint8Array(0),
      });
    })();
    const request = fetch(`${server.url}/v1/messages?wait=30`, { headers: { ...headers }, signal: controller.signal }).catch(() => null);
    await waitUntil(() => server.bus.waiting(channel) === 1);
    controller.abort();
    await request;
    await waitUntil(() => server.bus.waiting(channel) === 0);
  });

  it('keeps messages from a phone that deleted itself, and drops a deleted phone\'s mailbox', async () => {
    const [a, b] = await linkedPair();
    await a.call('POST', '/v1/messages', { messages: [{ to: b.deviceId, envelope: envelope() }] });
    await a.call('DELETE', '/v1/devices/me');
    expect((await b.call('GET', '/v1/messages')).body.messages).toHaveLength(1);
    const recipientId = await deviceRowId(b);
    await b.call('DELETE', '/v1/devices/me');
    const left = await server.db.selectFrom('messages').select('id').where('recipient', '=', recipientId).execute();
    expect(left).toEqual([]);
  });

  it('limits envelopes per phone', async () => {
    const limited = await startServer({ RATE_ENVELOPES_PER_DEVICE_PER_HOUR: '3' });
    try {
      const a = await registeredPhone(limited);
      const b = await registeredPhone(limited);
      await pair(a, b);
      const messages = (count: number) => Array.from({ length: count }, () => ({ to: b.deviceId, envelope: envelope() }));
      expect((await a.call('POST', '/v1/messages', { messages: messages(3) })).status).toBe(202);
      const refused = await a.call('POST', '/v1/messages', { messages: messages(1) });
      expect(refused.status).toBe(429);
      expect(Number(refused.headers.get('retry-after'))).toBeGreaterThan(0);
    } finally {
      await limited.close();
    }
  });
});

async function waitUntil(condition: () => boolean, timeoutMillis = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMillis;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('condition not met in time');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
