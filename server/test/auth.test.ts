/**
 * Request authentication (SPEC.md §4.2): what a signature covers, the time window, nonces, and
 * the per-device rate limit.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from '@tamodak/protocol/api';
import { PhoneClient, registeredPhone } from './support/client.ts';
import { startServer, type TestServer } from './support/server.ts';

let server: TestServer;
let phone: PhoneClient;

beforeAll(async () => {
  server = await startServer({ RATE_REQUESTS_PER_DEVICE_PER_MINUTE: '1000' });
  phone = await registeredPhone(server);
});

afterAll(async () => {
  await server.close();
});

describe('signed requests', () => {
  it('accept a correct signature', async () => {
    expect((await phone.call('GET', '/v1/links')).status).toBe(200);
  });

  it.each([
    ['no signature', { unsigned: true }],
    ['a signature for another server', { audience: 'api.tamodak.org' }],
    ['a signature for another path', { signedTarget: '/v1/devices/me' }],
    ['a signature for another query', { signedTarget: '/v1/links?x=1' }],
  ])('refuse %s', async (_, options) => {
    const response = await phone.call('GET', '/v1/links', undefined, options);
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: 'unauthorized', reason: 'invalid' });
  });

  it('cover the exact body bytes', async () => {
    const signedBody = new TextEncoder().encode('{"fcmToken":"a"}');
    const response = await phone.call('PUT', '/v1/devices/me/push', undefined, {
      rawBody: signedBody,
      // Same JSON meaning, different bytes than were signed.
      headers: {},
    });
    expect(response.status).toBe(204);
    const respaced = await fetch(`${server.url}/v1/devices/me/push`, {
      method: 'PUT',
      headers: { ...(await signedHeaders(signedBody)), 'content-type': 'application/json' },
      body: '{ "fcmToken": "a" }',
    });
    expect(respaced.status).toBe(401);
  });

  it('refuse a timestamp outside five minutes, saying so', async () => {
    for (const offset of [-301_000, 301_000]) {
      const response = await phone.call('GET', '/v1/links', undefined, { timestamp: server.clock.now() + offset });
      expect(response.body).toEqual({ error: 'unauthorized', reason: 'stale_timestamp' });
      expect(response.headers.get('date')).not.toBeNull();
    }
  });

  it('refuse a nonce used before', async () => {
    const nonce = randomBytes(16);
    expect((await phone.call('GET', '/v1/links', undefined, { nonce })).status).toBe(200);
    expect((await phone.call('GET', '/v1/links', undefined, { nonce })).status).toBe(401);
  });

  it('refuse an unregistered phone', async () => {
    expect((await new PhoneClient(server).call('GET', '/v1/links')).status).toBe(401);
  });

  it('refuse a repeated or malformed header', async () => {
    const response = await phone.call('GET', '/v1/links', undefined, { headers: { 'killit-timestamp': '0123' } });
    expect(response.status).toBe(401);
  });
});

describe('errors', () => {
  it('answer unknown routes with 404 not_found', async () => {
    const response = await phone.call('GET', '/v1/nothing');
    expect(response).toMatchObject({ status: 404, body: { error: 'not_found' } });
  });

  it('answer a body that isn\'t JSON with 400', async () => {
    const response = await phone.call('PUT', '/v1/devices/me/push', undefined, {
      rawBody: new TextEncoder().encode('not json'),
    });
    expect(response).toMatchObject({ status: 400, body: { error: 'bad_request' } });
  });

  it('answer a body over the route limit with 413', async () => {
    const big = { fcmToken: 'x'.repeat(20_000) };
    expect((await phone.call('PUT', '/v1/devices/me/push', big)).status).toBe(413);
  });

  it('set security headers on every answer', async () => {
    const response = await phone.call('GET', '/v1/links');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  });
});

describe('rate limits', () => {
  it('limit each phone separately', async () => {
    const limited = await startServer({ RATE_REQUESTS_PER_DEVICE_PER_MINUTE: '3' });
    try {
      const busy = await registeredPhone(limited);
      const quiet = await registeredPhone(limited);
      const statuses: number[] = [];
      for (let i = 0; i < 4; i++) statuses.push((await busy.call('GET', '/v1/links')).status);
      expect(statuses).toEqual([200, 200, 200, 429]);
      expect((await quiet.call('GET', '/v1/links')).status).toBe(200);
      limited.clock.advance(60_000);
      expect((await busy.call('GET', '/v1/links')).status).toBe(200);
    } finally {
      await limited.close();
    }
  });

  it('limit each address', async () => {
    const limited = await startServer({ RATE_IP_PER_MINUTE: '5' });
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) statuses.push((await fetch(`${limited.url}/healthz`)).status);
      expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200]);
      expect(statuses[5]).toBe(429);
    } finally {
      await limited.close();
    }
  });
});

/** Headers signing `body` for PUT /v1/devices/me/push. */
async function signedHeaders(body: Uint8Array): Promise<Record<string, string>> {
  const { signRequest } = await import('@tamodak/protocol/api');
  return {
    ...signRequest(phone.phone.signKey, phone.phone.fp, {
      audience: 'api.killit.test',
      method: 'PUT',
      target: '/v1/devices/me/push',
      timestamp: server.clock.now(),
      nonce: randomBytes(16),
      body,
    }),
  };
}
