/**
 * Invites and links (SPEC.md §6, §7): the ceremony's order, what each phone sees, and links.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { commitment, encodeReveal, randomBytes, toBase64Url } from '@tamodak/protocol/e2e';
import { registeredPhone, type PhoneClient } from './support/client.ts';
import { pair } from './support/ceremony.ts';
import { startServer, type TestServer } from './support/server.ts';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});

afterAll(async () => {
  await server.close();
});

const phones = (count: number) => Promise.all(Array.from({ length: count }, () => registeredPhone(server)));

async function invite(creator: PhoneClient) {
  const response = await creator.call('POST', '/v1/invites');
  return response.body as { id: string; code: string; expiresAt: number };
}

function commitFor(phone: PhoneClient, nonce = randomBytes(32)) {
  const reveal = encodeReveal(phone.phone.bundle, nonce);
  return { reveal, commit: toBase64Url(commitment(reveal)) };
}

describe('the ceremony', () => {
  it('links two phones that computed the same safety code', async () => {
    const [a, b] = await phones(2);
    const ceremony = await pair(a!, b!);
    expect(ceremony.creatorCode).toBe(ceremony.joinerCode);
    expect(ceremony.code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    const links = await a!.call('GET', '/v1/links');
    expect(links.body).toEqual({ links: [{ peer: b!.deviceId, lastSeenDaysAgo: 0 }] });
  });

  it('never stores or shows a role', async () => {
    const [a, b] = await phones(2);
    const ceremony = await pair(a!, b!);
    const view = await a!.call('GET', `/v1/invites/${ceremony.inviteId}`);
    expect(Object.keys(view.body).sort()).toEqual(
      ['commit', 'confirmed', 'creatorReveal', 'expiresAt', 'id', 'joinerReveal', 'role', 'state', 'version'].sort(),
    );
    // "role" is the caller's part in the ceremony, not guardian or protected.
    expect(view.body.role).toBe('creator');
  });

  it('accepts a code typed in lowercase, without the hyphen', async () => {
    const [a, b] = await phones(2);
    const { code } = await invite(a!);
    const joined = await b!.call('POST', '/v1/invites/join', { code: code.replace('-', '').toLowerCase(), commit: commitFor(b!).commit });
    expect(joined.status).toBe(200);
  });

  it('answers a wrong, malformed, own or used code with the same 404', async () => {
    const [a, b, c] = await phones(3);
    const { code } = await invite(a!);
    expect((await b!.call('POST', '/v1/invites/join', { code: '0000-0000', commit: commitFor(b!).commit })).status).toBe(404);
    expect((await b!.call('POST', '/v1/invites/join', { code: 'not a code', commit: commitFor(b!).commit })).status).toBe(404);
    expect((await a!.call('POST', '/v1/invites/join', { code, commit: commitFor(a!).commit })).status).toBe(404);
    expect((await b!.call('POST', '/v1/invites/join', { code, commit: commitFor(b!).commit })).status).toBe(200);
    expect((await c!.call('POST', '/v1/invites/join', { code, commit: commitFor(c!).commit })).status).toBe(404);
  });

  it('keeps the creator from revealing before the joiner commits', async () => {
    const [a] = await phones(1);
    const { id } = await invite(a!);
    const reveal = encodeReveal(a!.phone.bundle, randomBytes(32));
    const early = await a!.call('POST', `/v1/invites/${id}/reveal`, { reveal: toBase64Url(reveal) });
    expect(early).toMatchObject({ status: 409, body: { error: 'conflict', state: 'open' } });
  });

  it('keeps the joiner from revealing before the creator', async () => {
    const [a, b] = await phones(2);
    const { id, code } = await invite(a!);
    const { reveal, commit } = commitFor(b!);
    await b!.call('POST', '/v1/invites/join', { code, commit });
    const early = await b!.call('POST', `/v1/invites/${id}/reveal`, { reveal: toBase64Url(reveal) });
    expect(early).toMatchObject({ status: 409, body: { state: 'joined' } });
  });

  it('refuses a joiner reveal that does not match its commitment', async () => {
    const [a, b] = await phones(2);
    const { id, code } = await invite(a!);
    await b!.call('POST', '/v1/invites/join', { code, commit: commitFor(b!).commit });
    await a!.call('POST', `/v1/invites/${id}/reveal`, { reveal: toBase64Url(encodeReveal(a!.phone.bundle, randomBytes(32))) });
    const other = encodeReveal(b!.phone.bundle, randomBytes(32));
    expect((await b!.call('POST', `/v1/invites/${id}/reveal`, { reveal: toBase64Url(other) })).status).toBe(400);
  });

  it('refuses a reveal of someone else\'s bundle', async () => {
    const [a, b, c] = await phones(3);
    const { id, code } = await invite(a!);
    await b!.call('POST', '/v1/invites/join', { code, commit: commitFor(b!).commit });
    const foreign = encodeReveal(c!.phone.bundle, randomBytes(32));
    expect((await a!.call('POST', `/v1/invites/${id}/reveal`, { reveal: toBase64Url(foreign) })).status).toBe(400);
  });

  it('hides an invite from phones not taking part', async () => {
    const [a, b] = await phones(2);
    const { id } = await invite(a!);
    expect((await b!.call('GET', `/v1/invites/${id}`)).status).toBe(404);
    expect((await b!.call('DELETE', `/v1/invites/${id}`)).status).toBe(404);
    expect((await b!.call('POST', '/v1/links', { invite: id })).status).toBe(404);
  });

  it('expires an unjoined code after fifteen minutes', async () => {
    const [a, b] = await phones(2);
    const { id, code } = await invite(a!);
    server.clock.advance(15 * 60 * 1000 + 1);
    try {
      expect((await b!.call('POST', '/v1/invites/join', { code, commit: commitFor(b!).commit })).status).toBe(404);
      expect((await a!.call('GET', `/v1/invites/${id}`)).body.state).toBe('expired');
    } finally {
      server.clock.advance(-(15 * 60 * 1000 + 1));
    }
  });

  it('gives a joined ceremony fifteen minutes to finish', async () => {
    const [a, b] = await phones(2);
    const { id, code } = await invite(a!);
    await b!.call('POST', '/v1/invites/join', { code, commit: commitFor(b!).commit });
    server.clock.advance(15 * 60 * 1000 + 1);
    try {
      const late = await a!.call('POST', `/v1/invites/${id}/reveal`, { reveal: toBase64Url(encodeReveal(a!.phone.bundle, randomBytes(32))) });
      expect(late.status).toBe(410);
    } finally {
      server.clock.advance(-(15 * 60 * 1000 + 1));
    }
  });

  it('lets either side cancel ("They don\'t match")', async () => {
    const [a, b] = await phones(2);
    const { id, code } = await invite(a!);
    await b!.call('POST', '/v1/invites/join', { code, commit: commitFor(b!).commit });
    expect((await b!.call('DELETE', `/v1/invites/${id}`)).status).toBe(204);
    expect((await a!.call('GET', `/v1/invites/${id}`)).body.state).toBe('cancelled');
    expect((await a!.call('POST', '/v1/links', { invite: id })).body).toEqual({ error: 'conflict', state: 'cancelled' });
  });

  it('retires a creator\'s unfinished invite when it shows a new code', async () => {
    const [a] = await phones(1);
    const first = await invite(a!);
    await invite(a!);
    expect((await a!.call('GET', `/v1/invites/${first.id}`)).body.state).toBe('cancelled');
  });

  it('wakes a long poll when the invite changes', async () => {
    const [a, b] = await phones(2);
    const { id, code } = await invite(a!);
    const before = await a!.call('GET', `/v1/invites/${id}`);
    const started = Date.now();
    const poll = a!.call('GET', `/v1/invites/${id}?wait=20&known=${before.body.version}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
    await b!.call('POST', '/v1/invites/join', { code, commit: commitFor(b!).commit });
    const after = await poll;
    expect(after.body.state).toBe('joined');
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('answers a long poll at once when the caller is behind', async () => {
    const [a] = await phones(1);
    const { id } = await invite(a!);
    const started = Date.now();
    const response = await a!.call('GET', `/v1/invites/${id}?wait=20&known=stale`);
    expect(response.body.state).toBe('open');
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it('limits join attempts per phone: the code-guessing budget', async () => {
    const limited = await startServer({ RATE_JOINS_PER_HOUR: '3' });
    try {
      const guesser = await registeredPhone(limited);
      const statuses: number[] = [];
      for (let i = 0; i < 4; i++) {
        statuses.push((await guesser.call('POST', '/v1/invites/join', { code: `0000-000${i}`, commit: commitFor(guesser).commit })).status);
      }
      expect(statuses).toEqual([404, 404, 404, 429]);
    } finally {
      await limited.close();
    }
  });
});

describe('links', () => {
  it('are created once both phones confirm, and confirming again changes nothing', async () => {
    const [a, b] = await phones(2);
    const ceremony = await pair(a!, b!);
    expect((await a!.call('POST', '/v1/links', { invite: ceremony.inviteId })).body.state).toBe('linked');
    expect((await b!.call('GET', '/v1/links')).body.links).toHaveLength(1);
  });

  it('serve both directions of a mutual pairing with one link', async () => {
    const [a, b] = await phones(2);
    await pair(a!, b!);
    await pair(b!, a!);
    expect((await a!.call('GET', '/v1/links')).body.links).toHaveLength(1);
  });

  it('report last seen in whole days', async () => {
    const [a, b] = await phones(2);
    await pair(a!, b!);
    await server.db
      .updateTable('devices')
      .set({ last_seen_on: '2026-01-01' })
      .where('fingerprint', '=', Buffer.from(b!.phone.fp))
      .execute();
    const days = (await a!.call('GET', '/v1/links')).body.links[0].lastSeenDaysAgo;
    const expected = Math.floor((Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate()) - Date.UTC(2026, 0, 1)) / 86_400_000);
    expect(days).toBe(expected);
  });

  it('can be removed by either side, idempotently', async () => {
    const [a, b] = await phones(2);
    await pair(a!, b!);
    expect((await b!.call('DELETE', `/v1/links/${a!.deviceId}`)).status).toBe(204);
    expect((await a!.call('GET', '/v1/links')).body.links).toEqual([]);
    expect((await b!.call('DELETE', `/v1/links/${a!.deviceId}`)).status).toBe(204);
    expect((await b!.call('DELETE', `/v1/links/${toBase64Url(new Uint8Array(32))}`)).status).toBe(204);
  });

  it('are capped per phone', async () => {
    const [hub] = await phones(1);
    // Fill the hub's links directly, then try one more through the API.
    const others = await phones(2);
    await pair(hub!, others[0]!);
    const extra = Array.from({ length: 49 }, (_, i) => i);
    const hubRow = await server.db.selectFrom('devices').select('id').where('fingerprint', '=', Buffer.from(hub!.phone.fp)).executeTakeFirstOrThrow();
    for (const _ of extra) {
      const filler = await registeredPhone(server);
      const fillerRow = await server.db.selectFrom('devices').select('id').where('fingerprint', '=', Buffer.from(filler.phone.fp)).executeTakeFirstOrThrow();
      const [lo, hi] = [hubRow.id, fillerRow.id].sort();
      await server.db.insertInto('links').values({ device_lo: lo!, device_hi: hi! }).execute();
    }
    await expect(pair(hub!, others[1]!)).rejects.toThrow();
    expect((await hub!.call('GET', '/v1/links')).body.links).toHaveLength(50);
  });
});
