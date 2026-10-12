/**
 * Registration end to end (SPEC.md §5): challenge, attestation, proof of possession, and the
 * phone's own record.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sql } from 'kysely';
import { toBase64Url } from '@tamodak/protocol/api';
import { randomPhone } from '@tamodak/protocol/e2e';
import { buildChain } from './support/attestation.ts';
import { PhoneClient, registeredPhone } from './support/client.ts';
import { startServer, type TestServer } from './support/server.ts';

let server: TestServer;

beforeAll(async () => {
  server = await startServer();
});

afterAll(async () => {
  await server.close();
});

describe('POST /v1/register/challenge', () => {
  it('issues a fresh 32-byte challenge valid for ten minutes', async () => {
    const client = new PhoneClient(server);
    const first = await client.call('POST', '/v1/register/challenge', undefined, { unsigned: true });
    const second = await client.call('POST', '/v1/register/challenge', undefined, { unsigned: true });
    expect(first.status).toBe(200);
    expect(Buffer.from(first.body.challenge, 'base64url')).toHaveLength(32);
    expect(first.body.challenge).not.toBe(second.body.challenge);
    expect(first.body.expiresAt - server.clock.now()).toBeGreaterThan(9 * 60 * 1000);
  });
});

describe('POST /v1/devices', () => {
  it('registers a phone, and answers a retry with 200', async () => {
    const client = new PhoneClient(server);
    const first = await client.register();
    expect(first.status).toBe(201);
    expect(first.body).toEqual({ device: client.deviceId, securityLevel: 'tee' });
    const retry = await client.register();
    expect(retry.status).toBe(200);
    const me = await client.call('GET', '/v1/devices/me');
    expect(me.body).toEqual({ device: client.deviceId, securityLevel: 'tee' });
  });

  it('stores the attestation summary and nothing else from the chain', async () => {
    const client = await registeredPhone(server);
    const row = await server.db
      .selectFrom('devices')
      .select(['attestation', 'security_level'])
      .where('fingerprint', '=', Buffer.from(client.phone.fp))
      .executeTakeFirstOrThrow();
    expect(row.attestation).toEqual({
      attestationVersion: 200,
      attestationSecurityLevel: 1,
      keyMintSecurityLevel: 1,
      verifiedBootState: 0,
      deviceLocked: true,
      osVersion: 150000,
      osPatchLevel: 202609,
      untrustedRoot: false,
    });
  });

  it('refuses a chain for another challenge', async () => {
    const client = new PhoneClient(server);
    const issued = await client.call('POST', '/v1/register/challenge', undefined, { unsigned: true });
    const chain = await buildChain(server.root, { phone: client.phone, challenge: new Uint8Array(32).fill(5) });
    const response = await client.call('POST', '/v1/devices', { challenge: issued.body.challenge, chain: chain.map((d) => toBase64Url(d)) });
    expect(response.status).toBe(403);
    expect(response.body).toEqual({ error: 'attestation_rejected', reason: 'challenge_mismatch' });
  });

  it('refuses a challenge the server never issued, or one already used', async () => {
    const client = new PhoneClient(server);
    const invented = new Uint8Array(32).fill(9);
    const chain = await buildChain(server.root, { phone: client.phone, challenge: invented });
    const response = await client.call('POST', '/v1/devices', { challenge: toBase64Url(invented), chain: chain.map((d) => toBase64Url(d)) });
    expect(response.body.reason).toBe('challenge_mismatch');

    const issued = await client.call('POST', '/v1/register/challenge', undefined, { unsigned: true });
    const bytes = new Uint8Array(Buffer.from(issued.body.challenge, 'base64url'));
    const good = (await buildChain(server.root, { phone: client.phone, challenge: bytes })).map((d) => toBase64Url(d));
    expect((await client.call('POST', '/v1/devices', { challenge: issued.body.challenge, chain: good })).status).toBe(201);
    const other = new PhoneClient(server);
    const reused = (await buildChain(server.root, { phone: other.phone, challenge: bytes })).map((d) => toBase64Url(d));
    expect((await other.call('POST', '/v1/devices', { challenge: issued.body.challenge, chain: reused })).body.reason).toBe('challenge_mismatch');
  });

  it('refuses an expired challenge', async () => {
    const client = new PhoneClient(server);
    const issued = await client.call('POST', '/v1/register/challenge', undefined, { unsigned: true });
    const chain = await buildChain(server.root, {
      phone: client.phone,
      challenge: new Uint8Array(Buffer.from(issued.body.challenge, 'base64url')),
    });
    await server.db.updateTable('attestation_challenges').set({ expires_at: sql<Date>`now() - interval '1 second'` }).execute();
    const response = await client.call('POST', '/v1/devices', { challenge: issued.body.challenge, chain: chain.map((d) => toBase64Url(d)) });
    expect(response.status).toBe(410);
  });

  it('requires the caller to hold the attested key and to name itself by it', async () => {
    const owner = new PhoneClient(server);
    const thief = new PhoneClient(server);
    const issued = await owner.call('POST', '/v1/register/challenge', undefined, { unsigned: true });
    const chain = await buildChain(server.root, {
      phone: owner.phone,
      challenge: new Uint8Array(Buffer.from(issued.body.challenge, 'base64url')),
    });
    // The thief replays the owner's chain, signing with its own key.
    const response = await thief.call('POST', '/v1/devices', { challenge: issued.body.challenge, chain: chain.map((d) => toBase64Url(d)) });
    expect(response.body).toEqual({ error: 'attestation_rejected', reason: 'key_mismatch' });
    // The challenge survives a refused attempt, so the owner can still use it.
    const own = await owner.call('POST', '/v1/devices', { challenge: issued.body.challenge, chain: chain.map((d) => toBase64Url(d)) });
    expect(own.status).toBe(201);
  });

  it('reports why an attestation was refused', async () => {
    const client = new PhoneClient(server);
    const response = await client.register({ description: (d) => ({ ...d, hardwareEnforced: { ...d.hardwareEnforced, origin: 2 } }) });
    expect(response.body).toEqual({ error: 'attestation_rejected', reason: 'key_properties' });
  });

  it('refuses a revoked chain', async () => {
    server.revocation.revoked.add('77777');
    const response = await new PhoneClient(server).register({ attestationSerial: 0x77777 });
    expect(response.body.reason).toBe('revoked');
  });

  it('fails closed without a recent revocation list', async () => {
    server.revocation.fresh = false;
    try {
      const response = await new PhoneClient(server).register();
      expect(response.status).toBe(503);
      expect(response.headers.get('retry-after')).toBe('300');
    } finally {
      server.revocation.fresh = true;
    }
  });

  it('refuses malformed bodies', async () => {
    const client = new PhoneClient(server);
    for (const body of [
      {},
      { challenge: 'AA', chain: ['AA', 'AA'] },
      { challenge: 'AA', chain: ['AA', 'AA', 'AA'], extra: 1 },
      { challenge: 'A=', chain: ['AA', 'AA', 'AA'] },
    ]) {
      expect((await client.call('POST', '/v1/devices', body)).status).toBe(400);
    }
  });
});

describe('the phone\'s own record', () => {
  it('stores, replaces and clears the push FID', async () => {
    const client = await registeredPhone(server);
    const fid = async () =>
      (await server.db.selectFrom('devices').select('fcm_fid').where('fingerprint', '=', Buffer.from(client.phone.fp)).executeTakeFirstOrThrow())
        .fcm_fid;
    expect((await client.call('PUT', '/v1/devices/me/push', { fid: 'fid-1' })).status).toBe(204);
    expect(await fid()).toBe('fid-1');
    await client.call('PUT', '/v1/devices/me/push', { fid: 'fid-2' });
    expect(await fid()).toBe('fid-2');
    expect((await client.call('DELETE', '/v1/devices/me/push')).status).toBe(204);
    expect(await fid()).toBeNull();
    expect((await client.call('PUT', '/v1/devices/me/push', { fid: '' })).status).toBe(400);
  });

  it('deletes the phone, after which its key no longer authenticates', async () => {
    const client = await registeredPhone(server);
    expect((await client.call('DELETE', '/v1/devices/me')).status).toBe(204);
    const after = await client.call('GET', '/v1/devices/me');
    expect(after.status).toBe(401);
  });

  it('lets a deleted phone register again', async () => {
    const phone = randomPhone();
    const client = await registeredPhone(server, phone);
    await client.call('DELETE', '/v1/devices/me');
    expect((await client.register()).status).toBe(201);
  });
});
