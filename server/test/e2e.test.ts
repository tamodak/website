/**
 * The protocol end to end through the real server: two phones pair, exchange PAIR_OFFER and
 * PAIR_ANSWER, then an UNBLOCK_APP request and its DECISION, as real HPKE envelopes. And what the
 * server keeps of it all: ciphertext, and nothing it could read.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  Answer,
  DeclineReason,
  Kind,
  MESSAGE_VERSION,
  Role,
  Verdict,
  decodeBody,
  encodeBody,
  fromBase64Url,
  openEnvelope,
  randomBytes,
  sealMessage,
  seeded,
  toBase64Url,
  verifyDecision,
  verifyInner,
  type AppRef,
  type MessageBody,
  type TestPhone,
} from '@tamodak/protocol/e2e';
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

/** Seals a message and posts it, as Killit's sender will. */
async function send(from: PhoneClient, to: TestPhone, pairId: Uint8Array, body: MessageBody): Promise<Uint8Array> {
  const messageId = randomBytes(16);
  const envelope = sealMessage({
    header: {
      version: MESSAGE_VERSION,
      kind: body.kind,
      messageId,
      pairId,
      senderFp: from.phone.fp,
      recipientFp: to.fp,
      createdAt: Date.now(),
    },
    body: encodeBody(body),
    senderSignKey: from.phone.signKey,
    recipientEncPk: to.encPk,
  });
  const response = await from.call('POST', '/v1/messages', { messages: [{ to: toBase64Url(to.fp), envelope: toBase64Url(envelope) }] });
  expect(response.status).toBe(202);
  return messageId;
}

/** Fetches, opens and verifies the one waiting message, then acknowledges it. */
async function receive(client: PhoneClient, sender: TestPhone) {
  const inbox = await client.call('GET', '/v1/messages?wait=5');
  expect(inbox.body.messages).toHaveLength(1);
  const message = inbox.body.messages[0];
  const from = fromBase64Url(message.from);
  const opened = openEnvelope(fromBase64Url(message.envelope), client.phone.encKey, client.phone.fp, from);
  if (!opened.ok) throw new Error(opened.error);
  expect(verifyInner(sender.signPk, opened.value.inner, opened.value.signature)).toBe(true);
  await client.call('POST', '/v1/messages/ack', { ids: [message.id] });
  return opened.value;
}

describe('a guardian and a protected phone', () => {
  let guardian: PhoneClient;
  let protectedPhone: PhoneClient;
  let pairId: Uint8Array;
  const tiktok: AppRef = { packageName: 'com.zhiliaoapp.musically', certDigest: seeded('TikTok signing certificate') };
  const requestId = randomBytes(16);

  beforeAll(async () => {
    guardian = await registeredPhone(server);
    protectedPhone = await registeredPhone(server);
    const ceremony = await pair(guardian, protectedPhone);
    expect(ceremony.creatorCode).toBe(ceremony.joinerCode);
    pairId = ceremony.pairId;
  });

  it('agree on the pairing end to end', async () => {
    await send(guardian, protectedPhone.phone, pairId, {
      kind: Kind.PAIR_OFFER,
      senderRole: Role.GUARDIAN,
      selfName: 'Mom',
      deviceModel: 'Google Pixel 9',
      appManagement: false,
    });
    const offer = await receive(protectedPhone, guardian.phone);
    expect(offer.header.pairId).toEqual(pairId);
    expect(decodeBody(offer.header.kind, offer.body)).toMatchObject({ ok: true, value: { selfName: 'Mom', senderRole: Role.GUARDIAN } });

    await send(protectedPhone, guardian.phone, pairId, {
      kind: Kind.PAIR_ANSWER,
      answer: Answer.ACCEPT,
      reason: DeclineReason.NONE,
      selfName: 'Ali',
      deviceModel: 'samsung SM-S911B',
      appManagement: false,
    });
    const answer = await receive(guardian, protectedPhone.phone);
    expect(decodeBody(answer.header.kind, answer.body)).toMatchObject({ ok: true, value: { answer: Answer.ACCEPT, selfName: 'Ali' } });
  });

  it('carry an unblock request and the guardian\'s decision', async () => {
    await send(protectedPhone, guardian.phone, pairId, {
      kind: Kind.UNBLOCK_APP,
      requestId,
      app: { ...tiktok, label: 'TikTok', installer: 'com.android.vending', firstInstalled: Date.now(), icon: null },
      explanation: 'My school club posts announcements only on TikTok.',
      chancesLeft: 3,
      guardianCount: 1,
    });
    const request = await receive(guardian, protectedPhone.phone);
    expect(request.header.kind).toBe(Kind.UNBLOCK_APP);

    await send(guardian, protectedPhone.phone, pairId, {
      kind: Kind.DECISION,
      requestId,
      target: { requestKind: Kind.UNBLOCK_APP, app: tiktok },
      decision: Verdict.APPROVE,
      note: '',
    });
    const decision = await receive(protectedPhone, guardian.phone);
    const stored = {
      requestId,
      target: { requestKind: Kind.UNBLOCK_APP, app: tiktok },
      pairId,
      guardianFp: guardian.phone.fp,
      guardianSignPk: guardian.phone.signPk,
      ownFp: protectedPhone.phone.fp,
    } as const;
    expect(verifyDecision(stored, decision)).toEqual({ ok: true, value: { decision: Verdict.APPROVE, note: '' } });
    // The same decision can't be passed off as approving another app.
    const other = { ...stored, target: { requestKind: Kind.UNBLOCK_APP, app: { ...tiktok, packageName: 'com.instagram.android' } } } as const;
    expect(verifyDecision(other, decision).ok).toBe(false);
  });

  it('leave the server nothing it can read', async () => {
    await send(protectedPhone, guardian.phone, pairId, {
      kind: Kind.UNBLOCK_APP,
      requestId: randomBytes(16),
      app: { ...tiktok, label: 'TikTok', installer: 'com.android.vending', firstInstalled: Date.now(), icon: null },
      explanation: 'A very recognisable explanation, findable if it leaked.',
      chancesLeft: 2,
      guardianCount: 1,
    });
    const rows = await server.db.selectFrom('messages').select(['envelope', 'sender_fp']).execute();
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const bytes = Buffer.from(row.envelope);
      for (const secret of ['TikTok', 'musically', 'recognisable', 'Mom', 'Ali']) expect(bytes.includes(secret)).toBe(false);
      expect(bytes).toHaveLength(8240);
    }
    const invites = await server.db.selectFrom('invites').selectAll().execute();
    for (const invite of invites) {
      expect(Object.keys(invite)).not.toContain('role');
    }
  });

  it('can\'t be read by a third phone, even one the server routes to', async () => {
    const eavesdropper = await registeredPhone(server);
    const envelopeBytes = sealMessage({
      header: {
        version: MESSAGE_VERSION,
        kind: Kind.LEAVE,
        messageId: randomBytes(16),
        pairId,
        senderFp: guardian.phone.fp,
        recipientFp: protectedPhone.phone.fp,
        createdAt: Date.now(),
      },
      body: encodeBody({ kind: Kind.LEAVE }),
      senderSignKey: guardian.phone.signKey,
      recipientEncPk: protectedPhone.phone.encPk,
    });
    expect(openEnvelope(envelopeBytes, eavesdropper.phone.encKey, eavesdropper.phone.fp, guardian.phone.fp).ok).toBe(false);
    expect(openEnvelope(envelopeBytes, eavesdropper.phone.encKey, protectedPhone.phone.fp, guardian.phone.fp).ok).toBe(false);
  });
});
