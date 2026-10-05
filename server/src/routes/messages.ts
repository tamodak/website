/**
 * The mailbox (SPEC.md §8): opaque, fixed-size envelopes between linked phones, kept until the
 * recipient acknowledges them.
 *
 * The server can't open an envelope and doesn't try: it checks the size, the link and the caps,
 * stores the bytes, and wakes the recipient. Every envelope is the same size, so even the size
 * tells it nothing about what was sent.
 */
import { Type } from 'typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import {
  ENVELOPE_BYTES,
  FINGERPRINT_BYTES,
  MAX_ACK_IDS,
  MAX_ENVELOPES_PER_POST,
  MAX_MESSAGES_PER_FETCH,
  toBase64Url,
} from '@tamodak/protocol/api';
import { deviceOf } from '../auth.ts';
import { deviceChannel } from '../bus.ts';
import { mailboxFull, notLinked, rateLimited } from '../errors.ts';
import { Base64Url, StrictObject, Uuid, WaitSeconds, bytesOf, disconnectSignal } from './common.ts';
import { HOUR_MILLIS, longPoll, type RouteDeps } from './deps.ts';

/** 50 envelopes of 8240 bytes in base64url, plus JSON framing. */
const SEND_BODY_LIMIT = 640 * 1024;

export const messageRoutes: FastifyPluginAsyncTypebox<RouteDeps> = async (app, deps) => {
  const { db, config, bus, limiter, push } = deps;

  app.post(
    '/messages',
    {
      bodyLimit: SEND_BODY_LIMIT,
      schema: {
        body: StrictObject({
          messages: Type.Array(StrictObject({ to: Base64Url(FINGERPRINT_BYTES), envelope: Base64Url(ENVELOPE_BYTES) }), {
            minItems: 1,
            maxItems: MAX_ENVELOPES_PER_POST,
          }),
        }),
      },
    },
    async (request, reply) => {
      const device = deviceOf(request);
      const outgoing = request.body.messages.map((message) => ({
        to: bytesOf(message.to, FINGERPRINT_BYTES),
        envelope: bytesOf(message.envelope, ENVELOPE_BYTES),
      }));
      const wait = limiter.take(`envelopes:${device.id}`, outgoing.length, config.rateLimits.envelopesPerDevicePerHour, HOUR_MILLIS);
      if (wait > 0) throw rateLimited(wait);

      const recipientFps = [...new Map(outgoing.map((message) => [toBase64Url(message.to), message.to])).values()];
      const recipients = await db
        .selectFrom('devices')
        .select(['id', 'fingerprint'])
        .where('fingerprint', 'in', recipientFps.map((fp) => Buffer.from(fp)))
        .execute();
      const idOf = new Map(recipients.map((row) => [toBase64Url(row.fingerprint), row.id]));

      // Every recipient must be a registered phone linked to the sender; otherwise nothing is sent.
      const ids = [...idOf.values()];
      const links =
        ids.length === 0
          ? []
          : await db
              .selectFrom('links')
              .select(['device_lo', 'device_hi'])
              .where((eb) =>
                eb.or([
                  eb.and([eb('device_lo', '=', device.id), eb('device_hi', 'in', ids)]),
                  eb.and([eb('device_hi', '=', device.id), eb('device_lo', 'in', ids)]),
                ]),
              )
              .execute();
      const linkedIds = new Set(links.map((link) => (link.device_lo === device.id ? link.device_hi : link.device_lo)));
      const unlinked = recipientFps.map(toBase64Url).filter((fp) => !linkedIds.has(idOf.get(fp) ?? ''));
      if (unlinked.length > 0) throw notLinked(unlinked);

      const adding = new Map<string, number>();
      for (const message of outgoing) {
        const id = idOf.get(toBase64Url(message.to))!;
        adding.set(id, (adding.get(id) ?? 0) + 1);
      }
      const counts = await db
        .selectFrom('messages')
        .select((eb) => [
          'recipient',
          eb.fn.countAll<string>().as('total'),
          eb.fn.count<string>('id').filterWhere('sender_fp', '=', Buffer.from(device.fp)).as('mine'),
        ])
        .where('recipient', 'in', [...adding.keys()])
        .groupBy('recipient')
        .execute();
      const held = new Map(counts.map((row) => [row.recipient, row]));
      for (const [id, count] of adding) {
        const total = Number(held.get(id)?.total ?? 0);
        const mine = Number(held.get(id)?.mine ?? 0);
        if (total + count > config.mailbox.perRecipient || mine + count > config.mailbox.perSender) throw mailboxFull();
      }

      await db
        .insertInto('messages')
        .values(
          outgoing.map((message) => ({
            recipient: idOf.get(toBase64Url(message.to))!,
            sender_fp: device.fp,
            envelope: message.envelope,
          })),
        )
        .execute();
      for (const id of adding.keys()) {
        bus.notify(deviceChannel(id));
        push.schedule(id);
      }
      reply.status(202);
      return { accepted: outgoing.length };
    },
  );

  app.get(
    '/messages',
    { schema: { querystring: StrictObject({ wait: Type.Optional(WaitSeconds) }) } },
    async (request, reply) => {
      const device = deviceOf(request);
      const read = () =>
        db
          .selectFrom('messages')
          .select(['id', 'sender_fp', 'envelope', 'received_at'])
          .where('recipient', '=', device.id)
          .orderBy('seq')
          .limit(MAX_MESSAGES_PER_FETCH)
          .execute();
      const rows = await longPoll({
        bus,
        channel: deviceChannel(device.id),
        waitMillis: (request.query.wait ?? 0) * 1000,
        clientGone: disconnectSignal(reply.raw),
        read,
        ready: (found) => found.length > 0,
      });
      return {
        messages: rows.map((row) => ({
          id: row.id,
          from: toBase64Url(row.sender_fp),
          envelope: toBase64Url(row.envelope),
          receivedAt: row.received_at.getTime(),
        })),
      };
    },
  );

  app.post(
    '/messages/ack',
    { schema: { body: StrictObject({ ids: Type.Array(Uuid, { minItems: 1, maxItems: MAX_ACK_IDS }) }) } },
    async (request, reply) => {
      const device = deviceOf(request);
      // Only the caller's own messages; anyone else's ids simply match nothing.
      await db.deleteFrom('messages').where('recipient', '=', device.id).where('id', 'in', request.body.ids).execute();
      return reply.status(204).send();
    },
  );
};
