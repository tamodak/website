/**
 * Links (SPEC.md §7): permission for two phones to send each other envelopes.
 *
 * A link is created only when both participants of a revealed invite have confirmed the safety
 * code, and it says nothing about who guards whom. The phones decide pairing state themselves;
 * deleting a link only stops routing (PLAN.md §8.1, "routing only").
 */
import { sql } from 'kysely';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { FINGERPRINT_BYTES, MAX_LINKS, toBase64Url } from '@tamodak/protocol/api';
import { deviceOf } from '../auth.ts';
import { inviteChannel } from '../bus.ts';
import { conflict, expired, notFound } from '../errors.ts';
import { Base64Url, StrictObject, Uuid, bytesOf } from './common.ts';
import type { RouteDeps } from './deps.ts';
import { UNFINISHED } from './invites.ts';

/** The two ends of a link in their stored order, so a pair always maps to one row. */
export function linkKey(a: string, b: string): { device_lo: string; device_hi: string } {
  return a < b ? { device_lo: a, device_hi: b } : { device_lo: b, device_hi: a };
}

export const linkRoutes: FastifyPluginAsyncTypebox<RouteDeps> = async (app, deps) => {
  const { db, bus, now } = deps;

  app.post('/links', { schema: { body: StrictObject({ invite: Uuid }) } }, async (request) => {
    const device = deviceOf(request);
    const result = await db.transaction().execute(async (tx) => {
      const row = await tx
        .selectFrom('invites')
        .selectAll()
        .where('id', '=', request.body.invite)
        .where((eb) => eb.or([eb('creator', '=', device.id), eb('joiner', '=', device.id)]))
        .forUpdate()
        .executeTakeFirst();
      if (row === undefined || row.joiner === null) throw notFound();
      const isCreator = row.creator === device.id;
      const peerId = isCreator ? row.joiner : row.creator;
      if (row.state === 'linked') return { state: 'linked' as const, peerId, changed: false };
      if (UNFINISHED.includes(row.state) && row.expires_at.getTime() <= now()) throw expired();
      if (row.state !== 'revealed') throw conflict(row.state);

      const creatorConfirmed = row.creator_confirmed || isCreator;
      const joinerConfirmed = row.joiner_confirmed || !isCreator;
      if (!(creatorConfirmed && joinerConfirmed)) {
        await tx
          .updateTable('invites')
          .set(isCreator ? { creator_confirmed: true } : { joiner_confirmed: true })
          .where('id', '=', row.id)
          .execute();
        return { state: 'waiting' as const, peerId, changed: true };
      }

      const key = linkKey(row.creator, row.joiner);
      const existing = await tx.selectFrom('links').select('created_at').where('device_lo', '=', key.device_lo).where('device_hi', '=', key.device_hi).executeTakeFirst();
      if (existing === undefined) {
        // The cap is per phone, counted on both ends (PLAN.md §3.1: a technical cap against abuse).
        for (const id of [row.creator, row.joiner]) {
          const { count } = await tx
            .selectFrom('links')
            .select((eb) => eb.fn.countAll<string>().as('count'))
            .where((eb) => eb.or([eb('device_lo', '=', id), eb('device_hi', '=', id)]))
            .executeTakeFirstOrThrow();
          if (Number(count) >= MAX_LINKS) throw conflict('link_limit');
        }
        await tx.insertInto('links').values(key).execute();
      }
      await tx
        .updateTable('invites')
        .set({ creator_confirmed: true, joiner_confirmed: true, state: 'linked', finished_at: sql<Date>`now()` })
        .where('id', '=', row.id)
        .execute();
      return { state: 'linked' as const, peerId, changed: true };
    });
    if (result.changed) bus.notify(inviteChannel(request.body.invite));
    const peer = await db.selectFrom('devices').select('fingerprint').where('id', '=', result.peerId).executeTakeFirstOrThrow();
    return { state: result.state, peer: toBase64Url(peer.fingerprint) };
  });

  app.get('/links', async (request) => {
    const device = deviceOf(request);
    const rows = await db
      .selectFrom('links')
      .innerJoin('devices', (join) =>
        join.on((eb) =>
          eb.or([
            eb.and([eb('links.device_lo', '=', device.id), eb('devices.id', '=', eb.ref('links.device_hi'))]),
            eb.and([eb('links.device_hi', '=', device.id), eb('devices.id', '=', eb.ref('links.device_lo'))]),
          ]),
        ),
      )
      .select(['devices.fingerprint as fingerprint', sql<number>`current_date - devices.last_seen_on`.as('days')])
      .orderBy('links.created_at')
      .execute();
    return { links: rows.map((row) => ({ peer: toBase64Url(row.fingerprint), lastSeenDaysAgo: Number(row.days) })) };
  });

  app.delete(
    '/links/:peer',
    { schema: { params: StrictObject({ peer: Base64Url(FINGERPRINT_BYTES) }) } },
    async (request, reply) => {
      const device = deviceOf(request);
      const peerFp = bytesOf(request.params.peer, FINGERPRINT_BYTES);
      const peer = await db.selectFrom('devices').select('id').where('fingerprint', '=', Buffer.from(peerFp)).executeTakeFirst();
      if (peer !== undefined) {
        const key = linkKey(device.id, peer.id);
        await db.deleteFrom('links').where('device_lo', '=', key.device_lo).where('device_hi', '=', key.device_hi).execute();
      }
      // The same answer whether or not there was a link, or such a phone.
      return reply.status(204).send();
    },
  );
};
