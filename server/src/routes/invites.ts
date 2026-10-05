/**
 * Pairing invites (SPEC.md §6): the code, the commitment and the two reveals, in the one order
 * that keeps the safety code honest.
 *
 * The server enforces that order and checks the joiner's reveal against its commitment, but it is
 * not trusted for either: each phone repeats the checks itself (SPEC.md §6.4). What the server must
 * never learn is which phone will be the guardian, and it doesn't: roles travel end to end.
 */
import { Type } from 'typebox';
import { sql, type Transaction } from 'kysely';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import {
  COMMIT_BYTES,
  REVEAL_BYTES,
  constantTimeEqual,
  decodeReveal,
  fingerprint,
  formatInviteCode,
  hmacSha256,
  matchesCommitment,
  parseInviteCode,
  randomBytes,
  sha256,
  toBase64Url,
  INVITE_CODE_BYTES,
} from '@tamodak/protocol/api';
import { deviceOf } from '../auth.ts';
import { inviteChannel } from '../bus.ts';
import type { Database, InviteRow, InviteState } from '../db/schema.ts';
import { badRequest, conflict, expired, notFound, rateLimited } from '../errors.ts';
import { Base64Url, StrictObject, Uuid, WaitSeconds, bytesOf, disconnectSignal } from './common.ts';
import { HOUR_MILLIS, longPoll, type RouteDeps } from './deps.ts';

/** 15 minutes to join, then 15 to finish (SPEC.md §6.2); not shortened in debug builds. */
export const INVITE_LIFETIME_MILLIS = 15 * 60 * 1000;
/** States in which an invite is still going somewhere. */
export const UNFINISHED: readonly InviteState[] = ['open', 'joined', 'creator_revealed', 'revealed'];
/** Postgres' unique-violation code: a new code collided with a live one. */
const UNIQUE_VIOLATION = '23505';

/** What a participant sees of an invite (SPEC.md §6.2). */
export interface InviteView {
  readonly id: string;
  readonly state: InviteState | 'expired';
  readonly role: 'creator' | 'joiner';
  readonly expiresAt: number;
  readonly commit?: string;
  readonly creatorReveal?: string;
  readonly joinerReveal?: string;
  readonly confirmed: { readonly self: boolean; readonly peer: boolean };
  /** Changes whenever anything above does; a long poll waits while it equals `known`. */
  readonly version: string;
}

export function inviteView(row: InviteRow, deviceId: string, now: number): InviteView {
  const role = row.creator === deviceId ? 'creator' : 'joiner';
  const live = UNFINISHED.includes(row.state);
  const fields = {
    id: row.id,
    state: live && row.expires_at.getTime() <= now ? ('expired' as const) : row.state,
    role,
    expiresAt: row.expires_at.getTime(),
    ...(row.joiner_commit === null ? {} : { commit: toBase64Url(row.joiner_commit) }),
    ...(row.creator_reveal === null ? {} : { creatorReveal: toBase64Url(row.creator_reveal) }),
    ...(row.joiner_reveal === null ? {} : { joinerReveal: toBase64Url(row.joiner_reveal) }),
    confirmed: {
      self: role === 'creator' ? row.creator_confirmed : row.joiner_confirmed,
      peer: role === 'creator' ? row.joiner_confirmed : row.creator_confirmed,
    },
  } as const;
  const version = toBase64Url(sha256(new TextEncoder().encode(JSON.stringify(fields)))).slice(0, 16);
  return { ...fields, version };
}

export const inviteRoutes: FastifyPluginAsyncTypebox<RouteDeps> = async (app, deps) => {
  const { db, config, bus, limiter, now } = deps;

  const codeHash = (code: Uint8Array): Buffer => Buffer.from(hmacSha256(config.inviteCodeKey, code));

  /** Loads an invite the caller takes part in, or answers 404 as if it didn't exist. */
  const loadForParticipant = async (id: string, deviceId: string): Promise<InviteRow> => {
    const row = await db
      .selectFrom('invites')
      .selectAll()
      .where('id', '=', id)
      .where((eb) => eb.or([eb('creator', '=', deviceId), eb('joiner', '=', deviceId)]))
      .executeTakeFirst();
    if (row === undefined) throw notFound();
    return row;
  };

  app.post('/invites', async (request, reply) => {
    const device = deviceOf(request);
    const wait = limiter.take(`invites:${device.id}`, 1, config.rateLimits.invitesPerDevicePerHour, HOUR_MILLIS);
    if (wait > 0) throw rateLimited(wait);

    // One unfinished invite per creator: showing a new code retires the old one.
    const retired = await db
      .updateTable('invites')
      .set({ state: 'cancelled', finished_at: sql<Date>`now()` })
      .where('creator', '=', device.id)
      .where('state', 'in', UNFINISHED)
      .returning('id')
      .execute();
    for (const { id } of retired) bus.notify(inviteChannel(id));

    const expiresAt = now() + INVITE_LIFETIME_MILLIS;
    for (let attempt = 0; ; attempt++) {
      const code = randomBytes(INVITE_CODE_BYTES);
      try {
        const row = await db
          .insertInto('invites')
          .values({ code_hash: codeHash(code), creator: device.id, state: 'open', expires_at: new Date(expiresAt) })
          .returning('id')
          .executeTakeFirstOrThrow();
        reply.status(201);
        return { id: row.id, code: formatInviteCode(code), expiresAt };
      } catch (error) {
        // 40-bit codes collide only once in a very long while; try a fresh one.
        if ((error as { code?: string }).code !== UNIQUE_VIOLATION || attempt >= 3) throw error;
      }
    }
  });

  app.post(
    '/invites/join',
    { schema: { body: StrictObject({ code: Type.String({ maxLength: 32 }), commit: Base64Url(COMMIT_BYTES) }) } },
    async (request) => {
      const device = deviceOf(request);
      // Joining is where codes get guessed, so it is limited per phone and per address.
      for (const key of [`joins:${device.id}`, `joins-ip:${request.ip}`]) {
        const wait = limiter.take(key, 1, config.rateLimits.joinsPerHour, HOUR_MILLIS);
        if (wait > 0) throw rateLimited(wait);
      }
      const code = parseInviteCode(request.body.code);
      const commit = bytesOf(request.body.commit, COMMIT_BYTES);
      // A malformed, wrong, used or expired code all look the same from outside.
      if (!code.ok) throw notFound();

      const expiresAt = now() + INVITE_LIFETIME_MILLIS;
      const row = await db
        .updateTable('invites')
        .set({ joiner: device.id, joiner_commit: commit, state: 'joined', expires_at: new Date(expiresAt) })
        .where('code_hash', '=', codeHash(code.value))
        .where('state', '=', 'open')
        .where('expires_at', '>', new Date(now()))
        .where('creator', '<>', device.id)
        .returning('id')
        .executeTakeFirst();
      if (row === undefined) throw notFound();
      bus.notify(inviteChannel(row.id));
      return { id: row.id, expiresAt };
    },
  );

  app.get(
    '/invites/:id',
    {
      schema: {
        params: StrictObject({ id: Uuid }),
        querystring: StrictObject({ wait: Type.Optional(WaitSeconds), known: Type.Optional(Type.String({ maxLength: 32 })) }),
      },
    },
    async (request, reply) => {
      const device = deviceOf(request);
      const { id } = request.params;
      const known = request.query.known;
      return longPoll({
        bus,
        channel: inviteChannel(id),
        waitMillis: known === undefined ? 0 : (request.query.wait ?? 0) * 1000,
        clientGone: disconnectSignal(reply.raw),
        read: async () => inviteView(await loadForParticipant(id, device.id), device.id, now()),
        ready: (view) => view.version !== known,
      });
    },
  );

  app.post(
    '/invites/:id/reveal',
    { schema: { params: StrictObject({ id: Uuid }), body: StrictObject({ reveal: Base64Url(REVEAL_BYTES) }) } },
    async (request) => {
      const device = deviceOf(request);
      const revealBytes = bytesOf(request.body.reveal, REVEAL_BYTES);
      const reveal = decodeReveal(revealBytes);
      // A phone reveals its own bundle, so the transcript and the link name the same phones.
      if (!reveal.ok || !constantTimeEqual(fingerprint(reveal.value.bundle.signPk), device.fp)) throw badRequest();

      const view = await db.transaction().execute(async (tx) => {
        const row = await tx
          .selectFrom('invites')
          .selectAll()
          .where('id', '=', request.params.id)
          .where((eb) => eb.or([eb('creator', '=', device.id), eb('joiner', '=', device.id)]))
          .forUpdate()
          .executeTakeFirst();
        if (row === undefined) throw notFound();
        if (UNFINISHED.includes(row.state) && row.expires_at.getTime() <= now()) throw expired();
        if (row.creator === device.id) {
          // The creator reveals only once the joiner is committed (SPEC.md §6.3).
          if (row.state !== 'joined') throw conflict(row.state);
          await tx.updateTable('invites').set({ creator_reveal: revealBytes, state: 'creator_revealed' }).where('id', '=', row.id).execute();
        } else {
          if (row.state !== 'creator_revealed') throw conflict(row.state);
          if (row.joiner_commit === null || !matchesCommitment(revealBytes, row.joiner_commit)) throw badRequest();
          await tx.updateTable('invites').set({ joiner_reveal: revealBytes, state: 'revealed' }).where('id', '=', row.id).execute();
        }
        return inviteView(await reread(tx, row.id), device.id, now());
      });
      bus.notify(inviteChannel(view.id));
      return view;
    },
  );

  app.delete('/invites/:id', { schema: { params: StrictObject({ id: Uuid }) } }, async (request, reply) => {
    const device = deviceOf(request);
    const row = await loadForParticipant(request.params.id, device.id);
    if (UNFINISHED.includes(row.state)) {
      await db
        .updateTable('invites')
        .set({ state: 'cancelled', finished_at: sql<Date>`now()` })
        .where('id', '=', row.id)
        .where('state', 'in', UNFINISHED)
        .execute();
      bus.notify(inviteChannel(row.id));
    }
    return reply.status(204).send();
  });
};

/** Re-reads an invite inside a transaction, after updating it. */
function reread(tx: Transaction<Database>, id: string): Promise<InviteRow> {
  return tx.selectFrom('invites').selectAll().where('id', '=', id).executeTakeFirstOrThrow();
}
