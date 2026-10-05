/**
 * Registration and the phone's own record (SPEC.md §5).
 */
import { Type } from 'typebox';
import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { constantTimeEqual, fingerprint, randomBytes, toBase64Url, verifyRequest } from '@tamodak/protocol/api';
import { deviceOf, signedRequest } from '../auth.ts';
import { AttestationError, verifyAttestationChain } from '../attestation/verify.ts';
import type { TrustAnchor } from '../attestation/roots.ts';
import type { Config } from '../config.ts';
import type { RouteDeps } from './deps.ts';
import { attestationRejected, badRequest, expired, unauthorized, unavailable } from '../errors.ts';
import { Base64Url, StrictObject, bytesOf } from './common.ts';

/** A challenge is valid for 10 minutes (SPEC.md §5.1); not shortened in debug builds (PLAN.md §11). */
const CHALLENGE_LIFETIME_MILLIS = 10 * 60 * 1000;
const CHALLENGE_BYTES = 32;
/** A DER certificate in an attestation chain is a few hundred bytes to ~1.5 KB. */
const MAX_CERTIFICATE_BYTES = 8192;

const SECURITY_LEVEL_NAMES = ['software', 'tee', 'strongbox'] as const;

export interface DeviceRouteDeps extends RouteDeps {
  readonly trustAnchors: readonly TrustAnchor[];
  readonly revocation: { isFresh(): boolean; isRevoked(serialHex: string): boolean };
}

/** The per-IP limit for the two unauthenticated-key routes. */
function registrationLimit(config: Config) {
  return { max: config.rateLimits.registrationsPerIpPerHour, timeWindow: 60 * 60 * 1000 };
}

export const deviceRoutes: FastifyPluginAsyncTypebox<DeviceRouteDeps> = async (app, deps) => {
  const { db, config, now } = deps;

  app.post(
    '/register/challenge',
    { config: { auth: 'none', rateLimit: registrationLimit(config) } },
    async () => {
      const challenge = randomBytes(CHALLENGE_BYTES);
      const expiresAt = now() + CHALLENGE_LIFETIME_MILLIS;
      await db.insertInto('attestation_challenges').values({ challenge, expires_at: new Date(expiresAt) }).execute();
      return { challenge: toBase64Url(challenge), expiresAt };
    },
  );

  app.post(
    '/devices',
    {
      config: { auth: 'registration', rateLimit: registrationLimit(config) },
      bodyLimit: 64 * 1024,
      schema: {
        body: StrictObject({
          challenge: Base64Url(CHALLENGE_BYTES),
          chain: Type.Array(Base64Url(MAX_CERTIFICATE_BYTES), { minItems: 3, maxItems: 6 }),
        }),
      },
    },
    async (request, reply) => {
      const auth = request.auth;
      if (auth === null) throw unauthorized('invalid');
      const challenge = bytesOf(request.body.challenge, CHALLENGE_BYTES);
      const chain = request.body.chain.map((certificate) => {
        const der = Buffer.from(certificate, 'base64url');
        if (der.length === 0 || der.toString('base64url') !== certificate) throw badRequest();
        return new Uint8Array(der);
      });

      // Without a recent revocation list there is no registering at all (SPEC.md §5.2 step 5).
      if (!config.attestation.devAcceptAnyRoot && !deps.revocation.isFresh()) throw unavailable(300);

      let verified;
      try {
        verified = verifyAttestationChain(chain, {
          trustAnchors: deps.trustAnchors,
          acceptAnyRoot: config.attestation.devAcceptAnyRoot,
          packageName: config.attestation.packageName,
          certDigests: config.attestation.certDigests,
          isRevoked: (serial) => deps.revocation.isRevoked(serial),
          now: new Date(now()),
        });
      } catch (error) {
        if (error instanceof AttestationError) {
          request.log.info({ reason: error.reason }, 'attestation rejected');
          throw attestationRejected(error.reason);
        }
        throw error;
      }

      // Proof of possession: the caller holds the attested key, and names itself by it.
      const fp = fingerprint(verified.signPk);
      if (!constantTimeEqual(fp, auth.fp) || !verifyRequest(verified.signPk, signedRequest(request, auth, config.audience), auth.signature)) {
        throw attestationRejected('key_mismatch');
      }
      if (!constantTimeEqual(verified.challenge, challenge)) throw attestationRejected('challenge_mismatch');

      // Consume the challenge only now, so a request refused above can't waste a good one.
      const consumed = await db
        .deleteFrom('attestation_challenges')
        .where('challenge', '=', Buffer.from(challenge))
        .returning('expires_at')
        .executeTakeFirst();
      if (consumed === undefined) throw attestationRejected('challenge_mismatch');
      if (consumed.expires_at.getTime() < now()) throw expired();

      // A retry after a lost response finds its own row: refresh the summary and answer 200.
      const summary = JSON.stringify(verified.summary);
      const inserted = await db
        .insertInto('devices')
        .values({ fingerprint: fp, sign_pk: verified.signPk, security_level: verified.securityLevel, attestation: summary })
        .onConflict((conflict) => conflict.column('fingerprint').doNothing())
        .returning('id')
        .executeTakeFirst();
      if (inserted === undefined) {
        await db
          .updateTable('devices')
          .set({ security_level: verified.securityLevel, attestation: summary })
          .where('fingerprint', '=', Buffer.from(fp))
          .execute();
      }
      reply.status(inserted === undefined ? 200 : 201);
      return { device: toBase64Url(fp), securityLevel: SECURITY_LEVEL_NAMES[verified.securityLevel] };
    },
  );

  app.get('/devices/me', async (request) => {
    const device = deviceOf(request);
    const row = await db.selectFrom('devices').select('security_level').where('id', '=', device.id).executeTakeFirstOrThrow();
    return { device: device.deviceId, securityLevel: SECURITY_LEVEL_NAMES[row.security_level] };
  });

  app.put(
    '/devices/me/push',
    { schema: { body: StrictObject({ fcmToken: Type.String({ minLength: 1, maxLength: 4096, pattern: '^[\\x21-\\x7e]+$' }) }) } },
    async (request, reply) => {
      const device = deviceOf(request);
      await db.updateTable('devices').set({ fcm_token: request.body.fcmToken }).where('id', '=', device.id).execute();
      return reply.status(204).send();
    },
  );

  app.delete('/devices/me/push', async (request, reply) => {
    await db.updateTable('devices').set({ fcm_token: null }).where('id', '=', deviceOf(request).id).execute();
    return reply.status(204).send();
  });

  app.delete('/devices/me', async (request, reply) => {
    // Links, invites, nonces and the mailbox go with it (ON DELETE CASCADE).
    await db.deleteFrom('devices').where('id', '=', deviceOf(request).id).execute();
    return reply.status(204).send();
  });
};

