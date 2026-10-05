/**
 * Request authentication (SPEC.md §4.2): every route except the challenge and the health check is
 * signed by the phone's attested key. There are no sessions and no bearer tokens.
 *
 * The order of the checks matters. The signature is verified before the nonce is recorded, so a
 * flood of unsigned requests can't fill the nonce table or burn a phone's nonces; the per-device
 * rate limit is charged only to the phone that really sent the request.
 */
import { sql, type Kysely } from 'kysely';
import type { FastifyRequest } from 'fastify';
import {
  API_NONCE_RETENTION_MILLIS,
  API_WINDOW_MILLIS,
  parseAuthHeaders,
  toBase64Url,
  verifyRequest,
  type ParsedAuth,
} from '@tamodak/protocol/api';
import type { Config } from './config.ts';
import type { Database } from './db/schema.ts';
import { rateLimited, unauthorized } from './errors.ts';
import type { RateLimiter } from './rateLimiter.ts';

/** The phone a request came from, once its signature has verified. */
export interface AuthenticatedDevice {
  readonly id: string;
  readonly fp: Uint8Array;
  /** `base64url(fp)`, as it appears in the API. */
  readonly deviceId: string;
}

/** How a route authenticates. Registration verifies the signature itself, with the attested key. */
export type AuthMode = 'device' | 'registration' | 'none';

declare module 'fastify' {
  interface FastifyRequest {
    /** The exact body bytes, which the signature covers; empty when there is no body. */
    rawBody: Buffer;
    /** The parsed authentication headers, for `device` and `registration` routes. */
    auth: ParsedAuth | null;
    /** Set on `device` routes after the signature, nonce and rate checks pass. */
    device: AuthenticatedDevice | null;
  }
  interface FastifyContextConfig {
    auth?: AuthMode;
  }
}

export interface AuthDeps {
  readonly db: Kysely<Database>;
  readonly config: Config;
  readonly limiter: RateLimiter;
  readonly now: () => number;
}

/** The request as the signature covers it (SPEC.md §4.2). */
export function signedRequest(request: FastifyRequest, auth: ParsedAuth, audience: string) {
  return {
    audience,
    method: request.method,
    target: request.url,
    timestamp: auth.timestamp,
    nonce: auth.nonce,
    body: request.rawBody,
  };
}

/** The `preHandler` hook that authenticates every route according to its `auth` config. */
export function makeAuthenticate(deps: AuthDeps): (request: FastifyRequest) => Promise<void> {
  const { db, config, limiter, now } = deps;
  return async function authenticate(request) {
    const mode: AuthMode = request.routeOptions.config.auth ?? 'device';
    if (mode === 'none') return;

    const parsed = parseAuthHeaders(request.headers);
    if (!parsed.ok) throw unauthorized('invalid');
    const auth = parsed.value;
    if (Math.abs(now() - auth.timestamp) > API_WINDOW_MILLIS) throw unauthorized('stale_timestamp');
    request.auth = auth;
    if (mode === 'registration') return;

    const device = await db
      .selectFrom('devices')
      .select(['id', 'sign_pk'])
      .where('fingerprint', '=', Buffer.from(auth.fp))
      .executeTakeFirst();
    if (device === undefined) throw unauthorized('invalid');
    if (!verifyRequest(new Uint8Array(device.sign_pk), signedRequest(request, auth, config.audience), auth.signature)) {
      throw unauthorized('invalid');
    }

    const recorded = await db
      .insertInto('seen_nonces')
      .values({ device: device.id, nonce: auth.nonce, expires_at: new Date(now() + API_NONCE_RETENTION_MILLIS) })
      .onConflict((conflict) => conflict.doNothing())
      .returning('device')
      .executeTakeFirst();
    if (recorded === undefined) throw unauthorized('invalid');

    const wait = limiter.take(`requests:${device.id}`, 1, config.rateLimits.requestsPerDevicePerMinute, 60_000);
    if (wait > 0) throw rateLimited(wait);

    // Last seen is kept to the day (PLAN.md §3.11), so this writes at most once a day per phone.
    await db
      .updateTable('devices')
      .set({ last_seen_on: sql<string>`current_date` })
      .where('id', '=', device.id)
      .where('last_seen_on', '<', sql<string>`current_date`)
      .execute();

    request.device = { id: device.id, fp: auth.fp, deviceId: toBase64Url(auth.fp) };
  };
}

/** The authenticated device of a `device` route. The hook guarantees it; this narrows the type. */
export function deviceOf(request: FastifyRequest): AuthenticatedDevice {
  if (request.device === null) throw unauthorized('invalid');
  return request.device;
}
