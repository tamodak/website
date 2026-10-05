/**
 * Assembles the Fastify application: plugins, hooks, routes and error mapping (PLAN.md §6.6).
 *
 * Logging records the method, route pattern, status and duration of each request, and nothing
 * else: no bodies, no headers, no query strings (which can hold device ids), no IP addresses.
 * The server's logs therefore hold less than its database.
 */
import Fastify, { LogController, type FastifyError, type FastifyInstance, type FastifyRequest, type FastifyServerOptions } from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import { sql, type Kysely } from 'kysely';
import { makeAuthenticate } from './auth.ts';
import type { TrustAnchor } from './attestation/roots.ts';
import type { WakeBus } from './bus.ts';
import type { Config } from './config.ts';
import type { Database } from './db/schema.ts';
import { ApiError } from './errors.ts';
import type { RateLimiter } from './rateLimiter.ts';
import type { PushScheduler } from './routes/deps.ts';
import { deviceRoutes } from './routes/devices.ts';
import { inviteRoutes } from './routes/invites.ts';
import { linkRoutes } from './routes/links.ts';
import { messageRoutes } from './routes/messages.ts';

export interface AppDeps {
  readonly config: Config;
  readonly db: Kysely<Database>;
  readonly bus: WakeBus;
  readonly limiter: RateLimiter;
  readonly push: PushScheduler;
  readonly revocation: { isFresh(): boolean; isRevoked(serialHex: string): boolean };
  readonly trustAnchors: readonly TrustAnchor[];
  readonly now?: () => number;
  /** Fastify's logger option; tests pass `false`. */
  readonly logger?: FastifyServerOptions['logger'];
}

const EMPTY_BODY = Buffer.alloc(0);
const RAW_BODY = Symbol('rawBody');

export async function buildApp(deps: AppDeps): Promise<FastifyInstance> {
  const { config } = deps;
  const now = deps.now ?? Date.now;

  const app = Fastify({
    logger: deps.logger ?? { level: config.logLevel },
    // Fastify's own per-request lines log the URL and the address; the onResponse hook below
    // logs what is needed instead.
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: config.trustProxy,
    bodyLimit: 16 * 1024,
    // Long polls are cut on shutdown instead of holding it up for 30 seconds.
    forceCloseConnections: true,
    return503OnClosing: true,
    routerOptions: { maxParamLength: 100 },
    ajv: {
      // Strict validation: unknown properties are refused rather than silently dropped.
      customOptions: { removeAdditional: false, useDefaults: true, coerceTypes: 'array', allErrors: false },
    },
  }).withTypeProvider<TypeBoxTypeProvider>();

  // Fastify refuses object defaults for decorators (they would be shared between requests), so
  // the body bytes live in a per-request field behind a getter that defaults to empty.
  app.decorateRequest('rawBody', {
    getter(this: FastifyRequest & { [RAW_BODY]?: Buffer }) {
      return this[RAW_BODY] ?? EMPTY_BODY;
    },
    setter(this: FastifyRequest & { [RAW_BODY]?: Buffer }, value: Buffer) {
      this[RAW_BODY] = value;
    },
  });
  app.decorateRequest('auth', null);
  app.decorateRequest('device', null);

  // JSON bodies are kept as bytes too, because request signatures cover the exact body.
  // Fastify's own parser does the parsing, with its protection against prototype poisoning.
  const parseJson = app.getDefaultJsonParser('error', 'error');
  app.addContentTypeParser('application/json', { parseAs: 'buffer' }, (request, body, done) => {
    request.rawBody = body as Buffer;
    parseJson(request, (body as Buffer).toString('utf8'), done);
  });

  await app.register(helmet, {
    // An API serves no documents: nothing may be framed, loaded or run from its responses.
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
  });

  await app.register(rateLimit, {
    global: true,
    max: config.rateLimits.ipPerMinute,
    timeWindow: 60_000,
    keyGenerator: (request) => request.ip,
    errorResponseBuilder: (_request, context) => new ApiError(429, 'rate_limited', {}, Math.ceil(context.ttl / 1000)),
  });

  app.addHook('preHandler', makeAuthenticate({ db: deps.db, config, limiter: deps.limiter, now }));

  app.addHook('onResponse', async (request, reply) => {
    request.log.info(
      { method: request.method, route: request.routeOptions.url ?? 'unmatched', status: reply.statusCode, ms: Math.round(reply.elapsedTime) },
      'request',
    );
  });

  app.setErrorHandler((error: FastifyError | ApiError, request, reply) => {
    if (error instanceof ApiError) {
      if (error.retryAfter !== undefined) reply.header('retry-after', String(error.retryAfter));
      return reply.status(error.status).send({ error: error.code, ...error.details });
    }
    if (error.validation !== undefined || error.code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE' || error.code === 'FST_ERR_CTP_EMPTY_JSON_BODY' || error.statusCode === 400) {
      return reply.status(400).send({ error: 'bad_request' });
    }
    if (error.code === 'FST_ERR_CTP_BODY_TOO_LARGE') return reply.status(413).send({ error: 'too_large' });
    if (error.statusCode === 415) return reply.status(400).send({ error: 'bad_request' });
    request.log.error({ err: { type: error.name, code: error.code, message: error.message, stack: error.stack } }, 'unhandled error');
    return reply.status(500).send({ error: 'internal' });
  });

  app.setNotFoundHandler({ preHandler: app.rateLimit() }, (_request, reply) => reply.status(404).send({ error: 'not_found' }));

  app.get('/healthz', { config: { auth: 'none' } }, async (_request, reply) => {
    try {
      await sql`select 1`.execute(deps.db);
      return { status: 'ok' };
    } catch {
      return reply.status(503).send({ error: 'unavailable' });
    }
  });

  const routeDeps = { db: deps.db, config, bus: deps.bus, limiter: deps.limiter, push: deps.push, now };
  await app.register(deviceRoutes, { prefix: '/v1', ...routeDeps, trustAnchors: deps.trustAnchors, revocation: deps.revocation });
  await app.register(inviteRoutes, { prefix: '/v1', ...routeDeps });
  await app.register(linkRoutes, { prefix: '/v1', ...routeDeps });
  await app.register(messageRoutes, { prefix: '/v1', ...routeDeps });

  return app;
}
