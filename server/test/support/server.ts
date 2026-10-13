/**
 * A real server for integration tests: its own database, a test attestation root instead of
 * Google's, a clock tests can move, and recording fakes for push and the revocation list.
 */
import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { Kysely } from 'kysely';
import { toBase64Url, toHex } from '@tamodak/protocol/api';
import { buildApp } from '../../src/app.ts';
import { WakeBus } from '../../src/bus.ts';
import { loadConfig, type Config } from '../../src/config.ts';
import { openDb, type Db } from '../../src/db/database.ts';
import type { Database } from '../../src/db/schema.ts';
import { RateLimiter } from '../../src/rateLimiter.ts';
import type { PushScheduler } from '../../src/routes/deps.ts';
import { TEST_CERT_DIGEST, createTestRoot, type TestRoot } from './attestation.ts';
import { createTestDatabase, type TestDatabase } from './database.ts';

export const TEST_AUDIENCE = 'api.killit.test';

/** A clock that runs with real time, plus whatever offset a test adds. */
export class TestClock {
  offset = 0;
  now = (): number => Date.now() + this.offset;
  advance(millis: number): void {
    this.offset += millis;
  }
}

/** Remembers every push the server asks for. */
export class RecordingPush implements PushScheduler {
  readonly scheduled: string[] = [];
  schedule(deviceId: string): void {
    this.scheduled.push(deviceId);
  }
}

/** A revocation list tests control. */
export class FakeRevocation {
  fresh = true;
  readonly revoked = new Set<string>();
  isFresh(): boolean {
    return this.fresh;
  }
  isRevoked(serialHex: string): boolean {
    return this.revoked.has(serialHex.toLowerCase().replace(/^0+(?=.)/, ''));
  }
}

export interface TestServer {
  readonly url: string;
  readonly config: Config;
  readonly app: FastifyInstance;
  readonly db: Kysely<Database>;
  readonly root: TestRoot;
  readonly clock: TestClock;
  readonly push: RecordingPush;
  readonly revocation: FakeRevocation;
  readonly bus: WakeBus;
  readonly limiter: RateLimiter;
  close(): Promise<void>;
}

/** Shared across files: building a root costs a key generation. */
let sharedRoot: Promise<TestRoot> | null = null;

export async function startServer(env: Record<string, string> = {}): Promise<TestServer> {
  const database: TestDatabase = await createTestDatabase();
  const config = loadConfig({
    KILLIT_ENV: 'test',
    DATABASE_URL: database.appUrl,
    API_AUDIENCE: TEST_AUDIENCE,
    INVITE_CODE_KEY: toBase64Url(randomBytes(32)),
    ATTESTATION_CERT_DIGESTS: toHex(TEST_CERT_DIGEST),
    // Generous defaults; the rate-limit tests set their own.
    RATE_IP_PER_MINUTE: '100000',
    RATE_REQUESTS_PER_DEVICE_PER_MINUTE: '100000',
    RATE_REGISTRATIONS_PER_IP_PER_HOUR: '100000',
    RATE_INVITES_PER_DEVICE_PER_HOUR: '100000',
    RATE_JOINS_PER_HOUR: '100000',
    RATE_ENVELOPES_PER_DEVICE_PER_HOUR: '100000',
    ...env,
  });
  const dbHandle: Db = openDb(config.databaseUrl, (error) => {
    if (process.env['TEST_LOG']) console.warn(`idle database connection closed: ${error.message}`);
  });
  sharedRoot ??= createTestRoot();
  const root = await sharedRoot;
  const clock = new TestClock();
  const push = new RecordingPush();
  const revocation = new FakeRevocation();
  const bus = new WakeBus();
  const limiter = new RateLimiter(clock.now);
  const app = await buildApp({
    config,
    db: dbHandle.db,
    bus,
    limiter,
    push,
    revocation,
    trustAnchors: [root.anchor],
    now: clock.now,
    // TEST_LOG=1 shows the server's errors while debugging a test.
    logger: process.env['TEST_LOG'] ? { level: 'error' } : false,
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  if (address === null || typeof address === 'string') throw new Error('no address');
  return {
    url: `http://127.0.0.1:${address.port}`,
    config,
    app,
    db: dbHandle.db,
    root,
    clock,
    push,
    revocation,
    bus,
    limiter,
    async close() {
      await app.close();
      await dbHandle.close();
      await database.drop();
    },
  };
}
