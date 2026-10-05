/**
 * The server process: configuration, database, background jobs, HTTP, and an orderly shutdown.
 *
 * Migrations are not run here; `migrate.ts` runs them first, as the schema owner (PLAN.md §6.6).
 */
import { buildApp } from './app.ts';
import { GOOGLE_ROOTS } from './attestation/roots.ts';
import { RevocationList } from './attestation/revocation.ts';
import { WakeBus } from './bus.ts';
import { loadConfig } from './config.ts';
import { openDb } from './db/database.ts';
import { startPurging } from './jobs/purge.ts';
import { PushDispatcher } from './push/dispatcher.ts';
import { FcmClient, loadServiceAccount } from './push/fcm.ts';
import { RateLimiter } from './rateLimiter.ts';

const config = loadConfig();
const database = openDb(config.databaseUrl);

// The background pieces are built before the app, but should log through its logger once it
// exists; until then (only during startup) they log to the console.
let log: { info(message: string): void; warn(message: string): void } = console;
const backgroundLog = { info: (message: string) => log.info(message), warn: (message: string) => log.warn(message) };

const limiter = new RateLimiter();
const bus = new WakeBus();
const revocation = new RevocationList({
  url: config.attestation.revocationListUrl,
  onError: (error) => backgroundLog.warn(`revocation list refresh failed: ${(error as Error).message}`),
});
const sender = config.fcmCredentialsFile === null ? null : new FcmClient(loadServiceAccount(config.fcmCredentialsFile));
const push = new PushDispatcher({ db: database.db, sender, log: backgroundLog });

const app = await buildApp({ config, db: database.db, bus, limiter, push, revocation, trustAnchors: GOOGLE_ROOTS });
log = { info: (message) => app.log.info(message), warn: (message) => app.log.warn(message) };
if (sender === null) app.log.warn('FCM_CREDENTIALS_FILE is not set: phones will not be woken by push');
if (config.attestation.devAcceptAnyRoot) app.log.warn('development mode: attestation roots are not checked');

revocation.start();
const stopPurging = startPurging(database.db, limiter, (error) => backgroundLog.warn(`purge failed: ${(error as Error).message}`));

await app.listen({ host: config.host, port: config.port });

let closing = false;
async function shutdown(signal: string): Promise<void> {
  if (closing) return;
  closing = true;
  app.log.info({ signal }, 'shutting down');
  stopPurging();
  revocation.stop();
  push.stop();
  await app.close();
  await database.close();
  process.exit(0);
}
process.once('SIGTERM', () => void shutdown('SIGTERM'));
process.once('SIGINT', () => void shutdown('SIGINT'));
