/**
 * The connection pool and the Kysely instance over it.
 */
import { Kysely, PostgresDialect } from 'kysely';
import pg from 'pg';
import type { Database } from './schema.ts';

// `date` columns stay `YYYY-MM-DD` strings. pg's default turns them into a Date at local
// midnight, which shifts the day whenever the server's time zone isn't UTC.
const DATE_OID = 1082;
pg.types.setTypeParser(DATE_OID, (value) => value);

export interface Db {
  readonly db: Kysely<Database>;
  readonly pool: pg.Pool;
  /** Closes the pool; pending queries finish first. */
  close(): Promise<void>;
}

/**
 * Opens the application's pool.
 *
 * Statements time out after 10 seconds and idle transactions after 30, so a stuck query can't
 * pin a connection; long polls hold no connection while they wait.
 *
 * When the database ends a connection that sits idle in the pool (a restart, an administrator,
 * a network partition), the pool drops it and reports the error to `onIdleError`, and the next
 * query opens a new one. The listener is required: a pool that emits `error` with none attached
 * throws it as uncaught, and the whole server exits.
 */
export function openDb(connectionString: string, onIdleError: (error: Error) => void, max = 10): Db {
  const pool = new pg.Pool({
    connectionString,
    max,
    statement_timeout: 10_000,
    idle_in_transaction_session_timeout: 30_000,
    application_name: 'killit-server',
  });
  pool.on('error', onIdleError);
  const db = new Kysely<Database>({ dialect: new PostgresDialect({ pool }) });
  return {
    db,
    pool,
    async close() {
      await db.destroy();
    },
  };
}
