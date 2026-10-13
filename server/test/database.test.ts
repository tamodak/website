/**
 * The connection pool outlives the database ending its connections, as it does when PostgreSQL
 * restarts or stops: without a listener, the pool's error was uncaught and stopped the server.
 */
import { sql } from 'kysely';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { openDb, type Db } from '../src/db/database.ts';
import { createTestDatabase, type TestDatabase } from './support/database.ts';

describe('openDb', () => {
  let database: TestDatabase;
  let handle: Db;
  const idleErrors: Error[] = [];

  beforeAll(async () => {
    database = await createTestDatabase();
    handle = openDb(database.appUrl, (error) => idleErrors.push(error));
  });

  afterAll(async () => {
    await handle.close();
    await database.drop();
  });

  async function backendPid(): Promise<number> {
    const { rows } = await sql<{ pid: number }>`select pg_backend_pid() as pid`.execute(handle.db);
    return rows[0]!.pid;
  }

  it('reports an idle connection the database ended, and the next query opens a new one', async () => {
    // The query returns its connection to the pool, where it waits idle.
    const pid = await backendPid();

    // What a shutting-down PostgreSQL sends every session: 57P01, "terminating connection due
    // to administrator command".
    const admin = new pg.Client({ connectionString: database.adminUrl });
    await admin.connect();
    await admin.query('select pg_terminate_backend($1)', [pid]);
    await admin.end();

    await expect.poll(() => idleErrors.length).toBe(1);
    expect(idleErrors[0]).toMatchObject({ code: '57P01' });
    expect(await backendPid()).not.toBe(pid);
  });
});
