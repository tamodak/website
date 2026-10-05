/**
 * A database of the test file's own, cloned from the migrated template.
 */
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { inject } from 'vitest';

export interface TestDatabase {
  /** Connects as `killit_app`, like the server in production. */
  readonly appUrl: string;
  /** Connects as the superuser, for setting up states the API can't reach. */
  readonly adminUrl: string;
  drop(): Promise<void>;
}

export async function createTestDatabase(): Promise<TestDatabase> {
  const info = inject('database');
  const name = `test_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: info.adminUrl });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${name} TEMPLATE ${info.templateDatabase}`);
  await admin.end();

  const appUrl = new URL(info.adminUrl);
  appUrl.username = info.appUser;
  appUrl.password = info.appPassword;
  appUrl.pathname = `/${name}`;
  const adminUrl = new URL(info.adminUrl);
  adminUrl.pathname = `/${name}`;

  return {
    appUrl: appUrl.toString(),
    adminUrl: adminUrl.toString(),
    async drop() {
      const client = new pg.Client({ connectionString: info.adminUrl });
      await client.connect();
      await client.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await client.end();
    },
  };
}
