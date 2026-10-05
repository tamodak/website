/**
 * Starts one throwaway Postgres for the whole test run, migrates a template database in it, and
 * hands the connection details to the test files.
 *
 * Each test file then clones the template into a database of its own (`database.ts`), so files
 * never see each other's rows. The server under test connects as `killit_app`, the same
 * data-only role production uses, so a missing grant fails here first.
 *
 * Set TEST_DATABASE_URL (a superuser URL) to use an existing server instead of Docker.
 */
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import type { TestProject } from 'vitest/node';
import { migrate } from '../../src/migrate.ts';

export interface TestDatabaseInfo {
  /** Superuser URL of the server's maintenance database. */
  readonly adminUrl: string;
  readonly templateDatabase: string;
  readonly appUser: string;
  readonly appPassword: string;
}

declare module 'vitest' {
  export interface ProvidedContext {
    database: TestDatabaseInfo;
  }
}

const IMAGE = 'postgres:18-alpine';
const TEMPLATE = 'killit_template';
const APP_USER = 'killit_app';

function docker(...args: string[]): string {
  return execFileSync('docker', args, { encoding: 'utf8' }).trim();
}

async function waitForPostgres(url: string): Promise<void> {
  const deadline = Date.now() + 60_000;
  for (;;) {
    const client = new pg.Client({ connectionString: url });
    try {
      await client.connect();
      await client.query('select 1');
      await client.end();
      return;
    } catch (error) {
      await client.end().catch(() => {});
      if (Date.now() > deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

export default async function setup(project: TestProject): Promise<() => void> {
  let adminUrl = process.env['TEST_DATABASE_URL'];
  let container: string | null = null;
  if (adminUrl === undefined) {
    const password = randomBytes(12).toString('hex');
    container = docker(
      'run', '--detach', '--rm',
      '--env', `POSTGRES_PASSWORD=${password}`,
      '--publish', '127.0.0.1::5432',
      '--tmpfs', '/var/lib/postgresql',
      IMAGE,
      // Durability is pointless for a database that lives for one test run.
      '-c', 'fsync=off', '-c', 'synchronous_commit=off', '-c', 'full_page_writes=off',
    );
    const port = docker('port', container, '5432/tcp').split('\n')[0]!.split(':').pop();
    adminUrl = `postgres://postgres:${password}@127.0.0.1:${port}/postgres`;
  }
  await waitForPostgres(adminUrl);

  const appPassword = randomBytes(12).toString('hex');
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${TEMPLATE}`);
  await admin.query(`DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_USER}') THEN CREATE ROLE ${APP_USER} LOGIN; END IF;
    END $$`);
  await admin.query(`ALTER ROLE ${APP_USER} PASSWORD '${appPassword}'`);
  await admin.query(`CREATE DATABASE ${TEMPLATE}`);
  await admin.end();

  const templateUrl = new URL(adminUrl);
  templateUrl.pathname = `/${TEMPLATE}`;
  await migrate(templateUrl.toString(), () => {});

  project.provide('database', { adminUrl, templateDatabase: TEMPLATE, appUser: APP_USER, appPassword });

  return () => {
    if (container !== null) docker('rm', '--force', container);
  };
}
