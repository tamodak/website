/**
 * Applies pending schema migrations, then exits.
 *
 *     MIGRATION_DATABASE_URL=postgres://killit_owner:…@db/killit node dist/migrate.js
 *
 * Migrations run as the schema owner, in their own process, before the API starts. The API
 * itself connects as `killit_app`, which can read and write rows but not change the schema
 * (PLAN.md §6.6), so this is the only code path that holds DDL rights.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { runner } from 'node-pg-migrate';

/** The SQL migrations shipped next to `dist/`. */
export const MIGRATIONS_DIR = fileURLToPath(new URL('../migrations', import.meta.url));

/** Applies every pending migration in one transaction each. */
export async function migrate(databaseUrl: string, log: (message: string) => void = console.log): Promise<void> {
  await runner({
    databaseUrl,
    dir: MIGRATIONS_DIR,
    direction: 'up',
    migrationsTable: 'schema_migrations',
    checkOrder: true,
    log,
  });
}

/** Reads the owner's connection string from `MIGRATION_DATABASE_URL` or `MIGRATION_DATABASE_URL_FILE`. */
function databaseUrlFromEnv(): string {
  const file = process.env['MIGRATION_DATABASE_URL_FILE'];
  if (file) return readFileSync(file, 'utf8').trim();
  const url = process.env['MIGRATION_DATABASE_URL'];
  if (!url) throw new Error('MIGRATION_DATABASE_URL or MIGRATION_DATABASE_URL_FILE is required');
  return url;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  migrate(databaseUrlFromEnv()).then(
    () => process.exit(0),
    (error: unknown) => {
      console.error(error);
      process.exit(1);
    },
  );
}
