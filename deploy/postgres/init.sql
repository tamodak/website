-- Run once by entrypoint.sh when the cluster is created: the roles, then the database.
--
-- Four roles, each with only what its job needs (PLAN.md §6.6):
--   killit_owner   owns the schema; only the migration job connects as it.
--   killit_app     reads and writes rows; the API. Table grants come from the migrations.
--   killit_backup  reads everything, writes nothing; the nightly pg_dump.
--   postgres       the superuser; reachable only inside the database container.
--
-- The passwords are read from secret files with psql's backquote expansion, so they never appear
-- in a command line or the shell environment.

\set owner_password `cat /run/secrets/db_owner_password`
\set app_password `cat /run/secrets/db_app_password`
\set backup_password `cat /run/secrets/db_backup_password`

CREATE ROLE killit_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE killit_app LOGIN PASSWORD :'app_password';
CREATE ROLE killit_backup LOGIN PASSWORD :'backup_password' IN ROLE pg_read_all_data;

\ir database.sql
