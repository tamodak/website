-- Creates the empty killit database with its ownership and privileges. init.sql runs it when the
-- cluster is created; a restore runs it again after dropping the database (RUNBOOK.md,
-- "Restoring a backup"). Connect to the postgres database to run it.

CREATE DATABASE killit OWNER killit_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE killit FROM PUBLIC;
GRANT CONNECT ON DATABASE killit TO killit_owner, killit_app, killit_backup;

\connect killit
ALTER SCHEMA public OWNER TO killit_owner;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO killit_app, killit_backup;
