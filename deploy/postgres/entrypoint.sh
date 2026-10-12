#!/bin/bash
# Creates the database cluster on first start, then runs PostgreSQL in the foreground.
#
# Secrets come from /run/secrets (compose file secrets): db_superuser_password and the
# passwords init.sql reads for killit_owner, killit_app and killit_backup.
set -euo pipefail

if [ ! -s "${PGDATA}/PG_VERSION" ]; then
  echo "entrypoint: creating the cluster in ${PGDATA}"
  # --pwfile reads the first line, so the secret never appears on a command line.
  initdb --pgdata="${PGDATA}" --username=postgres --pwfile=/run/secrets/db_superuser_password \
    --auth-local=peer --auth-host=scram-sha-256 --encoding=UTF8 --locale=C.UTF-8

  # Roles and the database are created over the Unix socket only, before anything can connect.
  pg_ctl --pgdata="${PGDATA}" --wait --silent \
    --options="-c listen_addresses='' -c unix_socket_directories=/var/run/postgresql" start
  psql --no-psqlrc --set=ON_ERROR_STOP=1 --host=/var/run/postgresql --username=postgres --dbname=postgres \
    --file=/usr/local/share/killit/init.sql
  pg_ctl --pgdata="${PGDATA}" --wait --silent --mode=fast stop

  # Password logins only for Killit's three roles, only to the killit database, only from the
  # compose network the server shares with this container ("samenet"). The superuser can log in
  # only through the socket inside this container (peer authentication).
  cat >> "${PGDATA}/pg_hba.conf" <<'HBA'

# Killit (deploy/postgres/entrypoint.sh)
host    killit    killit_owner,killit_app,killit_backup    samenet    scram-sha-256
HBA
  echo "entrypoint: cluster ready"
fi

exec postgres -c listen_addresses='*' -c unix_socket_directories=/var/run/postgresql \
  -c password_encryption=scram-sha-256 -c log_connections=off -c log_line_prefix='%m [%p] %q%u@%d '
