# syntax=docker/dockerfile:1
#
# PostgreSQL 16 from Ubuntu 24.04's own archive, so Ubuntu's security updates cover it
# (RUNBOOK.md, "Updating"). entrypoint.sh creates the cluster and the roles on first start.

FROM ubuntu:24.04

# A fixed uid, so the secret files on the host can be owned by exactly this user. Creating the
# user first makes the postgresql packages adopt it.
RUN groupadd --system --gid 10002 postgres \
 && useradd --system --uid 10002 --gid postgres --home-dir /var/lib/postgresql --shell /bin/bash postgres

# postgresql-common would create a "main" cluster on install; the entrypoint makes its own.
RUN apt-get update \
 && apt-get upgrade -y \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-common \
 && sed -i 's/^#\?\s*create_main_cluster.*/create_main_cluster = false/' /etc/postgresql-common/createcluster.conf \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postgresql-16 \
 && rm -rf /var/lib/apt/lists/* \
 && install -d -o postgres -g postgres -m 700 /var/lib/postgresql/data \
 && install -d -m 755 /usr/local/share/killit

COPY --chmod=755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=644 init.sql database.sql /usr/local/share/killit/

ENV PATH=/usr/lib/postgresql/16/bin:$PATH \
    PGDATA=/var/lib/postgresql/data
USER postgres
EXPOSE 5432
# SIGINT is PostgreSQL's "fast" shutdown: sessions are cut, data is safe.
STOPSIGNAL SIGINT
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s \
  CMD ["pg_isready", "--host=/var/run/postgresql", "--username=postgres", "--dbname=killit"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
