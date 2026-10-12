# syntax=docker/dockerfile:1
#
# Nightly encrypted backups (PLAN.md §6.6): pg_dump, encrypted with age to a public key whose
# private half never touches the server, streamed to OCI Object Storage with rclone. Every tool
# comes from Ubuntu 24.04's archive.

FROM ubuntu:24.04
RUN apt-get update \
 && apt-get upgrade -y \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      postgresql-client-16 age rclone curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10003 killit-backup \
 && useradd --system --uid 10003 --gid killit-backup --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin killit-backup
RUN install -d -m 755 /usr/local/lib/killit-backup
COPY --chmod=644 common.sh /usr/local/lib/killit-backup/common.sh
COPY --chmod=755 backup.sh schedule.sh list-backups.sh fetch-backup.sh /usr/local/bin/
USER 10003:10003
# The default command runs the schedule; `docker compose run backup-test <script>` runs another.
CMD ["/usr/local/bin/schedule.sh"]
