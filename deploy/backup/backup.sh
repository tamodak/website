#!/bin/bash
# Takes one backup: pg_dump, encrypted by age as it is produced, then uploaded with rclone. No
# plaintext dump is ever written down.
#
# Environment: BACKUP_NAME (object prefix), BACKUP_BUCKET, BACKUP_REMOTE, OCI_S3_ENDPOINT,
# OCI_REGION, PGHOST, and optionally BACKUP_HEARTBEAT_URL, pinged after a successful upload.
# Secrets: backup_pgpass (a libpq password file for killit_backup), backup_age_recipients (the
# age public key), oci_s3_access_key_id and oci_s3_secret_access_key.
set -euo pipefail
. /usr/local/lib/killit-backup/common.sh

export PGPASSFILE=/run/secrets/backup_pgpass
object="${BACKUP_NAME}-$(date -u +%Y-%m-%dT%H%M%SZ).dump.age"

# The encrypted dump is complete before anything is uploaded: streaming straight into the upload
# would store an empty "backup" whenever pg_dump fails, and the upload credentials can't delete
# it again. /tmp is in memory, and holds only ciphertext.
encrypted=$(mktemp /tmp/backup.XXXXXX)
trap 'rm -f "${encrypted}"' EXIT
pg_dump --host="${PGHOST:?}" --port=5432 --username=killit_backup --dbname=killit \
        --format=custom --compress=6 --no-password \
  | age --encrypt --recipients-file=/run/secrets/backup_age_recipients > "${encrypted}"
rclone copyto --quiet "${encrypted}" "${BACKUP_ROOT}/${object}"
echo "backup: uploaded ${BACKUP_NAME}/${object} ($(stat -c %s "${encrypted}") bytes)"

if [ -n "${BACKUP_HEARTBEAT_URL:-}" ]; then
  curl --fail --silent --show-error --max-time 10 --retry 3 "${BACKUP_HEARTBEAT_URL}" >/dev/null
fi
