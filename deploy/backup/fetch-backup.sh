#!/bin/bash
# Downloads one backup and writes the decrypted dump (pg_dump's custom format) to stdout, for
# pg_restore to read (RUNBOOK.md, "Restoring a backup").
#
#     fetch-backup.sh <file name from list-backups.sh>
#
# Decrypting needs the age private key at /run/secrets/backup_age_identity. It lives with the
# administrator, not on the server, so a restore always means bringing it in on purpose.
set -euo pipefail
. /usr/local/lib/killit-backup/common.sh
name="${1:?usage: fetch-backup.sh <backup file name>}"
case "${name}" in */*) echo "give the file name only" >&2; exit 2 ;; esac
rclone cat "${BACKUP_ROOT}/${name}" | age --decrypt --identity=/run/secrets/backup_age_identity
