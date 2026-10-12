#!/bin/bash
# Runs backup.sh every day at BACKUP_HOUR_UTC (default 03:00 UTC). A failed backup is logged and
# retried the next day; the heartbeat in backup.sh is what tells someone it keeps failing.
set -euo pipefail

hour="${BACKUP_HOUR_UTC:-3}"
# Sleep in the background so `docker compose stop` (SIGTERM) ends the wait at once.
trap 'exit 0' TERM INT
while true; do
  now=$(date -u +%s)
  next=$(date -u -d "today ${hour}:00" +%s)
  if [ "${next}" -le "${now}" ]; then next=$(date -u -d "tomorrow ${hour}:00" +%s); fi
  echo "backup: next run $(date -u -d "@${next}" '+%Y-%m-%d %H:%M UTC')"
  sleep "$(( next - now ))" &
  wait $!
  if /usr/local/bin/backup.sh; then echo "backup: done"; else echo "backup: FAILED" >&2; fi
done
