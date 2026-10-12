#!/bin/bash
# Lists the stored backups, oldest first, with sizes and upload times.
set -euo pipefail
. /usr/local/lib/killit-backup/common.sh
rclone lsl "${BACKUP_ROOT}" | sort -k2,3
