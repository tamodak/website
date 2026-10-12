# Shared by the backup scripts: where backups live, and the rclone remote that reaches it.
#
# BACKUP_REMOTE=oci (the default) is OCI Object Storage through its S3-compatible API, with the
# endpoint and region from the environment and the keys from secret files. BACKUP_REMOTE=local
# treats BACKUP_BUCKET as a directory, for restore drills on a developer machine.
#
# Credentials travel in files and environment variables, never in arguments: anyone on the host
# can read a process's arguments with ps.

: "${BACKUP_NAME:?}" "${BACKUP_BUCKET:?}"
BACKUP_REMOTE="${BACKUP_REMOTE:-oci}"

if [ "${BACKUP_REMOTE}" = oci ]; then
  : "${OCI_S3_ENDPOINT:?}" "${OCI_REGION:?}"
  export RCLONE_CONFIG_OCI_TYPE=s3 \
         RCLONE_CONFIG_OCI_PROVIDER=Other \
         RCLONE_CONFIG_OCI_ENDPOINT="${OCI_S3_ENDPOINT}" \
         RCLONE_CONFIG_OCI_REGION="${OCI_REGION}" \
         RCLONE_CONFIG_OCI_FORCE_PATH_STYLE=true \
         RCLONE_CONFIG_OCI_NO_CHECK_BUCKET=true
  RCLONE_CONFIG_OCI_ACCESS_KEY_ID="$(cat /run/secrets/oci_s3_access_key_id)"
  RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY="$(cat /run/secrets/oci_s3_secret_access_key)"
  export RCLONE_CONFIG_OCI_ACCESS_KEY_ID RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY
  BACKUP_ROOT="oci:${BACKUP_BUCKET}/${BACKUP_NAME}"
elif [ "${BACKUP_REMOTE}" = local ]; then
  BACKUP_ROOT="${BACKUP_BUCKET}/${BACKUP_NAME}"
else
  echo "BACKUP_REMOTE must be oci or local" >&2
  exit 2
fi
