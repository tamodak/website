#!/bin/bash
# Creates the secret files compose.yaml reads, in deploy/secrets/ (RUNBOOK.md, "Secrets").
#
#     sudo scripts/new-secrets.sh [test]
#
# Generated values are random; values only the administrator can supply (the Firebase key, the
# backup public key, the Object Storage keys) get empty placeholders to replace. Existing files
# are never overwritten, so running it again only fills in what is missing.
#
# Each file is owned by the uid of the one container that reads it, with mode 400:
#   10001  api and migrate     10002  database     10003  backup
# so the API can't read the backup credentials, and the backup job can't read the API's.
#
# With --dev (a developer machine without root), files stay owned by the caller and are made
# readable by everyone instead, except the libpq password file, which libpq refuses unless only
# its owner can read it: run backup commands locally with --user "$(id -u):$(id -g)". Never use
# --dev on the server.
set -euo pipefail

cd "$(dirname "$0")/.."
dev=false
if [ "${1:-}" = --dev ]; then dev=true; shift; fi
env="${1:-test}"
case "${env}" in test | prod) ;; *) echo "environment must be test or prod" >&2; exit 2 ;; esac
if ! ${dev} && [ "$(id -u)" -ne 0 ]; then echo "run with sudo, so the files can be given to the container users" >&2; exit 1; fi

umask 077
mkdir -p secrets
chmod 700 secrets

API=10001 DB=10002 BACKUP=10003

# Writes a secret unless it exists, then sets its owner and mode.
put() {
  local name="$1" owner="$2" value="$3" file="secrets/$1"
  if [ -e "${file}" ]; then
    echo "kept     ${file}"
  else
    printf '%s\n' "${value}" > "${file}"
    echo "created  ${file}"
  fi
  if ! ${dev}; then
    chown "${owner}:${owner}" "${file}"
    chmod 400 "${file}"
  elif [[ "${name}" == *_pgpass ]]; then
    chmod 600 "${file}"
  else
    chmod 444 "${file}"
  fi
}

# A password: the existing one if the file is there (so derived files stay consistent), or a
# new 256-bit one in hex, which needs no escaping in a URL or a pgpass line.
password() {
  local file="secrets/$1"
  if [ -e "${file}" ]; then head -n 1 "${file}"; else openssl rand -hex 32; fi
}

host="db-${env}"
superuser=$(password "${env}_db_superuser_password")
owner=$(password "${env}_db_owner_password")
app=$(password "${env}_db_app_password")
backup=$(password "${env}_db_backup_password")

put "${env}_db_superuser_password" "${DB}" "${superuser}"
put "${env}_db_owner_password" "${DB}" "${owner}"
put "${env}_db_app_password" "${DB}" "${app}"
put "${env}_db_backup_password" "${DB}" "${backup}"
put "${env}_db_owner_url" "${API}" "postgres://killit_owner:${owner}@${host}:5432/killit"
put "${env}_db_app_url" "${API}" "postgres://killit_app:${app}@${host}:5432/killit"
put "${env}_backup_pgpass" "${BACKUP}" "${host}:5432:killit:killit_backup:${backup}"
# 32 random bytes, base64url without padding (SPEC.md §6.1: the invite-code HMAC key).
put "${env}_invite_code_key" "${API}" "$(openssl rand 32 | basenc --base64url | tr -d '=\n')"

# Supplied by the administrator; empty until then (RUNBOOK.md says where each comes from).
for name in fcm_service_account.json:${API} backup_age_recipients:${BACKUP} oci_s3_access_key_id:${BACKUP} oci_s3_secret_access_key:${BACKUP}; do
  put "${name%%:*}" "${name##*:}" ""
done
echo "Replace the empty files above with the real values before enabling push or backups."
