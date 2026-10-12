# Runbook: api.test.tamodak.org

How to set up, run, back up, restore and update the pairing server's test deployment. It runs with
Docker on the Oracle Cloud instance: Ubuntu 24.04 LTS on the Always Free Ampere A1 shape (arm64).

Every command runs **on the server**, from `/opt/killit/website/deploy`, unless it says "on your
computer". Nothing in this directory ever touches the server by itself.

---

## 1. What runs

| Container | Image | Runs as | Reads | Network |
|---|---|---|---|---|
| `caddy` | Ubuntu 24.04 + Caddy 2.11 | uid 10004 | `Caddyfile` | ports 80 and 443 (the only ones open) |
| `api-test` | Ubuntu 24.04 + Node 24 + the server | uid 10001 | its database URL, the invite-code key, the FCM key | Caddy only, plus the internet for FCM and Google's revocation list |
| `migrate-test` | the API image | uid 10001 | the schema owner's URL | the database only. Runs at every start, then exits. |
| `db-test` | Ubuntu 24.04 + PostgreSQL 16 | uid 10002 | the four role passwords (first start only) | an internal network with no route out |
| `backup-test` | Ubuntu 24.04 + pg_dump, age, rclone | uid 10003 | the backup role's password file, the age public key, the Object Storage keys | the database, and the internet for Object Storage |

Every container runs from a read-only filesystem with no Linux capabilities. Each reads only its
own secrets: the files are owned by that container's uid, with mode 400.

The database has four roles, each limited to its job (PLAN.md §6.6):

| Role | Can | Used by |
|---|---|---|
| `killit_owner` | change the schema | `migrate-test` |
| `killit_app` | read and write rows | `api-test` |
| `killit_backup` | read everything, write nothing | `backup-test` |
| `postgres` | everything | you, through `docker compose exec`, never over the network |

---

## 2. Setting up the server (once)

### 2.1 The instance

1. In the OCI console, create a compute instance: **Ubuntu 24.04**, shape **VM.Standard.A1.Flex**
   (2 OCPU and 12 GB are plenty; Always Free covers up to 4 and 24), with a public IPv4 address.
2. In its subnet's security list (or a network security group), allow ingress on **TCP 22 from your
   own IP only**, and on **TCP 80 and 443 from anywhere**. Remove any other ingress rule. These are
   the first of the two firewall layers (PLAN.md §6.6).

### 2.2 SSH

Log in with the key you gave OCI, then allow keys only:

```bash
sudo tee /etc/ssh/sshd_config.d/10-killit.conf >/dev/null <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
sudo systemctl restart ssh
```

Keep the current session open and test a new login before closing it.

### 2.3 Updates and fail2ban

Ubuntu Server installs security updates daily by itself (`unattended-upgrades`). Let it also reboot
at a quiet hour when an update needs it; the stack comes back up on its own:

```bash
sudo tee /etc/apt/apt.conf.d/52killit-reboot >/dev/null <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF
sudo apt-get update && sudo apt-get install -y fail2ban
```

Ubuntu's fail2ban package watches SSH out of the box.

### 2.4 The host firewall

Oracle's Ubuntu image ships iptables rules that accept only SSH. Leave them as they are: Docker
adds forwarding rules for the two ports it publishes, ahead of Oracle's reject rule. The OCI
security list stays the outer wall. Check from outside once the stack runs (§4).

### 2.5 Docker

Install Docker Engine and the compose plugin from Docker's own repository (docs.docker.com,
"Install Docker Engine on Ubuntu"):

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

The commands below use `sudo docker`. Adding your user to the `docker` group instead saves typing,
but that group is equivalent to root.

### 2.6 DNS

Point `api.test.tamodak.org` at the instance: an `A` record with its public IPv4, and an `AAAA`
record if it has IPv6. Caddy asks Let's Encrypt for the certificate on its first start, which needs
the name to resolve and ports 80 and 443 to be reachable.

---

## 3. Installing the stack

### 3.1 The code

`website/` has no remote yet. On your computer, bundle it:

```bash
git -C website bundle create /tmp/website.bundle --all
scp /tmp/website.bundle <server>:/tmp/
```

On the server:

```bash
sudo install -d -o "$USER" -g "$USER" /opt/killit
git clone /tmp/website.bundle /opt/killit/website
cd /opt/killit/website/deploy
```

Once the repository has a remote, `git clone` it into `/opt/killit/website` instead.

### 3.2 Configuration

```bash
cp .env.example .env && chmod 600 .env && nano .env
```

| Value | Where it comes from |
|---|---|
| `ACME_EMAIL` | your address, for Let's Encrypt's expiry warnings |
| `TEST_ATTESTATION_CERT_DIGESTS` | the SHA-256 of each certificate Killit builds may be signed with, comma-separated. For a release APK: `apksigner verify --print-certs killit.apk`. For debug builds made on a computer: `keytool -list -v -keystore ~/.android/debug.keystore -storepass android`. The current development machine's debug certificate is `9C:D7:62:73:A6:9F:F2:00:86:33:EC:22:E5:96:0A:95:DB:5E:C1:C3:68:95:04:AC:7D:8E:F3:90:B8:4A:05:C4`. |
| `TEST_FCM_CREDENTIALS_FILE` | empty for now; see §5 |
| `COMPOSE_PROFILES`, `BACKUP_*`, `OCI_*` | empty for now; see §6 |

### 3.3 Secrets

```bash
sudo scripts/new-secrets.sh test
```

This creates `secrets/` (mode 700). It generates the database passwords, the URLs and password
file derived from them, and the invite-code key, and gives each file to the uid of the container
that reads it. It also creates empty placeholders for the values only you can supply (§5, §6).
Running it again never overwrites a file.

To put a value into a placeholder, use `install`, which sets the owner and mode in one step:

```bash
sudo install -m 400 -o <uid> -g <uid> <source file> secrets/<name>
```

The uid is 10001 for the API's files and 10003 for the backup job's. A container sees a replaced
file only after it is recreated (`sudo docker compose up -d --force-recreate <service>`): a mounted
file stays the one that was there when the container started.

---

## 4. First start

```bash
sudo docker compose build --pull
sudo docker compose up -d
sudo docker compose ps          # db-test and api-test healthy, migrate-test "Exited (0)"
curl https://api.test.tamodak.org/healthz      # {"status":"ok"}
```

From your computer, also check that nothing else answers:

```bash
nc -zv -w 3 api.test.tamodak.org 5432     # must fail: the database is not reachable
curl -sI http://api.test.tamodak.org/healthz | head -1    # 308, a redirect to HTTPS
```

Logs: `sudo docker compose logs -f api-test`. Each request is one line with its method, route,
status and duration. No bodies, codes, tokens or IP addresses are logged, and Docker keeps at most
30 MB per container.

---

## 5. Push (Firebase Cloud Messaging)

Until this is done the API runs without push. Phones then learn of new messages when Killit
opens or polls (PLAN.md §7).

1. Create a Firebase project and add an Android app with the package name `org.tamodak.killit`.
   Phase 4 needs its `google-services.json`.
2. In the Google Cloud console for that project, make sure the **Firebase Cloud Messaging API (V1)**
   is enabled.
3. Under IAM & Admin → Service accounts, create a service account `killit-push` with only the role
   **Firebase Cloud Messaging API Admin**. Firebase's default "Admin SDK" account can do much more,
   so don't use it. Then use Keys → Add key → JSON.
4. Install the key and switch push on:

   ```bash
   sudo install -m 400 -o 10001 -g 10001 ~/killit-push.json secrets/fcm_service_account.json
   shred -u ~/killit-push.json
   # in .env:  TEST_FCM_CREDENTIALS_FILE=/run/secrets/fcm_service_account.json
   sudo docker compose up -d --force-recreate api-test
   ```

The server calls the FCM HTTP v1 API itself and sends only content-free "sync" pushes (SPEC.md §9).
A stolen key could make phones fetch their mailbox, and nothing else.

---

## 6. Backups

Every night at 03:00 UTC, `backup-test` dumps the database and encrypts it with
[age](https://age-encryption.org) to a public key. The private key **never** goes on the server.
The encrypted file is uploaded to OCI Object Storage. Nothing unencrypted is written anywhere.

### 6.1 Object Storage

1. Create a **private** bucket `killit-backups`.
2. Add a lifecycle rule that deletes objects older than 30 days. OCI asks for a policy letting the
   Object Storage service manage objects in the compartment the first time.
3. Create an IAM user `killit-backup` (no console password) in a group `killit-backup-writers`,
   with a policy that only lets it write and read backups in that bucket:

   ```
   Allow group killit-backup-writers to read buckets in compartment <compartment> where target.bucket.name = 'killit-backups'
   Allow group killit-backup-writers to manage objects in compartment <compartment> where all {target.bucket.name = 'killit-backups', any {request.permission = 'OBJECT_CREATE', request.permission = 'OBJECT_INSPECT', request.permission = 'OBJECT_READ'}}
   ```

   It can't delete or overwrite (each backup has a new name), so a compromised server can't wipe
   the backups; old ones expire through the lifecycle rule.
4. For that user, generate a **customer secret key**. That is an S3-compatible access key ID and
   secret.
5. Note the tenancy's Object Storage **namespace** (Tenancy details) and the **region** identifier.

### 6.2 The encryption key (on your computer)

```bash
sudo apt install age            # or: brew install age
age-keygen -o killit-backup.key # prints "Public key: age1…"
```

Keep `killit-backup.key` somewhere safe and offline, such as a password manager, with a second
copy. Without it no backup can be read, and anyone who has it can read every backup.

### 6.3 Switching backups on

```bash
echo 'age1…' | sudo install -m 400 -o 10003 -g 10003 /dev/stdin secrets/backup_age_recipients
printf '%s\n' '<access key id>' | sudo install -m 400 -o 10003 -g 10003 /dev/stdin secrets/oci_s3_access_key_id
printf '%s\n' '<secret key>'    | sudo install -m 400 -o 10003 -g 10003 /dev/stdin secrets/oci_s3_secret_access_key
```

In `.env`, set `COMPOSE_PROFILES=backups`, `OCI_S3_ENDPOINT=https://<namespace>.compat.objectstorage.<region>.oraclecloud.com`
and `OCI_REGION=<region>`. Then:

```bash
sudo docker compose up -d
sudo docker compose run --rm backup-test backup.sh          # one backup now
sudo docker compose run --rm backup-test list-backups.sh
```

Optionally, create a daily check at healthchecks.io (or similar) with a grace time of a few hours,
and put its URL in `TEST_BACKUP_HEARTBEAT_URL`. Then a backup that silently stops working raises an
alert.

A backup whose dump fails uploads nothing: the encrypted dump is finished before anything is sent.

---

## 7. Restoring a backup

Do the **drill** once after §6, and again every few months. A backup nobody has restored is only a
hope.

Both procedures need the private key on the server for a few minutes. Copy it there from your
computer (`scp killit-backup.key <server>:/tmp/`), then give it to the backup container's user:

```bash
sudo install -m 400 -o 10003 -g 10003 /tmp/killit-backup.key /tmp/backup-identity && shred -u /tmp/killit-backup.key
NAME=killit-test-2026-…Z.dump.age          # a name from list-backups.sh
fetch() { sudo docker compose run --rm -T -v /tmp/backup-identity:/run/secrets/backup_age_identity:ro backup-test fetch-backup.sh "$NAME"; }
```

### 7.1 Drill: restore into a scratch database

```bash
sudo docker compose exec db-test createdb -U postgres -O killit_owner killit_drill
fetch | sudo docker compose exec -T db-test pg_restore -U postgres -d killit_drill --no-owner --role=killit_owner --exit-on-error
sudo docker compose exec db-test psql -U postgres -d killit_drill -c 'select count(*) from devices' -c 'select count(*) from messages'
sudo docker compose exec db-test dropdb -U postgres killit_drill
sudo shred -u /tmp/backup-identity
```

### 7.2 Disaster: replace the live database

```bash
sudo docker compose stop api-test backup-test
sudo docker compose exec db-test psql -U postgres -d postgres -c 'DROP DATABASE killit WITH (FORCE)'
sudo docker compose exec db-test psql -U postgres -d postgres -v ON_ERROR_STOP=1 -f /usr/local/share/killit/database.sql
fetch | sudo docker compose exec -T db-test pg_restore -U postgres -d killit --no-owner --role=killit_owner --exit-on-error
sudo shred -u /tmp/backup-identity
sudo docker compose up -d
curl https://api.test.tamodak.org/healthz
```

`database.sql` recreates the empty database with the same ownership and privileges as the first
start. The restore brings back the tables, the rows and the grants to `killit_app`. This exact
sequence was run against the stack before release (Phase 3).

If the whole instance is lost: set up a new one (§2), install the stack (§3) with **the same
`secrets/`** if you still have them (new ones also work: the roles get new passwords), start it
(§4), and restore (§7.2).

---

## 8. Updating

### 8.1 The server code

```bash
sudo docker compose run --rm backup-test backup.sh     # a fresh backup first
git -C /opt/killit/website pull                        # or clone a new bundle
sudo docker tag killit/api:local killit/api:previous
sudo docker compose build --pull
sudo docker compose up -d                              # migrate-test runs before the API starts
```

To go back: `sudo docker tag killit/api:previous killit/api:local && sudo docker compose up -d api-test`.
That works only if no migration ran. Migrations go forward only; undoing one means restoring the
backup you just took (§7.2).

### 8.2 Security updates

- **The host** patches itself (§2.3).
- **The images** get Ubuntu's security updates when rebuilt: `apt-get upgrade` runs in every
  build. Rebuild monthly, and whenever a serious Ubuntu, OpenSSL or PostgreSQL advisory appears:
  `sudo docker compose build --pull --no-cache && sudo docker compose up -d`.
- **Pinned downloads** need a deliberate update. These are Node.js (`server/Dockerfile`), Caddy
  (`caddy/Dockerfile`) and pnpm (`package.json`):
  - Node: take the new version's two `linux-*.tar.xz` lines from `https://nodejs.org/dist/v<version>/SHASUMS256.txt`,
    after checking that file's signature against the Node.js release keys
    (`gpg --verify SHASUMS256.txt.sig SHASUMS256.txt`, keys from github.com/nodejs/release-keys).
  - Caddy: take the two `linux_*.tar.gz` SHA-512 lines from the release's `caddy_<version>_checksums.txt`,
    after `cosign verify-blob` with the `.sig` and `.pem` files published next to it.
  - pnpm: `npm view pnpm@<version> dist.integrity`, converted from base64 to hex, after `+sha512.` in
    `packageManager`.

---

## 9. Rotating secrets

| Secret | How | Effect |
|---|---|---|
| Invite-code key | `sudo rm secrets/test_invite_code_key && sudo scripts/new-secrets.sh test && sudo docker compose up -d --force-recreate api-test` | Codes shown in the last 15 minutes stop working; nothing else |
| A database password (`app`, `owner` or `backup`) | See below | None, if done in order |
| FCM key | Add a new key to `killit-push`, install it (§5), recreate `api-test`, then delete the old key in Google Cloud | None |
| Object Storage key | Generate a new customer secret key, install both files (§6.3), recreate `backup-test`, delete the old key | None |
| age key pair | New pair (§6.2), install the new public key, recreate `backup-test` | Keep the old private key until the last backup made with it has expired (30 days) |

Database password, for example `killit_app`:

```bash
sudo rm secrets/test_db_app_password secrets/test_db_app_url
sudo scripts/new-secrets.sh test                          # new password, new URL
sudo docker compose up -d --force-recreate db-test        # the database container sees the new file
printf '%s\n' '\set pw `cat /run/secrets/db_app_password`' "ALTER ROLE killit_app PASSWORD :'pw';" \
  | sudo docker compose exec -T db-test psql -U postgres -d postgres -X -v ON_ERROR_STOP=1
sudo docker compose up -d --force-recreate api-test
```

The password goes from the secret file into psql inside the container, so it never appears on a
command line. psql interpolates `:'pw'` only in input it reads itself, not in a `-c` argument,
hence the pipe.

For `killit_owner` the derived file is `test_db_owner_url`, and `migrate-test` picks it up at the
next start. For `killit_backup` it is `test_backup_pgpass`; recreate `backup-test`.

---

## 10. Watching it

- **Uptime:** an external monitor (UptimeRobot, healthchecks.io, …) requesting
  `https://api.test.tamodak.org/healthz` every few minutes. A protected phone can't open Killit
  while the server is down (PLAN.md §6.4).
- **Backups:** the heartbeat of §6.3, and the drill of §7.1.
- **Disk:** `df -h /` and `sudo docker system df`. The mailbox is capped per phone (SPEC.md §13).
- **Idle reclamation:** Oracle may reclaim an Always Free instance that stays nearly idle for seven
  days (PLAN.md §6.4). A low-traffic test server can look idle. Upgrading the tenancy to Pay As You
  Go keeps the Always Free resources free and, per Oracle's documentation, exempts them from idle
  reclamation.

---

## 11. Trying the stack locally

On a developer machine with Docker, the same stack runs with `compose.local.yaml`. Caddy serves
`https://localhost:18443` from its own local CA, and backups go to `./local-backups`:

```bash
cd website/deploy
scripts/new-secrets.sh --dev test
cp .env.example .env    # ACME_EMAIL=dev@example.org, API_TEST_HOST=localhost,
                        # TEST_ATTESTATION_CERT_DIGESTS=<your debug digest>
docker compose -f compose.yaml -f compose.local.yaml up -d --build
curl -k https://localhost:18443/healthz
```

For backups locally, put an age public key in `secrets/backup_age_recipients`, set
`COMPOSE_PROFILES=backups` and `BACKUP_BUCKET=/backups`, and run backup commands with
`--user "$(id -u):$(id -g)"`, because `--dev` leaves the files owned by you. Clean up with
`docker compose -f compose.yaml -f compose.local.yaml down --volumes`, then delete `secrets/`,
`.env` and `local-backups/`.
