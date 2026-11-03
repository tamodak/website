# Infrastructure

Which services does tamodak run on, how are they set up, and why? (§6.6, §10)

How to operate them step by step: [`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md). Access details
(addresses, SSH, account identifiers) are deliberately not written here.

## The domain: tamodak.org

One domain with subdomains (H14, I2): DNS records are free with the domain, and Caddy gets the
certificates by itself.

| Name | Serves | State (2026-11-03) |
|---|---|---|
| `tamodak.org` | the public site; for now the static placeholder with Hisar's privacy pages ([placeholder-site.md](placeholder-site.md)) | live |
| `www.tamodak.org` | a temporary redirect to `tamodak.org` | live |
| `api.test.tamodak.org` | the **test** pairing API; accepts debug and release builds of Killit | live since 2026-10-13 |
| `api.tamodak.org` | the production pairing API; release builds only | dark: no release signing key exists yet |
| `test.tamodak.org` | the test site | not set up |

- DNS is managed at the registrar (Turhost). Its zone tells resolvers to remember a missing name for
  a day (SOA minimum 86400 s), so create a record before anything looks the name up. Let's Encrypt
  asks the authoritative servers, so certificates aren't affected.
- `info@tamodak.org` is the public contact, the `security.txt` contact and the Let's Encrypt account.
- The old blog was deleted on 2026-10-13 (F4, N2), with its nginx and certbot, so Caddy owns ports 80
  and 443.

## Hosting

- **Oracle Cloud, Always Free tier.** The test server runs on the instance that already existed: an
  AMD `VM.Standard.E2.1.Micro` (x86_64, 1 GB of memory plus a 2 GB swap file, Ubuntu 24.04 LTS), not
  the roomier Ampere A1 (arm64) the design first chose (N1, L4). The running stack uses about 150 MB.
- **Docker, with every image built on Ubuntu 24.04** (L4), so Ubuntu's security updates cover them.
  PostgreSQL 16 comes from Ubuntu's archive; Node and Caddy are the official releases, pinned by
  checksum. The images are built on the server itself, so natively for its architecture, one at a
  time on the micro instance (about 12 minutes).
- Every container runs as its own non-root user, from a read-only filesystem, with no capabilities.
  Only Caddy publishes ports (80 and 443), and the database sits on an internal network with no
  route out.
- **Oracle reclaims Always Free instances that look idle** over 7 days, and a quiet test server looks
  idle. Upgrading the tenancy to Pay As You Go keeps the Always Free resources free and exempts them.

## §6.6 Server hardening

- SSH with keys only, no root login, automatic security updates, fail2ban.
- **Two firewall layers:** the OCI security list *and* the instance's iptables (Oracle's Ubuntu
  images are restrictive by default). Only 22 (limited by address), 80 and 443 are open.
- PostgreSQL is on the Docker network only, with a least-privilege role for the API, a separate role
  for migrations and a read-only one for backups.
- Secrets live in files outside git, each readable only by the one container that needs it.
- Nightly encrypted backups, with a tested restore.
- Schema validation on every route, body size limits, rate limits per address and per phone, Helmet
  headers, and logs without bodies.

## The test server

`api.test.tamodak.org`, live since 2026-10-13, runs the stack from `deploy/` as the runbook sets it
up. Its API accepts release and debug builds of Killit (both certificate digests are configured,
E-E9); production will accept release builds only. Push and nightly backups are on, and the restore
drill passed. The same Caddy serves the placeholder on `tamodak.org` and the `www` redirect.

- **Deploys are manual** (RUNBOOK §8), and no CI job holds a key to the server (N3). The server
  clones this public repository over HTTPS with no credential. Back up first.
- What's deployed can lag behind `master`: compare before assuming. The image before the last update
  is kept as `killit/api:previous`.
- Phase 5b's server was deployed on 2026-10-13 from a git bundle, before `master` was pushed; the
  server's checkout then moved onto the published history (its old head is tagged
  `deploy-before-5b`), so RUNBOOK §8's `git pull` fast-forwards. Hisar's privacy pages are static
  files, so updating them is a `git pull` alone (done for 0.2 on 2026-10-21).
- **Emulators can't use it:** their attestation chains don't end in a Google root. Real phones can.

## Push and Firebase

- Firebase project **`killit-27b49`**, Android app `org.tamodak.killit`. Killit commits its
  `google-services.json` (M3).
- The server sends pushes through the FCM HTTP v1 API directly (L2), with a least-privilege service
  account, `fcm-admin-sender`, whose only role is *Firebase Cloud Messaging API Admin* (N4). Of 13
  permissions probed, it holds only `cloudmessaging.messages.create`. Firebase's default Admin SDK key
  never goes on a server.
- How Killit uses it: [`../Killit/docs/push-and-sync.md`](../../Killit/docs/push-and-sync.md).

## Backups

- Nightly at 03:00 UTC: `pg_dump`, encrypted with **age** to a public key, uploaded to the private
  OCI Object Storage bucket `killit-backups` (Frankfurt). A lifecycle rule deletes objects after 30
  days.
- The server's key can add objects but can't overwrite or delete them (a probe confirmed it).
- The private key is never on the server. The restore drill (RUNBOOK §7.1) first passed on
  2026-10-13; it's meant to be repeated every few months.
- The encrypted dump is finished in memory before it's uploaded: a streamed `pg_dump | age | upload`
  stores an empty "backup" when the dump fails, and write-only credentials can't delete it again.

## Code and distribution

- The GitHub organisation `tamodak` holds every repository, all public.
- Hisar's picture-filter models are the assets of a `models-N` release in `tamodak/hisar-android`.
- Hisar ships on Google Play. Killit will ship through GitHub Releases (it can't be on Play). The
  Desktop Authenticator will be downloadable from the site.
