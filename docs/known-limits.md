# Known limits

What can't the server and its deployment do, and which lessons were learned the hard way?

## Limits

- **One process.** Rate limits and the bus that wakes long polls live in memory, so the server can't
  run as several processes without changes ([pairing-server.md](pairing-server.md)).
- **While the server is down, a guarded phone can't be unlocked or get apps approved.** Only the
  30-day unpair timer is local ([server-trust-model.md](server-trust-model.md) §6.4).
- **The server sees metadata:** who talks to whom, when and how often. That's stated, not hidden.
- **Emulators can't register** with the test or production server; only a development server accepts
  them.
- The free Oracle instance can be **reclaimed when it looks idle** ([infrastructure.md](infrastructure.md)).

## Lessons

- **Google's revocation list doesn't match its documentation.** It's documented as lowercase hex
  serial numbers, but more than half its entries are decimal, so the server looks up both
  (2026-10-05).
- **Since February 2026, attestation chains may end in Google's new ECDSA P-384 root** as well as the
  old RSA root, and remotely provisioned chains carry certificates valid for only days.
- **Android 8 emulator images ship software-attestation certificates that have expired.** Only the
  development server skips the dates of a chain that doesn't end in a Google root; production
  behaviour is unchanged.
- **A streamed backup stored an empty "backup" when the dump failed**, and write-only credentials
  can't delete it again. The backup job now finishes the encrypted dump in memory before uploading.
- **The host firewall was off** when the test server was set up: `iptables-persistent`, the package
  that loads Oracle's `rules.v4` at boot, was missing, so the OCI security list had been the only
  wall. It's reinstalled without letting it overwrite the file, and Docker's forwarding rules come
  before Oracle's reject rule after a reboot ([`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md) §2.4).
  Never run `netfilter-persistent save`.
- **The registrar's DNS remembers a missing name for a day**, so a name looked up before its record
  exists can stay invisible on some resolvers for up to a day.
- **Ubuntu 24.04's fail2ban** finds SSH's log lines through the `_COMM=sshd` journal match, so its
  `sshd` jail works although the unit is called `ssh.service`.
- **The restore drill** restored the first backup with the live database's tables, rows, owners and
  grants. Only the `public` schema's owner differs, because the drill creates its database with
  `createdb` instead of `database.sql`.
