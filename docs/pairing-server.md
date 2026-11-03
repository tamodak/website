# Pairing server

How is the pairing server built, how does it decide whom to trust, and which of its behaviours
aren't obvious from the code? (§6.3, §8)

The server (`server/`) is the mailbox and rendezvous Killit's pairing runs over. Why it can't do
harm: [server-trust-model.md](server-trust-model.md). The API and what it stores are specified in
[`protocol/SPEC.md`](../protocol/SPEC.md) §4–§9 and §12.

## §8 The stack, and why

- **Node 24 LTS, TypeScript, Fastify, `pg` with Kysely, `node-pg-migrate`, Vitest**, and `pkijs` /
  `asn1js` for attestation.
- **Push uses the FCM HTTP v1 API directly**, without `firebase-admin` (L2): a service-account JWT
  signed with `node:crypto` and exchanged for an access token. `firebase-admin` would have brought 61
  more packages that could reach the push credential.
- **No decryption code at all:** the server imports only the protocol package's API entry point,
  and a test fails if any server source imports anything else from it.
- **One process.** Rate limits and the event bus that wakes long polls live in memory. Several
  processes would need PostgreSQL's `LISTEN/NOTIFY` and shared limits.
- The live test database already ran the first migration, so **any schema change needs a new
  migration file** in `server/migrations/`; migrations only go forward. Migrations run as the
  schema owner in their own process before the API starts; the API connects with a role that can
  only read and write rows.

## §8.2 What it stores, and what it can't

- **No kind, role, name or encryption key anywhere:** the server can't know them.
- Messages never expire: they wait until acknowledged, because requests have no deadlines. Caps per
  recipient and per sender, and rate limits per phone, stop abuse.
- A periodic job purges expired challenges and nonces, and invites an hour after they end.
- Links are one row per pair of phones, deleted rather than marked removed.

## §6.3 Registration and request authentication

**Registration.** The phone generates its signing key with the server's challenge as its attestation
challenge and sends the certificate chain. The verifier (`server/src/attestation/`) follows
developer.android.com and Google's own verifier:

- the chain must end in **Google's roots**: the RSA root and, since February 2026, the ECDSA P-384
  root ("Key Attestation CA1"). They're compiled in, so changing them is a reviewed code change.
- **Revocation:** Google's status list is looked up in **both hex and decimal**, because more than
  half its entries are decimal although it's documented as hex (979 of 1759 on 2026-10-05); Google's
  own Kotlin verifier misses those. If the list is more than 24 hours old, registration **fails
  closed**.
- Expired certificates are accepted only for factory-provisioned chains, as Google does.
- The key-description extension is read only from the leaf, which stops the chain-extension attack.
- The challenge must match; the security level must be TEE or StrongBox (G12); the key must be a
  generated P-256 signing key; and `attestationApplicationId` must be `org.tamodak.killit` signed
  by a **configured certificate digest**: production accepts the release certificate only, the test
  server the release and debug ones (G13).
- The registration request is signed by the attested key itself, which proves possession.
- The verified-boot state is recorded, never rejected on.

The verifier was checked against nine real device chains from Google's test data, covering both
roots, factory and remote provisioning, TEE and StrongBox, and Android 8.1 to 17.

**Every other request is signed** by the phone's key, over the method, the path, a timestamp, a
nonce and the body's hash, and bound to the API host. A ±5-minute window and a remembered nonce stop
replays; there are no bearer tokens. The server checks the signature *before* storing the nonce, so
unsigned floods can't fill the nonce table.

An attestation can't be renewed: a key's chain answered one challenge. A phone whose registration
answer was lost settles it with `GET /v1/devices/me`, so the server's "retry gives 200" path is never
used by real phones.

## Behaviours worth knowing

- **Rate limits:** per IP before authentication, per phone after it.
- **Push:** at most one "sync" per phone every 10 seconds. Errors that say the installation is gone
  delete the stored installation id; temporary ones retry with backoff. TLS is always verified and
  redirects are refused.
- **Logs** hold the method, route pattern, status and duration of a request, and nothing else: no
  bodies, headers, query strings, codes, tokens or IP addresses.
- **Configuration** is read once at startup, and every problem is listed at once (`server/src/config.ts`).
  Secrets come inline or from a file (`NAME_FILE`), never both; the deploy stack always uses files.
- The development-only setting that accepts any attestation root is refused unless
  `KILLIT_ENV=development`.
- The server survives PostgreSQL closing an idle connection.

Running it locally for Killit's tests: [testing.md](testing.md).
