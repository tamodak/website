# Killit pairing protocol, version 1

Status: **draft for review** (Phase 3, 2026-10-12; app management and moving phones added in Phase 5b, 2026-10-13). It is normative for Killit and for the tamodak.org server.

PLAN.md explains the product and *why* (§2–§6). This document fixes *the bytes*: what is signed, encrypted, sent and checked. Where the two disagree, this document wins, and PLAN.md §16 lists every refinement it makes.

The test vectors in [`vectors/`](vectors/) belong to this specification. The TypeScript reference implementation in [`src/`](src/) generates them, the server's tests use them, and Killit's tests must reproduce them. If an implementation disagrees with a vector, that is a bug. If this text and a vector disagree, both get fixed before anything ships.

**Terms.** A *guardian* is PLAN.md's master and a *protected phone* is its slave (decision E5). A *phone* is one Killit installation with its own identity (§3). A *pairing* is one guardian–protected relationship between two phones. Two phones can have two pairings, one in each direction (A2). *Management* is a protected phone's setting that lets its guardians see and change which of its apps are blocked (PLAN.md §3.8). A *move* hands every pairing of an *old* phone to a *new* one (PLAN.md §3.10).

---

## 1. Encoding

### 1.1 Notation

| Notation | Meaning |
|---|---|
| `a ‖ b` | concatenation |
| `u8`, `u16`, `u64` | unsigned integers, big-endian |
| `bytes(n)` | exactly *n* bytes |
| `text16` | `u16 byteLength ‖ UTF-8 bytes`, under the text rules of §1.3 |
| `ascii16` | `u16 byteLength ‖ bytes`, each byte printable ASCII (`0x21`–`0x7E`), 1–2048 bytes. Used only for HTTP values (§4.2). |
| `blob16` | `u16 byteLength ‖ bytes` |
| `bool` | a `u8` that is `0x00` or `0x01`. Any other value is invalid. |
| `label(s)` | `u8 len(s) ‖ ASCII(s)`, a domain-separation prefix. Every label is listed in §2.3. |
| `fp` | a 32-byte phone fingerprint (§3.1) |
| time | `u64` milliseconds since the Unix epoch, UTC |
| base64url | RFC 4648 §5, without padding. Decoders reject `=`, characters outside the alphabet, and encodings whose unused trailing bits aren't zero, so every byte string has exactly one accepted encoding. |

### 1.2 Decoding is total

Every decoder takes bytes and returns either a fully validated value or a rejection. It never throws past its boundary. It checks every length before reading or allocating, never reads past the end, rejects trailing bytes, and rejects unknown values of every enumeration unless the field says otherwise. This is PLAN.md §6.2 rule 4, and it is what makes the decoders fuzzable in Phase 6.

### 1.3 Text

Every text field must satisfy all of these rules, or the whole structure is rejected:

1. **Well-formed UTF-8** (RFC 3629): no overlong forms, no surrogates (U+D800–U+DFFF), nothing above U+10FFFF.
2. **No control characters:** U+0000–U+001F, U+007F–U+009F, U+2028 and U+2029 are rejected. The one exception is U+000A (line feed) in *paragraph* fields.
3. **Trimmed:** the first and last code point aren't white space. White space here means exactly U+000A, U+0020, U+00A0, U+1680, U+2000–U+200A, U+202F, U+205F and U+3000: the Unicode `White_Space` characters that rule 2 leaves.
4. **Within limits:** each field has a code-point range (Unicode scalar values, not UTF-16 units) *and* a byte limit, and both must hold.

A field is either a *line* (no line feed) or a *paragraph* (line feeds allowed). Senders trim before sending; receivers reject untrimmed text instead of trimming it, so both sides validate the same bytes.

Receivers treat remote text as untrusted. They show it inside a bidi isolate (for example `BidiFormatter.unicodeWrap`), and never as markup or as a link.

### 1.4 Package names

Package names are ASCII, 1–255 bytes, matching `[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*`. This is Android's rule without its requirement for a dot, so system packages such as `android` also fit.

---

## 2. Cryptography

### 2.1 Algorithms

| Use | Algorithm |
|---|---|
| Hash | SHA-256 |
| MAC | HMAC-SHA256 |
| Signatures | ECDSA over P-256 with SHA-256 |
| Encryption | HPKE (RFC 9180), base mode, with the suite DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001` and AES-128-GCM `0x0001` |
| Randomness | the platform CSPRNG (`SecureRandom`, `crypto.randomBytes`) |

### 2.2 Formats

- **P-256 public keys** are 65-byte SEC 1 uncompressed points (`0x04 ‖ X ‖ Y`). Decoders reject any other length or prefix, and points that aren't on the curve.
- **Signatures** are 64 bytes, `r ‖ s` (IEEE P1363), each a 32-byte big-endian integer. Android Keystore returns DER, and Killit converts it. Verifiers accept any valid signature, including high-S ones, so **signature bytes are never used as identifiers**.
- **X25519 public keys** are 32 raw bytes. An all-zero Diffie-Hellman result is rejected (RFC 9180 §7.1.4).
- **HPKE** is used single-shot (sequence number 0) with empty AAD. That is exactly Tink's `HybridEncrypt` with the parameters `DHKEM_X25519_HKDF_SHA256 / HKDF_SHA256 / AES_128_GCM` and no output prefix (`NO_PREFIX`, the `…_RAW` template): `encrypt(plaintext, contextInfo)` uses `contextInfo` as the HPKE `info` and returns `enc ‖ ciphertext`.

### 2.3 Labels

Every signed, hashed or MACed structure starts with its own label, so bytes signed for one purpose never verify for another. The old QR pairing taught that lesson (PLAN.md §0).

| Label | Used for |
|---|---|
| `KILLIT-FP-v1` | fingerprints (§3.1) |
| `KILLIT-ENCKEY-v1` | binding the encryption key to the signing key (§3.2) |
| `KILLIT-API-v1` | request signatures (§4.2) |
| `KILLIT-COMMIT-v1` | the joiner's commitment (§6.3) |
| `KILLIT-SAS-v1` | the safety-code HMAC key. Raw ASCII, not `label()`-encoded, because it is a key, not a prefix. (§6.4) |
| `KILLIT-PAIR-v1` | pair ids (§6.4) |
| `KILLIT-MSG-v1` | message signatures (§10.2) |
| `KILLIT-ENV-v1` | the HPKE `info` of every envelope (§10.1) |

---

## 3. Identity

### 3.1 Keys and fingerprint

| Key | Where it lives | What it does |
|---|---|---|
| `sign` | **Android Keystore**: P-256, `PURPOSE_SIGN`, `DIGEST_SHA256`, StrongBox when available, else the TEE. It is generated with an attestation challenge (§5) and is never exported or silently regenerated. | The authority key. It signs messages, API requests and the encryption key. |
| `enc` | An X25519 HPKE key pair in a Tink keyset, encrypted by a Keystore AES-256-GCM key (PLAN.md §5.1) | Decrypts envelopes sent to this phone |

```
fp = SHA-256(label("KILLIT-FP-v1") ‖ signPk)                         32 bytes
```

The fingerprint is the phone's address on the server (`deviceId = base64url(fp)`, 43 characters) and its identity to its pairs. The server computes it from the attested key (§5.2), so a phone can't claim someone else's.

### 3.2 Bundle

The bundle is what two phones exchange during the pairing ceremony (§6):

```
bundle = u8 version (= 1) ‖ signPk (65) ‖ encPk (32) ‖ encSig (64)    162 bytes
encSig = ECDSA(sign, label("KILLIT-ENCKEY-v1") ‖ u16 0x0020 ‖ u16 0x0001 ‖ u16 0x0001 ‖ encPk)
```

`encSig` binds the encryption key and its HPKE suite to the signing key. A receiver verifies it before it uses `encPk` for anything.

---

## 4. HTTP conventions

### 4.1 Hosts

| Environment | Base URL | `audience` |
|---|---|---|
| Production | `https://api.tamodak.org` | `api.tamodak.org` |
| Test | `https://api.test.tamodak.org` | `api.test.tamodak.org` |
| Local development | for example `http://10.0.2.2:8080` from the emulator | whatever the server's `API_AUDIENCE` is set to |

TLS is required everywhere except local development. Bodies are JSON in UTF-8, and binary values in JSON are base64url strings. Every path starts with `/v1` except `/healthz`. The server sends no CORS headers: there are no browser clients.

### 4.2 Request signatures

Every route except `POST /v1/register/challenge` and `GET /healthz` must carry these headers:

| Header | Value |
|---|---|
| `Killit-Device` | `base64url(fp)` |
| `Killit-Timestamp` | the time in decimal milliseconds, no sign, no leading zeros |
| `Killit-Nonce` | base64url of 16 random bytes, fresh for every request |
| `Killit-Signature` | base64url of the 64-byte signature |

```
signedBytes = label("KILLIT-API-v1")
            ‖ ascii16(audience)         the API host (§4.1)
            ‖ ascii16(method)           uppercase
            ‖ ascii16(target)           path and query exactly as sent, e.g. "/v1/messages?wait=25"
            ‖ u64 timestamp
            ‖ bytes(16) nonce
            ‖ bytes(32) SHA-256(body)   the exact body bytes; no body hashes the empty string
signature   = ECDSA(sign, signedBytes)
```

The server checks, in this order, and answers `401` at the first failure:

1. The headers are well-formed.
2. `|now − timestamp| ≤ 300 s`.
3. The device is registered. Registration itself is the exception (§5.2).
4. The signature verifies with the stored key.
5. The nonce hasn't been seen for this device in the last 600 s. It is stored before the handler runs.

Binding the `audience` stops a request signed for one server being replayed against another, for example a test-server request against production.

**Clock correction.** Every response carries an HTTP `Date` header. On `stale_timestamp` a client may compute its clock offset from that header and retry once, with a new nonce.

**Responses are not signed.** Killit trusts nothing in a response for anything that matters. Everything that matters is signed end to end (§10) or checked locally (§6.4).

### 4.3 Errors

Errors are JSON, `{ "error": "<code>", … }`, with these statuses:

| Status | `error` | Extra fields | When |
|---|---|---|---|
| 400 | `bad_request` | | Schema validation, a bad base64url value, a wrong size |
| 401 | `unauthorized` | `reason`: `stale_timestamp` or `invalid` | §4.2. Unknown devices, bad signatures and replayed nonces all report `invalid`. |
| 403 | `attestation_rejected` | `reason` (§5.2) | Registration failed verification |
| 403 | `not_linked` | `peers` | A message to a phone with no link (§8), or a link handover to one (§7) |
| 404 | `not_found` | | Unknown invite, or one the caller isn't part of; an unknown phone in a link handover |
| 409 | `conflict` | `state` | An invite in the wrong state for the call, or `link_limit` (§7) |
| 410 | `expired` | | An expired challenge or invite |
| 413 | `too_large` | | A body over the route's limit |
| 429 | `rate_limited` or `mailbox_full` | | Includes a `Retry-After` header |
| 503 | `unavailable` | | The database or Google's revocation list is unreachable |
| 500 | `internal` | | A server bug. The details go to the server's log, never to the client. |

---

## 5. Registration and key attestation

### 5.1 Challenge

`POST /v1/register/challenge`, unsigned and with an empty body, returns `200 { "challenge": base64url(32 bytes), "expiresAt": time }`. A challenge is valid for 10 minutes and can be used once.

### 5.2 Register

Killit generates its `sign` key with `setAttestationChallenge(challenge)` and sends the chain returned by `KeyStore.getCertificateChain`, leaf first, as DER:

```
POST /v1/devices        signed (§4.2) with the new key
{ "challenge": base64url, "chain": [base64url(DER), …] }        3–6 certificates
```

The answer is `201 { "device": base64url(fp), "securityLevel": "tee" | "strongbox" | "software" }`, or `200` with the same body if this key is already registered. Registration is idempotent, so a phone whose first attempt timed out can simply try again.

The server verifies everything below, following developer.android.com's *Verify hardware-backed key pairs with key attestation* and Google's `android/keyattestation` verifier. Any failure is `403 attestation_rejected` with the `reason` in brackets.

1. **Chain shape** [`chain_invalid`]. 3–6 certificates that parse as X.509.
2. **Trust anchor** [`untrusted_root`]. The last certificate's public key (its SPKI) equals a Google root's (§5.3). One exception exists, for emulators talking to a developer's own machine: a server started with `KILLIT_ENV=development` and `ATTESTATION_DEV_ACCEPT_ANY_ROOT=true` accepts any self-signed root and software-level keys, doesn't check the dates of such a chain (older emulator images ship software-attestation certificates that have since expired), and records that it did. The production and test servers refuse to start with that setting.
3. **Name chaining and signatures** [`chain_invalid`]. Each certificate's issuer equals the next one's subject, and each verifies under the next one's public key. The certificate below the root verifies under the trust anchor's key.
4. **Validity** [`chain_invalid`]. Checked at the current time for every certificate except the leaf, whose dates the phone sets, and the root, which is a trust anchor. A certificate that isn't valid yet fails. An expired one fails too, unless the chain is *factory-provisioned* (the certificate directly below the root has a `serialNumber` attribute in its subject): factory keys can't be rotated, so Google accepts their expired certificates.
5. **Revocation** [`revoked`]. No certificate's serial number appears in Google's status list (`https://android.googleapis.com/attestation/status`) as `REVOKED` or `SUSPENDED`. The list is documented as lowercase hex without leading zeros, but on 2026-10-05 more than half of its entries were 17–20-digit decimal numbers, so each serial is looked up in both forms. If the list hasn't been fetched within the last 24 hours, registration fails closed with `503 unavailable`.
6. **Extension placement** [`extension_missing`, `extension_misplaced`, `extension_invalid`]. The key-description extension (OID `1.3.6.1.4.1.11129.2.1.17`) is in the leaf and in no other certificate. Without this rule, an attested key could sign a fake leaf that carries a forged extension: the chain-extension attack.
7. **Key description:**
   - [`challenge_mismatch`] `attestationChallenge` equals the challenge in the body, and that challenge was issued by this server, isn't expired and hasn't been used. It is consumed now.
   - [`security_level`] `attestationSecurityLevel` and `keyMintSecurityLevel` are both `TrustedEnvironment` (1) or `StrongBox` (2). `Software` (0) is accepted only where software attestation is allowed.
   - [`key_properties`] In `hardwareEnforced`: `origin` is `GENERATED` (0), `purpose` contains `SIGN` (2), `algorithm` is `EC` (3), `ecCurve` is `P_256` (1) (Keymaster 2 and 3 may leave it out; then `keySize` must be 256), and `rootOfTrust` is present.
   - [`application_id`] `attestationApplicationId` (from `softwareEnforced`, or `hardwareEnforced` if absent there) lists exactly one package, `org.tamodak.killit`, and at least one of its signature digests is a configured signing-certificate digest. Production accepts the release certificate. The test server accepts the release and the debug certificates (PLAN.md E-E9).
8. **Key** [`key_mismatch`]. The leaf's key is a P-256 uncompressed point, its `fp` equals `Killit-Device`, and the request signature verifies with it. This is the proof that the caller holds the key.

The server records the security level, `attestationVersion`, `verifiedBootState`, `deviceLocked`, `osVersion` and `osPatchLevel`, to understand the fleet. It never rejects on boot state (PLAN.md §6.3), and it keeps nothing else from the chain.

### 5.3 Trust anchors

The trust anchors are Google's attestation roots, as published on developer.android.com: one RSA key (published as four certificates) and the ECDSA P-384 *Key Attestation CA1* root used since February 2026. They are compiled into the server (`server/src/attestation/roots.ts`). Changing them is a code change, reviewed against that page.

### 5.4 The phone's own record

| Call | Result |
|---|---|
| `GET /v1/devices/me` | `200 { "device", "securityLevel" }` |
| `PUT /v1/devices/me/push` `{ "fid": string }` (1–4096 printable ASCII characters): the Firebase Installation ID FCM reaches the phone by (§9) | `204` |
| `DELETE /v1/devices/me/push` | `204` |
| `DELETE /v1/devices/me` | `204`. Deletes the device, its links, its invites and its mailbox. Messages it already sent stay in their recipients' mailboxes, so a goodbye NOTICE still arrives. |

---

## 6. Pairing invites and the safety code

### 6.1 Invite code

- 5 random bytes, written as 8 Crockford base32 symbols (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, most significant bits first) and shown as `XXXX-XXXX`, for example `K7QX-M2PD`. That's 40 bits.
- **Parsing** (phone and server alike) accepts printable ASCII only: remove `-` and spaces, uppercase `a`–`z`, map `I` and `L` to `1` and `O` to `0`. What remains must be exactly 8 alphabet symbols. Unicode case mapping differs between platforms, so the phone maps its keyboard's input to ASCII before parsing (a Turkish `ı` becomes `I`).
- The server stores `HMAC-SHA256(inviteKey, codeBytes)`, never the code. `inviteKey` is a server secret, so a leaked database can't be brute-forced into live codes.

### 6.2 Flow

The *creator* ("A") shows the code and the *joiner* ("B") types it. **The server never learns which of them will be the guardian.** That travels end to end, in PAIR_OFFER (§11.1).

| Step | Who | Call | Server rule |
|---|---|---|---|
| 1 | A | `POST /v1/invites` | Creates the invite in state `open`, valid for 15 minutes. Cancels A's earlier unfinished invites. Returns `201 { "id", "code", "expiresAt" }`. |
| 2 | B | `POST /v1/invites/join` `{ "code", "commit" }` | `open` → `joined`. B must not be A. The deadline resets to now + 15 minutes. Returns `{ "id", "expiresAt" }`. A wrong, used or expired code is `404`, all three alike. |
| 3 | A | `POST /v1/invites/{id}/reveal` `{ "reveal" }` | Only in `joined`, → `creator_revealed` |
| 4 | B | `POST /v1/invites/{id}/reveal` `{ "reveal" }` | Only in `creator_revealed`, and only if it matches B's commitment. → `revealed` |
| 5 | both | `POST /v1/links` `{ "invite" }` after the users tap "They match" | Only in `revealed`. When both have confirmed, → `linked`, and the link exists (§7). |
| – | either | `DELETE /v1/invites/{id}` | → `cancelled` ("They don't match", back, timeout) |

Both phones follow the invite with `GET /v1/invites/{id}`:

```
{ "id", "state", "role": "creator" | "joiner", "expiresAt",
  "commit"?, "creatorReveal"?, "joinerReveal"?,
  "confirmed": { "self": bool, "peer": bool }, "version" }
```

`state` is one of the states above, or `expired` once the deadline has passed. `role` is the caller's part in the ceremony, never guardian or protected. To wait for news, a phone sends back the `version` it last saw: `GET /v1/invites/{id}?wait=s&known=<version>` (`s` ≤ 30) answers as soon as anything changes, or after `s` seconds.

For every reveal, the server also checks its length, the bundle version, and that `fp(signPk)` is the revealing device. That keeps the transcript and the link consistent. It doesn't replace the phones' own checks.

### 6.3 Reveal and commitment

```
reveal = bundle (162) ‖ nonce (32)                                   194 bytes
commit = SHA-256(label("KILLIT-COMMIT-v1") ‖ reveal_B)               32 bytes
```

- **B** draws `n_B` when it joins and sends only `commit`. It reveals only after A's reveal is visible.
- **A** draws `n_A` and reveals only after the server shows B's commitment. A keeps the commitment it saw *before* revealing, and checks B's reveal against that copy, never against one fetched later.

### 6.4 Safety code and pair id

```
transcript = bundle_A ‖ bundle_B ‖ n_A ‖ n_B
mac        = HMAC-SHA256(key = ASCII("KILLIT-SAS-v1"), transcript)
safetyCode = u64(mac[0..8]) mod 1 000 000      shown as six digits with leading zeros, "042 917"
pairId     = SHA-256(label("KILLIT-PAIR-v1") ‖ transcript)
```

Before showing the code, each phone checks that the peer's `encSig` verifies and that the peer's fingerprint differs from its own. A also checks B's reveal against the commitment it kept. **The peer's address is `fp(peer signPk)` from the bundle, never an id the server supplies.**

**Why the server gets a single guess** (PLAN.md §4). To sit in the middle, the server must show A a fake joiner B′, and B a fake creator A′. B′ has to be committed before A reveals `n_A`, and A′ has to be revealed before B reveals `n_B`. Each phone's code then depends on a nonce the server had to fix before it could see the other one, so the two codes match with probability 10⁻⁶, and a failed attempt shows up as a mismatch on the call.

`pairId` names the pairing from then on. Every message carries it (§10.2), so messages from an earlier pairing between the same two phones can never be replayed into a newer one.

### 6.5 The ceremony of a move

Moving to a new phone (§11.14) runs the same ceremony between the two phones of one person: the **new phone creates** the invite and shows the code, and the **old phone joins**. The two screens sit side by side, so the people compare the safety code by looking rather than on a call, and it guards against exactly the same thing. A code alone would not do: a server that answered the join with its own bundle would receive the old phone's every pairing.

The server can't tell a move from a pairing. Each phone knows which one it started (PLAN.md §15.1, principle 3), and the first message after the link says it: PAIR_OFFER for a pairing, MOVE_REQUEST for a move. A phone that receives the other one ends the ceremony without a pairing. The ceremony's `pairId` names the move's messages, as it names PAIR_OFFER and PAIR_ANSWER.

---

## 7. Links

- The server routes messages only between linked phones. A link is undirected and carries no roles, so one link serves both directions of a mutual pairing.
- A link is created only by step 5 of §6.2, once both phones have confirmed. `POST /v1/links` returns `{ "state": "waiting" | "linked", "peer": base64url(fp) }`, and the phone checks that `peer` equals the fingerprint from the bundle.
- `GET /v1/links` returns `{ "links": [{ "peer", "lastSeenDaysAgo" }] }`: whole days since the peer's last signed request (PLAN.md §3.11). The server stores only the date.
- `DELETE /v1/links/{peer}` returns `204` and is idempotent. A phone deletes a link only when no pairing is left between the two phones in either direction (after LEAVE, a completed UNPAIR, a declined offer, or the end of device-owner release), and only after its last message on it has been sent.
- A phone has at most 50 links. The confirmation that would create a 51st answers `409 conflict` with `state: "link_limit"`.

**Handing links to a new phone.** The new phone of a move has a new fingerprint and none of the old phone's links, so its pairs couldn't reach it. Just before telling them (§11.14), the old phone asks the server to copy its links:

```
POST /v1/links/handover   { "to": base64url(fp) }      signed by the old phone
→ 200 { "copied": n }                                  links the new phone gained
```

- `to` must be a registered phone other than the caller (`404 not_found` otherwise) that is linked to the caller (`403 not_linked` with `peers: [to]` otherwise). That link comes from the move's ceremony, which `to` took part in, so the new phone consented.
- Every other link of the caller is copied to `to`, in one transaction. Links `to` already has are kept, and the call is idempotent.
- `to` may not end up with more than 50 links (`409 conflict`, `state: "link_limit"`, and nothing is copied). Each pair gains a link to `to` while it still has the caller's; that one goes when the old phone deletes itself (§5.4), so the pairs' own limit isn't checked here.
- The server learns that one phone handed its links to another (§12). It learns nothing about the pairings themselves.

---

## 8. Mailbox

| Call | Result |
|---|---|
| `POST /v1/messages` `{ "messages": [{ "to": base64url(fp), "envelope": base64url }] }`, 1–50 items, each envelope exactly 8240 bytes | `202 { "accepted": n }`. All or nothing: if any recipient isn't linked, `403 not_linked` with `peers`. A full mailbox is `429 mailbox_full`. |
| `GET /v1/messages?wait=s` (`s` 0–30) | `{ "messages": [{ "id", "from", "envelope", "receivedAt" }] }`, in the order the server accepted them, at most 32. With `wait`, the server holds the request until a message arrives or `s` seconds pass. |
| `POST /v1/messages/ack` `{ "ids": [...] }` (1–64) | `204`. The server deletes them. Ids that aren't the caller's are ignored. |

- Killit acknowledges a message once it has stored it locally or rejected it, not when the user acts on it. Unacknowledged messages are delivered again, and the `messageId` check (§10.3) absorbs the duplicates.
- Messages have no expiry, because requests have none. A mailbox holds at most 1000 messages, and at most 200 from any one sender.

---

## 9. Push

After storing messages for a phone, the server sends that phone one FCM data message. Several messages arriving close together produce one push (at most one every 10 seconds per phone).

```json
{ "message": { "fid": "<Firebase Installation ID>", "data": { "sync": "1" },
  "android": { "priority": "HIGH", "collapse_key": "sync", "ttl": "86400s",
               "restricted_package_name": "org.tamodak.killit" } } }
```

- **A phone is addressed by its Firebase Installation ID.** firebase-messaging 26 registers apps by FID and hands it to `onRegistered`; FCM has deprecated the message's `token` field in favour of `fid`. Killit sends the FID with `PUT /v1/devices/me/push` once it has a pairing, and again whenever FCM registers it anew.
- **A push carries no content.** Killit treats every push, whatever it holds, as "fetch the mailbox now" (PLAN.md §6.2 rule 6). So a forged or replayed push, even one sent with a stolen FCM credential, can at most make phones poll.
- **Registration cleanup.** `UNREGISTERED` (404), `SENDER_ID_MISMATCH`, or `INVALID_ARGUMENT` about `message.fid`, deletes the FID. `QUOTA_EXCEEDED`, `UNAVAILABLE` and `INTERNAL` are retried with exponential backoff, honouring `Retry-After`. A push that never arrives only delays things: the message waits in the mailbox until the next app open or WorkManager poll (PLAN.md §7).
- **Authentication** uses the FCM HTTP v1 API directly. The server signs a service-account JWT (RS256, scope `https://www.googleapis.com/auth/firebase.messaging`) with `node:crypto`, exchanges it at the account's `token_uri` for an access token, and caches the token until five minutes before it expires. There's no Firebase SDK: one documented HTTPS call doesn't justify about 60 more packages that could reach the credential (Phase 3 decision). TLS certificates are verified and redirects are refused.

---

## 10. End-to-end messages

### 10.1 Envelope

```
plaintext = u16 innerLength ‖ inner ‖ signature (64) ‖ zero bytes up to 8192        8192 bytes
info      = label("KILLIT-ENV-v1") ‖ senderFp ‖ recipientFp
envelope  = HPKE-Seal(recipient encPk, info, aad = empty, plaintext)
          = enc (32) ‖ ciphertext and tag (8208)                                     8240 bytes
```

**Every message pads to the same single size,** so the server can't tell kinds apart by length (PLAN.md §5.2). `innerLength` is 122–8126.

### 10.2 Inner header and signature

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `version` = 1 |
| 1 | 1 | `kind` (§11) |
| 2 | 16 | `messageId`: random, unique for every envelope |
| 18 | 32 | `pairId`: the pairing this message belongs to (§6.4) |
| 50 | 32 | `senderFp` |
| 82 | 32 | `recipientFp` |
| 114 | 8 | `createdAt` |
| 122 | … | `body` (§11), to the end of `inner` |

```
signature = ECDSA(sender's sign key, label("KILLIT-MSG-v1") ‖ inner)
```

The request kind is inside the ciphertext (PLAN.md §5.2). Because `recipientFp` is signed, a phone can't re-encrypt a message it received and pass it to a third phone as if it had been sent there.

### 10.3 Opening a message

The receiving phone runs these steps in order. Any failure drops the message silently. Killit acknowledges dropped messages too, so a broken message can't clog its mailbox.

1. The envelope is 8240 bytes, and `from` (the server's hint) is a phone with a current pairing, or the peer of a ceremony in progress.
2. HPKE-Open with `info` built from `from` and the phone's own fingerprint.
3. `innerLength` is in range and every padding byte is zero.
4. `version` is 1. Another version goes to step 9. `senderFp` equals `from`, and `recipientFp` is this phone.
5. `pairId` names a current pairing between sender and receiver. For the *ceremony kinds* (PAIR_OFFER, PAIR_ANSWER and the four MOVE_ kinds), it is the `pairId` of the ceremony in progress instead.
6. The signature verifies with the sender's stored `signPk`.
7. This `messageId` hasn't been seen from this sender. Seen ids are kept for at least 400 days, and anything with a `createdAt` older than 365 days by the receiver's clock is dropped.
8. The kind is allowed for the sender's role in that pairing (§11), and the body decodes strictly.
9. An unknown kind or version isn't dropped. Killit keeps it as received, shows "Update Killit to see this request", and sends no answer (PLAN.md E-F1).
10. Apply the message (§11, and PLAN.md §3 for the behaviour).

A DECISION has one more rule, in §11.6.

---

## 11. Message kinds

| Code | Kind | Sent by → to (roles in the pairing) | Body |
|---|---|---|---|
| `0x01` | PAIR_OFFER | creator → joiner | §11.1 |
| `0x02` | PAIR_ANSWER | joiner → creator | §11.1 |
| `0x10` | UNBLOCK_APP | protected → each guardian | §11.3 |
| `0x11` | UNLOCK | protected → each guardian | §11.4 |
| `0x12` | UNPAIR | protected → each guardian | §11.5 |
| `0x13` | DECISION | guardian → protected | §11.6 |
| `0x14` | STATUS | protected → each guardian | §11.7 |
| `0x15` | LEAVE | guardian → protected | §11.8 |
| `0x16` | UNPAIRED | protected → the guardian it removed | §11.8 |
| `0x20` | NOTICE | either | §11.9 |
| `0x30` | LIST_REQUEST | guardian → protected | §11.10 |
| `0x31` | APP_LIST | protected → guardian | §11.10 |
| `0x32` | MANAGE | guardian → protected | §11.11 |
| `0x33` | GUARDIAN_UNBLOCK | protected → each guardian | §11.12 |
| `0x34` | HANDOVER | either: the side that moved | §11.13 |
| `0x35` | MOVE_REQUEST | creator (the new phone) → joiner (the old one) | §11.14 |
| `0x36` | MOVE_STATE | joiner → creator | §11.14 |
| `0x37` | MOVE_ANSWER | creator → joiner | §11.14 |
| `0x38` | MOVE_DONE | joiner → creator | §11.14 |

The *requests* a guardian decides on are UNBLOCK_APP, UNLOCK, UNPAIR and GUARDIAN_UNBLOCK. Kinds `0x39`–`0xFF` are unassigned: §10.3 step 9 applies to them.

### 11.1 PAIR_OFFER and PAIR_ANSWER

Once the link exists, A sends PAIR_OFFER and B answers it. PAIR_OFFER is sent by the creator whichever role it takes.

```
PAIR_OFFER  = u8     senderRole      1 = GUARDIAN (the sender will guard the recipient)
                                     2 = PROTECTED (the sender asks the recipient to guard it)
            ‖ text16 selfName        line, 1–40 code points, ≤ 160 bytes: the name the sender calls itself
            ‖ text16 deviceModel     line, 0–64 code points, ≤ 256 bytes: Build.MANUFACTURER + " " + Build.MODEL
            ‖ bool   appManagement   the protected side's setting (PLAN.md §3.8); 0 when senderRole = GUARDIAN

PAIR_ANSWER = u8     answer          1 = ACCEPT, 2 = DECLINE
            ‖ u8     reason          0 with ACCEPT; with DECLINE 1 = USER, 2 = ROLE_CONFLICT
            ‖ text16 selfName        ACCEPT: 1–40 code points; DECLINE: empty
            ‖ text16 deviceModel     ACCEPT: 0–64 code points; DECLINE: empty
            ‖ bool   appManagement   ACCEPT by a joiner that becomes the protected phone: its setting; otherwise 0
```

- B started from a section, so it knows the role it expects (PLAN.md §15.1, principle 3). If `senderRole` isn't the opposite of that, B declines with `ROLE_CONFLICT` without asking.
- A decoder can't see roles, so the creator checks one thing itself: an ACCEPT from a joiner that becomes the *guardian* must have `appManagement = 0`, and is refused otherwise.
- Each side proposes its own `selfName`. The receiving side stores it as the *default* for its local nickname (A5), and also keeps it unchanged as the peer's own name. The G2 relay and STATUS use the own name, which the other phone can't edit.
- The pairing exists on B once B sends ACCEPT, and on A once A receives it. The protected side then sends NOTICE `GUARDIAN_ADDED` to its existing guardians (A4).

### 11.2 Common structures

```
AppRef  = text16  packageName        §1.4
        ‖ bytes(32) certDigest       SigningDigest.ofSigners (PLAN.md §1.1)

AppInfo = AppRef
        ‖ text16  label              line, 0–100 code points, ≤ 400 bytes
        ‖ text16  installer          a package name, or empty when unknown or sideloaded
        ‖ u64     firstInstalled     time
        ‖ u8      iconFormat         0 = none, 1 = RGBA8888, 32 × 32
        ‖ bytes   icon               4096 bytes when iconFormat = 1, absent when 0
```

**Icons are raw pixels**: rows top to bottom, each pixel as R, G, B, A bytes, not premultiplied. The receiver builds a `Bitmap` straight from them. That keeps every image decoder away from network input; libwebp's CVE-2023-4863 is the reason not to send WebP or PNG.

### 11.3 UNBLOCK_APP

```
body = bytes(16) requestId          random; shared by every guardian's copy
     ‖ AppInfo   app
     ‖ text16    explanation        paragraph, 10–500 code points, ≤ 2000 bytes
     ‖ u8        chancesLeft        1–3, counting this request (D4)
     ‖ u8        guardianCount      how many guardians must approve, 1–50
```

### 11.4 UNLOCK

```
body = bytes(16) requestId
     ‖ bytes(32) sessionNonce       lives only in the process's memory (PLAN.md §3.4)
     ‖ text16    explanation        paragraph, 0–500 code points, ≤ 2000 bytes
     ‖ u8        guardianCount
```

An approval binds `sessionNonce`, which is never stored, so it can't open anything once the waiting screen is gone, even after a process restart.

### 11.5 UNPAIR

```
body = bytes(16) requestId
     ‖ bytes(32) targetPairId       the pairing to remove
     ‖ bytes(32) targetFp           the guardian to remove; that guardian receives the request too (B1)
     ‖ text16    explanation        paragraph, 10–500 code points, ≤ 2000 bytes
     ‖ u8        chancesLeft        1–3 (G8)
     ‖ u8        guardianCount
     ‖ u64       timerEndsAt        when the 30-day timer completes, by the protected phone's clock
```

### 11.6 DECISION

```
body = bytes(16) requestId
     ‖ u8        requestKind        0x10, 0x11, 0x12 or 0x33
     ‖ target                       UNBLOCK_APP and GUARDIAN_UNBLOCK: AppRef
                                    UNLOCK: bytes(32) sessionNonce · UNPAIR: bytes(32) targetPairId
     ‖ u8        decision           1 = APPROVE, 2 = DENY
     ‖ text16    note               paragraph, 0–300 code points, ≤ 1200 bytes (G9)
```

**The protected phone verifies a decision against its own stored request, not against what the decision says** (PLAN.md §5.2). It finds the request by `requestId` and the guardian by `pairId`. Then it rebuilds the inner bytes from:

- `version`, `kind`, and the received `messageId` and `createdAt`;
- its stored `pairId`, the stored guardian's fingerprint as sender, and its own as recipient;
- a body of the stored `requestId`, `requestKind` and target, followed by the received `decision` and `note`.

It verifies the received signature over `label("KILLIT-MSG-v1") ‖ rebuilt` with the guardian's stored key. A decision that names another app, certificate, nonce or pairing fails to verify, because the guardian never signed those bytes. A decision for a request that isn't open, or a second one from the same guardian, is ignored. Every request accepts one decision per guardian.

### 11.7 STATUS

STATUS keeps every guardian's copy of a request current. It covers PLAN.md's CANCEL: the protected phone sends it when it withdraws a request, and whenever a request's state changes.

```
body = bytes(16) requestId
     ‖ u8        requestKind        a request kind (§11)
     ‖ u8        outcome            0 = OPEN, 1 = APPROVED, 2 = DENIED, 3 = CANCELLED
     ‖ u8        reason             0 unless CANCELLED: 1 = WITHDRAWN (left the waiting screen, a call, H12;
                                    the protected user withdrew it; management was turned off; the phone
                                    moved; or the guardian who proposed a GUARDIAN_UNBLOCK blocked the app
                                    again), 2 = APP_UNINSTALLED (H11), 3 = RESOLVED_BY_UNLOCK (G11),
                                    4 = GUARDIAN_REMOVED (its pairing ended)
     ‖ u8        count              0–40
     ‖ count × ( bytes(32) guardianFp ‖ text16 guardianName ‖ u8 state )
                                    state: 0 = WAITING, 1 = APPROVED, 2 = DENIED.
                                    The name is that guardian's own selfName (§11.1).
```

This is how guardians see each other's decisions (G10) without being paired with each other. Above 40 guardians the list is cut off; the UI warns long before that (A3). A guardian whose own entry shows a decision it never sent records it as its own: that happens when one of its MANAGE commands answered the request (§11.11).

### 11.8 LEAVE and UNPAIRED

```
LEAVE    = (empty body)              the guardian stops guarding; the header's pairId names the pairing
UNPAIRED = u8 how                    1 = ALL_APPROVED, 2 = TIMER, 3 = RELEASED (device owner given up, H7)
```

Both end the pairing named in the header, on receipt and without approval. LEAVE comes from the guardian, and UNPAIRED tells a guardian it was removed.

### 11.9 NOTICE

```
body = u16 code ‖ params
```

| Code | Name | Sent by | `params` |
|---|---|---|---|
| `0x0001` | APP_INSTALLED | protected | `AppInfo ‖ bool blocked` (D1) |
| `0x0002` | GUARDIAN_ADDED | protected | `bytes(32) guardianFp ‖ text16 guardianName` (A4) |
| `0x0003` | GUARDIAN_REMOVED | protected | `bytes(32) guardianFp ‖ text16 guardianName ‖ u8 how` (1 = LEFT, 2 = UNPAIRED) (B5) |
| `0x0004` | RELEASE_STARTED | protected | `u64 completesAt` (C8, H6) |
| `0x0005` | RELEASE_CANCELLED | protected | none |
| `0x0006` | PROTECTION_CHANGED | protected | `u8 option ‖ bool enabled`. Options: 1 = uninstall, 2 = force stop, 3 = safe boot, 4 = factory reset, 5 = managing apps, 6 = date and time (H6) |
| `0x0007` | MANAGEMENT_CHANGED | protected | `bool enabled` (H6) |
| `0x0008` | APP_MANAGED | protected | `AppRef app ‖ text16 label ‖ u8 change ‖ bytes(32) guardianFp ‖ text16 guardianName`. The label is a line of 0–100 code points. Changes: 1 = BLOCKED, 2 = UNBLOCKED, 3 = REFUSED (Android wouldn't block it). The guardian is the one whose MANAGE made the change, by its own name (§11.11) |
| `0x0009` | GUARDIAN_MOVED | protected | `bytes(32) guardianFp ‖ text16 guardianName`: one of the other guardians moved to a new phone, now called `guardianFp` (B6, §11.13) |

Notices only inform. An unknown code shows as "Update Killit to see this" (E-F1), and its `params` aren't parsed. Release completing is UNPAIRED with `how = RELEASED`.

### 11.10 LIST_REQUEST and APP_LIST

A guardian asks to see the protected phone's apps, and the protected phone answers with its list (PLAN.md §3.8: pulled, never streamed).

```
LIST_REQUEST = bytes(16) listId     random; the APP_LIST pages that answer it carry it

APP_LIST  = bytes(16) listId        the LIST_REQUEST's
          ‖ u8     page             0 … pageCount − 1
          ‖ u8     pageCount        1–255
          ‖ u8     count            apps on this page; 0 only when the whole list is empty (one page)
          ‖ count × ListedApp
ListedApp = AppRef
          ‖ text16 label            line, 0–100 code points, ≤ 400 bytes
          ‖ text16 installer        a package name, or empty when unknown or sideloaded
          ‖ u64    firstInstalled   time
          ‖ u8     state            1 = ALLOWED, 2 = BLOCKED, 3 = NEW (default-blocking blocked it and
                                    nobody has decided yet)
          ‖ u8     iconFormat       0 = none, 2 = RGBA8888, 16 × 16
          ‖ bytes  icon             1024 bytes when iconFormat = 2, absent when 0
```

- The protected phone answers only while management is on, and at most 4 times per guardian per hour; it ignores further requests, and the guardian keeps showing its last list. While management is off it answers with NOTICE MANAGEMENT_CHANGED (`enabled` = 0) instead, which corrects a guardian whose view is stale.
- The list holds every installed app the user installed or that has a launcher icon (G5), Killit excepted, sorted by package name and cut at 1000. `state` says whether the app is suspended now.
- Pages are filled in order, each as full as it fits (§10.1), and all carry the same `listId` and `pageCount`. A package appears once in the whole list. The guardian assembles the list once every page has arrived, drops a list that breaks a rule, and uses only the list it asked for last.
- Icons are 16 × 16, a quarter of a request's 32 × 32, so about seven apps fit on a page and a long list takes a few dozen envelopes rather than hundreds. They are raw pixels for the reason given in §11.2.

### 11.11 MANAGE

A guardian changes which apps are blocked.

```
body = u64 seq                      this guardian's counter in this pairing: starts at 1, only grows
     ‖ u8  count                    1–25
     ‖ count × ( AppRef app ‖ u8 desired )      desired: 1 = ALLOWED, 2 = BLOCKED
```

A package appears at most once in a MANAGE.

**The protected phone's rules** (PLAN.md §3.8, G2–G4, G7) apply only while management is on; otherwise a MANAGE is ignored. Commands are state-based: for each package the phone keeps the highest `seq` it applied from each guardian, and ignores an entry whose `seq` is not higher, so neither a replayed nor a reordered MANAGE can undo a newer one. Killit's own package is never changed. Each other entry:

- **BLOCKED** applies at once, whatever the certificate, since blocking is the stricter direction. The app is blocked, and stays blocked if it is reinstalled, and every guardian receives NOTICE APP_MANAGED (BLOCKED). If Android refuses to suspend the package, only the sender receives APP_MANAGED (REFUSED). An open request to unblock the package is answered too: as this guardian's denial if it hadn't decided yet (an UNBLOCK_APP then costs a chance, D4), and otherwise by cancelling it (WITHDRAWN).
- **ALLOWED** needs every guardian, and only counts for the app the guardian saw. The installed app must be signed by the entry's certificate and be blocked now, or the entry is ignored. Then:
  - an open request to unblock the package (UNBLOCK_APP or GUARDIAN_UNBLOCK) counts it as this guardian's approval, if it hadn't decided yet;
  - otherwise, with a single guardian, the app is unblocked at once, G7 resets its chances, and the guardian receives APP_MANAGED (UNBLOCKED);
  - otherwise the protected phone opens a GUARDIAN_UNBLOCK (§11.12) for it, which this guardian has already approved.

The protected user is told of every change (G4). A guardian's phone that knows of an open request for a package answers the request with a DECISION instead of putting the package in a MANAGE; the rules above settle the race in which it didn't know yet.

### 11.12 GUARDIAN_UNBLOCK

The relay of G2: one guardian's MANAGE is unblocking an app, and every other guardian must approve too. The guardians aren't paired with each other, so the protected phone, which they all trust, asks them on that guardian's behalf.

```
body = bytes(16) requestId
     ‖ AppInfo   app
     ‖ bytes(32) proposerFp         the guardian unblocking it
     ‖ text16    proposerName       that guardian's own name (§11.1), line 1–40
     ‖ u8        guardianCount      1–50: every guardian who must approve, the proposer included
```

Every guardian receives it, the proposer too, whose copy is already approved, so its phone shows the progress without Deny and Approve. The others decide with DECISION, whose target is the AppRef, and STATUS keeps every copy current, as for UNBLOCK_APP. When everyone has approved, the app is unblocked and G7 resets its chances. A denial closes it and costs no chance, because chances belong to the protected phone's own requests. It is cancelled when the proposer stops being a guardian (GUARDIAN_REMOVED), when management is turned off, and when the proposer blocks the app again (both WITHDRAWN). A package has at most one open request to unblock it, whichever kind it is.

### 11.13 HANDOVER

```
body = bundle    newBundle (162)    the phone that takes this side of the pairing over (§3.2)
     ‖ text16    deviceModel        its Build.MANUFACTURER + " " + Build.MODEL, line 0–64
```

The old phone of a move sends one HANDOVER for each of its pairings. It is signed with the old phone's key, which its pair already trusts, and that signature is what vouches for the new key (PLAN.md §3.10). The receiver checks that `newBundle`'s encSig verifies and that the new fingerprint is neither its own nor the sender's. From then on the pairing named in the header belongs to `fp(newBundle.signPk)`: its signing key, encryption key and device model are replaced, and everything else stays, the pair id, names and counters included. The new fingerprint's badge is different, as it should be (PLAN.md §3.2).

A protected receiver sends its open requests again, to the new phone, wherever the moving guardian hadn't decided yet, and forgets that pairing's MANAGE sequence numbers (§11.11): they counted the old phone's commands, whose key it no longer trusts, and the new phone counts afresh. It also tells its other guardians, with NOTICE GUARDIAN_MOVED (B6). A HANDOVER is never answered.

### 11.14 Moving to a new phone

Four messages travel between the two phones of a move, over the link their ceremony created (§6.5), in this order:

```
MOVE_REQUEST = text16 deviceModel       the new phone's, line 0–64
             ‖ bool   deviceOwner       whether it can take guardians: device owner, with a passkey,
                                        and not frozen by a move of its own

MOVE_STATE   = bytes(16) moveId         random, chosen by the old phone; the same on every page
             ‖ u8     page              0 … pageCount − 1
             ‖ u8     pageCount         1–255
             ‖ bool   appManagement     the old phone's management setting; 0 unless it has guardians
             ‖ u8     protection        its protection options: bit (option − 1) set for each one that is
                                        on, options as in NOTICE PROTECTION_CHANGED; 0 unless it has
                                        guardians. Bits 6 and 7 are 0.
             ‖ u8     pairingCount      pairings on this page
             ‖ pairingCount × MovedPairing
             ‖ u16    appCount          apps on this page
             ‖ appCount × MovedApp
MovedPairing = bytes(32) pairId
             ‖ u8     role              the old phone's side: 1 = GUARDIAN, 2 = PROTECTED
             ‖ bundle peer (162)
             ‖ text16 peerName          line, 1–40 code points: the peer's own name
             ‖ text16 nickname          line, 1–40 code points: what the old phone calls the peer (A5)
             ‖ text16 peerModel         line, 0–64 code points
             ‖ bool   appManagement     GUARDIAN: the peer's setting, as last heard; PROTECTED: 0
             ‖ u8     unpairChances     PROTECTED: 0–3 (G8); GUARDIAN: 0
             ‖ u64    createdAt
MovedApp     = AppRef
             ‖ u8     state             1 = ALLOWED, 2 = BLOCKED, 3 = NEW
             ‖ u8     chancesLeft       0–3 (D4)

MOVE_ANSWER  = bytes(16) moveId
             ‖ u8     answer            1 = READY, 2 = DECLINE
             ‖ u8     reason            0 with READY; with DECLINE: 1 = USER, 2 = NOT_DEVICE_OWNER,
                                        3 = HAS_PAIRINGS, 4 = INVALID

MOVE_DONE    = bytes(16) moveId
             ‖ u8     outcome           1 = COMMITTED, 2 = ABANDONED
```

1. **Once linked, the new phone sends MOVE_REQUEST.** If the old phone has guardians and `deviceOwner` is 0, it stops there: only a device owner can be protected (PLAN.md §4).
2. **The old phone sends MOVE_STATE**: every pairing, and, if it has guardians, its management setting, its protection options and its decisions about apps. Those are every package it has decided about except the approved ones of its own system image, with each one's chances.
3. **The new phone checks the pages and answers MOVE_ANSWER.** Every page carries the same `moveId`, `pageCount`, `appManagement` and `protection`; each page from 0 to `pageCount` − 1 arrives exactly once; pair ids and packages are unique across the pages; and every peer's bundle verifies, with no peer being the new phone or the old one. It answers READY and keeps the state staged, not yet in use, or DECLINE: USER when its user gave up, NOT_DEVICE_OWNER when the state has guardians it can't take, HAS_PAIRINGS when it has pairings already (a move needs a phone without any), INVALID when a page breaks a rule.
4. **On READY, the old phone waits for its user to confirm**, for at most 30 minutes. Then it asks the server to hand its links over (§7), withdraws its own open requests (STATUS, WITHDRAWN), sends a HANDOVER for every pairing, and sends MOVE_DONE (COMMITTED) last, in the same `POST /v1/messages` when everything fits. After that it forgets every pairing and deletes its identity and its registration (`DELETE /v1/devices/me`). If it had guardians, it stays frozen (PLAN.md §3.10): blocked apps stay blocked, and the only way out is releasing device owner. An old phone that gives up sends MOVE_DONE (ABANDONED) instead.
5. **On COMMITTED, the new phone puts the state in use**, and it sends nothing to its pairs before then. The old phone sent every HANDOVER before MOVE_DONE, so each pair's mailbox holds the HANDOVER ahead of anything the new phone sends it. On ABANDONED the new phone discards the state. After READY it waits for MOVE_DONE, and only an hour later may its user give up, when the old phone can no longer commit.

Putting the state in use makes the pairings the new phone's own. If they include guardians, the new phone also takes the old one's management setting, protection options (the clock always locked, I1) and chance counters, and keeps its decisions about apps (PLAN.md §3.10). Apps blocked on the old phone are blocked here, and approved ones stay approved. An app the user installed here that the old phone never decided about is blocked as new and announced as an install is (NOTICE APP_INSTALLED, D1). The new phone's own system apps stay as they were.

---

## 12. What the server stores and sees

| Table | Holds | Kept until |
|---|---|---|
| `devices` | fingerprint, `signPk`, security level and the attestation summary (§5.2), FCM installation ID, creation time, the date last seen | `DELETE /v1/devices/me` |
| `attestation_challenges` | the challenge | used, or 10 minutes |
| `seen_nonces` | device and nonce | 10 minutes |
| `invites` | code HMAC, creator, joiner, commitment, reveals, confirmations, state | 1 hour after finishing or expiring |
| `links` | the two devices, creation time | `DELETE /v1/links` or the device's deletion |
| `messages` | sender fingerprint, recipient, envelope, time received | acknowledged |

The server **never** has: roles, names, nicknames, device models, app names or packages, app lists, request kinds, decisions, explanations, or any decryption key. It does see who talks to whom, when and how often (PLAN.md §5.3), the security level of each phone, the public keys exchanged during pairing, and which phone handed its links to which when someone moved (§7). Logs carry no bodies, codes, tokens or IP addresses.

---

## 13. Limits

| Limit | Value |
|---|---|
| Envelope | exactly 8240 bytes (8192-byte plaintext) |
| Envelopes per `POST /v1/messages` | 50 |
| Messages per `GET /v1/messages` | 32 |
| Mailbox | 1000 messages per phone, 200 from any one sender |
| Links per phone | 50 |
| Request time window | ±300 s; nonces remembered 600 s |
| Attestation challenge | 10 minutes, single use |
| Invite | 15 minutes to join, then 15 minutes to finish |
| Long polls | 30 s |
| Push | at most one every 10 s per phone |
| App list (§11.10) | 1000 apps; 255 pages; 4 answers per guardian per hour |
| MANAGE (§11.11) | 25 apps per message |
| Move (§11.14) | 255 pages; 100 pairings and 4000 apps in all; 30 minutes for the old phone to commit after READY, an hour before the new phone may give up |

Rate limits are server configuration (defaults in `server/src/config.ts`), set per IP address and per device.

---

## 14. Test vectors

[`vectors/`](vectors/) holds JSON files. Byte strings are lowercase hex. Fixed test identities, derived from seeds, make every value reproducible. ECDSA signatures are randomised by nature, so a vector's signature is *a* valid signature: implementations must verify it, and must produce the same signed bytes, but can't be expected to produce the same signature.

| File | Covers |
|---|---|
| `identities.json` | Test phones A, B and C: private keys, `signPk`, `encPk`, `fp`, `bundle`, `encSig` |
| `encoding.json` | text rules (§1.3), package names (§1.4) and base64url (§1.1): accepted and rejected inputs |
| `api-auth.json` | `signedBytes` for sample requests, a signature, and tampered variants that must fail |
| `invite-code.json` | code bytes ↔ display form, and accepted and rejected inputs |
| `ceremony.json` | reveals, commitment, safety code and `pairId` |
| `hpke.json` | RFC 9180 A.1 and the `info` used by Killit |
| `messages.json` | every kind: the field values, `body`, `inner`, signature, padded plaintext and envelope; plus envelopes and bodies that must be rejected, and DECISIONs checked against stored requests |

Run `pnpm --filter @tamodak/protocol vectors` to regenerate them and `pnpm --filter @tamodak/protocol test` to check them.

---

## 15. Versioning

Version 1 is the header byte `version = 1`, the `-v1` labels, bundle version 1 and the `/v1` API. A change that breaks any of them increments all of them together. Killit has no users yet (decision K5), so until its first release this version is still edited in place rather than bumped.
