# tamodak.org — Website, pairing server, and Killit pairing plan

Status: **draft v12**. Every product decision so far is folded in (§3, §11). Use cases are in §13, edge cases in §14, the UI/UX design in §15, and the protocol in §16 and `protocol/SPEC.md`. No product questions are open. **Phases 1, 3, 4 and 5 are implemented**: Killit's default-blocking (2026-10-05); the protocol, the pairing server and its deploy stack (2026-10-12); and pairing in Killit, push included (2026-10-13). **`api.test.tamodak.org` is live** (2026-10-13), and tamodak.org shows a placeholder until Phase 2. Next is Phase 5b. See §11 and §12.

This covers three things that have to be designed together:

1. **Killit (app)**: default-block newly installed apps, then master/slave pairing with signed, end-to-end encrypted requests.
2. **Backend (Node.js + PostgreSQL)**: the rendezvous and mailbox server that pairing runs over. It only sees ciphertext.
3. **Frontend (Vue 3)**: the public tamodak.org site: who we are, what Killit is, and the privacy policy.

---

## 0. What Killit looks like today (relevant findings)

| Area | Current state | Consequence for this plan |
|---|---|---|
| Blocking | OS package suspension via `DevicePolicyController.applyBlocklist`. The suspended set *is* the blocklist, and nothing is persisted alongside it. | "Default-block new apps" needs a persisted **known/approved package set**, because suspension state alone can't tell "new" from "user unblocked it". |
| Install awareness | None. There is no receiver or service, and no `PACKAGE_ADDED` handling. | Has to be built (§1). |
| Network | **No `INTERNET` permission.** Today the app has zero remote attack surface. | Adding networking is the biggest security change Killit will ever make, so §6 is written around it. |
| Durable state | `DurableStore` holds the application restrictions, which survive Clear data. `LockPreferences` (DataStore) is the cache. | The pair list, key material references, the approved set, pending requests and unpair deadlines must go into **both** stores, per CLAUDE.md. |
| Prior pairing | The QR pairing was **deliberately removed** in `2cf8877` and won't be restored. | New code. The lesson worth keeping from it is that signed bytes must bind purpose, nonce, requester and signer, and that both ends must build those bytes from one shared spec. |
| Passkey hashing | `SHA-256(salt ‖ passkey)`, one iteration (`CredentialStore`). | A 6-digit PIN falls in milliseconds if the hash ever leaks. After pairing this passkey **authorises approvals for other people's devices**, so it matters more. Move to PBKDF2 (≥ 310k iterations) or Argon2id, with a record-format migration. |
| Release delay | `RELEASE_DELAY_MILLIS` = 3 days in release builds. | **Raise it to 14 days** (`1_209_600_000L`), as decided. |
| Hardening | Blocks uninstall, force stop, safe boot, factory reset and add-user, plus optional apps-control and date/time. | Add `DISALLOW_ADD_PRIVATE_PROFILE` (Android 15 Private Space) and verify `DISALLOW_ADD_MANAGED_PROFILE`, because apps in another profile are outside Killit's reach. The 30-day unpair timer relies on `blockDateTime`. Consider `DISALLOW_DEBUGGING_FEATURES` once pairing exists (see §6.1). |

---

## 1. Default-block new installs (app only, no server)

This ships first and has value on its own.

### 1.1 Data model

Add a persisted map, kept in both stores:

```
knownPackages: packageName -> { certSha256, status: APPROVED | PENDING | USER_BLOCKED, since }
```

- **Key approvals by package name *and* signing certificate digest.** Otherwise a sideloaded APK that reuses an approved package name inherits the approval. Updates signed by the same key, or by a key-rotation lineage via `PackageManager.hasSigningCertificate`, keep the approval.
- **Baseline.** When the feature is first enabled, snapshot everything currently installed as `APPROVED`, or as `USER_BLOCKED` if it's already suspended.
- Anything installed that isn't in `knownPackages`, or whose cert doesn't match, counts as **new**. It gets suspended immediately and marked `PENDING`.

### 1.2 Detecting installs

| Mechanism | Latency | Works when Killit is dead? | Notes |
|---|---|---|---|
| Manifest receiver for `PACKAGE_ADDED` | – | **No.** It isn't on the API 26+ implicit-broadcast exemption list. | Not usable alone. |
| Context-registered receiver (`PACKAGE_ADDED` / `REPLACED` / `CHANGED`) in a **foreground service** | ~ms | The service is kept alive. Force stop is already blocked, and DO apps are exempt from standby buckets. | **Primary path (decided).** Costs a persistent low-priority notification. |
| `getChangedPackages(seq)` + full diff against `knownPackages` | On each check | Catches up later | **Safety net.** Runs on `BOOT_COMPLETED` / `LOCKED_BOOT_COMPLETED`, on service start, on app open, and periodically. |
| `DISALLOW_INSTALL_APPS` | – | – | Too blunt, since it also blocks updates. Possibly a later "strict mode". |

The foreground service does double duty: once pairing ships, it's also where the slave's new-app request is sent from.

### 1.3 Edge cases

- **Disabled system apps that get re-enabled** (`PACKAGE_CHANGED`) count as new.
- **Updates** with a matching cert are not new. A cert mismatch is new.
- **Uninstall then reinstall** with a matching cert is not new.
- The **Play Store "Open" button** race is why the foreground service exists.
- The platform **refuses to suspend** some packages. Surface those, as the app list does now.
- **Private Space, work profiles and OEM "dual apps"** are restricted (§0).
- **Instant Apps** are a known gap.

---

## 2. Architecture principle: the server is a mailbox, not an authority

> **The phone that enforces the block is the only thing that can lift it, and it lifts it only after decrypting and verifying signatures from its masters' hardware-held keys. The server can never tell Killit to unblock, unlock, unpair, or change any policy, and it can't read what devices say to each other.**

- A **fully compromised server** can delay or drop messages, which is a denial of service (§6.4). It can't approve anything, can't read requests, and can't make Killit call a `DevicePolicyManager` API.
- The server stores **opaque, padded ciphertext**, routes it between devices that are paired, pushes content-free wake-ups, and rate-limits.

```
 Slave phone (DO)               tamodak.org API               Master phone
 ────────────────               ───────────────               ────────────
 event (new app / unlock /
        unpair)
 sign(approval key A)
 encrypt to each master  ──POST /messages──►  store ciphertext
                                               push "sync" ───►  wake, notification
                                                                 GET /messages
                                                                 decrypt, verify sig(pk A)
                                                                 gate → "Requests" → password
                                                                 approve / deny
                                                                 sign(key B), encrypt to A
                         ◄──GET /messages──   store ciphertext ◄──POST /messages
 decrypt, verify sig(pk B) ✔
 all masters approved? → apply locally
```

---

## 3. Pairing model

> **Terminology.** This plan says *master/slave*. The app UI says **Guardian / Protected** (decided, E5). Code may use either, as long as it's consistent.

### 3.1 Roles (decided)

- **Master:** approves requests for a slave's device. It **doesn't need Device Owner**: Killit is installed as an ordinary app and its pairing state lives in DataStore.
- **Slave:** a Device Owner device whose new apps and Killit lock are controlled by its masters.
- The relation is directed. A device can be master of B and slave of C, and mutual pairs are allowed.
- Either side can start a pairing and chooses the role in the invite.
- Every user sets a Killit password, as today.
  - **With at least one master**, the password no longer opens your own Killit. It only opens the Requests area, where you approve other devices and manage your pairs.
  - **With zero masters**, the password opens Killit exactly as today, and you block and unblock freely.
  - Apps blocked before the first pairing are just blocked apps. There's no special "pending" carry-over (A6).
- **Unanimity:** every master must approve every request.
- **No hard limit on the number of masters or slaves** (A3). The UI gives guidance instead:
  - With 1 master: "Adding a second master gives you more protection."
  - When adding a 5th or later: "More than 4 masters is rarely needed and makes every request harder to get approved."

  The server keeps a high technical cap (e.g. 50 links per device) purely against abuse.

### 3.2 Telling pairs apart (new, answers "a master with several slaves")

A master with three slaves has to know at a glance whose request it is. Three layers:

1. **A local nickname set by the receiving side.** During pairing, the slave proposes a name ("Ali's phone"), and the master can accept or edit it ("Ali — Samsung"). The **nickname is stored only on the master's device** and is what every notification and request shows. A slave **can't** rename themselves on the master's screen, so a child can't make their request look like their sibling's. The same applies the other way: a slave labels each of its masters.
2. **A fingerprint badge.** A small colour and shape pattern (an identicon) is derived from the pair's public key and shown next to the nickname. Two slaves with similar nicknames still look different, and the badge never changes unless the key does (for example after moving to a new phone, §3.10).
3. **Secondary line:** the device model (`Build.MANUFACTURER` + `MODEL`), sent inside the PAIR message, plus "last seen" (§3.11).

Notifications read, for example: **"Ali — Samsung wants to unblock Instagram."** They're specific enough to act on, and don't show the explanation (E4).

### 3.3 Messages

| Kind | Sent by → to | Rule | Effect |
|---|---|---|---|
| **PAIR** | Initiator → invitee, after the safety-code check (§4) | The invitee approves with their password | A link is added on both devices. The slave's existing masters get a NOTICE (A4). |
| **UNPAIR** (slave-initiated) | Slave → **all** its masters | **All masters approve** → the master is removed immediately. **Any master denies** → the request is cancelled and the timer stops. **No deny** within 30 days → removed by the slave's local timer. | The master is removed on the slave |
| **LEAVE** (master-initiated) | Master → slave (+ NOTICE to the slave's other masters) | **No approval, immediate** | The slave and the other masters are notified. **With zero masters left, the slave is free.** |
| **UNBLOCK_APP** | Slave → all masters | All approve. Asynchronous, no expiry. An explanation of 10–500 characters is required. **3 chances per app** (§3.6). | The app is unsuspended and becomes `APPROVED` |
| **UNLOCK_KILLIT** | Slave → all masters | All approve **while the slave is still waiting in Killit** (§3.4). One deny closes the request. | Killit opens with **full control** (§3.5) |
| **MANAGE** (optional feature, §3.8) | Master → slave | Only if the slave has **enabled** master app management | Remote block / unblock proposal |
| **APP_LIST** (optional feature, §3.8) | Slave → masters | Only if enabled | Keeps the masters' view of installed apps current |
| **HANDOVER** | Old device → pairs | Signed by the old key (§3.10) | Pairs replace the old key with the new one |
| CANCEL | Slave → masters | A live unlock was abandoned | Marked "cancelled" |
| NOTICE | Any → pairs | Informational only | Notification only |

### 3.4 UNLOCK_KILLIT is a live, in-app request (decided)

Unlocking is meant to be hard. The intended ritual:

1. The slave contacts every master first: "I want to open Killit, can you approve now?"
2. Each master answers: "Okay, send it."
3. The slave sends the request and **waits in Killit**.
4. Every master approves, and Killit opens.

Mechanics:

- The request carries a **session nonce that lives only in the process's memory** and is never persisted.
- When the waiting screen leaves the foreground (`onStop`), Killit sends CANCEL and discards the nonce. A later approval matches nothing and opens nothing, even if the CANCEL was lost.
- The **screen is kept on** while waiting (C1). There's **no maximum wait** while Killit is in the foreground (C2).
- **One deny closes the request** (C3). After a deny or cancel there's a **5-minute cooldown**, and **at most 6 unlock requests per day** (C4).
- The explanation is optional, since the unlock was agreed by voice (C5).
- The slave's app holds a long-poll/SSE connection while waiting. Masters are reached by FCM.
- **The masters' approval screen spells out what approving means:** "Approving gives Ali full control of Killit until they leave the app." (§3.5)

### 3.5 Inside an unlocked Killit: full control (decided)

**There's no timer. Leaving the app is the only thing that locks it again** (C6).

Inside the unlocked app **nothing needs approval**:

- unblock any app, including new ones (C7);
- change the password (C9);
- change hardening, turn master app management off (§3.8), move to a new phone (§3.10), and start the 14-day Device Owner release. Masters get NOTICEs for the release (C8).

This is deliberate:

- **Adults** configure their own Killit freely, but only when their masters let them in.
- **Parents** can open their child's Killit to set it up, while the child can't open it on their own.

This is exactly why unlocking is live, unanimous, and has a wider Deny button.

**One exception (G1): removing masters.** It always follows the UNPAIR rules (all approve, any deny cancels, otherwise 30 days), even when unlocked. Otherwise a child could ask for an unlock "to change one setting" and remove both parents.

When the slave resolves something directly (e.g. unchecks an app that has an open request), that request is closed automatically and the masters are told "resolved by unlock" (G11).

### 3.6 UNBLOCK_APP flow (decided)

1. The app is installed and **blocked at once** (§1). The masters get a NOTICE: "Ali — Samsung installed TikTok (blocked)" (D1).
2. The slave gets a local notification: "TikTok was blocked. Ask your guardians to allow it."
3. The slave writes an explanation of **10–500 characters**, counted after trimming. The password is entered on entering *My phone* (J1), and nothing further is needed to send it. Each package can have **only one open request** at a time.
4. **Each app gets 3 chances** (D4):
   - A *denied* request uses up a chance. The UI shows "2 of 3 requests left", so they can be used wisely.
   - There's no waiting period between requests.
   - The counter is kept in both stores and survives uninstalling and reinstalling the app, so reinstalling can't reset it.
   - After 3 denies, the only way is UNLOCK_KILLIT, then unchecking the app in the list (§3.5).
5. Once every master approves, the app unblocks, whenever that happens. There's no expiry.
6. **Reminders:** each master gets one daily digest notification in the daytime (e.g. 10:00 local) while any asynchronous request is still waiting for them (D9). Live unlocks never need reminders.
7. Several apps installed at once produce one request per app and **one grouped notification** (D10).
8. An approved app that's uninstalled and reinstalled with the same signing certificate stays approved (D6).
9. **Every new package counts**, including keyboards, VPNs and launchers (D8).

### 3.7 Blocking more apps without unlocking (decided, D7)

Blocking is the stricter direction, so a slave can do it without the masters, from **Requests** (with their password):

- They pick the apps and get a confirmation: *"You won't be able to unblock these yourself. Unblocking will need your guardians' approval."*
- The **Cancel** button is wider than Confirm (60/40), matching the approval UI.
- Once blocked, the app follows the normal rules: UNBLOCK_APP with 3 chances, or UNLOCK_KILLIT.

### 3.8 Master app management: optional, off by default (decided: D5, G2–G5)

**What it does:** a master can see the slave's apps and change **one thing only: the block status of the apps in that list**.

**Pull, not sync:**
1. The master taps "Manage apps".
2. A LIST_REQUEST goes to the slave.
3. The slave replies with an E2E-encrypted APP_LIST: label, package, installer, install date, blocked or allowed, and a small icon. It covers user-installed apps plus system apps with a launcher icon (G5).
4. The master changes the block status of apps in that list and sends a MANAGE message.

Nothing is streamed continuously.

**Quorum (G2):**
- **Block:** any single master, applied immediately.
- **Unblock:** needs **every** master, and becomes a request to the others:
  1. Master A's signed MANAGE (unblock) goes to the slave.
  2. The slave **acts as coordinator**. It forwards a request to every other master, signed by the slave, notified as *"Guardian A is unblocking Instagram for Ali — Samsung. It needs your approval too."*
  3. Once all the others approve, the slave unblocks.

  The other masters aren't paired with each other and have no keys for each other, so the slave's device, which they already trust, does the relaying. "Guardian A" is A's own display name plus A's badge; the slave's nickname for A isn't used, because the slave could edit it.
- **With one master,** both block and unblock are immediate.
- The slave is **always** notified of a change (G4).

**Toggle (G3):** only **inside the unlocked Killit**, in both directions. There's no shortcut from Requests. It's shown during pairing, so both sides know what they're agreeing to.

**Security.** This is the only place the network can *initiate* a change:
- **Only suspend or unsuspend a named package.** There's no uninstall, hardening, release, wipe, password or toggle change. The whitelist lives in one function (`RemoteEffects.apply`).
- Commands are **state-based**: "desired state of `pkg` + cert = BLOCKED, seq = 17". Every master has a monotonic sequence number, so replayed or reordered commands are harmless.
- A master's unblock of an app counts as an approval route, so it resets that app's chance counter (G7).

### 3.9 Approval UI (decided)

- **Deny 60% · Approve 40%, with Deny on the left** (E1). It mirrors to the right in Arabic (RTL), because Android's start-side convention keeps it on the reading-first side.
- No hold-to-approve or extra step (E2). The wider Deny button and the password are enough friction.
- The password is entered once per visit to Requests (E3).
- Each request shows the nickname and badge, the request kind, the app details (§5.4), the explanation, the time, and "waiting now" for live unlocks. An unlock request also shows what approving means (§3.4).

### 3.10 Moving to a new phone (answers B4, first half)

**Why it's needed.** A device's identity is a key locked inside that phone's secure hardware, and it **can't be copied**. A new phone means a new key, and without help every pair would have to pair again with a new safety-code call.

**Handover, when the old phone still works:**
1. On the new phone, install Killit, set a password, and choose "I'm moving from another phone". It shows a one-time code.
2. On the old phone, enter that code. The old phone signs a **HANDOVER** statement with its old key: "my identity is now this new key", and it's sent end to end to every pair.
3. Each pair checks the signature with the **old key it already trusts**. It swaps in the new key automatically and shows a NOTICE ("Ali — Samsung moved to a new phone"). No new safety-code call is needed, because the trusted old key vouched for the new one.
4. The old phone deletes its pairing data.

**Where it lives:**
- **Master:** from Requests (with password), since a master moving doesn't weaken anyone.
- **Slave:** only **inside the unlocked Killit**. Otherwise a slave could "move" to a spare phone and leave their real phone with zero masters, which is free. The new slave phone also needs Device Owner (a factory reset) before it can be the target.

**When the old phone is lost:** there's nothing to sign with, so it's handled as a fresh start.
- A lost **master** pairs again from its new phone (a new PAIR with a safety code). The slave removes the dead key with an UNPAIR. The dead key can't deny, so the 30-day timer runs out, or the other masters approve it sooner.
- A lost **slave** phone simply sets up again.

### 3.11 Last seen (decided, B4 second half)

- The server already records each device's last contact. `GET /v1/links` returns it for linked devices only, **rounded to the day** ("today", "3 days ago") to keep the metadata coarse.
- It's shown on the Pairs screen, so a slave can tell a master who has gone quiet from one who is just slow.

### 3.12 Escape hatches (updated for B1/B2)

| Situation | Way out |
|---|---|
| A master wants out | LEAVE, immediately |
| Every master agrees to unpair | Immediate |
| A master is gone (lost phone, uninstalled Killit) | 30 days, because a vanished master can't deny |
| **A master actively denies the unpair** | **None inside Killit.** By design (B2), this is what makes parental use work. |
| Last resort | A factory reset from **recovery mode** (the hardware buttons). `DISALLOW_FACTORY_RESET` blocks the Settings reset, not the recovery wipe on most devices. Every piece of data is lost. |

**Pairing warning (G14, decided).** A required checkbox on the slave side, and the same text on the website:

> *Only pair with people you know well and have met in real life. If a guardian refuses to unpair, you can only leave by wiping the phone.*

Users are expected to pair with people they trust, so abuse isn't the design case. The warning is there to explain how Killit behaves.

---

## 4. Remote pairing ceremony (the only pairing method)

A remote code alone isn't enough, because whoever runs the server could put themselves in the middle. So the two people check a short safety code on a call, and the protocol makes sure the server can't cheat that code:

1. **A** taps "Add pair" and chooses a role ("be my master" or "let me be your master"). The server issues an **invite code**: 40-bit random, Crockford base32 such as `K7QX-M2PD`, single use, expires after 15 minutes, stored **hashed**, rate-limited per IP and per device.
2. A gives B the code over any channel.
3. **B** enters the code and uploads `commit = SHA-256(pkB_bundle ‖ nB)`, **before** seeing A's keys.
4. **A** uploads `pkA_bundle ‖ nA`.
5. **B** reveals `pkB_bundle ‖ nB`. A checks it against the commit.
6. Both phones show `SAS = HMAC-SHA256("KILLIT-SAS-v1", pkA ‖ pkB ‖ nA ‖ nB) mod 10⁶` as 6 digits. **The users compare them over a call.** Because the server had to commit before learning the other side's nonce, it gets one guess in a million, not unlimited tries.
7. If the digits match, A confirms. That sends a signed and encrypted **PAIR** request to B, which B approves under Requests with their password.

A *bundle* is the signing key plus the encryption key (§5.1).

Other notes:

- A device can only become a **slave** if Killit is Device Owner. Being a master doesn't require it (§10, Q2).
- A person can pair their own second phone as their own master. That's the one trust decision Killit can't police. Key attestation (§6.3) rules out emulators and scripts, but not a second real phone. Document it honestly.

---

## 5. End-to-end encryption (v1 requirement)

### 5.1 Keys per device

| Key | Where | Purpose |
|---|---|---|
| `sign` (P-256 ECDSA) | **Android Keystore**, StrongBox→TEE, non-exportable | Signs every request, response and pairing statement, and authenticates API calls. It's the authority key, so it lives in hardware. |
| `enc` (X25519, HPKE) | Software, via **Google Tink**'s `AndroidKeysetManager`, with the keyset **encrypted by a Keystore AES-GCM master key** | Decrypts messages to this device. Keystore ECDH (`PURPOSE_AGREE_KEY`) needs API 31 but minSdk is 26, so hardware agreement isn't available everywhere. Leaking this key would expose message *contents*, not authority. |

A signing key can't be regenerated silently. If Clear data or a reinstall on a master loses its keys, the slave rejects that master's signatures, and the pair re-pairs. A slave's keys are protected by the existing Clear-data hardening.

### 5.2 Message construction

**Sign then encrypt.** Inside the envelope:

```
inner  = kind ‖ version ‖ requestId(16B) ‖ senderFp ‖ recipientFp ‖ body(kind-specific) ‖ createdAt
sig    = ECDSA-P256(sign_key_sender, "KILLIT-MSG-v1" ‖ inner)
env    = HPKE-seal(enc_pk_recipient, info="KILLIT-ENV-v1" ‖ senderFp ‖ recipientFp,
                   pad_to_bucket(inner ‖ sig))
```

- **The request kind lives inside the ciphertext.** The server can't tell an UNLOCK from an UNBLOCK_APP from an UNPAIR.
- **Pad to fixed buckets** (e.g. 1 KB and 4 KB) so message sizes don't give the kind away either.
- **A response binds** `requestId ‖ requesterFp ‖ signerFp ‖ kind ‖ target (package + certSha256, or the pair id) ‖ decision`. The slave rebuilds the bytes from **its own stored request**, never from what the response claims. It verifies against the stored master key, and a `requestId` is consumed exactly once. That stops replay across requests, devices, apps or reinstalls, and stops one master being counted twice.
- A request is fanned out as one envelope per master.

### 5.3 What the server still learns

It sees **who talks to whom, when, and roughly how often**: device IDs, pairing links and timestamps. It never sees app names, request kinds, decisions or labels. State that in the privacy policy.

### 5.4 Limits of what a master sees

A master sees the label and icon supplied by the slave's device, and a malicious APK can call itself "Calculator". So UNBLOCK_APP shows:

- the label,
- the **package name**,
- the installer (Play Store vs. sideloaded),
- a "View on Play Store" link built from the package name.

The UI should say the master is approving *a package*, not a verified identity.

---

## 6. Security analysis

### 6.1 Adversaries

| Adversary | Capability | Main defences |
|---|---|---|
| **The slave user, in a weak moment** (primary) | Physical access, their own password, adb if enabled, a second phone, a master's phone left lying around, patience | DO hardening, the durable stores, unanimous masters, the password no longer opening a slave's own Killit, live in-app unlock, cert-bound approvals, 3 chances per app, UNPAIR needing all masters with any deny cancelling it, slave handover only while unlocked, nicknames the slave can't set on the master side, the private-profile restriction. Approvals on a master's phone need the master's own Killit password. Consider `DISALLOW_DEBUGGING_FEATURES`: with the password gone, adb becomes the obvious place to look. |
| Network attacker | MITM, DNS spoofing | TLS, and E2E signing plus encryption: MITM can only cause DoS |
| **Compromised server** | Full DB and code control | Mailbox-only design (§2), E2E encryption (§5), and the SAS commit-reveal (§4). What remains is metadata and DoS. |
| Other apps on the device | Send intents, bind to exported components | Add **no** new exported components except the FCM service, which Google gates. Notifications open the gate and carry no actions. |
| Malicious or abusive master | Withholds approvals, denies unpairing, and (with management on) sees and controls the slave's apps | **By design (B2) a master can veto unpairing**, so in that case the only way out is a recovery-mode wipe (§3.12). Mitigations: management is **off by default** and visible at pairing; the slave gets a **required warning checkbox** (G14); the slave sees every remote change (G4); nothing beyond apps is ever visible (no usage, location or messages). **Coercive-control risk** has to be stated on the website. |
| Stolen master phone | Can approve for its slaves | Approvals need the master's Killit password, with the existing backoff/lockout. That's another reason the stronger KDF is required. |
| Fake clients | Scripts or emulators on the API | Key attestation at registration, signed requests, rate limits |
| **Supply chain** | Swaps the Killit APK on the website | *Critical:* a malicious DO APK owns the device. See §6.5. |

### 6.2 Rules for Killit's network code (Device Owner-specific)

1. **The complete list of effects network input can have:**
   - (a) unsuspend a package after every master approved this device's own request;
   - (b) open the gate for a live session whose in-memory nonce still exists (§3.4);
   - (c) **only if the slave enabled management:** suspend or unsuspend a named package on a master's signed, sequence-numbered command, with the quorum from G2;
   - (d) change the local peer list (PAIR, UNPAIR, LEAVE, HANDOVER).

   One function (`RemoteEffects.apply`) holds this whitelist.
2. There is never a remote command for anything else: no hardening changes, uninstall, release, wipe, password change, or management toggle.
3. **One class owns networking** (`net/ApiClient`), and one class owns the envelope crypto (`pairing/Envelope`), in the same way `DevicePolicyController` owns DPM.
4. **Decoding is strict and total:** fixed schemas, a hard size cap before decryption, and decoders that never throw. No reflective JSON binding of untrusted input, no `WebView`, no dynamic code loading.
5. HTTPS only, with `cleartextTrafficPermitted=false`. Certificate pinning is optional, because E2E already covers integrity and confidentiality.
6. **Push messages carry no content**, only "sync".
7. Never send, log or derive anything network-visible from the password hash or salt. Never log envelopes or plaintext bodies.
8. **Shared test vectors** in `website/protocol/`: JSON test cases (payload bytes, signatures, SAS) consumed by the Kotlin tests *and* the Node tests. The server only needs the API-auth and SAS-transcript parts, but keeping one spec stops drift.

### 6.3 Server-side authentication

- **Registration:** the device generates its `sign` key with `setAttestationChallenge(serverNonce)` and sends the chain. The server verifies:
  - the chain to Google's roots, plus the revocation list at `android.googleapis.com/attestation/status`;
  - the challenge;
  - `attestationApplicationId`, which must be `org.tamodak.killit` with **our signing cert digest**;
  - a security level of TEE or StrongBox.

  Record the verified-boot state without rejecting on it.
- **Per request:** send headers `device-id`, `ts`, `nonce`, and a `sig` over `method ‖ path ‖ ts ‖ nonce ‖ SHA-256(body)`. The server accepts a ±5 minute window and rejects a nonce it has already seen. There are no bearer tokens. In Node: `crypto.verify('sha256', data, {key, dsaEncoding: 'ieee-p1363'}, sig)`.

### 6.4 Availability is now a security property

A slave **can't open its own Killit** while the server is unreachable, and can't get new apps approved. So:

- The 30-day unpair is **purely local**. It's the guarantee that the server going away never locks anyone in for good.
- Monitor uptime with an external checker, keep a documented rebuild runbook, and take backups (§6.6).
- **Oracle reclaims idle Always Free compute** (very low CPU, network and memory over 7 days). Watch for it.
- The API hostname is baked into the app, so moving hosts means a DNS change, not an app update.

### 6.5 Distribution and supply chain

- Killit isn't on Google Play, so **the first install is the moment of greatest risk**. Android's signature check protects every update after that.
- Publish the **signing cert SHA-256** on the site, the GitHub README, and GitHub Releases. Document `apksigner verify --print-certs`.
- **The release keystore never touches the Oracle server.**
- Serve `/.well-known/security.txt`.

### 6.6 Server hardening (Oracle free tier)

- SSH with keys only and no root login. Automatic security updates. fail2ban or CrowdSec.
- **Two firewall layers:** the OCI security list *and* the instance's iptables (Oracle's Ubuntu images are restrictive by default). Open only 22 (limited by IP), 80 and 443.
- Postgres is on the Docker network only, with a least-privilege app role and a separate migration role.
- Secrets live in an env file outside git, with mode 600.
- Nightly encrypted `pg_dump` to OCI Object Storage, with a tested restore.
- Schema validation on every route, body size limits, rate limits per IP and per device, Helmet headers, and pino logs **without bodies**.

---

## 7. Push delivery

| Option | Pros | Cons |
|---|---|---|
| **FCM data message ("sync" only)** | Reliable, battery-friendly, and works for masters with no foreground service | Needs Google Play Services and a Firebase project. Google sees that a message arrived, but nothing else. |
| UnifiedPush / self-hosted **ntfy** | No Google | The user needs a distributor app. Less reliable under Doze. |
| WorkManager polling (15 min minimum) | Zero infrastructure | Slow |

**Decided:** use FCM "sync" tickles, plus a long-poll/SSE connection while a slave waits on the live unlock screen, with polling on app open and WorkManager as a fallback. Add UnifiedPush later, as the Google-free flavor for F-Droid (G13). There are no request deadlines, so a missed push only means a delay, never a lost request.

---

## 8. Backend design (`website/server`)

**Stack:** Node 24 LTS, TypeScript, **Fastify**, `pg` + **Kysely**, `node-pg-migrate`, pino, `@fastify/helmet`, `@fastify/rate-limit`, `pkijs`/`asn1js` (attestation), and Vitest. Push uses the FCM HTTP v1 API directly, without `firebase-admin` (L2). The server has **no decryption code at all**: it imports only the protocol package's API entry point, and a test fails if any server source imports anything else from it.

`protocol/SPEC.md` defines the API (§4–§9) and what the server stores (§12) precisely. This section is the summary.

### 8.1 API (v1)

| Method & path | Purpose |
|---|---|
| `POST /v1/register/challenge` | Get a nonce for key attestation (unsigned) |
| `POST /v1/devices` | Register: the attestation chain, signed with the new key itself |
| `GET /v1/devices/me` | The phone's own record |
| `PUT` / `DELETE /v1/devices/me/push` | Set or clear the FCM installation ID |
| `DELETE /v1/devices/me` | Delete the device and all its data |
| `POST /v1/invites` | Create a pairing invite: the code and its expiry |
| `POST /v1/invites/join` | Join by code, uploading B's commitment |
| `GET /v1/invites/{id}` | Follow the ceremony, with a long poll (`wait`, `known`) |
| `POST /v1/invites/{id}/reveal` | `pkA‖nA`, then `pkB‖nB`; the server enforces the order and checks B's against its commitment |
| `DELETE /v1/invites/{id}` | Cancel ("They don't match") |
| `POST /v1/links` | Confirm the safety code; the link exists once both have. **Routing only:** the phones decide pairing state. |
| `GET /v1/links` / `DELETE /v1/links/{peer}` | List links with "last seen", or remove one |
| `POST /v1/links/handover` | Moving phones (§3.10): copy the old phone's links to the new phone it linked with |
| `POST /v1/messages` | Send envelopes to linked phones |
| `GET /v1/messages` | Fetch the mailbox, with a long poll (`wait`) |
| `POST /v1/messages/ack` | Acknowledge, after which the server deletes |
| `GET /healthz` | Liveness check |

### 8.2 Schema (Postgres)

`server/migrations/` holds it. It has six tables: `devices` (fingerprint, attested key, security level, attestation summary, FCM installation ID, the *date* last seen), `attestation_challenges`, `seen_nonces`, `invites` (code HMAC, participants, commitment, reveals, confirmations), `links` (one row per pair of phones), and `messages` (sender fingerprint, recipient, the 8240-byte envelope).

- There's **no `kind` column**, no role, and no encryption key: the server can't know them.
- Unacknowledged messages stay until they're acknowledged, since requests have no expiry. A cap per recipient and per sender, and a per-device rate limit, stop abuse.
- A periodic job purges expired challenges and nonces, and invites an hour after they end.

---

## 9. Frontend (`website/web`)

- **Vue 3 + Vite + vite-ssg** (static pre-rendering) and `vue-i18n` in **all 9 Killit languages**: en, tr, de, es, fr, pt, ru, ar (RTL) and id. Note the web uses `id` where Android uses `in`. Pages are pre-rendered per language (`/tr/`, …) with `hreflang`. The first visit to `/` picks the language from `navigator.languages`, falling back to English, and a manual choice is remembered (G15). Plain CSS in Killit's visual language: dark, green means protected.
- **Pages:**
  - Home: tamodak, a 2-person digital wellbeing and safe internet organisation.
  - Killit: how Device Owner blocking works, how Guardian/Protected pairing works, parental use vs. adult self-control, and honest limitations: the 14-day release, the 30-day unpair, a denied unpair meaning a wipe, and what a guardian can and can't see.
  - Install guide: Shizuku, QR provisioning and adb, plus the factory-reset warning.
  - Download: a link to **GitHub Releases** (open source), the SHA-256, the signing cert fingerprint, how to verify them, and the source repository.
  - About / Contact.
  - **Privacy policy** (KVKK/GDPR): what the server sees (metadata) and what it can't (anything E2E).
  - `security.txt`.
- No trackers and no third-party scripts, with a strict CSP.

---

## 10. Repo layout and deployment

```
website/
  PLAN.md
  protocol/          SPEC.md, its TypeScript reference implementation (src/), and the JSON test vectors
                     (vectors/) that Killit's tests and the server's tests both check
  server/            Fastify API: src/{attestation,db,jobs,push,routes}/, migrations/, test/, Dockerfile
  web/               Vue 3 + vite-ssg site (Phase 2, built last)
  deploy/
    compose.yaml     caddy + api + migrate + postgres + backup, every image built on Ubuntu 24.04
    Caddyfile        api.test. now; tamodak.org · api. · test. at the cutover (I2)
    caddy/ postgres/ backup/     the images' Dockerfiles and scripts
    scripts/new-secrets.sh       creates the secret files, each owned by the one container that reads it
    RUNBOOK.md       provision, deploy, back up, restore, update, rotate secrets
```

- The server is **Ubuntu 24.04 LTS on an Always Free shape**: today the AMD `VM.Standard.E2.1.Micro` (x86_64, 1 GB, N1); the Ampere A1 (arm64) is the roomier choice. It runs the stack with **Docker, on images built from Ubuntu 24.04** (L4). The images are built on the server itself, so natively for its architecture.
- Every container runs as its own non-root user, from a read-only filesystem, with no capabilities. Only Caddy publishes ports (80 and 443), and the database sits on an internal network with no route out.
- **Cutover:**
  1. Stand up `api.tamodak.org`, `test.tamodak.org` and `api.test.tamodak.org`. `api.test` came first (RUNBOOK.md), on 2026-10-13.
  2. When the site is ready, point `tamodak.org` at `web/dist`, in place of the placeholder page (N2).
  3. **Delete the blog** (F4): done on 2026-10-13, ahead of the site, since nothing used it (N2).

---

## 11. Decisions

### Settled

**2026-09-28**
- Roles are master and slave, directed, and one device can hold both. A slave's password stops opening its own Killit.
- Every master must approve.
- The release delay goes from 3 days to 14 days.
- Pairing is remote only, with no QR. Everything is end-to-end encrypted in v1.

**2026-09-30, round 1**
- A master can leave immediately. With zero masters the slave is free.
- A master doesn't need Device Owner.
- FCM and a foreground service are used.
- UNLOCK_KILLIT is live and in-app.
- UNBLOCK_APP needs an explanation of at least 10 characters.
- The Deny button is wider.

**2026-09-30, round 2**

| # | Decision |
|---|---|
| A1 | Either side can start a pairing and choose the role |
| A2 | Mutual pairing is allowed |
| A3 | No limit on masters or slaves. The UI recommends 2 and warns above 4. A high technical cap applies server-side. |
| A4 | When a new master is added, existing masters are notified. They don't have to approve. |
| A5 | Pairs are told apart by a nickname set by the receiving side, plus a fingerprint badge and the device model (§3.2) |
| A6 | No "pending" carry-over at the first pairing |
| A7 | The safety-code call is guided, and both sides must confirm |
| B1 | A slave's UNPAIR needs **all** masters to approve |
| B2 | **Any deny cancels the 30-day timer** |
| B3 | A slave can cancel their own UNPAIR |
| B4 | Handover to a new phone as in §3.10. "Last seen" is shown, rounded to the day. |
| B5, B6 | Other masters are notified when a master leaves or moves |
| C1–C4 | The screen stays on while waiting; no maximum wait; one deny closes the request; 5-minute cooldown and at most 6 unlock requests a day |
| C5 | The explanation for an unlock is optional |
| C6, C7, C9 | Unlocked means full control with no timer. Leaving the app locks it again. |
| C8 | Masters are notified when a release starts and when it completes |
| D1, D2, D3 | Masters are notified at install. Sending a request needs no *extra* password; *My phone* itself asks for one (J1 replaced D2). Explanations are 10–500 characters. |
| D4 | **3 chances per app.** Only denies count, and there's no waiting period. After that, the only way is unlock. |
| D5 | Master app management is **optional**; the slave toggles it inside the unlocked Killit |
| D6, D8, D10 | Reinstalling with the same cert keeps the approval. Every package counts. One request per app, with grouped notifications. |
| D7 | A slave can block more apps without unlocking, after a confirmation stating it can't be undone alone (Cancel is wider) |
| D9 | Masters get one daytime reminder a day while requests are waiting |
| E1–E4 | Deny 60 / Approve 40, Deny on the left (mirrored for RTL). No hold-to-approve. Password once per visit. Notifications read "Ali — Samsung wants to unblock Instagram". |
| E5 | The UI says "Guardian / Protected" |
| F1 | No user accounts, only device identities |
| F2 | Killit is **open source**: GitHub Releases, published signing fingerprints |
| F3 | The website ships in **all 9 Killit languages**, uses the browser's preferred language, and falls back to English |
| F4 | The old blog is deleted |
| F5 | Minimum Android stays at 8 (API 26) |

**2026-09-30, round 3**

| # | Decision |
|---|---|
| G1 | Removing masters always follows UNPAIR, even when unlocked |
| G2 | Block by any one master. Unblock needs every master, with the slave relaying a request to the others ("Guardian A is unblocking Instagram for B. It needs your approval too.") |
| G3 | The management toggle lives only inside the unlocked Killit |
| G4–G13, G15 | As recommended: slave notified of remote changes; launcher-visible apps; the master set is recounted; chances reset only on unblock; 3 UNPAIR chances with an explanation; optional deny reason; masters see each other's decisions; auto-resolve on unlock; hardware attestation required; official builds only; per-language URLs |
| G14 | A pairing warning with a required checkbox, including "only pair with people you know and have met in real life" |
| — | Management is **pull-based**. The master requests the list, the slave sends it, and the master edits only the block/unblock list (§3.8). |
| — | **Every waiting period is 3 seconds in debug builds** (see below) |

### Durations per build type (decided)

Every wait is a `BuildConfig` field in Killit, following the existing `RELEASE_DELAY_MILLIS` pattern. Server-side values come from environment config.

| Wait | Release | Debug |
|---|---|---|
| Device Owner release delay | 14 days | 3 s |
| Slave UNPAIR timer | 30 days | 3 s |
| Unlock cooldown after a deny or cancel | 5 min | 3 s |
| Master reminder | daily, daytime | 3 s after the request, once |
| Unlock requests per day | 6 | unlimited |
| Silence alert (H8) | 7 days | 3 s |

**Not shortened in debug**, because they are windows the user has to *act within*, and 3 seconds would make them unusable:
- the invite code lifetime (15 min),
- the attestation challenge,
- the ±5 minute signed-request window.

**2026-09-30, round 4**

| # | Decision |
|---|---|
| H1 | **No first-launch role question.** Both roles are always available and can be combined later in any order. The Hub has *My phone* and *Phones I guard* (§15). |
| H2 | adb / developer options are turned off automatically while a phone has guardians |
| H3 | **No extra timer protection.** The existing "Block date & time changes" hardening covers clock changes (see I1 for the one gap) |
| H4 | Auto-approve non-launchable system packages, static libraries and overlays. Block everything else that's new. |
| H5 | No emergency bypass. Onboarding advises approving essential apps before the first pairing. |
| H6 | Guardians are notified of hardening-off, management-off and release |
| H7 | Releasing Device Owner removes all guardians and notifies them |
| H8 | Silence alert after 7 days offline. Offline phones are usually harmless, but guardians should know. |
| H9 | Notification permission is required on guardian phones, and battery exemption is requested |
| H10 | Fix the lock-on-leave holes (explained below) |
| H11, H12 | Uninstalling a pending app cancels its request without using a chance. An incoming call cancels a live unlock. |
| H13 | **A password reset must exist.** Banning it only hurts the honest guardian. If a child knows Mom's password, Mom changes it. Mechanism: see I3. |
| H14 | **One domain (`tamodak.org`).** The test server lives under `/test/` (see I2) |
| — | Wording fix: a guardian can only change **the block status of the apps in the list** (§3.8) |

### H10 explained: how leaving the app can leave Killit unlocked today

`MainActivity.onStop` calls `KillitViewModel.lockOnBackground()`. There are three ways the lock doesn't happen, or is undone:

1. **The `busy` exception.** `lockOnBackground` returns early while `busy` is true. That exception exists so the **Shizuku permission prompt** (another app's screen) doesn't re-lock Killit mid-provisioning. But `busy` is also true during a password check, password setup, **Save** and **Device Owner release**. If you leave the app during a Save, `onStop` fires, the lock is skipped, and it isn't retried later. You come back hours later and Killit is still open.
2. **A late success after leaving.** `submitGate` and `setCredential` set `authenticated = true` and `screen = Home` when the coroutine finishes. If the app was left in the meantime, the session is unlocked *in the background*. The unlock waiting screen will have the same shape: an approval landing after the user left.
3. **The snapshot overwrite in `save()`.** `save()` reads `snapshot = _state.value`, then *later* (the coroutine starts on the next main-thread frame) writes `snapshot.copy(busy = true, …)`. If `onStop` locks in between, that write puts back the snapshot's `screen = Apps` while `authenticated` is false. The window is tiny, but it's real.

**Fix, in phase 1:**
- **Replace the `busy` exemption with a dedicated `awaitingExternalScreen` flag,** set only around `shizuku.requestPermission()`. That flow only runs *before* Device Owner exists, so it can never apply to a protected phone with guardians. `lockOnBackground` then locks unconditionally otherwise. A Save or release that is running keeps running in `viewModelScope` and finishes correctly behind the gate.
- **Unlock only while in the foreground.** Every path that sets `authenticated = true` (password success, password set, and later the all-approved unlock) first checks that the activity is at least `STARTED`. If it isn't, the result is thrown away. For the live unlock, that's the same rule as the in-memory nonce.
- **Never write back a whole snapshot.** `save()` uses `_state.update { it.copy(busy = true, …) }` and keeps the snapshot only for *reading* the selection.
- Add an instrumented test: start a Save, send the activity to the background, bring it back, and expect the Gate.

**2026-09-30, round 5**

| # | Decision |
|---|---|
| I1 | While a phone has at least one guardian, "Block date & time changes" is **on and greyed out**, with "Required while you have guardians" |
| I2 | **Subdomains**, which are free with the domain you own (just DNS records, and Caddy gets the certificates automatically). `tamodak.org` is the site, `api.tamodak.org` the API, `test.tamodak.org` the test site and `api.test.tamodak.org` the test API. |
| I3 | **No password reset feature.** Today's "change password after unlocking with the current one" stays. Protecting the password is the guardian's responsibility. When a phone first takes the guardian role, a clear explanation is shown (§15.11). |
| I4–I7, I9–I11 | As recommended: the Hub names; counts before the password, never names; the role follows from where you start; an inline optional deny note; a local 90-day history; the onboarding flow; three sections on the Apps screen |
| I8 | Reworded, see J1 |

**2026-09-30, round 6**

| # | Decision |
|---|---|
| J1 | **One password at the door (option B).** Every part of the app asks for the phone's Killit password first: *My phone* (locked or not) and *Phones I guard*. The protected user knows their own password, so they can use every action. Nobody else holding the phone can do anything. Keeping the password private is the user's responsibility. This **replaces D2** ("sending a request needs no password"). |

No product questions are open. Next: the protocol and API specification (§16).

**2026-10-05, implementing Phase 1**

| # | Decision |
|---|---|
| K1 | The passkey is hashed with **Argon2id** using RFC 9106's second recommended parameters (t=3, p=4, m=64 MiB, 128-bit salt, 256-bit output), through the Argon2 reference C implementation (argon2kt). The platform's PBKDF2 was measured first and rejected: it runs in Java, and 310k iterations took 1.2–2.5 s per unlock on emulators against ~0.1 s for Argon2id. |
| K2 | Default-blocking is **always on** once Killit is device owner and has a passkey. There is no switch. |
| K3 | Local structured data (the known-package list now; requests, chance counters and history later) lives in **Room**. The durable copy stays in application restrictions. |
| K4 | Counted strings use **`<plurals>`** (developer.android.com), replacing the count-last rule (§15.10). |
| K5 | Killit has **no users yet**, so nothing needs backward compatibility or data migration until its first release. |

Findings while implementing Phase 1:

- **The durable store never persisted anything.** Application restrictions can't hold a `long`, and system_server silently dropped every write that contained one, so the copy meant to survive Clear data was always empty. Fixed: wall-clock times are stored as strings, and a bundle with an unsupported type is refused.
- `DISALLOW_CONFIG_DATE_TIME` only exists from Android 9, so on Android 8 the date/time toggle did nothing and the release delay could be skipped. Fixed with `setAutoTimeRequired` below API 28.
- Private Space and work profiles are already blocked by platform default for a device owner (verified). Killit sets both restrictions anyway and never clears them.
- **Android 14's first release** (fixed in QPR1) restores a device owner's restrictions after a reboot as restrictions no admin owns. They can't be cleared, and they even survive releasing device owner, until a recovery wipe. This is a platform bug Killit can't work around; it fails in the restrictive direction.

**2026-10-05 to 10-12, implementing Phase 3**

| # | Decision |
|---|---|
| L1 | Signed messages use **length-prefixed binary**, a fixed hand-written layout per kind (no CBOR or JSON), so both sides build identical bytes and every decoder is strict and fuzzable. |
| L2 | The server calls the **FCM HTTP v1 API directly**: a service-account JWT signed with `node:crypto`, exchanged for an access token. `firebase-admin` would bring 61 more packages that could reach the credential. Accepted on condition that it adds no vulnerability: the phone acts on no field of a push, TLS is always verified, redirects are refused, and nothing secret is logged. |
| L3 | Phase 3 includes the **deploy stack** for `api.test.tamodak.org`, so Phase 4 can pair real phones. The site itself stays last. |
| L4 | The server runs **Docker on Ubuntu 24.04 (Ampere, arm64), with Ubuntu-based images**. PostgreSQL is 16, from Ubuntu's own archive, so Ubuntu's security updates cover it. Node and Caddy are the official releases, pinned by checksum. |

Findings while implementing Phase 3:

- **Google's revocation list doesn't match its documentation.** It is documented as lowercase hex serial numbers, but more than half its entries (979 of 1759 on 2026-10-05) are decimal. Google's own Kotlin verifier only looks up hex, so it misses those. Killit's server looks up both.
- Since February 2026, attestation chains may end in Google's new **ECDSA P-384 root** ("Key Attestation CA1") as well as the old RSA root, and remotely provisioned chains carry certificates valid for only days. The verifier was checked against nine real device chains from Google's test data, covering both roots, factory and remote provisioning, TEE and StrongBox, and Android 8.1 to 17.
- A streamed backup (`pg_dump | age | upload`) stores an empty "backup" when the dump fails, and write-only backup credentials can't delete it again. The backup job now finishes the encrypted dump in memory before uploading.

**2026-10-12 to 10-13, implementing Phases 4 and 5**

| # | Decision |
|---|---|
| M1 | Phases 4 and 5 are **built together**, on branch `phase-4` (5b stays separate). |
| M2 | The API client uses **OkHttp and kotlinx.serialization**, with JSON codecs generated at compile time, so nothing from the network is bound by reflection. |
| M3 | **FCM is part of it.** The app reads the Firebase project from `app/google-services.json` at build time; a build without the file has no push and relies on polling. |
| M4 | **H2 applies to release builds only.** Debug builds keep adb while guarded, so a test phone with guardians can still be debugged. |
| M5 | The password is asked **once per visit** (J1, "at the door"): it opens both sections until Killit leaves the foreground, and leaving locks everything again. |

Findings while implementing Phases 4 and 5:

- **An attestation can't be renewed.** A registration whose answer was lost can't be retried with the same key, since its certificate chain answered one challenge. The phone settles it with `GET /v1/devices/me`, and the server's "retry gives 200" path is never used by real phones.
- Android 8 **emulator images ship software-attestation certificates that have expired**. The development server (only) no longer checks the dates of a chain that doesn't end in a Google root; production behaviour is unchanged.
- In review, the **joiner of a ceremony** now pins the creator's reveal before sending its own, so a server can't swap the creator's reveal after seeing the joiner's.
- **UNPAIR timers are checked after the inbox** on every sync: a denial that was already waiting on the server stops a timer that has run out, while an unreachable server still can't hold a timer back (§6.4).
- **firebase-messaging 26 registers apps by Firebase Installation ID.** `getToken`/`onNewToken` are deprecated for `register()`/`onRegistered`, and FCM v1 deprecated `message.token` for `message.fid`. The server stores and addresses FIDs (SPEC.md §9). The FID API is opt-in: without the manifest flag `firebase_messaging_installation_id_enabled`, `register()` throws "API disabled". The Firebase project is `killit-27b49` (deploy/RUNBOOK.md §5); a real push was delivered to an emulator end to end on 2026-10-13.
- Toolchain limits: OkHttp 5.5 needs compileSdk 37 (5.4 is used), kotlinx.serialization 1.10 needs Kotlin 2.3 (1.9 is used), and AGP 9 needs `resValues` switched on for the Firebase resources.

**2026-10-13, deploying `api.test.tamodak.org`**

| # | Decision |
|---|---|
| N1 | The test server runs on the instance that already existed: the Always Free AMD `VM.Standard.E2.1.Micro` (x86_64, 1 GB of memory, a 2 GB swap file), not an Ampere A1. L4's Ubuntu-based images are unchanged. They build there one at a time (about 12 minutes), and the running stack uses about 150 MB. |
| N2 | The old blog is **deleted now** (F4), with nginx and certbot, so Caddy owns ports 80 and 443 as planned. Until the site exists, `tamodak.org` shows a one-page placeholder (`deploy/placeholder/`) with `security.txt`, and `www` redirects to it. `api.tamodak.org` stays dark until the cutover: no release signing key exists yet. |
| N3 | `website` is **public** on GitHub (`tamodak/website`), like Killit, Hisar and the Desktop Authenticator: the protocol and the server's privacy claims are meant to be checkable. The server clones it over HTTPS with no credential, and **deploys stay manual**: no CI job holds a key to the server. |
| N4 | The FCM key belongs to a service account (`fcm-admin-sender`) whose only role is *Firebase Cloud Messaging API Admin*. Of 13 permissions probed, it holds only `cloudmessaging.messages.create`. The Admin SDK key stays off the server. |

Findings while deploying:

- **The host firewall was off.** `iptables-persistent`, the package that loads Oracle's `rules.v4` at boot, was missing, so the OCI security list had been the only wall (§6.6 asks for two). It is reinstalled without letting it overwrite the file. After a reboot the rules are live, with Docker's forwarding rules ahead of Oracle's reject rule (RUNBOOK §2.4).
- Turhost's zone tells resolvers to remember a missing name for a day (SOA minimum 86400 s), so a name looked up before its record exists can stay invisible on some resolvers for up to a day. Let's Encrypt asks the authoritative servers, so certificates are unaffected.
- Ubuntu 24.04's fail2ban finds SSH's log lines through the `_COMM=sshd` journal match, so its `sshd` jail works although the unit is called `ssh.service`.
- **Backups are on** (RUNBOOK §6): nightly at 03:00 UTC to the private bucket `killit-backups` in Frankfurt. The drill (§7.1) restored the first one with the live database's tables, rows, owners and grants. Only the `public` schema's owner differs, because the drill creates its database with `createdb` instead of `database.sql`. A probe confirmed that the server's key can add objects but can't overwrite or delete them.

---

## 12. Phased roadmap

| Phase | Scope | Server needed? |
|---|---|---|
| **1** ✅ | Killit: `knownPackages`, install watcher (foreground service + diff), default-block, pending UI, Private Space restriction, passkey KDF (K1), 14-day release delay, the `lockOnBackground` busy fix (H10), the Android 8 date/time lock (H3). The other per-build durations arrive with the features that use them. **Done 2026-10-05.** | No |
| **2** | `website/`: Vue site on `test.tamodak.org`, privacy policy, APK download with fingerprints, the Hisar Play link and the Desktop Authenticator download. The compose/Caddy stack moved into Phase 3 (L3). | Static only |
| **3** ✅ | `protocol/` spec and test vectors. API: attestation registration, signed requests, invites with commit/reveal, links, mailbox, push. The deploy stack and runbook for `api.test.tamodak.org` (L3, L4). **Done 2026-10-12.** | Yes |
| **4** ✅ | Killit: `INTERNET`, `net/` + `pairing/Envelope` (Keystore sign + Tink HPKE), remote pairing with the safety code, the new gate (Unlock / Requests), the pairs screen. **Done 2026-10-13, together with Phase 5 (M1).** | Yes |
| **5** ✅ | UNBLOCK_APP (explanation, 3 chances), live UNLOCK_KILLIT, UNPAIR/LEAVE/NOTICE, the 30-day timer, the approval UI (60/40 Deny), nicknames and badges, last seen, daily reminders, block-more (D7) | Yes |
| **5b** | Optional master app management (APP_LIST + MANAGE, `RemoteEffects` whitelist) and phone handover | Yes |
| **6** | Security review (threat-model walk-through, dependency audit, fuzzing envelope and invite decoders), then cut `tamodak.org` over | – |

---

## 13. Use cases

Each use case is walked through with today's app plus the planned features. "→ §x" points to the rule that covers each step.

### UC1 — Adult, self-control, no pairs (today's app + §1)
1. Install Killit, provision Device Owner (Shizuku / QR / adb), set a password, block apps.
2. A new app is installed → blocked at once → the password opens Killit → uncheck it.
3. **What changes:** only the default block (§1) and the stronger password KDF. Nothing is networked. Pairing features stay invisible until the user adds a pair.

### UC2 — Adult with one accountability partner (management off)
1. The partner installs Killit as **guardian only** (H1), with no factory reset.
2. The slave starts the pairing in Requests → gives the code by phone → they compare the safety code on a call → the warning checkbox (G14) → the partner approves the PAIR.
3. From now on the slave's password only opens Requests. New installs → NOTICE to the partner → the slave writes an explanation → the partner approves or denies (3 chances, D4).
4. Changing settings → they talk first → the slave sends an UNLOCK and waits in the app → the partner approves → full control until the slave leaves the app.
5. **Weak spot:** with a single master, uninstalling Killit on the master's phone (if the slave gets hold of it) leaves a master who can never deny, so the 30-day timer frees the slave. That's why the UI recommends 2 masters (A3). See E-D5.

### UC3 — Two friends, mutual
- A is B's master and B is A's master. Each approves the other from **Requests** with their own password. Neither needs their own Killit unlocked to help, so there's no deadlock.
- **Risk:** collusion ("you approve mine, I'll approve yours"). That's a human problem Killit can't solve. The website should suggest a third, uninvolved master for people who want it to be really strict.

### UC4 — Parents and a child (management on)
1. A parent provisions the child's phone, sets its password and tells it to the child (J1: the child needs it to send any request), and pairs **Mom** and **Dad** as masters. Management is switched on inside the unlocked session.
2. New app → NOTICE to both → the child explains → both must approve. Mom sees "Dad approved" (G10).
3. A parent wants to block TikTok → any one parent blocks it immediately (G2). Unblocking → the other parent gets "Mom is unblocking TikTok for Ali — Samsung. It needs your approval too."
4. The child wants out → UNPAIR goes to both parents → **any deny cancels it** (B2). The child's only way out is a recovery-mode wipe (§3.12).
5. The child takes Mom's phone → needs Mom's Killit password to approve or LEAVE (H13). Removing Mom through UNPAIR still reaches Dad, who denies (B1).

### UC5 — One parent, several children
- The master sees a list of slaves with nicknames ("Ali — Samsung", "Ayşe — Redmi") and different badges (§3.2). Each notification names the child.
- The Requests screen groups by slave.

### UC6 — Support circle (e.g. a recovery group), 3–4 masters
- Unanimity makes every request slow. That's intended, but the A3 guidance ("more than 4 is rarely needed") applies.
- A master drifting away shows up through "last seen" (§3.11). They either LEAVE, or the slave's UNPAIR runs its 30 days, provided nobody active denies.

### UC7 — Guardian changes phones
- **Old phone still works:** HANDOVER from Requests (§3.10). Slaves see "moved to a new phone" and nothing else changes.
- **Old phone lost:** re-pair from the new phone. The slave's UNPAIR of the dead key runs its 30 days, or the other masters approve it sooner.

### UC8 — Protected user wants out of Killit entirely
1. They talk to the masters → UNLOCK → start the release (masters get a NOTICE, C8/H6) → leave the app.
2. 14 days later → a **second** UNLOCK → confirm the release.
3. Device Owner is removed → all masters are unpaired automatically (H7).

---

## 14. Edge-case catalogue

Status: ✅ decided · ❓ open (see the §11 question).

### E-A Install detection
| # | Case | Handling |
|---|---|---|
| A1 | The app is opened from the Play Store's "Open" button before it's suspended | The foreground service receiver makes this a matter of milliseconds ✅ |
| A2 | Killit's process was dead during the install | Full diff on boot, service start, app open and periodically ✅ |
| A3 | An OTA adds system packages / a Chrome update adds a library package | Auto-approve non-launchable system packages, libraries and overlays (H4) ✅ |
| A4 | A disabled system app is re-enabled | Treated as new ✅ |
| A5 | An update comes signed with a different cert | Treated as new ✅ |
| A6 | Private Space / work profile / OEM dual apps | Restrict creating them (§0) ✅ |
| A7 | Many apps at once (restoring a backup) | One request each, one grouped notification ✅ |
| A8 | A pending app is uninstalled | Request cancelled, no chance used (H11) ✅ |
| A9 | The platform refuses to suspend a package | Shown in the UI, as today ✅ |

### E-B Unlock (live)
| # | Case | Handling |
|---|---|---|
| B1 | The screen times out while waiting | The screen is kept on ✅ |
| B2 | Incoming call / notification shade / split screen | A call means `onStop`, so the request is cancelled (H12 ✅). The shade and split screen don't stop the activity, and that's harmless. |
| B3 | An approval arrives after cancel | No in-memory nonce, so it's ignored ✅ |
| B4 | A master leaves while the slave waits | Recount (G6) ✅ |
| B5 | The slave's network drops while waiting | Keep waiting and reconnect. Approvals are stored on the server until fetched ✅ |
| B6 | The process dies while waiting or unlocked | Locked, and the nonce is gone ✅ |
| B7 | Leaving while `busy` keeps Killit unlocked (today's code) | Fixed in phase 1 (H10) ✅ |
| B8 | Spamming unlock requests | 5-minute cooldown, 6 per day ✅ |

### E-C Unblock requests
| # | Case | Handling |
|---|---|---|
| C1 | Master approves after the slave already unchecked the app while unlocked | Auto-resolved (G11) ✅ |
| C2 | A new master is added while a request is open | The request is sent to them too (G6) ✅ |
| C3 | An explanation like "aaaaaaaaaa" | Allowed. The masters judge it and have Deny ✅ |
| C4 | All 3 chances used | Only via UNLOCK ✅ |
| C5 | Reinstalling to reset the chance counter | The counter is kept by package + cert and survives uninstall ✅ |
| C6 | A malicious APK names itself "Calculator" | Masters see the package, the installer and a Play link (§5.4) ✅ |

### E-D Pairing / unpairing
| # | Case | Handling |
|---|---|---|
| D1 | A stranger guesses an invite code | 40-bit code, 15 min, rate limits, plus the safety-code call ✅ |
| D2 | The server swaps keys (MITM) | The commit-reveal SAS catches it ✅ |
| D3 | The slave pairs with their own second phone | Can't be prevented. Documented ✅ |
| D4 | The slave "moves" to a spare phone to get free | Slave HANDOVER only while unlocked ✅ |
| D5 | The only master uninstalls, or the slave uninstalls Killit on the master's phone | 30-day timer frees the slave. The UI recommends 2 masters ✅ |
| D6 | A master denies an unpair forever | By design. Recovery wipe only, with a warning at pairing ✅ |
| D7 | Unpair spam | 3 chances per master (G8) ✅ |
| D8 | The release completes while masters exist | All guardians removed and notified (H7) ✅ |

### E-E Devices and platform
| # | Case | Handling |
|---|---|---|
| E1 | Clock moved forward to skip timers (including via adb) | Date/time hardening (H3). adb is off while guarded (H2). The toggle is locked on while guarded (I1) ✅ |
| E2 | adb / Shizuku shell access on a slave | Developer features are off while guarded (H2) ✅ |
| E3 | A slave is factory-reset via recovery | Masters notice through last seen / the silence alert (H8 ✅) and can LEAVE ✅ |
| E4 | A guardian phone doesn't get pushes (permissions, OEM battery killers) | Onboarding requirements (H9 ✅). Requests wait on the server with no expiry, so nothing is lost, only delayed ✅ |
| E5 | A guardian forgets their password | No reset. Reinstall and pair again. Guardians are warned when they take the role (I3, §15.11) ✅ |
| E6 | A guardian clears data or uninstalls | New identity. Same as UC7's "old phone lost" path ✅ |
| E7 | A phone without hardware attestation | Pairing unavailable (G12) ✅ |
| E8 | The server is down or reclaimed | Unlock and requests wait. The 30-day timer is local ✅ |
| E9 | A debug APK against the production server | `api.test.tamodak.org` accepts the debug cert. Production accepts only the release cert (H14/I2) ✅ |
| E10 | The slave is offline for a long time | Requests queue locally and send when back online. Masters get the silence alert (H8) |

### E-F Messages and versions
| # | Case | Handling |
|---|---|---|
| F1 | An older Killit receives a message kind it doesn't know | Versioned kinds. Unknown kinds are shown as "Update Killit to see this request" and never auto-acknowledged ✅ |
| F2 | Duplicate or replayed messages | `requestId` / sequence numbers are consumed once ✅ |
| F3 | Pairs speak different languages | Messages carry structured codes, not text, so each phone renders them in its own language. Only explanations and deny reasons are free text ✅ |

---

## 15. App UI/UX redesign

### 15.1 Principles

1. **Non-technical people first.** Every screen answers "What is my phone's state?" and "What can I do now?" Say "Blocked", not "suspended", and "Guardian", not "peer". Device Owner is mentioned only on the setup screens.
2. **Two roles, one app, any time** (H1, decided). A phone can protect itself, guard others, or both. The roles can change later, in any order. So there's **no role question at first launch**: both roles are always visible.
3. **The role follows from where you start.** "Add a guardian" is started from *My phone*, and "Guard a new phone" from *Phones I guard*. Neither the pairing wizard nor anything else shows a role picker.
4. **Friction goes where the risk is.** Deny is wider (60/40) everywhere a weakening action is confirmed. Blocking is cheap and unblocking is expensive.
5. **Keep today's visual language:** the custom `ui/components/Killit.kt` widgets, a fixed dark theme, **green = protected** and **red = exposed**, hand-drawn icons. New screens are built from the same widgets.
6. **Everything that isn't needed daily moves into Settings**, so the main screens stay short.

### 15.2 Screen map

```
Hub (first screen, no password; each card asks for the Killit password, J1)
├── My phone (password) ──────────────────────────────────────────────────────────────
│   ├─ not Device Owner  → Setup wizard (Shizuku / QR / adb, today's SetupSection)
│   ├─ no guardians      → My phone (unlocked)
│   ├─ has guardians     → My phone (locked)
│   │    ├─ Unlock Killit → live waiting screen → My phone (unlocked)
│   │    ├─ Ask to unblock an app → pick app → explanation → sent
│   │    ├─ Block more apps → pick → confirm (Cancel wider)
│   │    └─ My guardians → list · add a guardian · ask to remove
│   └─ tampered          → Tampered screen (as today)
│
│   My phone (unlocked)
│   ├─ Status card (Protected · 2 guardians · 14 apps blocked)
│   ├─ Apps (block list)
│   ├─ Guardians
│   └─ Settings
│        ├─ Protection options (today's hardening toggles)
│        ├─ Let guardians manage my apps (D5 toggle)
│        ├─ Change password
│        ├─ Move to a new phone
│        ├─ Language
│        └─ Stop protecting this phone (release, red, 14 days)
│
└── Phones I guard (password) ─────────────────────────────────────────────
    ├─ Requests inbox (live unlocks pinned at the top with "waiting now")
    │    └─ Request detail → Deny 60% | Approve 40%
    ├─ Phones list (nickname · badge · last seen · pending count)
    │    └─ Phone detail: open requests · Manage apps (if allowed) · history
    │         · Stop guarding (LEAVE)
    ├─ Guard a new phone → pairing wizard
    └─ Settings (Language, Change password, Move to a new phone)
```

**The language picker** moves from the top of Home to the Hub's top bar (a globe icon) and to Settings. The Hub is the first screen with text, so the language is still read in `bootstrap()` before it's drawn.

### 15.3 Hub

```
┌──────────────────────────────────────┐
│ Killit                           🌐  │
│                                      │
│ ┌──────────────────────────────────┐ │
│ │ 🔒 My phone                      │ │  green border when protected
│ │ Protected · 2 guardians          │ │
│ │ 1 new app waiting                │ │
│ └──────────────────────────────────┘ │
│ ┌──────────────────────────────────┐ │
│ │ 🛡 Phones I guard                │ │
│ │ 3 phones · 2 requests waiting    │ │  badge when there are requests
│ └──────────────────────────────────┘ │
└──────────────────────────────────────┘
```

- **Status text by state:**
  - "Not protected yet · Set up" when the phone isn't Device Owner.
  - "Protected by your password" with no guardians.
  - "Protected · N guardians" with guardians.
  - "You don't guard any phones yet" when guarding nobody.
- **Before the password:** only counts are shown, never app or person names (I5).
- **Notifications** open straight into the relevant place. There's still one password prompt on the way in.

### 15.4 My phone: locked (has guardians)

Reached after the Killit password (J1). On a guarded phone, the password opens **this locked screen**, not the settings. Every action below is available without asking again.

- **Explains itself:** "Your guardians keep this phone protected. To change settings, talk to them first, then send an unlock request."
- **Unlock Killit** (primary button) → a **live waiting screen**:
  - one row per guardian: badge, name, and ⏳ waiting / ✅ approved / ❌ denied;
  - "Stay on this screen. Leaving cancels the request.";
  - the screen is kept on, and the cooldown is shown after a deny.
- **Ask to unblock an app:** a list of blocked new apps, each showing its chance counter ("2 of 3 requests left") and state (not asked / waiting / denied). Asking opens the explanation sheet (10–500 characters, with a live counter).
- **Block more apps:** a list of allowed apps → confirmation *"You won't be able to unblock these yourself."* → **Cancel 60% | Block 40%**.
- **My guardians:**
  - the guardian list with last seen;
  - "Add a guardian" (wizard, §15.7), showing the A3 hint about 2 guardians and a warning above 4;
  - "Ask to remove", which shows the UNPAIR rules, the chance counter and the explanation box, and then the 30-day countdown.

### 15.5 My phone: unlocked

The three rows (**Apps · Guardians · Settings**) replace today's long Home screen, which currently has the language, status, apps, hardening, release and password all on one page.

- **The Apps screen gets sections** instead of one flat list:
  1. **New: blocked automatically.** Just-installed apps, with a "New" chip. Paired phones also show each app's request status.
  2. **Blocked.**
  3. **Allowed.**

  Search, the checkboxes and "Save" work as today. Without guardians, unchecking a new app is how you approve it (UC1). With guardians it still works here, because an unlocked session means full control (§3.5).
- **Settings:** hardening moves from Home into "Protection options", keeping today's texts. "Stop protecting this phone" is the last item, in red. It explains the 14 days, notifies guardians, and removes them at the end (H7).

### 15.6 Phones I guard

- **The inbox is sorted with live unlocks first,** then by age. Each card shows the badge, nickname, request type icon, the app (icon, name, package), a one-line explanation and the time.
- **Request detail:**

```
┌──────────────────────────────────────┐
│ 🟪 Ali — Samsung            2 min ago │
│ wants to unblock                      │
│ [icon] TikTok                         │
│ com.zhiliaoapp.musically · Play Store │
│ View on Play Store ↗                  │
│                                       │
│ "My school club posts announcements   │
│  only on TikTok."                     │
│                                       │
│ Other guardians: Mom ✅ approved       │
│ Add a note (optional) ▾               │
│ ┌───────────────────────┐┌─────────┐ │
│ │         Deny          ││ Approve │ │
│ └───────────────────────┘└─────────┘ │
└──────────────────────────────────────┘
```

  - **An unlock request** adds a banner: *"Approving gives Ali full control of Killit until they leave the app."* It also shows a pulsing "waiting now" marker.
  - **A master's unblock proposal** reads: *"Mom is unblocking Instagram for Ali — Samsung. It needs your approval too."*
- **Manage apps:**
  1. Tap to request the list; it shows "Asking Ali's phone…" and then the list.
  2. Blocked and allowed sections, with checkboxes. **Blocking applies immediately. Unblocking says "Needs the other guardians' approval".**
  3. "Send changes" goes out.
- **Stop guarding:** a confirmation *"Ali — Samsung will be told. If you are their last guardian, their phone becomes unprotected."* → **Cancel 60% | Stop guarding 40%**.

### 15.7 Pairing wizard (shared by both sides)

1. **What this means.** The role-specific explanation, plus the G14 warning with its **required checkbox** on the protected side. If the protected phone isn't Device Owner yet → setup comes first.
2. **Code.**
   - One side taps "Show code" and sees `K7QX-M2PD`, a 15-minute timer and a Share button.
   - The other side types the code. Either side can show the code; the roles are already known from the starting point.
3. **Call and compare.** *"Call Mom now. Read your 6 digits to each other."* Big digits, and **"They don't match" (60%) | "They match" (40%)**. A mismatch aborts the pairing and explains that someone may be interfering.
4. **Name.** A suggested nickname and the badge. Editable.
5. **Done.** The invitee approves in their Phones I guard / My phone section. Both sides see "Paired".

### 15.8 Notifications

| Channel | Importance | Examples |
|---|---|---|
| Requests from phones I guard | High | "Ali — Samsung wants to unblock Instagram", "Ali — Samsung wants to unlock Killit (waiting now)", the daily digest |
| News from phones I guard | Default | "Ali — Samsung: TikTok was installed and blocked", "Turned off: Block uninstalling", "Ali — Samsung has gone quiet" (H8) |
| My phone | Default | "TikTok was blocked. Ask your guardians to allow it.", "Mom approved Instagram", "Dad stopped guarding this phone" |
| Protection service | Min (silent) | The ongoing "Killit is protecting this phone". It only exists on protected phones. |

The text is built on the receiving phone, in its own language, from structured codes (E-F3). News has its own channel so a guardian can quiet it and still hear requests; several notifications arriving together make one sound.

### 15.9 Onboarding (first launch)

1. Language, pre-selected from the system.
2. Three short skippable cards: *What Killit does* · *Protect your phone* · *Guard someone you care about*.
3. The Hub.

The password is created the first time either card needs it. There's **one Killit password per phone**, used for both roles.

### 15.10 Copy rules

- Short sentences, and say what happens next: "Leaving cancels the request."
- Each screen states its consequences once, in the place where the action is taken. Don't repeat them in dialogs.
- Every new string goes into all 9 locales, counted strings are `<plurals>` with every quantity each language needs (K4), and Arabic mirroring is checked (the Deny button moves to the right).

### 15.11 Password explanation for guardians (I3)

This is shown the first time a phone takes the guardian role: after its first pairing as a guardian, or when a password is set on a phone that already guards others. The user must tap "I understand".

> **Your Killit password is now your guardian key.**
> You'll need it every time you approve, deny or block something for the phones you guard.
> **Anyone who knows it can approve requests in your name**, so don't share it and keep it for yourself.
> Also set a screen lock on your phone.
> If you forget it, you'll have to reinstall Killit and pair again.

It stays readable from *Phones I guard → Settings*. There's no reset feature: changing the password needs the current one, as today.

---

## 16. Protocol and API specification

[`protocol/SPEC.md`](protocol/SPEC.md) is the normative specification: the encoding rules, keys and fingerprints, request signatures, registration and key attestation, the invite ceremony, links, the mailbox, push, the envelope, and the body of every message kind. Where it and this plan disagree, the specification wins.

[`protocol/vectors/`](protocol/vectors/) holds the test vectors, generated by the TypeScript reference implementation in `protocol/src/`. The server's tests run against them, and Killit's Kotlin tests must reproduce them in Phase 4 (§6.2 rule 8). Each vector states the outcome it was written to show, and the generator refuses to write one the implementation disagrees with.

### 16.1 Refinements of this plan

The specification settles details this plan left open, and changes a few it had sketched:

1. **Fingerprints** are a full SHA-256 of the labelled signing key (32 bytes), never truncated, so finding a collision is out of reach.
2. **Every structure starts with its own domain-separation label**, and every message carries a **pair id**: a hash of the pairing ceremony's transcript. Messages from an earlier pairing between the same two phones can never be replayed into a newer one.
3. **Message header order** (§5.2): `version ‖ kind ‖ messageId ‖ pairId ‖ senderFp ‖ recipientFp ‖ createdAt ‖ body`. The fixed fields come first.
4. **One padded size for every message** (an 8 KiB plaintext, an 8240-byte envelope) instead of 1 KB and 4 KB buckets. The server accepts nothing else, so sizes say nothing about kinds.
5. **Icons are 32 × 32 raw RGBA pixels**, so no image decoder ever parses network input (libwebp's CVE-2023-4863 is the reason).
6. **CANCEL is part of STATUS**, which also carries the other guardians' decisions (G10). A request has one message for "what's the state now".
7. **Roles never reach the server.** The creator's role travels in the end-to-end PAIR_OFFER, and the joiner declines it if it conflicts with the role the joiner chose.
8. **DECISIONs are verified against the protected phone's stored request** (§5.2): the signed bytes are rebuilt from the stored request, and only the verdict and the note are read from the message.
9. **Request signatures bind the API host**, so a request signed for the test server can't be replayed against production.
10. **Registration is itself a signed request** with the newly attested key, which proves the caller holds it. Verification mirrors Google's own verifier, including the chain-extension check and the factory-key exception for expired certificates.
11. **The server stores no encryption key and no link signatures.** Phones exchange encryption keys in the ceremony, signed by their signing keys. Links are plain rows that are deleted, not marked removed, and "last seen" is stored as a date only.
12. **The mailbox has no cursor** (`?after=` is gone). Unacknowledged messages are simply delivered again, in the order received, and the phone's message-id check drops the duplicates.
13. **Invites live 15 minutes to be joined, then 15 more to finish**, and both phones follow them with a long poll.
14. **The test server accepts the debug signing certificate; a local development server can accept emulators.** The latter needs `KILLIT_ENV=development` plus an explicit setting that the test and production servers refuse to start with.
