# Server trust model

Why can a fully compromised tamodak server still not unblock anything, what does it learn, and why
is its availability a security property? (§2, §5.3, §6.4)

## §2 The server is a mailbox, not an authority

> **The phone that enforces the block is the only thing that can lift it, and it lifts it only after
> decrypting and verifying signatures from its guardians' hardware-held keys. The server can never
> tell Killit to unblock, unlock, unpair, or change any policy, and it can't read what phones say to
> each other.**

- A **fully compromised server** can delay or drop messages: a denial of service (§6.4). It can't
  approve anything, can't read requests, and can't make Killit call a `DevicePolicyManager` API.
- The server stores **opaque, padded ciphertext**, routes it between phones that are linked, sends
  content-free wake-ups, and rate-limits.

```
 Protected phone (Device Owner)   tamodak.org API             Guardian phone
 ──────────────────────────────   ───────────────             ──────────────
 event (new app / unlock / unpair)
 sign (key A)
 encrypt to each guardian  ──POST /messages──►  store ciphertext
                                                 push "sync" ───►  wake, notification
                                                                   GET /messages
                                                                   decrypt, verify sig (A)
                                                                   password → approve / deny
                                                                   sign (key B), encrypt to A
                           ◄──GET /messages──   store ciphertext ◄──POST /messages
 decrypt, verify sig (B) against the stored request
 every guardian approved? → apply locally
```

What a compromised server, and every other adversary, can and can't do is walked through in
Killit's security model: [`../Killit/docs/security-model.md`](../../Killit/docs/security-model.md)
§6.1.

## §5.3 What the server learns

- **Never:** roles, names, nicknames, device models, app names or packages, app lists, request
  kinds, decisions, explanations, or any decryption key. The kind of a message lives inside the
  ciphertext, and every envelope has the same size.
- **It does see** who talks to whom, when, and roughly how often (fingerprints, links, timestamps),
  each phone's security level, the public keys exchanged during pairing, and which phone handed its
  links to which in a move. "Last seen" is stored as a date only, and returned to linked phones
  rounded to days.
- The privacy policy must say this. The exact list is in
  [`protocol/SPEC.md`](../protocol/SPEC.md) §12.

## §6.4 Availability is a security property

A protected phone **can't open its own Killit** while the server is unreachable, and can't get new
apps approved. So:

- The 30-day unpair timer is **purely local.** It's the guarantee that the server going away never
  locks anyone in for good.
- Uptime is watched from outside, a runbook documents how to rebuild the server, and backups are
  taken and restored in drills ([`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md) §6, §7, §10).
- **Oracle reclaims Always Free compute that looks idle** (very low CPU, network and memory over 7
  days), and a quiet test server looks idle. Watch for it ([infrastructure.md](infrastructure.md)).
- The API's host name is compiled into Killit, so moving the server is a DNS change, not an app
  update.
