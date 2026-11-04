# Overview

What does the website repository hold, how do its parts fit together, and why?

Despite its name, most of this repository today is the **pairing server** that Killit's guardians
and protected phones talk through, the **protocol** they speak, and the **deploy stack** that runs
both on tamodak's server. The public tamodak.org site comes last; until then a static placeholder
serves the domain.

## The parts

| Part | What it is | Where | Doc |
|---|---|---|---|
| Protocol | the normative specification of Killit's pairing protocol, a TypeScript reference implementation, and the test vectors Killit's tests also check | `protocol/` | [`protocol/SPEC.md`](../protocol/SPEC.md), [protocol-design.md](protocol-design.md) |
| Pairing server | the mailbox and rendezvous server: Fastify and PostgreSQL | `server/` | [pairing-server.md](pairing-server.md), [server-trust-model.md](server-trust-model.md) |
| Deploy stack | the Docker stack for the Ubuntu server: Caddy, the API, migrations, PostgreSQL, backups | `deploy/` | [`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md), [infrastructure.md](infrastructure.md) |
| Placeholder site | what tamodak.org serves until the site exists, including Hisar's privacy pages | `deploy/placeholder/` | [placeholder-site.md](placeholder-site.md) |
| Site | the Vue site, not started (built last) | `web/` | — |

## How they fit together

- **Killit is the only client.** Killit's `protocol/` package is a Kotlin port of `protocol/` here,
  and both must produce the same bytes: the test vectors in `protocol/vectors/` are generated here
  and copied into Killit's tests ([testing.md](testing.md)).
- **The server only needs the protocol's API part:** request signatures, registration and the
  ceremony's transcript. It has no decryption code at all, and a test fails if any server source
  imports anything but the protocol package's API entry point.
- **The server is a mailbox, not an authority** ([server-trust-model.md](server-trust-model.md)):
  it stores opaque, padded ciphertext, routes it between phones that are linked, sends
  content-free wake-ups, and rate-limits.
- **One Caddy serves everything** on the server: the test API, the placeholder on tamodak.org, and
  the `www` redirect ([infrastructure.md](infrastructure.md)).

## Facts the code doesn't show

- **The specification wins.** Where `protocol/SPEC.md` and anything else disagree about bytes, the
  specification is right. [protocol-design.md](protocol-design.md) explains why.
- **A protocol change is one change:** `SPEC.md`, the reference implementation, the vectors, and
  Killit's copies of the vectors, together.
- The design was worked out in `PLAN.md` from 2026-09-28. The protocol, the server and the deploy
  stack were built in Phase 3 (done 2026-10-12); the server's part of Phase 5b (moving phones) was
  added on 2026-10-13, when `api.test.tamodak.org` went live. The section numbers in these docs (§2,
  §6.4, …) and the decision ids are PLAN.md's, kept so that older citations still lead somewhere.
  PLAN.md itself is in git history (deleted on 2026-11-04).
- The repository is public (N3), so the protocol and the server's privacy claims can be checked.
