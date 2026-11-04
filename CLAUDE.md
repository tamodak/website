# website

## What this is

Everything server-side for tamodak.org. Today that is mostly the **pairing server** Killit's guardians
and protected phones talk through, the **protocol** they speak, and the **deploy stack** that runs on
tamodak's server, plus a static placeholder on tamodak.org with Hisar's privacy pages. The public
site comes later, in `web/`.

It works with two other tamodak repositories:
- `../Killit/`: the only client. Its `protocol/` package is a Kotlin port of `protocol/` here, and its
  tests check copies of `protocol/vectors/`.
- `../hisar-android/`: its privacy policy and data-safety pages live here, in `deploy/placeholder/hisar/`.

## Current state (2026-11-03)

- `api.test.tamodak.org` is live (since 2026-10-13): the pairing server with push, nightly encrypted
  backups and a passed restore drill. It accepts debug and release builds of Killit.
- `tamodak.org` serves the placeholder; Hisar's privacy pages were last updated for Hisar 0.4.
- `api.tamodak.org` (production) isn't set up: no release signing key exists for Killit yet.

## Build, run, test

Node 24 LTS, pnpm (the version `package.json` pins; `corepack enable`), and Docker:

```bash
pnpm install
pnpm test          # protocol and server: type checks, then every test
pnpm vectors       # regenerate protocol/vectors/ after changing the specification
```

The server's tests start a throwaway PostgreSQL in Docker. Running a development server for Killit's
emulators, and this machine's setup: [docs/testing.md](docs/testing.md). Deploying:
[deploy/RUNBOOK.md](deploy/RUNBOOK.md).

## How it works

- `protocol/`: [SPEC.md](protocol/SPEC.md), the normative protocol; the TypeScript reference
  implementation that generates the test vectors.
- `server/`: the Fastify and PostgreSQL mailbox. It has no decryption code: it imports only the
  protocol package's API entry point, and a test enforces that.
- `deploy/`: the Docker stack (Caddy, the API, migrations, PostgreSQL, backups), every image built on
  Ubuntu 24.04, and the runbook.
- `deploy/placeholder/`: the static tamodak.org.

The big picture: [docs/overview.md](docs/overview.md). Why a compromised server can't unblock anything:
[docs/server-trust-model.md](docs/server-trust-model.md).

## Conventions

- **`protocol/SPEC.md` wins** wherever anything disagrees with it about bytes.
- **A protocol change is one change:** SPEC.md, the reference implementation, the regenerated vectors,
  and Killit's copies of the vectors, together. Until Killit's first release, version 1 is edited in
  place.
- **The live test database already ran the first migration:** a schema change needs a new migration
  file in `server/migrations/`. Migrations only go forward.
- **The server trusts nothing it doesn't verify,** and its logs hold the method, route, status and
  duration of a request, nothing else: no bodies, headers, query strings, codes, tokens or IP
  addresses.
- **Secrets are files** (`NAME_FILE`), never command-line values. Nothing secret, no internal address
  and nothing private goes into this public repository.
- **TLS is always verified and redirects are refused** on the server's outgoing requests.
- **Few dependencies, pinned:** a dependency has to earn its place. Node, Caddy and pnpm are pinned by
  checksum or integrity; pnpm 11 enforces a minimum release age, so pick an older version rather than
  adding an exclusion.
- **The placeholder has no scripts** and keeps its strict CSP. Hisar's pages keep their URLs.
- **Nothing here touches the server by itself:** deploys are manual (RUNBOOK §8).

## Docs

[docs/README.md](docs/README.md) says which doc answers which question:
- [overview](docs/overview.md), [decisions](docs/decisions.md) (F3, F4, H14, I2, L1–L4, N1–N4),
  [testing](docs/testing.md), [known limits](docs/known-limits.md)
- [server trust model](docs/server-trust-model.md), [protocol design](docs/protocol-design.md),
  [pairing server](docs/pairing-server.md), [infrastructure](docs/infrastructure.md),
  [placeholder site](docs/placeholder-site.md)
- Next to their code: [protocol/SPEC.md](protocol/SPEC.md), [deploy/RUNBOOK.md](deploy/RUNBOOK.md)
- PLAN.md, where the design was first worked out, is in git history (deleted on 2026-11-04). Its
  section numbers and decision ids live on in the docs here and in Killit's.
