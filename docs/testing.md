# Testing

How are the protocol and the server tested, how is this machine set up for it, and how does Killit
get a local server to pair against?

## Commands

From the repository's root, with Node 24 and pnpm (the version `package.json` pins; `corepack
enable` provides it):

```bash
pnpm install
pnpm test                              # protocol and server: type checks, then every test, one package at a time
pnpm --filter @tamodak/server test     # only the server
pnpm vectors                           # regenerate protocol/vectors/ after changing the specification
```

- The server's tests start a throwaway `postgres:16-alpine` container in Docker. Set
  `TEST_DATABASE_URL` to a PostgreSQL superuser URL to use an existing server instead, and
  `TEST_LOG=1` to see the server's errors while a test runs.
- **After regenerating the vectors, copy all of them into Killit together:**
  `cp protocol/vectors/*.json ../Killit/app/src/sharedTest/resources/protocol-vectors/`. ECDSA is
  randomised, so a vector's signature is *a* valid one: implementations must verify it and produce
  the same signed bytes, not the same signature.
- The attestation verifier's tests use real certificate chains, kept as fixtures with their sources
  in `server/test/fixtures/attestation/README.md`.

## This machine

These facts held on 2026-10-13; verify before relying on them.

- **Node:** nvm holds several versions, and its default is too old for the server. Use 24:
  `export PATH=$HOME/.nvm/versions/node/v24.19.0/bin:$PATH`.
- **pnpm 11 enforces a minimum release age:** when a package is too new, pick an older version
  rather than adding an exclusion.
- Docker and Compose are installed; there's no local PostgreSQL server, only the `psql` client.
  There's no passwordless sudo.
- Something already listens on port 8080, so local stacks use other ports: 18080 and 18443 for the
  deploy stack, 18090 for the development server.
- Other Docker containers on this machine belong to other projects: leave them alone.

## A local server for Killit's end-to-end tests

Emulators can't register with the test server, because their attestation chains don't end in a
Google root. So Killit's pairing tests on emulators run against a development server on this
machine ([`../Killit/docs/testing.md`](../../Killit/docs/testing.md)).

The database is the Docker container `killit-dev-db` (`postgres:16-alpine`, password `killit-dev`,
database `killit`, bound to `127.0.0.1:15432`). Start it with `docker start killit-dev-db` if it's
stopped. Its data is what the emulators' pairings rely on, so don't reset it unasked. Then, from
`server/`:

```bash
pnpm -s build
export DATABASE_URL=postgres://postgres:killit-dev@127.0.0.1:15432/killit
MIGRATION_DATABASE_URL=$DATABASE_URL node dist/migrate.js
KILLIT_ENV=development ATTESTATION_DEV_ACCEPT_ANY_ROOT=true \
API_AUDIENCE=10.0.2.2:18090 HOST=127.0.0.1 PORT=18090 \
INVITE_CODE_KEY=<any 32-byte value, base64url> \
ATTESTATION_CERT_DIGESTS=<the SHA-256 of the debug signing certificate> \
node dist/main.js &
```

- The emulator reaches this machine's `127.0.0.1` as `10.0.2.2`, which is why the audience is
  `10.0.2.2:18090`.
- The debug certificate's digest: `keytool -list -v -keystore ~/.android/debug.keystore -storepass android`.
- Without `FCM_CREDENTIALS_FILE` the server sends no pushes, and the phones poll. Real pushes need a
  Firebase service-account key, which is a secret: only a task that needs it is given one.
- Keep the process id in a file and stop the server by that id: `pkill -f "node dist/main.js"` once
  killed the shell that called it.

## The whole stack, locally

`deploy/compose.local.yaml` runs the same Docker stack on a developer machine, with Caddy on
`https://localhost:18443` and its own local CA: [`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md) §11.
