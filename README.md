# tamodak.org

The pairing server for [Killit](https://github.com/tamodak/Killit), the protocol it speaks, its
deployment, and (later) the tamodak.org site. [PLAN.md](PLAN.md) is the plan and the record of
every decision.

| Directory | What |
|---|---|
| [`protocol/`](protocol/) | [SPEC.md](protocol/SPEC.md), the normative protocol; a TypeScript reference implementation; the test vectors Killit's tests also check |
| [`server/`](server/) | The Fastify + PostgreSQL mailbox server |
| [`deploy/`](deploy/) | The Docker stack for the Ubuntu server, and its [RUNBOOK.md](deploy/RUNBOOK.md) |

## Working on it

Node 24 LTS, pnpm (the version `package.json` pins; `corepack enable` provides it) and Docker,
which the server's tests use for a throwaway PostgreSQL:

```bash
pnpm install
pnpm test          # protocol and server: type checks, then every test
pnpm vectors       # regenerate protocol/vectors/ after changing the specification
```

`pnpm --filter @tamodak/server test` runs only the server's tests. Set `TEST_DATABASE_URL` to a
PostgreSQL superuser URL to use an existing server instead of Docker, and `TEST_LOG=1` to see the
server's errors while a test runs.
