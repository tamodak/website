# syntax=docker/dockerfile:1
#
# The pairing API (PLAN.md §10), on Ubuntu 24.04 like the server it runs on.
#
# Build from the workspace root, so the protocol package and the lockfile are in the context:
#     docker build -f server/Dockerfile -t killit/api:local .
# deploy/compose.yaml does this. On the Ampere server the build is native arm64; elsewhere,
#     docker buildx build --platform linux/arm64 -f server/Dockerfile .
#
# Every download is pinned: Node by the SHA-256 in its signed SHASUMS256.txt (RUNBOOK.md, "Updating
# pinned versions"), pnpm by the hash in package.json's packageManager field, npm packages by the
# lockfile. The final image holds the Node binary and the built server, and runs as a non-root
# user from a filesystem compose mounts read-only.

ARG UBUNTU=ubuntu:24.04

# ---------------------------------------------------------------------------------------- node
FROM ${UBUNTU} AS node
ARG TARGETARCH
ARG NODE_VERSION=24.21.0
ARG NODE_SHA256_ARM64=6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2
ARG NODE_SHA256_AMD64=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH}" in \
      arm64) arch=arm64; sha="${NODE_SHA256_ARM64}" ;; \
      amd64) arch=x64; sha="${NODE_SHA256_AMD64}" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz"; \
    echo "${sha}  /tmp/node.tar.xz" | sha256sum -c -; \
    mkdir /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1 --no-same-owner; \
    rm /tmp/node.tar.xz

# --------------------------------------------------------------------------------------- build
FROM node AS build
ENV PATH=/opt/node/bin:$PATH \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0
WORKDIR /src
# corepack installs the pnpm version package.json pins, and checks it against the pinned hash.
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY protocol/package.json protocol/
COPY server/package.json server/
RUN pnpm install --frozen-lockfile
COPY protocol/ protocol/
COPY server/ server/
RUN pnpm --filter @tamodak/server build \
 && pnpm --filter @tamodak/server deploy --legacy --prod /out

# ------------------------------------------------------------------------------------- runtime
FROM ${UBUNTU}
RUN apt-get update \
 && apt-get upgrade -y \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 killit \
 && useradd --system --uid 10001 --gid killit --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin killit
COPY --from=node /opt/node/bin/node /usr/local/bin/node
COPY --from=build /out /app
WORKDIR /app
USER 10001:10001
ENV NODE_ENV=production
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "dist/main.js"]
