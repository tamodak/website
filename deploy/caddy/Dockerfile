# syntax=docker/dockerfile:1
#
# Caddy, the TLS front of the stack: it gets and renews the certificates and proxies to the API.
# The official release binary on Ubuntu 24.04, checked against the SHA-512 in the release's
# checksum file (RUNBOOK.md, "Updating pinned versions"). Ubuntu's own caddy package is 2.6,
# from 2022.

FROM ubuntu:24.04 AS download
ARG TARGETARCH
ARG CADDY_VERSION=2.11.7
ARG CADDY_SHA512_ARM64=3db36ba90c7a6e8dda40ee3dd71fa08844c76b5fb08f61b31e5e78d2ed38e71c51dc7baed875e50d1ca1279196e84302967237386ae87c91ae9f2aaceada682e
ARG CADDY_SHA512_AMD64=a7a433a1b133efc3c8d10eb0b99d52a24b5ef5c322dc77f5282182b1c0402139ab83f3a99f0c52409df77d20123fb0b523edad8a66d8f5e49136197bf61ef0e7
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH}" in \
      arm64) sha="${CADDY_SHA512_ARM64}" ;; \
      amd64) sha="${CADDY_SHA512_AMD64}" ;; \
      *) echo "unsupported architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/caddy.tar.gz "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    echo "${sha}  /tmp/caddy.tar.gz" | sha512sum -c -; \
    tar -xzf /tmp/caddy.tar.gz -C /usr/local/bin caddy

FROM ubuntu:24.04
# ca-certificates: Caddy talks TLS to Let's Encrypt.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10004 caddy \
 && useradd --system --uid 10004 --gid caddy --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin caddy \
 && install -d -o caddy -g caddy -m 700 /data /config
COPY --from=download /usr/local/bin/caddy /usr/local/bin/caddy
# Certificates and ACME account in /data, autosave in /config: both are volumes.
ENV XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config
# Docker lets containers bind ports below 1024 without privileges (ip_unprivileged_port_start=0).
USER 10004:10004
EXPOSE 80 443
ENTRYPOINT ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
