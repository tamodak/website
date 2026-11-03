# Decisions

What has been decided about the protocol, the server, the deploy stack and the site, when, and why?

**Don't re-ask these.** The ids are the ones PLAN.md gave them. Killit's decisions (A1 … O10,
except the ones below) are in [`../Killit/docs/decisions.md`](../../Killit/docs/decisions.md); the
two sets share one numbering because they were decided together.

## 2026-09-30: product rounds

| # | Decision |
|---|---|
| F3 | The website ships in **all nine Killit languages**, uses the browser's preferred language, and falls back to English. Per-language URLs (G15). |
| F4 | The old blog is deleted. Done on 2026-10-13 (N2). |
| H14 | **One domain, `tamodak.org`.** The test environment lives under it too (I2 settled how). |
| I2 | **Subdomains**, free with the domain (just DNS records, and Caddy gets the certificates by itself): `tamodak.org` is the site, `api.tamodak.org` the API, `test.tamodak.org` the test site, and `api.test.tamodak.org` the test API |

## 2026-10-05 to 10-12: Phase 3

| # | Decision |
|---|---|
| L1 | Signed messages use **length-prefixed binary**, a fixed hand-written layout per kind, with no CBOR or JSON, so both sides build identical bytes and every decoder is strict and fuzzable |
| L2 | The server calls the **FCM HTTP v1 API directly**: a service-account JWT signed with `node:crypto`, exchanged for an access token. **Rejected:** `firebase-admin`, which would bring 61 more packages that could reach the credential. Accepted on the condition that it adds no vulnerability ("because our app is Device Owner any security vulnerability could be dangerous"): the phone acts on no field of a push, TLS is always verified, redirects are refused, and nothing secret is logged. |
| L3 | Phase 3 includes the **deploy stack** for `api.test.tamodak.org`, so that Phase 4 could pair real phones. The site itself stays last. |
| L4 | The server runs **Docker on Ubuntu 24.04, with Ubuntu-based images.** PostgreSQL is 16, from Ubuntu's own archive, so Ubuntu's security updates cover it. Node and Caddy are the official releases, pinned by checksum. (The design chose an Ampere arm64 instance; N1 changed that.) |

## 2026-10-13: deploying `api.test.tamodak.org`

| # | Decision |
|---|---|
| N1 | The test server runs on the instance that already existed: the Always Free AMD `VM.Standard.E2.1.Micro` (x86_64, 1 GB of memory, a 2 GB swap file), not an Ampere A1. L4's Ubuntu-based images are unchanged. They build there one at a time (about 12 minutes), and the running stack uses about 150 MB. |
| N2 | The old blog is **deleted now** (F4), with nginx and certbot, so Caddy owns ports 80 and 443. Until the site exists, `tamodak.org` shows a one-page placeholder with `security.txt`, and `www` redirects to it. `api.tamodak.org` stays dark until the cutover: no release signing key exists yet. |
| N3 | `website` is **public** on GitHub, like Killit, Hisar and the Desktop Authenticator: the protocol and the server's privacy claims are meant to be checkable. The server clones it over HTTPS with no credential, and **deploys stay manual**: no CI job holds a key to the server. |
| N4 | The FCM key belongs to a service account (`fcm-admin-sender`) whose only role is *Firebase Cloud Messaging API Admin*. Of 13 permissions probed, it holds only `cloudmessaging.messages.create`. The Admin SDK key stays off the server. |

What was learned while building and deploying: [known-limits.md](known-limits.md).
