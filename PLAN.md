# PLAN.md: where its sections went

This file was the plan for Killit, its pairing protocol, its server and the website (draft v13,
2026-10-13). On 2026-11-03 its finished parts moved into the docs of the repository that owns each
part, **under the same section numbers and decision ids**, and its future parts into tamodak's plans
([github.com/tamodak/hq](https://github.com/tamodak/hq), `plans/`). The full text is in git history.

Code and docs still cite "PLAN.md §x" or a decision id. This map says where each one went. It will be
deleted once those citations point to the new places.

Paths are relative to the tamodak folder: `Killit/` is
[tamodak/Killit](https://github.com/tamodak/Killit), `website/` this repository.

| PLAN.md | Now |
|---|---|
| Status line, intro | `Killit/docs/overview.md`, `website/docs/overview.md`; the status: hq's `plans/killit.md` |
| §0 What Killit looked like before Phase 1 | removed (all of it was built); its lessons: `Killit/docs/decisions.md` (2026-09-28), `Killit/docs/passkey-and-access.md` |
| §1 Default-block new installs, §1.1–§1.3 | `Killit/docs/default-blocking.md` |
| §2 The server is a mailbox | `website/docs/server-trust-model.md` §2 |
| §3.1 Roles, §3.2 Telling pairs apart, §3.3 Messages | `Killit/docs/pairing.md` |
| §3.4 The live unlock, §3.5 Full control, §3.6 Unblocking an app, §3.7 Blocking more | `Killit/docs/requests.md` |
| §3.8 Master app management | `Killit/docs/app-management.md` |
| §3.9 Approval UI | `Killit/docs/ui.md` |
| §3.10 Moving to a new phone | `Killit/docs/moving-to-a-new-phone.md` |
| §3.11 Last seen, §3.12 Escape hatches | `Killit/docs/pairing.md` |
| §4 Remote pairing ceremony | `Killit/docs/pairing.md` §4; the bytes: `website/protocol/SPEC.md` §6 |
| §5.1 Keys, §5.2 Message construction | `website/docs/protocol-design.md` |
| §5.3 What the server learns | `website/docs/server-trust-model.md` |
| §5.4 What a master sees | `Killit/docs/security-model.md` |
| §6.1 Adversaries, §6.2 Rules for Killit's network code | `Killit/docs/security-model.md` |
| §6.3 Server-side authentication | `website/docs/pairing-server.md` |
| §6.4 Availability | `website/docs/server-trust-model.md` |
| §6.5 Distribution and supply chain | `Killit/docs/release.md` |
| §6.6 Server hardening | `website/docs/infrastructure.md` |
| §7 Push delivery | `Killit/docs/push-and-sync.md` |
| §8 Backend design, §8.2 Schema | `website/docs/pairing-server.md`; §8.1's API: `website/protocol/SPEC.md` §4–§9 |
| §9 Frontend | hq's `plans/website.md` |
| §10 Repo layout and deployment | `website/docs/overview.md`, `website/docs/infrastructure.md`; the cutover: hq's `plans/website.md` |
| §11 decisions A1–K5, M1–M5, O1–O10 | `Killit/docs/decisions.md` |
| §11 decisions F3, F4, H14, I2, L1–L4, N1–N4 | `website/docs/decisions.md` |
| §11 Durations per build type | `Killit/docs/requests.md` |
| §11 H10 explained | `Killit/docs/passkey-and-access.md` |
| §11 Findings while implementing and deploying | `Killit/docs/known-limits.md`, `website/docs/known-limits.md` |
| §12 Phased roadmap | hq's `plans/killit.md` |
| §13 Use cases (UC1–UC8) | `Killit/docs/use-cases.md` |
| §14 Edge cases (E-A … E-F) | `Killit/docs/edge-cases.md` |
| §15 App UI/UX (§15.1–§15.11) | `Killit/docs/ui.md` |
| §16 Protocol specification, §16.1 Refinements | `website/docs/protocol-design.md` |
