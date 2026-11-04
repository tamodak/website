# The website repository's docs

Which doc answers which question?

| Doc | The question it answers |
|---|---|
| [overview.md](overview.md) | What does this repository hold, how do its parts fit together, and why? |
| [decisions.md](decisions.md) | What has been decided about the protocol, the server, the deploy stack and the site? (F3, F4, H14, I2, L1–L4, N1–N4) |
| [testing.md](testing.md) | How are the protocol and the server tested, and how does Killit get a local server to pair against? |
| [known-limits.md](known-limits.md) | What can't the server and its deployment do, and which lessons were learned the hard way? |
| [server-trust-model.md](server-trust-model.md) | Why can a compromised server still not unblock anything, and what does it learn? (§2, §5.3, §6.4) |
| [protocol-design.md](protocol-design.md) | Why is the protocol built this way, and where did the specification change the design? (§5.1, §5.2, §16) |
| [pairing-server.md](pairing-server.md) | How is the server built, and how does it decide whom to trust? (§6.3, §8) |
| [infrastructure.md](infrastructure.md) | Which services does tamodak run on, and how are they set up? (§6.6, §10) |
| [placeholder-site.md](placeholder-site.md) | What does tamodak.org serve until the site exists, and what do Hisar's privacy pages promise? |
| `security/` | Fixed security problems, one report each. None yet: the folder starts with the first one. |

Docs that live next to their code:

| Doc | The question it answers |
|---|---|
| [`protocol/SPEC.md`](../protocol/SPEC.md) | What exactly goes over the wire? (normative) |
| [`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md) | How is the server set up, deployed, backed up, restored and updated? |
| [`server/test/fixtures/attestation/README.md`](../server/test/fixtures/attestation/README.md) | Where do the attestation test chains come from? |

The section numbers (§2, §6.4, …) and decision ids come from `PLAN.md`, where the design was first
worked out; it is in git history (deleted on 2026-11-04). Killit's side of the design is in
[`../Killit/docs/`](../../Killit/docs/README.md).
