/**
 * Sizes and limits both sides enforce (SPEC.md §13).
 *
 * The envelope size is here, not beside the envelope code, because the server checks it without
 * importing anything that can open an envelope.
 */

/** Every plaintext pads to exactly this size (SPEC.md §10.1). */
export const PLAINTEXT_BYTES = 8192;
/** HPKE's encapsulated key: the sender's ephemeral X25519 public key. */
export const HPKE_ENC_BYTES = 32;
/** The AES-128-GCM tag. */
export const HPKE_TAG_BYTES = 16;
/** `enc ‖ ciphertext ‖ tag`: the only envelope size the server accepts. */
export const ENVELOPE_BYTES = HPKE_ENC_BYTES + PLAINTEXT_BYTES + HPKE_TAG_BYTES;

/** Envelopes in one `POST /v1/messages`: one per guardian, and a phone has at most 50 links. */
export const MAX_ENVELOPES_PER_POST = 50;
/** Messages in one `GET /v1/messages` answer. */
export const MAX_MESSAGES_PER_FETCH = 32;
/** Ids in one `POST /v1/messages/ack`. */
export const MAX_ACK_IDS = 64;
/** Links per phone (PLAN.md §3.1, the "high technical cap"). */
export const MAX_LINKS = 50;
/** The longest a long poll is held. */
export const MAX_WAIT_SECONDS = 30;
