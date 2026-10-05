/**
 * The pairing ceremony's cryptography (SPEC.md §6.3, §6.4): reveals, the joiner's commitment,
 * the safety code and the pair id.
 *
 * The commitment is what limits a man-in-the-middle server to one guess. The joiner fixes its
 * bundle and nonce before it sees the creator's, and the creator reveals before it sees the
 * joiner's, so the server must commit to its fake keys on each side before learning the nonce
 * that decides that side's safety code.
 */
import { ByteReader, ByteWriter, DecodeError, constantTimeEqual, decodeWith, type Result } from './bytes.ts';
import { hmacSha256, sha256 } from './crypto.ts';
import { BUNDLE_BYTES, encodeBundle, readBundle, type Bundle } from './identity.ts';
import { LABEL_COMMIT, LABEL_PAIR, SAFETY_CODE_KEY } from './labels.ts';

/** Length of each side's ceremony nonce. */
export const CEREMONY_NONCE_BYTES = 32;
/** `bundle ‖ nonce`. */
export const REVEAL_BYTES = BUNDLE_BYTES + CEREMONY_NONCE_BYTES;
/** A commitment is one SHA-256. */
export const COMMIT_BYTES = 32;
/** A pair id is one SHA-256. */
export const PAIR_ID_BYTES = 32;

/** One side's reveal, decoded. `bundleBytes` is kept exactly as received for the transcript. */
export interface Reveal {
  readonly bundle: Bundle;
  readonly bundleBytes: Uint8Array;
  readonly nonce: Uint8Array;
}

/** Encodes `reveal = bundle ‖ nonce`. */
export function encodeReveal(bundle: Bundle, nonce: Uint8Array): Uint8Array {
  return new ByteWriter().raw(encodeBundle(bundle)).fixed(nonce, CEREMONY_NONCE_BYTES).finish();
}

/** Decodes a reveal. Like {@link decodeBundle}, it doesn't verify `encSig`. */
export function decodeReveal(bytes: Uint8Array): Result<Reveal> {
  return decodeWith(() => {
    if (bytes.length !== REVEAL_BYTES) throw new DecodeError('a reveal is 194 bytes');
    const reader = new ByteReader(bytes);
    const bundle = readBundle(reader);
    const nonce = reader.fixed(CEREMONY_NONCE_BYTES);
    reader.end();
    return { bundle, bundleBytes: bytes.slice(0, BUNDLE_BYTES), nonce };
  });
}

/** `commit = SHA-256(label("KILLIT-COMMIT-v1") ‖ reveal_B)`. */
export function commitment(reveal: Uint8Array): Uint8Array {
  return sha256(LABEL_COMMIT, reveal);
}

/** True when a reveal matches a commitment. */
export function matchesCommitment(reveal: Uint8Array, commit: Uint8Array): boolean {
  return commit.length === COMMIT_BYTES && constantTimeEqual(commitment(reveal), commit);
}

/** `transcript = bundle_A ‖ bundle_B ‖ n_A ‖ n_B`, A being the creator and B the joiner. */
export function transcript(creator: Reveal, joiner: Reveal): Uint8Array {
  return new ByteWriter()
    .raw(creator.bundleBytes)
    .raw(joiner.bundleBytes)
    .raw(creator.nonce)
    .raw(joiner.nonce)
    .finish();
}

/**
 * The six-digit safety code both people compare on a call.
 *
 * `u64(HMAC-SHA256("KILLIT-SAS-v1", transcript)[0..8]) mod 10^6`. Taking 64 bits before the
 * reduction makes the bias towards low codes about 5 × 10^-14, which is nothing.
 */
export function safetyCode(transcriptBytes: Uint8Array): string {
  const mac = hmacSha256(SAFETY_CODE_KEY, transcriptBytes);
  const value = new DataView(mac.buffer, mac.byteOffset, 8).getBigUint64(0) % 1_000_000n;
  return value.toString().padStart(6, '0');
}

/** Groups a safety code for reading aloud: `"042917"` → `"042 917"`. */
export function formatSafetyCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

/** `pairId = SHA-256(label("KILLIT-PAIR-v1") ‖ transcript)`: the pairing's name in every message. */
export function pairId(transcriptBytes: Uint8Array): Uint8Array {
  return sha256(LABEL_PAIR, transcriptBytes);
}
