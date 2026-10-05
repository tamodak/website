/**
 * Domain-separation labels (SPEC.md §2.3).
 *
 * Every signed, hashed or MACed structure starts with its own label, so bytes produced for one
 * purpose can never be accepted for another: an API signature can't pass as a message signature,
 * a commitment can't pass as a pair id. A label is written as its length and its ASCII bytes,
 * which also keeps a future `-v10` from being a prefix of `-v1`.
 */
import { concat } from './bytes.ts';

/** Encodes `label(s) = u8 len(s) ‖ ASCII(s)`. */
export function label(text: string): Uint8Array {
  if (!/^[\x21-\x7e]{1,255}$/.test(text)) throw new RangeError(`labels are printable ASCII: ${text}`);
  return concat(Uint8Array.of(text.length), new TextEncoder().encode(text));
}

/** Fingerprints (SPEC.md §3.1). */
export const LABEL_FINGERPRINT = label('KILLIT-FP-v1');
/** Binding the encryption key to the signing key (SPEC.md §3.2). */
export const LABEL_ENC_KEY = label('KILLIT-ENCKEY-v1');
/** API request signatures (SPEC.md §4.2). */
export const LABEL_API = label('KILLIT-API-v1');
/** The joiner's commitment (SPEC.md §6.3). */
export const LABEL_COMMIT = label('KILLIT-COMMIT-v1');
/** Pair ids (SPEC.md §6.4). */
export const LABEL_PAIR = label('KILLIT-PAIR-v1');
/** Message signatures (SPEC.md §10.2). */
export const LABEL_MESSAGE = label('KILLIT-MSG-v1');
/** The HPKE `info` of every envelope (SPEC.md §10.1). */
export const LABEL_ENVELOPE = label('KILLIT-ENV-v1');

/**
 * The safety-code HMAC key (SPEC.md §6.4). Raw ASCII, not `label()`-encoded: it is a key, not a
 * prefix of the data.
 */
export const SAFETY_CODE_KEY = new TextEncoder().encode('KILLIT-SAS-v1');
