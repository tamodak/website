/**
 * Phone identities (SPEC.md §3): the fingerprint, and the bundle two phones exchange while
 * pairing.
 */
import type { KeyObject } from 'node:crypto';
import { ByteReader, ByteWriter, DecodeError, decodeWith, u16, type Result } from './bytes.ts';
import { P256_POINT_BYTES, SIGNATURE_BYTES, X25519_KEY_BYTES, p256PublicKey, p256Sign, p256Verify, sha256 } from './crypto.ts';
import { HPKE_AEAD_ID, HPKE_KDF_ID, HPKE_KEM_ID } from './suite.ts';
import { LABEL_ENC_KEY, LABEL_FINGERPRINT } from './labels.ts';

/** A fingerprint is a full SHA-256: nothing is truncated, so finding a collision is out of reach. */
export const FINGERPRINT_BYTES = 32;
/** The only bundle version this implementation reads or writes. */
export const BUNDLE_VERSION = 1;
/** `u8 version ‖ signPk (65) ‖ encPk (32) ‖ encSig (64)`. */
export const BUNDLE_BYTES = 1 + P256_POINT_BYTES + X25519_KEY_BYTES + SIGNATURE_BYTES;

/** `fp = SHA-256(label("KILLIT-FP-v1") ‖ signPk)`: a phone's address and identity. */
export function fingerprint(signPk: Uint8Array): Uint8Array {
  return sha256(LABEL_FINGERPRINT, signPk);
}

/** A decoded bundle. Structure and key encodings are valid; {@link verifyBundle} checks `encSig`. */
export interface Bundle {
  readonly signPk: Uint8Array;
  readonly encPk: Uint8Array;
  readonly encSig: Uint8Array;
}

/**
 * The bytes `encSig` signs: the encryption key together with its HPKE suite, so the key can't be
 * reused under a weaker suite than the one it was published for.
 */
export function encKeyBindingBytes(encPk: Uint8Array): Uint8Array {
  return new ByteWriter()
    .raw(LABEL_ENC_KEY)
    .raw(u16(HPKE_KEM_ID))
    .raw(u16(HPKE_KDF_ID))
    .raw(u16(HPKE_AEAD_ID))
    .fixed(encPk, X25519_KEY_BYTES)
    .finish();
}

/** Signs a new encryption key with the phone's signing key, producing `encSig`. */
export function signEncKey(signKey: KeyObject, encPk: Uint8Array): Uint8Array {
  return p256Sign(signKey, encKeyBindingBytes(encPk));
}

/** Encodes a bundle (SPEC.md §3.2). */
export function encodeBundle(bundle: Bundle): Uint8Array {
  return new ByteWriter()
    .u8(BUNDLE_VERSION)
    .fixed(bundle.signPk, P256_POINT_BYTES)
    .fixed(bundle.encPk, X25519_KEY_BYTES)
    .fixed(bundle.encSig, SIGNATURE_BYTES)
    .finish();
}

/** Reads a bundle from a reader; shared by {@link decodeBundle} and the reveal decoder. */
export function readBundle(reader: ByteReader): Bundle {
  if (reader.u8() !== BUNDLE_VERSION) throw new DecodeError('unsupported bundle version');
  const signPk = reader.fixed(P256_POINT_BYTES);
  p256PublicKey(signPk);
  const encPk = reader.fixed(X25519_KEY_BYTES);
  const encSig = reader.fixed(SIGNATURE_BYTES);
  return { signPk, encPk, encSig };
}

/**
 * Decodes a bundle: version, sizes, and a signing key that is a real P-256 point. It doesn't
 * verify `encSig`; a phone must still call {@link verifyBundle} before using `encPk`.
 */
export function decodeBundle(bytes: Uint8Array): Result<Bundle> {
  return decodeWith(() => {
    const reader = new ByteReader(bytes);
    const bundle = readBundle(reader);
    reader.end();
    return bundle;
  });
}

/** True when `encSig` binds `encPk` to `signPk`. */
export function verifyBundle(bundle: Bundle): boolean {
  return p256Verify(bundle.signPk, encKeyBindingBytes(bundle.encPk), bundle.encSig);
}
