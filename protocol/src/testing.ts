/**
 * Test phones: complete identities derived from a name, so the vectors are reproducible and the
 * server's integration tests can act as phones without Android.
 *
 * Real phones keep their signing key in Android Keystore and draw every key at random. Nothing
 * here is used outside tests and vector generation.
 */
import type { KeyObject } from 'node:crypto';
import { equalBytes } from './bytes.ts';
import { p256Point, p256PrivateKeyFromScalar, p256Verify, randomBytes, sha256, x25519PrivateKey, x25519PublicBytes } from './crypto.ts';
import { encKeyBindingBytes, encodeBundle, fingerprint, signEncKey, type Bundle } from './identity.ts';

/** One phone's keys and the values derived from them. */
export interface TestPhone {
  readonly name: string;
  readonly signKey: KeyObject;
  /** The raw private scalar; only test vectors ever see one. */
  readonly signPrivate: Uint8Array;
  readonly signPk: Uint8Array;
  readonly fp: Uint8Array;
  readonly encKey: KeyObject;
  readonly encPrivate: Uint8Array;
  readonly encPk: Uint8Array;
  readonly bundle: Bundle;
  readonly bundleBytes: Uint8Array;
}

/** Deterministic bytes for a test value: SHA-256 of a description, cut to `length` (≤ 32). */
export function seeded(description: string, length = 32): Uint8Array {
  if (length > 32) throw new RangeError('seeded() gives at most 32 bytes');
  return sha256(new TextEncoder().encode(`killit test vector: ${description}`)).slice(0, length);
}

/**
 * Builds a phone from fixed key material.
 *
 * @param encSig reuse this `encSig` when it verifies. ECDSA signatures are randomised, so
 *   without it every run would produce a different bundle and churn every vector downstream.
 */
export function phoneFromKeys(name: string, signPrivate: Uint8Array, encPrivate: Uint8Array, encSig?: Uint8Array): TestPhone {
  const signKey = p256PrivateKeyFromScalar(signPrivate);
  const signPk = p256Point(signKey);
  const encKey = x25519PrivateKey(encPrivate);
  const encPk = x25519PublicBytes(encKey);
  const reuse = encSig !== undefined && p256Verify(signPk, encKeyBindingBytes(encPk), encSig);
  const bundle: Bundle = { signPk, encPk, encSig: reuse ? encSig : signEncKey(signKey, encPk) };
  return {
    name,
    signKey,
    signPrivate,
    signPk,
    fp: fingerprint(signPk),
    encKey,
    encPrivate,
    encPk,
    bundle,
    bundleBytes: encodeBundle(bundle),
  };
}

/** The named phone whose keys every vector file shares ("A", "B", "C"). */
export function testPhone(name: string, encSig?: Uint8Array): TestPhone {
  return phoneFromKeys(name, seeded(`phone ${name} sign key`), seeded(`phone ${name} enc key`), encSig);
}

/** A phone with fresh random keys, for tests that need many distinct phones. */
export function randomPhone(name = 'random'): TestPhone {
  // A uniformly random 32-byte string is a valid P-256 scalar except with probability ~2^-32;
  // drawing again in that case keeps this total.
  for (;;) {
    const scalar = randomBytes(32);
    try {
      return phoneFromKeys(name, scalar, randomBytes(32));
    } catch {
      continue;
    }
  }
}

/** True when two phones are the same identity. */
export function samePhone(a: TestPhone, b: TestPhone): boolean {
  return equalBytes(a.fp, b.fp);
}
