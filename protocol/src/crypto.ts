/**
 * The cryptographic primitives of SPEC.md §2, on `node:crypto` (OpenSSL) and nothing else.
 *
 * Every function takes and returns raw protocol formats: 65-byte uncompressed P-256 points,
 * 64-byte `r ‖ s` signatures and 32-byte X25519 keys. Conversions to and from Node's
 * `KeyObject` live here, so the rest of the package never touches DER or JWK.
 */
import {
  createECDH,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  randomBytes as nodeRandomBytes,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { DecodeError, concat, fromBase64Url, toBase64Url } from './bytes.ts';

/** Length of an uncompressed P-256 point: `0x04 ‖ X ‖ Y`. */
export const P256_POINT_BYTES = 65;
/** Length of a P1363 signature: `r ‖ s`. */
export const SIGNATURE_BYTES = 64;
/** Length of an X25519 key. */
export const X25519_KEY_BYTES = 32;

/** SHA-256 over the concatenation of `parts`. */
export function sha256(...parts: readonly Uint8Array[]): Uint8Array {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}

/** HMAC-SHA256 under `key` over the concatenation of `parts`. */
export function hmacSha256(key: Uint8Array, ...parts: readonly Uint8Array[]): Uint8Array {
  const mac = createHmac('sha256', key);
  for (const part of parts) mac.update(part);
  return new Uint8Array(mac.digest());
}

/** Draws `length` bytes from the operating system's CSPRNG. */
export function randomBytes(length: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(length));
}

/**
 * Turns a 65-byte uncompressed P-256 point into a public key.
 *
 * OpenSSL refuses a point that isn't on the curve, so a decoded key is always a real one.
 *
 * @throws DecodeError on any other length or prefix, or a point off the curve.
 */
export function p256PublicKey(point: Uint8Array): KeyObject {
  if (point.length !== P256_POINT_BYTES || point[0] !== 0x04) throw new DecodeError('not an uncompressed P-256 point');
  try {
    return createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: toBase64Url(point.subarray(1, 33)), y: toBase64Url(point.subarray(33)) },
      format: 'jwk',
    });
  } catch {
    throw new DecodeError('P-256 point not on the curve');
  }
}

/** Exports a P-256 key (public, or the public half of a private one) as its uncompressed point. */
export function p256Point(key: KeyObject): Uint8Array {
  const jwk = (key.type === 'private' ? createPublicKey(key) : key).export({ format: 'jwk' });
  if (jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') throw new TypeError('not a P-256 key');
  return concat(Uint8Array.of(0x04), fromBase64Url(jwk.x), fromBase64Url(jwk.y));
}

/**
 * Builds a P-256 private key from its 32-byte scalar. Only the test vectors need this: real
 * signing keys never leave Android Keystore.
 */
export function p256PrivateKeyFromScalar(scalar: Uint8Array): KeyObject {
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(scalar);
  const point = new Uint8Array(ecdh.getPublicKey(null, 'uncompressed'));
  return createPrivateKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      d: toBase64Url(scalar),
      x: toBase64Url(point.subarray(1, 33)),
      y: toBase64Url(point.subarray(33)),
    },
    format: 'jwk',
  });
}

/** Signs `data` with ECDSA P-256 / SHA-256 and returns the 64-byte `r ‖ s` form. */
export function p256Sign(privateKey: KeyObject, data: Uint8Array): Uint8Array {
  return new Uint8Array(sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
}

/**
 * Verifies a 64-byte `r ‖ s` ECDSA P-256 / SHA-256 signature.
 *
 * Returns false, never throws, for a malformed signature or key: this guards authority, so
 * anything short of a positive verification is a refusal.
 */
export function p256Verify(publicKey: KeyObject | Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== SIGNATURE_BYTES) return false;
  try {
    const key = publicKey instanceof Uint8Array ? p256PublicKey(publicKey) : publicKey;
    return verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
  } catch {
    return false;
  }
}

// DER prefixes that wrap a raw X25519 key as PKCS#8 (private) and SubjectPublicKeyInfo (public),
// the only forms Node imports it from.
const X25519_PKCS8_PREFIX = Uint8Array.from(Buffer.from('302e020100300506032b656e04220420', 'hex'));
const X25519_SPKI_PREFIX = Uint8Array.from(Buffer.from('302a300506032b656e032100', 'hex'));

/** Builds an X25519 private key from its 32 raw bytes. */
export function x25519PrivateKey(raw: Uint8Array): KeyObject {
  if (raw.length !== X25519_KEY_BYTES) throw new RangeError('X25519 private key must be 32 bytes');
  return createPrivateKey({ key: Buffer.from(concat(X25519_PKCS8_PREFIX, raw)), format: 'der', type: 'pkcs8' });
}

/**
 * Builds an X25519 public key from its 32 raw bytes.
 *
 * @throws DecodeError on any other length.
 */
export function x25519PublicKey(raw: Uint8Array): KeyObject {
  if (raw.length !== X25519_KEY_BYTES) throw new DecodeError('X25519 public key must be 32 bytes');
  return createPublicKey({ key: Buffer.from(concat(X25519_SPKI_PREFIX, raw)), format: 'der', type: 'spki' });
}

/** Returns the 32 raw bytes of an X25519 public key, or of a private key's public half. */
export function x25519PublicBytes(key: KeyObject): Uint8Array {
  const jwk = (key.type === 'private' ? createPublicKey(key) : key).export({ format: 'jwk' });
  if (jwk.crv !== 'X25519' || typeof jwk.x !== 'string') throw new TypeError('not an X25519 key');
  return fromBase64Url(jwk.x);
}

/**
 * X25519 Diffie-Hellman.
 *
 * @throws DecodeError when the result is all zeros, which happens only for a small-order public
 *   key; RFC 9180 §7.1.4 requires refusing it.
 */
export function x25519(privateKey: KeyObject, publicKey: KeyObject): Uint8Array {
  let shared: Uint8Array;
  try {
    shared = new Uint8Array(diffieHellman({ privateKey, publicKey }));
  } catch {
    throw new DecodeError('X25519 failed');
  }
  if (shared.every((byte) => byte === 0)) throw new DecodeError('X25519 produced the all-zero secret');
  return shared;
}
