/**
 * HPKE (RFC 9180) for the one suite Killit uses (SPEC.md §2.1): base mode,
 * DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, single-shot.
 *
 * `node:crypto` has no HPKE, so this composes it from X25519, HMAC and AES-GCM, exactly as the
 * RFC's pseudocode does; the RFC's own test vector (A.1) checks it. Killit uses Tink's
 * implementation of the same suite, and the vectors in `vectors/hpke.json` check that the two
 * agree.
 *
 * This file is end-to-end code: the server never imports it (PLAN.md §8, "no decryption code").
 */
import { createCipheriv, createDecipheriv, type KeyObject } from 'node:crypto';
import { DecodeError, concat, u16 } from './bytes.ts';
import {
  X25519_KEY_BYTES,
  hmacSha256,
  randomBytes,
  x25519,
  x25519PrivateKey,
  x25519PublicBytes,
  x25519PublicKey,
} from './crypto.ts';
import { HPKE_ENC_BYTES, HPKE_TAG_BYTES } from './limits.ts';
import { HPKE_AEAD_ID, HPKE_KDF_ID, HPKE_KEM_ID } from './suite.ts';

const MODE_BASE = 0x00;
/** `Nsecret`, `Nh`: the KEM's shared secret and the KDF's output are both one SHA-256. */
const N_SECRET = 32;
const N_H = 32;
/** `Nk`, `Nn`, `Nt` for AES-128-GCM. */
const N_K = 16;
const N_N = 12;

const ascii = (text: string): Uint8Array => new TextEncoder().encode(text);
const HPKE_V1 = ascii('HPKE-v1');
const SUITE_KEM = concat(ascii('KEM'), u16(HPKE_KEM_ID));
const SUITE_HPKE = concat(ascii('HPKE'), u16(HPKE_KEM_ID), u16(HPKE_KDF_ID), u16(HPKE_AEAD_ID));
const EMPTY = new Uint8Array(0);

/** HKDF-Extract (RFC 5869). An empty salt means `Nh` zero bytes. */
function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacSha256(salt.length === 0 ? new Uint8Array(N_H) : salt, ikm);
}

/** HKDF-Expand (RFC 5869). */
function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let previous: Uint8Array = EMPTY;
  for (let filled = 0, counter = 1; filled < length; counter++) {
    previous = hmacSha256(prk, previous, info, Uint8Array.of(counter));
    out.set(previous.subarray(0, Math.min(previous.length, length - filled)), filled);
    filled += previous.length;
  }
  return out;
}

/** `LabeledExtract(salt, label, ikm)` (RFC 9180 §4). */
function labeledExtract(suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return hkdfExtract(salt, concat(HPKE_V1, suite, ascii(label), ikm));
}

/** `LabeledExpand(prk, label, info, L)` (RFC 9180 §4). */
function labeledExpand(suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number): Uint8Array {
  return hkdfExpand(prk, concat(u16(length), HPKE_V1, suite, ascii(label), info), length);
}

/** An X25519 key pair, with the public half in raw form. */
export interface HpkeKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: Uint8Array;
}

/**
 * `DeriveKeyPair(ikm)` (RFC 9180 §7.1.3). Real phones generate keys randomly in Tink; this exists
 * for the RFC's test vector and for deterministic test vectors of our own.
 */
export function deriveKeyPair(ikm: Uint8Array): HpkeKeyPair {
  const dkpPrk = labeledExtract(SUITE_KEM, EMPTY, 'dkp_prk', ikm);
  const raw = labeledExpand(SUITE_KEM, dkpPrk, 'sk', EMPTY, X25519_KEY_BYTES);
  const privateKey = x25519PrivateKey(raw);
  return { privateKey, publicKey: x25519PublicBytes(privateKey) };
}

/** `ExtractAndExpand(dh, kem_context)` (RFC 9180 §4.1). */
function extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Uint8Array {
  const eaePrk = labeledExtract(SUITE_KEM, EMPTY, 'eae_prk', dh);
  return labeledExpand(SUITE_KEM, eaePrk, 'shared_secret', kemContext, N_SECRET);
}

/** The base-mode key schedule (RFC 9180 §5.1): the AEAD key and nonce for sequence number 0. */
function keySchedule(sharedSecret: Uint8Array, info: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const pskIdHash = labeledExtract(SUITE_HPKE, EMPTY, 'psk_id_hash', EMPTY);
  const infoHash = labeledExtract(SUITE_HPKE, EMPTY, 'info_hash', info);
  const context = concat(Uint8Array.of(MODE_BASE), pskIdHash, infoHash);
  const secret = labeledExtract(SUITE_HPKE, sharedSecret, 'secret', EMPTY);
  return {
    key: labeledExpand(SUITE_HPKE, secret, 'key', context, N_K),
    nonce: labeledExpand(SUITE_HPKE, secret, 'base_nonce', context, N_N),
  };
}

/**
 * Single-shot `Seal` (RFC 9180 §6.1). Returns `enc ‖ ciphertext ‖ tag`, the layout Tink's
 * `HybridEncrypt` produces.
 *
 * @param ephemeral the sender's ephemeral key pair. Omit it in real use, so a fresh one is
 *   drawn; test vectors pass a derived one to be reproducible.
 */
export function hpkeSeal(
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
  ephemeral: HpkeKeyPair = deriveKeyPair(randomBytes(X25519_KEY_BYTES)),
): Uint8Array {
  const dh = x25519(ephemeral.privateKey, x25519PublicKey(recipientPublicKey));
  const enc = ephemeral.publicKey;
  const sharedSecret = extractAndExpand(dh, concat(enc, recipientPublicKey));
  const { key, nonce } = keySchedule(sharedSecret, info);
  const cipher = createCipheriv('aes-128-gcm', key, nonce, { authTagLength: HPKE_TAG_BYTES });
  cipher.setAAD(aad);
  return concat(enc, cipher.update(plaintext), cipher.final(), cipher.getAuthTag());
}

/**
 * Single-shot `Open` (RFC 9180 §6.1) of `enc ‖ ciphertext ‖ tag`.
 *
 * @throws DecodeError on any failure: a short input, a small-order `enc`, or a failed tag.
 */
export function hpkeOpen(recipientPrivateKey: KeyObject, info: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Uint8Array {
  if (sealed.length < HPKE_ENC_BYTES + HPKE_TAG_BYTES) throw new DecodeError('HPKE ciphertext too short');
  const enc = sealed.subarray(0, HPKE_ENC_BYTES);
  const ciphertext = sealed.subarray(HPKE_ENC_BYTES, sealed.length - HPKE_TAG_BYTES);
  const tag = sealed.subarray(sealed.length - HPKE_TAG_BYTES);
  const dh = x25519(recipientPrivateKey, x25519PublicKey(enc));
  const sharedSecret = extractAndExpand(dh, concat(enc, x25519PublicBytes(recipientPrivateKey)));
  const { key, nonce } = keySchedule(sharedSecret, info);
  try {
    const decipher = createDecipheriv('aes-128-gcm', key, nonce, { authTagLength: HPKE_TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return concat(decipher.update(ciphertext), decipher.final());
  } catch {
    throw new DecodeError('HPKE authentication failed');
  }
}
