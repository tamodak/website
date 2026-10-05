/**
 * End-to-end envelopes (SPEC.md §10): sign, pad, encrypt; and the reverse.
 *
 * Sign-then-encrypt: the signature sits inside the ciphertext, so the server can't see who
 * signed, and the signed bytes name both the sender and the recipient, so a recipient can't
 * re-encrypt a message and pass it off as sent to someone else. Every plaintext pads to one size,
 * so the server learns nothing from lengths either.
 *
 * End-to-end code: the server never imports it.
 */
import type { KeyObject } from 'node:crypto';
import { ByteReader, ByteWriter, DecodeError, concat, decodeWith, equalBytes, type Result } from './bytes.ts';
import { SIGNATURE_BYTES, p256Sign, p256Verify } from './crypto.ts';
import { PAIR_ID_BYTES } from './ceremony.ts';
import { hpkeOpen, hpkeSeal, type HpkeKeyPair } from './hpke.ts';
import { FINGERPRINT_BYTES } from './identity.ts';
import { LABEL_ENVELOPE, LABEL_MESSAGE } from './labels.ts';
import { ENVELOPE_BYTES, PLAINTEXT_BYTES } from './limits.ts';

/** The only message version this implementation reads or writes. */
export const MESSAGE_VERSION = 1;
/** `version ‖ kind ‖ messageId ‖ pairId ‖ senderFp ‖ recipientFp ‖ createdAt`. */
export const HEADER_BYTES = 1 + 1 + 16 + PAIR_ID_BYTES + FINGERPRINT_BYTES + FINGERPRINT_BYTES + 8;
/** The largest inner that fits beside its length prefix and signature. */
export const MAX_INNER_BYTES = PLAINTEXT_BYTES - 2 - SIGNATURE_BYTES;
/** The largest body that fits behind the header. */
export const MAX_BODY_BYTES = MAX_INNER_BYTES - HEADER_BYTES;
/** Length of a message id. */
export const MESSAGE_ID_BYTES = 16;

/** The fixed header of every inner message (SPEC.md §10.2). */
export interface MessageHeader {
  readonly version: number;
  readonly kind: number;
  readonly messageId: Uint8Array;
  readonly pairId: Uint8Array;
  readonly senderFp: Uint8Array;
  readonly recipientFp: Uint8Array;
  readonly createdAt: number;
}

/** An inner message split into its header and its still-encoded body. */
export interface Inner {
  readonly header: MessageHeader;
  readonly body: Uint8Array;
}

/** Encodes `inner = header ‖ body`. */
export function encodeInner(header: MessageHeader, body: Uint8Array): Uint8Array {
  if (body.length > MAX_BODY_BYTES) throw new RangeError('message body too long');
  return new ByteWriter()
    .u8(header.version)
    .u8(header.kind)
    .fixed(header.messageId, MESSAGE_ID_BYTES)
    .fixed(header.pairId, PAIR_ID_BYTES)
    .fixed(header.senderFp, FINGERPRINT_BYTES)
    .fixed(header.recipientFp, FINGERPRINT_BYTES)
    .u64(header.createdAt)
    .raw(body)
    .finish();
}

/**
 * Splits an inner message into header and body. Any version and kind are returned as they are:
 * deciding what an unknown one means is the caller's job (SPEC.md §10.3 step 9).
 */
export function decodeInner(inner: Uint8Array): Result<Inner> {
  return decodeWith(() => {
    if (inner.length < HEADER_BYTES || inner.length > MAX_INNER_BYTES) throw new DecodeError('inner length out of range');
    const reader = new ByteReader(inner);
    const header: MessageHeader = {
      version: reader.u8(),
      kind: reader.u8(),
      messageId: reader.fixed(MESSAGE_ID_BYTES),
      pairId: reader.fixed(PAIR_ID_BYTES),
      senderFp: reader.fixed(FINGERPRINT_BYTES),
      recipientFp: reader.fixed(FINGERPRINT_BYTES),
      createdAt: reader.u64(),
    };
    return { header, body: reader.rest() };
  });
}

/** The bytes a message signature covers: `label("KILLIT-MSG-v1") ‖ inner`. */
export function messageSignedBytes(inner: Uint8Array): Uint8Array {
  return concat(LABEL_MESSAGE, inner);
}

/** Signs an inner message with the sender's signing key. */
export function signInner(signKey: KeyObject, inner: Uint8Array): Uint8Array {
  return p256Sign(signKey, messageSignedBytes(inner));
}

/** True when `signature` covers `inner` under the sender's `signPk`. */
export function verifyInner(signPk: KeyObject | Uint8Array, inner: Uint8Array, signature: Uint8Array): boolean {
  return p256Verify(signPk, messageSignedBytes(inner), signature);
}

/** Builds the padded plaintext: `u16 innerLength ‖ inner ‖ signature ‖ zeros` to 8192 bytes. */
export function padPlaintext(inner: Uint8Array, signature: Uint8Array): Uint8Array {
  if (inner.length < HEADER_BYTES || inner.length > MAX_INNER_BYTES) throw new RangeError('inner length out of range');
  if (signature.length !== SIGNATURE_BYTES) throw new RangeError('signature must be 64 bytes');
  const plaintext = new Uint8Array(PLAINTEXT_BYTES);
  plaintext.set(new ByteWriter().u16(inner.length).finish(), 0);
  plaintext.set(inner, 2);
  plaintext.set(signature, 2 + inner.length);
  return plaintext;
}

/** Splits a padded plaintext back into inner and signature, refusing non-zero padding. */
export function unpadPlaintext(plaintext: Uint8Array): Result<{ inner: Uint8Array; signature: Uint8Array }> {
  return decodeWith(() => {
    if (plaintext.length !== PLAINTEXT_BYTES) throw new DecodeError('plaintext must be 8192 bytes');
    const reader = new ByteReader(plaintext);
    const length = reader.u16();
    if (length < HEADER_BYTES || length > MAX_INNER_BYTES) throw new DecodeError('inner length out of range');
    const inner = reader.fixed(length);
    const signature = reader.fixed(SIGNATURE_BYTES);
    if (reader.rest().some((byte) => byte !== 0)) throw new DecodeError('non-zero padding');
    return { inner, signature };
  });
}

/** The HPKE `info`: `label("KILLIT-ENV-v1") ‖ senderFp ‖ recipientFp`. */
export function envelopeInfo(senderFp: Uint8Array, recipientFp: Uint8Array): Uint8Array {
  return new ByteWriter()
    .raw(LABEL_ENVELOPE)
    .fixed(senderFp, FINGERPRINT_BYTES)
    .fixed(recipientFp, FINGERPRINT_BYTES)
    .finish();
}

/** Everything needed to seal one message for one recipient. */
export interface SealInput {
  readonly header: MessageHeader;
  readonly body: Uint8Array;
  readonly senderSignKey: KeyObject;
  readonly recipientEncPk: Uint8Array;
  /** Test vectors only: a fixed ephemeral key, so the envelope is reproducible. */
  readonly ephemeral?: HpkeKeyPair;
}

/** Signs, pads and encrypts a message (SPEC.md §10.1). */
export function sealMessage(input: SealInput): Uint8Array {
  const inner = encodeInner(input.header, input.body);
  const plaintext = padPlaintext(inner, signInner(input.senderSignKey, inner));
  const info = envelopeInfo(input.header.senderFp, input.header.recipientFp);
  const empty = new Uint8Array(0);
  return input.ephemeral === undefined
    ? hpkeSeal(input.recipientEncPk, info, empty, plaintext)
    : hpkeSeal(input.recipientEncPk, info, empty, plaintext, input.ephemeral);
}

/** A message that decrypted, unpadded and whose header names the right parties. Not yet verified. */
export interface OpenedMessage {
  readonly inner: Uint8Array;
  readonly signature: Uint8Array;
  readonly header: MessageHeader;
  readonly body: Uint8Array;
}

/**
 * Steps 1–4 of SPEC.md §10.3: size, HPKE-Open, padding, and a header whose sender is `fromFp`
 * and whose recipient is this phone. The signature, pair, replay and kind checks need the
 * phone's own state and come after this.
 *
 * @param fromFp the sender the server named; it is also bound into the HPKE `info`.
 */
export function openEnvelope(envelope: Uint8Array, ownEncKey: KeyObject, ownFp: Uint8Array, fromFp: Uint8Array): Result<OpenedMessage> {
  return decodeWith(() => {
    if (envelope.length !== ENVELOPE_BYTES) throw new DecodeError('envelope must be 8240 bytes');
    const plaintext = hpkeOpen(ownEncKey, envelopeInfo(fromFp, ownFp), new Uint8Array(0), envelope);
    const unpadded = unpadPlaintext(plaintext);
    if (!unpadded.ok) throw new DecodeError(unpadded.error);
    const decoded = decodeInner(unpadded.value.inner);
    if (!decoded.ok) throw new DecodeError(decoded.error);
    const { header, body } = decoded.value;
    if (!equalBytes(header.senderFp, fromFp)) throw new DecodeError('sender does not match');
    if (!equalBytes(header.recipientFp, ownFp)) throw new DecodeError('recipient does not match');
    return { inner: unpadded.value.inner, signature: unpadded.value.signature, header, body };
  });
}
