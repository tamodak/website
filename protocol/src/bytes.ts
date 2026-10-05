/**
 * Byte-level building blocks for every encoder and decoder in this package (SPEC.md §1).
 *
 * Decoding is total (SPEC.md §1.2): a decoder either returns a fully validated value or a
 * rejection. Internally the readers throw {@link DecodeError}; the public `decode…` functions
 * catch it at their boundary and return a {@link Result}, so no exception escapes into code
 * that handles network input.
 */
import { timingSafeEqual } from 'node:crypto';

/** Why a decoder rejected its input. Thrown only inside this package. */
export class DecodeError extends Error {
  override readonly name = 'DecodeError';
}

/** The outcome of a total decoder: a validated value, or the reason it was refused. */
export type Result<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: string };

/** Wraps a validated value. */
export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

/** Wraps a rejection. */
export function fail<T>(error: string): Result<T> {
  return { ok: false, error };
}

/**
 * Runs a decoder that may throw and turns every failure into a rejection.
 *
 * Any error counts, not only {@link DecodeError}: a decoder bug must still end in a refusal
 * rather than an exception in the caller's request handler.
 */
export function decodeWith<T>(decode: () => T): Result<T> {
  try {
    return ok(decode());
  } catch (error) {
    return fail(error instanceof DecodeError ? error.message : 'malformed input');
  }
}

/** Joins byte strings in order. */
export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Compares two byte strings by content. Not constant-time; use {@link constantTimeEqual} for secrets. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Compares two byte strings without leaking where they differ. Unequal lengths are simply unequal. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Encodes bytes as lowercase hex, the form the test vectors use. */
export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex');
}

/**
 * Decodes lowercase hex.
 *
 * @throws DecodeError on odd length or any character outside `0-9a-f`.
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) throw new DecodeError('invalid hex');
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/** Encodes bytes as base64url without padding (SPEC.md §1.1). */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/**
 * Decodes base64url without padding, accepting only the canonical encoding.
 *
 * Node's decoder is lenient: it skips unknown characters and ignores non-zero trailing bits, so
 * two different strings can decode to the same bytes. Re-encoding and comparing rejects every
 * string except the one canonical form, which keeps signed and hashed values unambiguous.
 *
 * @param maxBytes refuses longer input before decoding anything.
 * @throws DecodeError on padding, foreign characters, impossible lengths or non-canonical bits.
 */
export function fromBase64Url(text: string, maxBytes = Number.MAX_SAFE_INTEGER): Uint8Array {
  if (text.length > Math.ceil((maxBytes * 4) / 3)) throw new DecodeError('base64url too long');
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw new DecodeError('invalid base64url');
  const bytes = Buffer.from(text, 'base64url');
  if (bytes.toString('base64url') !== text) throw new DecodeError('non-canonical base64url');
  if (bytes.length > maxBytes) throw new DecodeError('base64url too long');
  return new Uint8Array(bytes);
}

/** Encodes a `u16` (SPEC.md §1.1). */
export function u16(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new RangeError(`u16 out of range: ${value}`);
  return Uint8Array.of(value >>> 8, value & 0xff);
}

/**
 * Encodes a `u64`.
 *
 * Values are JavaScript numbers, so only safe integers are accepted. Every `u64` in the protocol
 * is a time in milliseconds, which stays a safe integer for the next 285,000 years.
 */
export function u64(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new RangeError(`u64 out of range: ${value}`);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

/** Appends protocol fields in order, validating each one, so an encoder can't emit what a decoder would refuse. */
export class ByteWriter {
  private readonly parts: Uint8Array[] = [];

  /** Appends a `u8`. */
  u8(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) throw new RangeError(`u8 out of range: ${value}`);
    this.parts.push(Uint8Array.of(value));
    return this;
  }

  /** Appends a `bool` as `0x00` or `0x01`. */
  bool(value: boolean): this {
    return this.u8(value ? 1 : 0);
  }

  /** Appends a `u16`. */
  u16(value: number): this {
    this.parts.push(u16(value));
    return this;
  }

  /** Appends a `u64`. */
  u64(value: number): this {
    this.parts.push(u64(value));
    return this;
  }

  /** Appends exactly `length` bytes; anything else is a programming error. */
  fixed(value: Uint8Array, length: number): this {
    if (value.length !== length) throw new RangeError(`expected ${length} bytes, got ${value.length}`);
    this.parts.push(value);
    return this;
  }

  /** Appends bytes as they are, with no length prefix. */
  raw(value: Uint8Array): this {
    this.parts.push(value);
    return this;
  }

  /** Appends a `blob16`: a `u16` length and the bytes. */
  blob16(value: Uint8Array): this {
    this.parts.push(u16(value.length), value);
    return this;
  }

  /** Returns everything written so far as one byte string. */
  finish(): Uint8Array {
    return concat(...this.parts);
  }
}

/** Reads protocol fields in order and refuses anything malformed, short or left over. */
export class ByteReader {
  private offset = 0;
  private readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  /** How many bytes are left unread. */
  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  /** Reads a `u8`. */
  u8(): number {
    this.need(1);
    return this.bytes[this.offset++] as number;
  }

  /** Reads a `bool`, refusing any byte other than `0x00` and `0x01`. */
  bool(): boolean {
    const value = this.u8();
    if (value > 1) throw new DecodeError('invalid bool');
    return value === 1;
  }

  /** Reads a `u16`. */
  u16(): number {
    this.need(2);
    const value = ((this.bytes[this.offset] as number) << 8) | (this.bytes[this.offset + 1] as number);
    this.offset += 2;
    return value;
  }

  /** Reads a `u64`, refusing values that aren't safe integers (see {@link u64}). */
  u64(): number {
    this.need(8);
    const view = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 8);
    const value = view.getBigUint64(0);
    this.offset += 8;
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new DecodeError('u64 out of range');
    return Number(value);
  }

  /** Reads exactly `length` bytes, as a copy. */
  fixed(length: number): Uint8Array {
    this.need(length);
    const value = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  /** Reads a `blob16`, refusing a declared length above `maxBytes` before reading it. */
  blob16(maxBytes: number): Uint8Array {
    const length = this.u16();
    if (length > maxBytes) throw new DecodeError('field too long');
    return this.fixed(length);
  }

  /** Reads everything that is left. */
  rest(): Uint8Array {
    return this.fixed(this.remaining);
  }

  /** Refuses trailing bytes; every decoder ends with this. */
  end(): void {
    if (this.remaining !== 0) throw new DecodeError('trailing bytes');
  }

  private need(length: number): void {
    if (this.remaining < length) throw new DecodeError('truncated');
  }
}
