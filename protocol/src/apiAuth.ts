/**
 * API request signatures (SPEC.md §4.2).
 *
 * There are no bearer tokens: every request is signed by the phone's hardware-held key, so a
 * leaked request can't be reused (the nonce and the 300-second window stop that) and a server
 * breach yields no credential to steal.
 */
import type { KeyObject } from 'node:crypto';
import { ByteWriter, DecodeError, decodeWith, fromBase64Url, toBase64Url, type Result } from './bytes.ts';
import { SIGNATURE_BYTES, p256Sign, p256Verify, sha256 } from './crypto.ts';
import { FINGERPRINT_BYTES } from './identity.ts';
import { LABEL_API } from './labels.ts';

/** Header names, lowercase as Node presents them. */
export const HEADER_DEVICE = 'killit-device';
export const HEADER_TIMESTAMP = 'killit-timestamp';
export const HEADER_NONCE = 'killit-nonce';
export const HEADER_SIGNATURE = 'killit-signature';

/** Length of a request nonce. */
export const API_NONCE_BYTES = 16;
/** How far a request's timestamp may be from the server's clock. */
export const API_WINDOW_MILLIS = 300_000;
/** How long a server remembers a nonce: the whole window on both sides of now. */
export const API_NONCE_RETENTION_MILLIS = 2 * API_WINDOW_MILLIS;

/** Everything a request signature covers. */
export interface ApiRequest {
  /** The API host the request is meant for, e.g. `api.tamodak.org`. */
  readonly audience: string;
  /** The HTTP method. Signed in uppercase. */
  readonly method: string;
  /** The path and query exactly as sent. */
  readonly target: string;
  /** Milliseconds since the epoch. */
  readonly timestamp: number;
  readonly nonce: Uint8Array;
  /** The exact body bytes; empty when there is no body. */
  readonly body: Uint8Array;
}

/** Writes an ASCII header-like value as `text16`. Audience, method and target are plain ASCII. */
function asciiText16(writer: ByteWriter, value: string): ByteWriter {
  if (!/^[\x21-\x7e]{1,2048}$/.test(value)) throw new RangeError(`not printable ASCII: ${value}`);
  return writer.blob16(new TextEncoder().encode(value));
}

/** Builds `signedBytes` (SPEC.md §4.2). */
export function apiSignedBytes(request: ApiRequest): Uint8Array {
  if (request.nonce.length !== API_NONCE_BYTES) throw new RangeError('nonce must be 16 bytes');
  const writer = new ByteWriter().raw(LABEL_API);
  asciiText16(writer, request.audience);
  asciiText16(writer, request.method.toUpperCase());
  asciiText16(writer, request.target);
  return writer.u64(request.timestamp).fixed(request.nonce, API_NONCE_BYTES).raw(sha256(request.body)).finish();
}

/** The four authentication headers, as a phone sends them. */
export interface AuthHeaders {
  readonly [HEADER_DEVICE]: string;
  readonly [HEADER_TIMESTAMP]: string;
  readonly [HEADER_NONCE]: string;
  readonly [HEADER_SIGNATURE]: string;
}

/** Signs a request and returns its headers. */
export function signRequest(signKey: KeyObject, fp: Uint8Array, request: ApiRequest): AuthHeaders {
  return {
    [HEADER_DEVICE]: toBase64Url(fp),
    [HEADER_TIMESTAMP]: String(request.timestamp),
    [HEADER_NONCE]: toBase64Url(request.nonce),
    [HEADER_SIGNATURE]: toBase64Url(p256Sign(signKey, apiSignedBytes(request))),
  };
}

/** The authentication headers after parsing; nothing is verified yet. */
export interface ParsedAuth {
  readonly fp: Uint8Array;
  readonly timestamp: number;
  readonly nonce: Uint8Array;
  readonly signature: Uint8Array;
}

/** Reads one header, refusing a missing or repeated one. */
function single(headers: Record<string, string | string[] | undefined>, name: string): string {
  const value = headers[name];
  if (typeof value !== 'string') throw new DecodeError(`missing or repeated ${name}`);
  return value;
}

/** Parses the four authentication headers strictly. */
export function parseAuthHeaders(headers: Record<string, string | string[] | undefined>): Result<ParsedAuth> {
  return decodeWith(() => {
    const timestampText = single(headers, HEADER_TIMESTAMP);
    if (!/^(0|[1-9][0-9]{0,15})$/.test(timestampText)) throw new DecodeError('invalid timestamp');
    const timestamp = Number(timestampText);
    if (!Number.isSafeInteger(timestamp)) throw new DecodeError('invalid timestamp');
    const fp = fromBase64Url(single(headers, HEADER_DEVICE), FINGERPRINT_BYTES);
    const nonce = fromBase64Url(single(headers, HEADER_NONCE), API_NONCE_BYTES);
    const signature = fromBase64Url(single(headers, HEADER_SIGNATURE), SIGNATURE_BYTES);
    if (fp.length !== FINGERPRINT_BYTES) throw new DecodeError('invalid device');
    if (nonce.length !== API_NONCE_BYTES) throw new DecodeError('invalid nonce');
    if (signature.length !== SIGNATURE_BYTES) throw new DecodeError('invalid signature');
    return { fp, timestamp, nonce, signature };
  });
}

/** True when `signature` covers `request` under `signPk`. Never throws. */
export function verifyRequest(signPk: KeyObject | Uint8Array, request: ApiRequest, signature: Uint8Array): boolean {
  let bytes: Uint8Array;
  try {
    bytes = apiSignedBytes(request);
  } catch {
    return false;
  }
  return p256Verify(signPk, bytes, signature);
}
