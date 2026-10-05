/**
 * Schema pieces and decoders shared by the routes.
 *
 * Request bodies are validated twice: TypeBox schemas reject wrong shapes and oversized strings
 * before a handler runs, and the protocol's strict decoders then turn base64url into bytes of
 * exactly the right size. `additionalProperties: false` everywhere: an unknown field is a client
 * bug worth hearing about, not something to ignore.
 */
import { Type, type TSchema } from 'typebox';
import { decodeWith, fromBase64Url } from '@tamodak/protocol/api';
import { badRequest } from '../errors.ts';

/** A base64url string holding at most `maxBytes` bytes. */
export function Base64Url(maxBytes: number) {
  return Type.String({ pattern: '^[A-Za-z0-9_-]*$', maxLength: Math.ceil((maxBytes * 4) / 3) });
}

/** A strict JSON object: every listed property required, nothing else allowed. */
export function StrictObject<T extends Record<string, TSchema>>(properties: T) {
  return Type.Object(properties, { additionalProperties: false });
}

/** A UUID path parameter or field. */
export const Uuid = Type.String({ format: 'uuid', maxLength: 36 });

/** Long-poll seconds: 0 answers at once, at most 30 (SPEC.md §13). */
export const WaitSeconds = Type.Integer({ minimum: 0, maximum: 30, default: 0 });

/**
 * Decodes base64url that must be exactly `length` bytes.
 *
 * @throws ApiError 400 for anything else.
 */
export function bytesOf(text: string, length: number): Uint8Array {
  const decoded = decodeWith(() => fromBase64Url(text, length));
  if (!decoded.ok || decoded.value.length !== length) throw badRequest();
  return decoded.value;
}

/**
 * An abort signal that fires when the client disconnects, so a long poll stops waiting.
 *
 * It listens on the response, not the request: since Node 16 a request emits `close` as soon as
 * its body has been read, while a response emits it when the connection goes away before the
 * reply is sent. During a wait no reply has been sent, so any `close` means the client left.
 */
export function disconnectSignal(response: NodeJS.EventEmitter): AbortSignal {
  const controller = new AbortController();
  response.once('close', () => controller.abort());
  return controller.signal;
}
