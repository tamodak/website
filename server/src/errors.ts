/**
 * API errors (SPEC.md §4.3): an HTTP status, a stable machine-readable code, and nothing a
 * client could use to learn more than it needs.
 */

/** An error the client is meant to see. Anything else becomes a bare 500. */
export class ApiError extends Error {
  override readonly name = 'ApiError';
  readonly status: number;
  readonly code: string;
  /** Extra JSON fields, e.g. `reason` or `peers`. */
  readonly details: Readonly<Record<string, unknown>>;
  /** Seconds, sent as `Retry-After` with a 429 or 503. */
  readonly retryAfter: number | undefined;

  constructor(status: number, code: string, details: Record<string, unknown> = {}, retryAfter?: number) {
    super(code);
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfter = retryAfter;
  }
}

export const badRequest = (): ApiError => new ApiError(400, 'bad_request');
export const unauthorized = (reason: 'stale_timestamp' | 'invalid'): ApiError => new ApiError(401, 'unauthorized', { reason });
export const attestationRejected = (reason: string): ApiError => new ApiError(403, 'attestation_rejected', { reason });
export const notLinked = (peers: string[]): ApiError => new ApiError(403, 'not_linked', { peers });
export const notFound = (): ApiError => new ApiError(404, 'not_found');
export const conflict = (state: string): ApiError => new ApiError(409, 'conflict', { state });
export const expired = (): ApiError => new ApiError(410, 'expired');
export const rateLimited = (retryAfter: number): ApiError => new ApiError(429, 'rate_limited', {}, retryAfter);
export const mailboxFull = (): ApiError => new ApiError(429, 'mailbox_full', {}, 60);
export const unavailable = (retryAfter = 60): ApiError => new ApiError(503, 'unavailable', {}, retryAfter);
