/**
 * A minimal client for the FCM HTTP v1 API (SPEC.md §9), on `node:crypto` and `fetch` alone.
 *
 * The server only ever sends one content-free "sync" message, so this implements the one
 * documented call instead of pulling in firebase-admin and its ~60 packages, each of which could
 * reach the credential (Phase 3 decision). The flow is Google's "OAuth 2.0 for Server to Server
 * Applications": an RS256-signed JWT is exchanged for an access token, which is cached until
 * shortly before it expires.
 *
 * Why this adds no risk on the phones: Killit acts on no field of a push (PLAN.md §6.2 rule 6), so
 * even a stolen credential could only make phones fetch their mailbox. On the server, TLS
 * certificates are always verified, redirects are refused (a token request is never forwarded
 * anywhere), every request has a timeout, and neither the credential nor any token is logged.
 */
import { createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { toBase64Url } from '@tamodak/protocol/api';

export const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
export const GOOGLE_TOKEN_URI = 'https://oauth2.googleapis.com/token';
const FCM_SEND_BASE = 'https://fcm.googleapis.com/v1/projects';

/** Refresh the access token this long before Google says it expires. */
const TOKEN_MARGIN_MILLIS = 5 * 60 * 1000;
const REQUEST_TIMEOUT_MILLIS = 10_000;

/** The fields of a Firebase service-account key file that this client uses. */
export interface ServiceAccount {
  readonly projectId: string;
  readonly clientEmail: string;
  readonly privateKeyId: string;
  readonly privateKey: KeyObject;
}

/**
 * Reads and checks a service-account JSON file (Firebase console → Project settings → Service
 * accounts). The token endpoint must be Google's: the file decides where the signed assertion is
 * sent, so a tampered file must not be able to send it elsewhere.
 */
export function loadServiceAccount(path: string): ServiceAccount {
  const json = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  const field = (name: string): string => {
    const value = json[name];
    if (typeof value !== 'string' || value === '') throw new Error(`FCM credentials: ${name} is missing`);
    return value;
  };
  if (field('type') !== 'service_account') throw new Error('FCM credentials: not a service-account key');
  if (field('token_uri') !== GOOGLE_TOKEN_URI) throw new Error(`FCM credentials: token_uri must be ${GOOGLE_TOKEN_URI}`);
  const projectId = field('project_id');
  if (!/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/.test(projectId)) throw new Error('FCM credentials: project_id is malformed');
  const privateKey = createPrivateKey(field('private_key'));
  if (privateKey.asymmetricKeyType !== 'rsa') throw new Error('FCM credentials: the private key is not RSA');
  return { projectId, clientEmail: field('client_email'), privateKeyId: field('private_key_id'), privateKey };
}

/** The outcome of one send, as the dispatcher needs to act on it. */
export type SendResult =
  | { readonly ok: true }
  /** The token is dead (uninstalled, rotated, another project's): forget it. */
  | { readonly ok: false; readonly kind: 'token_invalid' }
  /** FCM is overloaded or rate-limiting: try again later. */
  | { readonly ok: false; readonly kind: 'retry'; readonly retryAfterSeconds: number | null }
  /** Anything else; logged, not retried. */
  | { readonly ok: false; readonly kind: 'error'; readonly status: number; readonly code: string | null };

export interface FcmEndpoints {
  readonly token: string;
  readonly send: string;
}

export interface FcmClientOptions {
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  /** Tests point these at a local stub; production always uses Google's. */
  readonly endpoints?: FcmEndpoints;
}

export class FcmClient {
  private readonly account: ServiceAccount;
  private readonly fetch: typeof fetch;
  private readonly now: () => number;
  private readonly endpoints: FcmEndpoints;
  private cached: { readonly token: string; readonly refreshAt: number } | null = null;
  private pending: Promise<string> | null = null;

  constructor(account: ServiceAccount, options: FcmClientOptions = {}) {
    this.account = account;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.now = options.now ?? Date.now;
    this.endpoints = options.endpoints ?? {
      token: GOOGLE_TOKEN_URI,
      send: `${FCM_SEND_BASE}/${account.projectId}/messages:send`,
    };
  }

  /** Sends the content-free "sync" push to one registration token. */
  async send(registrationToken: string): Promise<SendResult> {
    let result = await this.post(registrationToken);
    if (result === 'unauthorized') {
      // The cached access token was revoked or expired early: fetch a new one once.
      this.cached = null;
      result = await this.post(registrationToken);
    }
    return result === 'unauthorized' ? { ok: false, kind: 'error', status: 401, code: 'UNAUTHENTICATED' } : result;
  }

  /** The message body (SPEC.md §9). Nothing in it depends on what the phone has received. */
  static syncMessage(registrationToken: string): unknown {
    return {
      message: {
        token: registrationToken,
        data: { sync: '1' },
        android: {
          priority: 'HIGH',
          collapse_key: 'sync',
          ttl: '86400s',
          restricted_package_name: 'org.tamodak.killit',
        },
      },
    };
  }

  private async post(registrationToken: string): Promise<SendResult | 'unauthorized'> {
    const accessToken = await this.accessToken();
    const response = await this.fetch(this.endpoints.send, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify(FcmClient.syncMessage(registrationToken)),
      redirect: 'error',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MILLIS),
    });
    if (response.ok) {
      await response.body?.cancel();
      return { ok: true };
    }
    if (response.status === 401) {
      await response.body?.cancel();
      return 'unauthorized';
    }
    return classifyError(response.status, response.headers.get('retry-after'), await readJson(response));
  }

  /** An access token, from the cache or from one shared exchange. */
  private accessToken(): Promise<string> {
    if (this.cached !== null && this.now() < this.cached.refreshAt) return Promise.resolve(this.cached.token);
    this.pending ??= this.exchange().finally(() => {
      this.pending = null;
    });
    return this.pending;
  }

  private async exchange(): Promise<string> {
    const issuedAt = Math.floor(this.now() / 1000);
    const encode = (value: unknown): string => toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
    const header = encode({ alg: 'RS256', typ: 'JWT', kid: this.account.privateKeyId });
    const claims = encode({
      iss: this.account.clientEmail,
      scope: FCM_SCOPE,
      aud: GOOGLE_TOKEN_URI,
      iat: issuedAt,
      exp: issuedAt + 3600,
    });
    const signature = toBase64Url(sign('sha256', Buffer.from(`${header}.${claims}`), this.account.privateKey));
    const response = await this.fetch(this.endpoints.token, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: `${header}.${claims}.${signature}`,
      }).toString(),
      redirect: 'error',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MILLIS),
    });
    const body = (await readJson(response)) as { access_token?: unknown; expires_in?: unknown } | null;
    if (!response.ok || typeof body?.access_token !== 'string' || typeof body.expires_in !== 'number') {
      throw new Error(`FCM token exchange failed: HTTP ${response.status}`);
    }
    this.cached = { token: body.access_token, refreshAt: this.now() + body.expires_in * 1000 - TOKEN_MARGIN_MILLIS };
    return body.access_token;
  }
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * Maps an FCM error to what the dispatcher should do, following the v1 `ErrorCode` reference.
 *
 * A token is only forgotten when FCM blames the token itself: `UNREGISTERED`, `SENDER_ID_MISMATCH`,
 * or an `INVALID_ARGUMENT` whose violation names `message.token`. Any other invalid argument would
 * be a bug in our fixed message, and must not wipe every phone's token.
 */
export function classifyError(status: number, retryAfterHeader: string | null, body: unknown): SendResult {
  const error = (body as { error?: { status?: unknown; details?: unknown } } | null)?.error;
  const details = Array.isArray(error?.details) ? (error.details as Record<string, unknown>[]) : [];
  const fcmCode = details.find((detail) => typeof detail['errorCode'] === 'string')?.['errorCode'] as string | undefined;
  const code = fcmCode ?? (typeof error?.status === 'string' ? error.status : null);
  const tokenViolation = details.some(
    (detail) =>
      Array.isArray(detail['fieldViolations']) &&
      (detail['fieldViolations'] as { field?: unknown }[]).some((violation) => violation.field === 'message.token'),
  );

  if (code === 'UNREGISTERED' || code === 'SENDER_ID_MISMATCH' || status === 404) return { ok: false, kind: 'token_invalid' };
  if (code === 'INVALID_ARGUMENT' && tokenViolation) return { ok: false, kind: 'token_invalid' };
  if (status === 429 || status === 500 || status === 503 || code === 'QUOTA_EXCEEDED' || code === 'UNAVAILABLE' || code === 'INTERNAL') {
    const seconds = retryAfterHeader !== null && /^[0-9]{1,6}$/.test(retryAfterHeader) ? Number(retryAfterHeader) : null;
    return { ok: false, kind: 'retry', retryAfterSeconds: seconds };
  }
  return { ok: false, kind: 'error', status, code };
}
