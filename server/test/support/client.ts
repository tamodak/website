/**
 * A test phone talking to a test server the way Killit will: every request signed (SPEC.md §4.2),
 * registration through a forged attestation chain for the phone's own key.
 */
import { randomBytes, signRequest, toBase64Url, type ApiRequest } from '@tamodak/protocol/api';
import { randomPhone, type TestPhone } from '@tamodak/protocol/e2e';
import { buildChain, type ChainOptions } from './attestation.ts';
import { TEST_AUDIENCE, type TestServer } from './server.ts';

export interface Response<T = any> {
  readonly status: number;
  readonly body: T;
  readonly headers: Headers;
}

export interface CallOptions {
  /** Send these exact body bytes instead of serialising `body`. */
  readonly rawBody?: Uint8Array;
  readonly timestamp?: number;
  readonly nonce?: Uint8Array;
  readonly audience?: string;
  /** Sign as if the target were this (a signature over another path). */
  readonly signedTarget?: string;
  /** Leave the authentication headers off. */
  readonly unsigned?: boolean;
  readonly headers?: Record<string, string>;
}

export class PhoneClient {
  readonly server: TestServer;
  readonly phone: TestPhone;
  readonly deviceId: string;

  constructor(server: TestServer, phone: TestPhone = randomPhone()) {
    this.server = server;
    this.phone = phone;
    this.deviceId = toBase64Url(phone.fp);
  }

  /** Sends a signed request and parses the JSON answer, if any. */
  async call<T = any>(method: string, path: string, body?: unknown, options: CallOptions = {}): Promise<Response<T>> {
    const bytes = options.rawBody ?? (body === undefined ? new Uint8Array(0) : new TextEncoder().encode(JSON.stringify(body)));
    const request: ApiRequest = {
      audience: options.audience ?? TEST_AUDIENCE,
      method,
      target: options.signedTarget ?? path,
      timestamp: options.timestamp ?? this.server.clock.now(),
      nonce: options.nonce ?? randomBytes(16),
      body: bytes,
    };
    const headers: Record<string, string> = {
      ...(options.unsigned ? {} : signRequest(this.phone.signKey, this.phone.fp, request)),
      ...(bytes.length > 0 ? { 'content-type': 'application/json' } : {}),
      ...options.headers,
    };
    const response = await fetch(`${this.server.url}${path}`, {
      method,
      headers,
      ...(bytes.length > 0 ? { body: Buffer.from(bytes) } : {}),
    });
    const text = await response.text();
    return { status: response.status, body: text === '' ? null : JSON.parse(text), headers: response.headers };
  }

  /** Registers this phone, with a valid chain unless `chain` changes something. */
  async register(chain: Partial<ChainOptions> = {}): Promise<Response> {
    const challenge = await this.call('POST', '/v1/register/challenge', undefined, { unsigned: true });
    const challengeBytes = new Uint8Array(Buffer.from(challenge.body.challenge, 'base64url'));
    const certificates = await buildChain(this.server.root, { phone: this.phone, challenge: challengeBytes, ...chain });
    return this.call('POST', '/v1/devices', {
      challenge: challenge.body.challenge,
      chain: certificates.map((der) => toBase64Url(der)),
    });
  }
}

/** Registers a fresh phone and returns its client. */
export async function registeredPhone(server: TestServer, phone?: TestPhone): Promise<PhoneClient> {
  const client = new PhoneClient(server, phone);
  const response = await client.register();
  if (response.status !== 201) throw new Error(`registration failed: ${response.status} ${JSON.stringify(response.body)}`);
  return client;
}
