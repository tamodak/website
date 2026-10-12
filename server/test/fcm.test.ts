/**
 * The FCM HTTP v1 client (SPEC.md §9) against a local stub of Google's token and send endpoints.
 * The stub checks the JWT the way Google does, so a malformed assertion fails here, not in
 * production.
 */
import { generateKeyPairSync, verify, type KeyObject } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { FCM_SCOPE, FcmClient, GOOGLE_TOKEN_URI, classifyError, loadServiceAccount, type ServiceAccount } from '../src/push/fcm.ts';

type SendBehaviour = (request: IncomingMessage, body: string) => { status: number; body?: unknown; headers?: Record<string, string> };

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const account: ServiceAccount = {
  projectId: 'killit-test',
  clientEmail: 'push@killit-test.iam.gserviceaccount.com',
  privateKeyId: 'key-1',
  privateKey,
};

let stub: Server;
let base: string;
let tokenRequests = 0;
let sendRequests: { authorization: string | undefined; body: unknown }[] = [];
let sendBehaviour: SendBehaviour = () => ({ status: 200, body: { name: 'projects/killit-test/messages/1' } });

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    request.on('data', (chunk) => (data += chunk));
    request.on('end', () => resolve(data));
  });
}

/** Checks an RS256 JWT bearer assertion the way Google's token endpoint would. */
function checkAssertion(assertion: string, key: KeyObject): Record<string, unknown> {
  const [header, claims, signature] = assertion.split('.');
  if (!header || !claims || !signature) throw new Error('not a JWT');
  const valid = verify('sha256', Buffer.from(`${header}.${claims}`), key, Buffer.from(signature, 'base64url'));
  if (!valid) throw new Error('bad JWT signature');
  const parsedHeader = JSON.parse(Buffer.from(header, 'base64url').toString());
  if (parsedHeader.alg !== 'RS256' || parsedHeader.kid !== 'key-1') throw new Error('bad JWT header');
  return JSON.parse(Buffer.from(claims, 'base64url').toString());
}

beforeAll(async () => {
  stub = createServer(async (request: IncomingMessage, response: ServerResponse) => {
    const body = await readBody(request);
    const reply = (status: number, json?: unknown, headers: Record<string, string> = {}) => {
      response.writeHead(status, { 'content-type': 'application/json', ...headers });
      response.end(json === undefined ? '' : JSON.stringify(json));
    };
    if (request.url === '/token') {
      tokenRequests++;
      const form = new URLSearchParams(body);
      try {
        if (form.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:jwt-bearer') throw new Error('grant type');
        const claims = checkAssertion(form.get('assertion') ?? '', publicKey);
        if (claims['iss'] !== account.clientEmail || claims['scope'] !== FCM_SCOPE || claims['aud'] !== GOOGLE_TOKEN_URI) throw new Error('claims');
        if ((claims['exp'] as number) - (claims['iat'] as number) !== 3600) throw new Error('lifetime');
        reply(200, { access_token: `access-${tokenRequests}`, expires_in: 3599, token_type: 'Bearer' });
      } catch (error) {
        reply(400, { error: 'invalid_grant', error_description: (error as Error).message });
      }
      return;
    }
    if (request.url === '/send') {
      sendRequests.push({ authorization: request.headers.authorization, body: JSON.parse(body) });
      const result = sendBehaviour(request, body);
      reply(result.status, result.body, result.headers);
      return;
    }
    if (request.url === '/redirect') {
      response.writeHead(302, { location: '/send' });
      response.end();
      return;
    }
    reply(404);
  });
  await new Promise<void>((resolve) => stub.listen(0, '127.0.0.1', resolve));
  const address = stub.address();
  if (address === null || typeof address === 'string') throw new Error('no address');
  base = `http://127.0.0.1:${address.port}`;
});

afterAll(() => {
  stub.close();
});

afterEach(() => {
  tokenRequests = 0;
  sendRequests = [];
  sendBehaviour = () => ({ status: 200, body: { name: 'projects/killit-test/messages/1' } });
});

function client(now?: () => number, send = '/send'): FcmClient {
  return new FcmClient(account, { endpoints: { token: `${base}/token`, send: `${base}${send}` }, ...(now ? { now } : {}) });
}

const fcmError = (status: string, errorCode?: string, extra: object[] = []) => ({
  error: {
    status,
    details: [
      ...(errorCode ? [{ '@type': 'type.googleapis.com/google.firebase.fcm.v1.FcmError', errorCode }] : []),
      ...extra,
    ],
  },
});

describe('sending', () => {
  it('sends the content-free sync message with a token from a valid JWT, and reuses the token', async () => {
    const fcm = client();
    expect(await fcm.send('device-fid')).toEqual({ ok: true });
    expect(await fcm.send('device-fid')).toEqual({ ok: true });
    expect(tokenRequests).toBe(1);
    expect(sendRequests[0]).toEqual({ authorization: 'Bearer access-1', body: FcmClient.syncMessage('device-fid') });
    expect(FcmClient.syncMessage('f')).toEqual({
      message: {
        fid: 'f',
        data: { sync: '1' },
        android: { priority: 'HIGH', collapse_key: 'sync', ttl: '86400s', restricted_package_name: 'org.tamodak.killit' },
      },
    });
  });

  it('fetches a new token shortly before the old one expires', async () => {
    let now = Date.now();
    const fcm = client(() => now);
    await fcm.send('f');
    now += 3599_000 - 5 * 60_000 - 1000;
    await fcm.send('f');
    expect(tokenRequests).toBe(1);
    now += 2000;
    await fcm.send('f');
    expect(tokenRequests).toBe(2);
  });

  it('shares one token exchange between concurrent sends', async () => {
    const fcm = client();
    await Promise.all([fcm.send('a'), fcm.send('b'), fcm.send('c')]);
    expect(tokenRequests).toBe(1);
  });

  it('retries once with a new token after a 401', async () => {
    let first = true;
    sendBehaviour = () => {
      if (first) {
        first = false;
        return { status: 401, body: fcmError('UNAUTHENTICATED') };
      }
      return { status: 200, body: {} };
    };
    expect(await client().send('f')).toEqual({ ok: true });
    expect(tokenRequests).toBe(2);
  });

  it('refuses to follow a redirect', async () => {
    await expect(client(undefined, '/redirect').send('f')).rejects.toThrow();
  });
});

describe('error handling', () => {
  it.each([
    ['UNREGISTERED', 404, fcmError('NOT_FOUND', 'UNREGISTERED'), { ok: false, kind: 'fid_invalid' }],
    ['SENDER_ID_MISMATCH', 403, fcmError('PERMISSION_DENIED', 'SENDER_ID_MISMATCH'), { ok: false, kind: 'fid_invalid' }],
    [
      'an invalid FID',
      400,
      fcmError('INVALID_ARGUMENT', 'INVALID_ARGUMENT', [{ '@type': 'type.googleapis.com/google.rpc.BadRequest', fieldViolations: [{ field: 'message.fid' }] }]),
      { ok: false, kind: 'fid_invalid' },
    ],
    ['any other invalid argument', 400, fcmError('INVALID_ARGUMENT', 'INVALID_ARGUMENT'), { ok: false, kind: 'error', status: 400, code: 'INVALID_ARGUMENT' }],
    ['QUOTA_EXCEEDED', 429, fcmError('RESOURCE_EXHAUSTED', 'QUOTA_EXCEEDED'), { ok: false, kind: 'retry', retryAfterSeconds: null }],
    ['UNAVAILABLE', 503, fcmError('UNAVAILABLE', 'UNAVAILABLE'), { ok: false, kind: 'retry', retryAfterSeconds: null }],
  ])('treats %s as %j', async (_, status, body, expected) => {
    sendBehaviour = () => ({ status, body });
    expect(await client().send('f')).toEqual(expected);
  });

  it('honours Retry-After', () => {
    expect(classifyError(503, '120', null)).toEqual({ ok: false, kind: 'retry', retryAfterSeconds: 120 });
    expect(classifyError(503, 'Wed, 21 Oct 2015 07:28:00 GMT', null)).toEqual({ ok: false, kind: 'retry', retryAfterSeconds: null });
  });
});

describe('service-account files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'killit-fcm-'));
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  const file = (content: object): string => {
    const path = join(dir, `${Math.random()}.json`);
    writeFileSync(path, JSON.stringify(content));
    return path;
  };
  const valid = {
    type: 'service_account',
    project_id: 'killit-test',
    private_key_id: 'key-1',
    private_key: pem,
    client_email: account.clientEmail,
    token_uri: GOOGLE_TOKEN_URI,
  };

  it('loads a valid file', () => {
    expect(loadServiceAccount(file(valid))).toMatchObject({ projectId: 'killit-test', clientEmail: account.clientEmail });
  });

  it.each([
    ['another token endpoint', { token_uri: 'https://evil.example/token' }],
    ['another key type', { type: 'authorized_user' }],
    ['a malformed project id', { project_id: '../etc' }],
    ['an EC key', { private_key: generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }) }],
    ['a missing field', { client_email: '' }],
  ])('refuses %s', (_, change) => {
    expect(() => loadServiceAccount(file({ ...valid, ...change }))).toThrow();
  });
});
