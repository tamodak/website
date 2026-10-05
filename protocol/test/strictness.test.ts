/**
 * Edge cases of the total decoders and the primitives under them, beyond what the vectors show.
 */
import { describe, expect, it } from 'vitest';
import * as P from '../src/e2e.ts';

describe('ByteReader', () => {
  it('refuses reading past the end, a bad bool and trailing bytes', () => {
    expect(() => new P.ByteReader(new Uint8Array(1)).u16()).toThrow(P.DecodeError);
    expect(() => new P.ByteReader(Uint8Array.of(2)).bool()).toThrow(P.DecodeError);
    const reader = new P.ByteReader(new Uint8Array(2));
    reader.u8();
    expect(() => reader.end()).toThrow(P.DecodeError);
  });

  it('refuses a declared length over the field limit before reading it', () => {
    const reader = new P.ByteReader(Uint8Array.of(0x01, 0x00));
    expect(() => reader.blob16(255)).toThrow('field too long');
  });

  it('refuses a u64 beyond the safe-integer range', () => {
    expect(() => new P.ByteReader(new Uint8Array(8).fill(0xff)).u64()).toThrow(P.DecodeError);
    expect(new P.ByteReader(P.u64(Number.MAX_SAFE_INTEGER)).u64()).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('turns any decoder failure into a rejection', () => {
    const result = P.decodeWith(() => {
      throw new TypeError('bug');
    });
    expect(result).toEqual({ ok: false, error: 'malformed input' });
  });
});

describe('base64url', () => {
  it('refuses input longer than the caller allows before decoding it', () => {
    expect(() => P.fromBase64Url('A'.repeat(1000), 16)).toThrow('base64url too long');
    expect(P.fromBase64Url(P.toBase64Url(new Uint8Array(16)), 16)).toHaveLength(16);
  });
});

describe('text', () => {
  it('trims exactly the listed white space', () => {
    expect(P.trimText('　 Ali \n')).toBe('Ali');
    // U+180E (Mongolian vowel separator) is no longer White_Space, so it stays.
    expect(P.trimText('᠎Ali')).toBe('᠎Ali');
  });

  it('refuses to encode a lone surrogate instead of turning it into U+FFFD', () => {
    expect(() => P.encodeText('A\ud800', P.TEXT.selfName)).toThrow(RangeError);
  });

  it('refuses to encode untrimmed text', () => {
    expect(() => P.encodeText('Ali ', P.TEXT.selfName)).toThrow(RangeError);
  });
});

describe('crypto', () => {
  const phone = P.testPhone('A');

  it('refuses a P-256 point off the curve, compressed or of the wrong size', () => {
    const offCurve = phone.signPk.slice();
    offCurve[64]! ^= 1;
    expect(() => P.p256PublicKey(offCurve)).toThrow(P.DecodeError);
    expect(() => P.p256PublicKey(phone.signPk.slice(0, 33))).toThrow(P.DecodeError);
    const wrongPrefix = phone.signPk.slice();
    wrongPrefix[0] = 0x02;
    expect(() => P.p256PublicKey(wrongPrefix)).toThrow(P.DecodeError);
  });

  it('verifies P1363 signatures and refuses malformed ones without throwing', () => {
    const data = P.seeded('data');
    const signature = P.p256Sign(phone.signKey, data);
    expect(signature).toHaveLength(64);
    expect(P.p256Verify(phone.signPk, data, signature)).toBe(true);
    expect(P.p256Verify(phone.signPk, data, signature.slice(0, 63))).toBe(false);
    expect(P.p256Verify(phone.signPk, data, new Uint8Array(64))).toBe(false);
    expect(P.p256Verify(new Uint8Array(65), data, signature)).toBe(false);
  });

  it('refuses a small-order X25519 public key', () => {
    // The all-zero point has small order; a shared secret with it is all zeros.
    expect(() => P.x25519(phone.encKey, P.x25519PublicKey(new Uint8Array(32)))).toThrow(P.DecodeError);
  });
});

describe('API headers', () => {
  const phone = P.testPhone('B');
  const request: P.ApiRequest = {
    audience: 'api.tamodak.org',
    method: 'get',
    target: '/v1/links',
    timestamp: 1_790_000_000_000,
    nonce: P.seeded('nonce', 16),
    body: new Uint8Array(0),
  };

  it('signs the method in uppercase', () => {
    expect(P.toHex(P.apiSignedBytes(request))).toBe(P.toHex(P.apiSignedBytes({ ...request, method: 'GET' })));
  });

  it('round-trips through the headers', () => {
    const headers = P.signRequest(phone.signKey, phone.fp, request);
    const parsed = P.parseAuthHeaders({ ...headers });
    if (!parsed.ok) throw new Error(parsed.error);
    expect(P.verifyRequest(phone.signPk, request, parsed.value.signature)).toBe(true);
  });

  it.each([
    ['a timestamp with a leading zero', { [P.HEADER_TIMESTAMP]: '01790000000000' }],
    ['a signed timestamp', { [P.HEADER_TIMESTAMP]: '+1790000000000' }],
    ['a timestamp beyond 16 digits', { [P.HEADER_TIMESTAMP]: '12345678901234567' }],
    ['a short nonce', { [P.HEADER_NONCE]: P.toBase64Url(new Uint8Array(15)) }],
    ['a padded device id', { [P.HEADER_DEVICE]: `${P.toBase64Url(phone.fp)}=` }],
    ['a repeated header', { [P.HEADER_DEVICE]: [P.toBase64Url(phone.fp), P.toBase64Url(phone.fp)] }],
    ['a missing header', { [P.HEADER_SIGNATURE]: undefined }],
  ])('refuses %s', (_, change) => {
    const headers: Record<string, string | string[] | undefined> = { ...P.signRequest(phone.signKey, phone.fp, request), ...change };
    expect(P.parseAuthHeaders(headers).ok).toBe(false);
  });
});

describe('envelopes', () => {
  const a = P.testPhone('A');
  const b = P.testPhone('B');
  const header: P.MessageHeader = {
    version: P.MESSAGE_VERSION,
    kind: P.Kind.LEAVE,
    messageId: P.seeded('id', 16),
    pairId: P.seeded('pair'),
    senderFp: a.fp,
    recipientFp: b.fp,
    createdAt: 1,
  };

  it('seals with a fresh ephemeral key each time, and both open', () => {
    const first = P.sealMessage({ header, body: new Uint8Array(0), senderSignKey: a.signKey, recipientEncPk: b.encPk });
    const second = P.sealMessage({ header, body: new Uint8Array(0), senderSignKey: a.signKey, recipientEncPk: b.encPk });
    expect(P.toHex(first.subarray(0, 32))).not.toBe(P.toHex(second.subarray(0, 32)));
    for (const envelope of [first, second]) {
      const opened = P.openEnvelope(envelope, b.encKey, b.fp, a.fp);
      expect(opened.ok && P.verifyInner(a.signPk, opened.value.inner, opened.value.signature)).toBe(true);
    }
  });

  it('only the recipient can open it', () => {
    const envelope = P.sealMessage({ header, body: new Uint8Array(0), senderSignKey: a.signKey, recipientEncPk: b.encPk });
    expect(P.openEnvelope(envelope, a.encKey, b.fp, a.fp).ok).toBe(false);
  });

  it('fits the largest body and refuses a larger one', () => {
    const largest = new Uint8Array(P.MAX_BODY_BYTES);
    expect(P.encodeInner(header, largest)).toHaveLength(P.MAX_INNER_BYTES);
    expect(() => P.encodeInner(header, new Uint8Array(P.MAX_BODY_BYTES + 1))).toThrow(RangeError);
  });

  it('has the sizes SPEC.md §10 states', () => {
    expect(P.HEADER_BYTES).toBe(122);
    expect(P.MAX_INNER_BYTES).toBe(8126);
    expect(P.ENVELOPE_BYTES).toBe(8240);
  });
});

describe('message bodies', () => {
  it('fits the largest UNBLOCK_APP inside one envelope', () => {
    const longest: P.UnblockApp = {
      kind: P.Kind.UNBLOCK_APP,
      requestId: new Uint8Array(16),
      app: {
        packageName: `a${'b'.repeat(254)}`,
        certDigest: new Uint8Array(32),
        label: '\u{1F600}'.repeat(100),
        installer: `c${'d'.repeat(254)}`,
        firstInstalled: 0,
        icon: new Uint8Array(P.ICON_BYTES),
      },
      explanation: '\u{1F600}'.repeat(500),
      chancesLeft: 1,
      guardianCount: 50,
    };
    expect(P.encodeBody(longest).length).toBeLessThanOrEqual(P.MAX_BODY_BYTES);
  });

  it('refuses to encode what its decoder would refuse', () => {
    expect(() =>
      P.encodeBody({ kind: P.Kind.UNPAIRED, how: 9 as P.UnpairedHow }),
    ).toThrow(RangeError);
    expect(() =>
      P.encodeBody({
        kind: P.Kind.PAIR_OFFER,
        senderRole: P.Role.GUARDIAN,
        selfName: 'Mom',
        deviceModel: '',
        appManagement: true,
      }),
    ).toThrow(RangeError);
  });

  it('refuses an unknown kind', () => {
    expect(P.decodeBody(0x30, new Uint8Array(0)).ok).toBe(false);
    expect(P.isKnownKind(0x30)).toBe(false);
  });
});
