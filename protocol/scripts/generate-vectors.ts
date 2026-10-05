/**
 * Regenerates `vectors/*.json` from the reference implementation (SPEC.md §14).
 *
 *     pnpm --filter @tamodak/protocol vectors
 *
 * Every value is deterministic: keys, nonces, message ids and HPKE ephemeral keys come from
 * seeds. ECDSA signatures are randomised, so a signature already in the files is reused whenever
 * it still verifies over the same bytes; regenerating without a change to the spec rewrites
 * nothing.
 *
 * Each case also states the outcome it was written to show (valid or rejected, and the expected
 * value where one is known independently, like RFC 9180's), and generation stops if the
 * implementation disagrees. A vector file is a claim about the specification, not a recording of
 * whatever the code happened to do.
 */
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import type { KeyObject } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import * as P from '../src/e2e.ts';

const VECTOR_DIR = new URL('../vectors/', import.meta.url);
const hex = P.toHex;
const fromHex = P.fromHex;
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(`vector generation: ${message}`);
}

// ------------------------------------------------------------------------------------------------
// Signature reuse

/** signedBytes (hex) → every signature (hex) over them in the files as they are now. */
const knownSignatures = new Map<string, string[]>();

function collectSignatures(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(collectSignatures);
  } else if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    for (const [bytesKey, sigKey] of [
      ['signedBytes', 'signature'],
      ['encKeySignedBytes', 'encSig'],
    ] as const) {
      const bytes = record[bytesKey];
      const sig = record[sigKey];
      if (typeof bytes === 'string' && typeof sig === 'string') knownSignatures.set(bytes, [...(knownSignatures.get(bytes) ?? []), sig]);
    }
    Object.values(record).forEach(collectSignatures);
  }
}

for (const file of readdirSync(VECTOR_DIR)) {
  if (file.endsWith('.json')) collectSignatures(JSON.parse(readFileSync(new URL(file, VECTOR_DIR), 'utf8')));
}

/**
 * Signs, reusing an existing signature over the same bytes when one verifies under this key.
 * The same bytes can carry signatures by different keys (the rejection cases sign with the wrong
 * phone on purpose), hence the list.
 */
function sign(key: KeyObject, signedBytes: Uint8Array): Uint8Array {
  const point = P.p256Point(key);
  for (const known of knownSignatures.get(hex(signedBytes)) ?? []) {
    const signature = fromHex(known);
    if (P.p256Verify(point, signedBytes, signature)) return signature;
  }
  return P.p256Sign(key, signedBytes);
}

// ------------------------------------------------------------------------------------------------
// JSON

/** Converts a value for JSON: byte strings become lowercase hex, everything else stays. */
function toJson(value: unknown): unknown {
  if (value instanceof Uint8Array) return hex(value);
  if (Array.isArray(value)) return value.map(toJson);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, toJson(inner)]));
  }
  return value;
}

function write(name: string, content: Record<string, unknown>): void {
  writeFileSync(new URL(name, VECTOR_DIR), `${JSON.stringify(toJson(content), null, 2)}\n`);
  console.log(`wrote vectors/${name}`);
}

// ------------------------------------------------------------------------------------------------
// identities.json

function phone(name: string): P.TestPhone {
  const encPk = P.x25519PublicBytes(P.x25519PrivateKey(P.seeded(`phone ${name} enc key`)));
  // testPhone() keeps whichever of these verifies; the binding bytes only ever carry this phone's own encSig.
  const known = knownSignatures.get(hex(P.encKeyBindingBytes(encPk)))?.[0];
  return P.testPhone(name, known === undefined ? undefined : fromHex(known));
}

const A = phone('A');
const B = phone('B');
const C = phone('C');
const phones = [A, B, C];

write('identities.json', {
  description:
    'Fixed test phones (SPEC.md §3). signPrivate is the P-256 scalar and encPrivate the raw X25519 private key. ' +
    'encSig signs encKeySignedBytes; bundle is the 162-byte bundle of §3.2.',
  phones: phones.map((p) => ({
    name: p.name,
    signPrivate: p.signPrivate,
    signPk: p.signPk,
    fp: p.fp,
    deviceId: P.toBase64Url(p.fp),
    encPrivate: p.encPrivate,
    encPk: p.encPk,
    encKeySignedBytes: P.encKeyBindingBytes(p.encPk),
    encSig: p.bundle.encSig,
    bundle: p.bundleBytes,
  })),
});

// ------------------------------------------------------------------------------------------------
// encoding.json

function textCase(rule: keyof typeof P.TEXT, input: string | Uint8Array, valid: boolean, why: string) {
  const bytes = typeof input === 'string' ? utf8(input) : input;
  let accepted = true;
  try {
    P.checkText(bytes, P.TEXT[rule]);
  } catch {
    accepted = false;
  }
  assert(accepted === valid, `text case "${why}" should be ${valid ? 'accepted' : 'rejected'}`);
  return { rule, utf8: bytes, valid, why };
}

const emoji = '\u{1F600}';
const textCases = [
  textCase('selfName', 'Ali', true, 'plain name'),
  textCase('selfName', 'Ayşe', true, 'non-ASCII letters'),
  textCase('selfName', 'أحمد', true, 'right-to-left script'),
  textCase('selfName', emoji.repeat(40), true, '40 four-byte code points: both limits exactly'),
  textCase('selfName', 'A\u{FEFF}B', true, 'U+FEFF inside text is not white space'),
  textCase('deviceModel', '', true, 'empty where zero code points are allowed'),
  textCase('requiredExplanation', 'Line one\nline two', true, 'line feed inside a paragraph'),
  textCase('selfName', '', false, 'empty where at least one code point is required'),
  textCase('selfName', emoji.repeat(41), false, '41 code points'),
  textCase('selfName', ' Ali', false, 'leading space'),
  textCase('selfName', 'Ali ', false, 'trailing no-break space'),
  textCase('selfName', 'Ali　', false, 'trailing ideographic space'),
  textCase('selfName', 'A\nB', false, 'line feed in a line field'),
  textCase('requiredExplanation', 'Line one is here\n', false, 'trailing line feed'),
  textCase('selfName', 'A\u0007B', false, 'C0 control character'),
  textCase('selfName', 'A\u0085B', false, 'C1 control character (NEL)'),
  textCase('selfName', 'A B', false, 'line separator'),
  textCase('requiredExplanation', 'too short', false, 'nine code points where ten are required'),
  textCase('selfName', fromHex('41c0af'), false, 'overlong UTF-8'),
  textCase('selfName', fromHex('41eda080'), false, 'UTF-8-encoded surrogate'),
  textCase('selfName', fromHex('41e282'), false, 'truncated UTF-8 sequence'),
  textCase('selfName', fromHex('41f4908080'), false, 'code point above U+10FFFF'),
];

function packageCase(name: string, valid: boolean) {
  assert(P.isPackageName(name) === valid, `package name "${name}" should be ${valid ? 'valid' : 'invalid'}`);
  return { name, valid };
}

const packageCases = [
  packageCase('org.tamodak.killit', true),
  packageCase('com.zhiliaoapp.musically', true),
  packageCase('android', true),
  packageCase('a_b.C1', true),
  packageCase('', false),
  packageCase('1abc', false),
  packageCase('com..example', false),
  packageCase('com.example.', false),
  packageCase('.com', false),
  packageCase('com.1example', false),
  packageCase('com-example', false),
  packageCase('çom.example', false),
  packageCase(`a${'b'.repeat(255)}`, false),
];

function base64Case(text: string, bytes: Uint8Array | null) {
  let decoded: Uint8Array | null;
  try {
    decoded = P.fromBase64Url(text);
  } catch {
    decoded = null;
  }
  assert(
    bytes === null ? decoded === null : decoded !== null && P.equalBytes(decoded, bytes),
    `base64url "${text}" should ${bytes === null ? 'be rejected' : 'decode'}`,
  );
  return bytes === null ? { text, valid: false } : { text, valid: true, bytes };
}

write('encoding.json', {
  description:
    'Text rules (SPEC.md §1.3), package names (§1.4) and base64url (§1.1). Each text case names the rule from ' +
    '`rules` it is checked against; utf8 is the exact field content.',
  rules: P.TEXT,
  text: textCases,
  packageNames: packageCases,
  base64url: [
    base64Case('', new Uint8Array(0)),
    base64Case('AA', fromHex('00')),
    base64Case('AAE', fromHex('0001')),
    base64Case('-_8', fromHex('fbff')),
    base64Case('AA==', null),
    base64Case('AB', null),
    base64Case('A', null),
    base64Case('AA AA', null),
    base64Case('+/8', null),
  ],
});

// ------------------------------------------------------------------------------------------------
// api-auth.json

interface ApiCase {
  name: string;
  signer: P.TestPhone;
  verifier: P.TestPhone;
  request: P.ApiRequest;
  signature: Uint8Array;
  valid: boolean;
}

function apiRequest(audience: string, method: string, target: string, timestamp: number, nonceSeed: string, body: string): P.ApiRequest {
  return { audience, method, target, timestamp, nonce: P.seeded(nonceSeed, 16), body: utf8(body) };
}

const baseRequests: { name: string; signer: P.TestPhone; request: P.ApiRequest }[] = [
  {
    name: 'POST with a JSON body',
    signer: A,
    request: apiRequest(
      'api.tamodak.org',
      'POST',
      '/v1/messages',
      1_790_000_000_000,
      'api nonce 1',
      '{"messages":[]}',
    ),
  },
  {
    name: 'GET with a query and no body',
    signer: B,
    request: apiRequest('api.test.tamodak.org', 'GET', '/v1/messages?wait=25', 1_790_000_000_123, 'api nonce 2', ''),
  },
  {
    name: 'DELETE with a path parameter',
    signer: C,
    request: apiRequest('10.0.2.2:8080', 'DELETE', `/v1/links/${P.toBase64Url(A.fp)}`, 1_790_000_100_000, 'api nonce 3', ''),
  },
];

const apiCases: ApiCase[] = [];
for (const base of baseRequests) {
  const signature = sign(base.signer.signKey, P.apiSignedBytes(base.request));
  apiCases.push({ ...base, verifier: base.signer, signature, valid: true });
}
const first = apiCases[0]!;
const tampered: [string, Partial<P.ApiRequest>][] = [
  ['another audience', { audience: 'api.test.tamodak.org' }],
  ['another method', { method: 'PUT' }],
  ['another target', { target: '/v1/messages?wait=1' }],
  ['another timestamp', { timestamp: first.request.timestamp + 1 }],
  ['another nonce', { nonce: P.seeded('api nonce other', 16) }],
  ['another body', { body: utf8('{"messages":[ ]}') }],
];
for (const [what, change] of tampered) {
  apiCases.push({ ...first, name: `signature of the first case over ${what}`, request: { ...first.request, ...change }, valid: false });
}
apiCases.push({ ...first, name: 'signature of the first case checked with another key', verifier: B, valid: false });

for (const c of apiCases) {
  assert(P.verifyRequest(c.verifier.signPk, c.request, c.signature) === c.valid, `api case "${c.name}"`);
}

write('api-auth.json', {
  description:
    'Request signatures (SPEC.md §4.2). signedBytes is what the signer signs; headers are what it sends. ' +
    'Cases with valid=false must fail verification with the verifier phone\'s signPk.',
  cases: apiCases.map((c) => ({
    name: c.name,
    signer: c.signer.name,
    verifier: c.verifier.name,
    audience: c.request.audience,
    method: c.request.method,
    target: c.request.target,
    timestamp: c.request.timestamp,
    nonce: c.request.nonce,
    body: c.request.body,
    bodySha256: P.sha256(c.request.body),
    signedBytes: P.apiSignedBytes(c.request),
    signature: c.signature,
    headers: c.valid
      ? {
          [P.HEADER_DEVICE]: P.toBase64Url(c.signer.fp),
          [P.HEADER_TIMESTAMP]: String(c.request.timestamp),
          [P.HEADER_NONCE]: P.toBase64Url(c.request.nonce),
          [P.HEADER_SIGNATURE]: P.toBase64Url(c.signature),
        }
      : undefined,
    valid: c.valid,
  })),
});

// ------------------------------------------------------------------------------------------------
// invite-code.json

function formatCase(bytes: Uint8Array, code: string) {
  assert(P.formatInviteCode(bytes) === code, `invite code ${hex(bytes)} should format as ${code}`);
  return { bytes, code };
}

function parseCase(input: string, bytes: Uint8Array | null) {
  const parsed = P.parseInviteCode(input);
  assert(
    bytes === null ? !parsed.ok : parsed.ok && P.equalBytes(parsed.value, bytes),
    `invite code input "${input}" should ${bytes === null ? 'be rejected' : 'parse'}`,
  );
  return bytes === null ? { input, valid: false } : { input, valid: true, bytes };
}

const sampleCode = P.seeded('invite code', 5);
const sampleText = P.formatInviteCode(sampleCode);
write('invite-code.json', {
  description: 'Invite codes (SPEC.md §6.1): 5 bytes as 8 Crockford base32 symbols, and how typed input parses.',
  alphabet: P.CROCKFORD_ALPHABET,
  format: [
    formatCase(fromHex('0000000000'), '0000-0000'),
    formatCase(fromHex('ffffffffff'), 'ZZZZ-ZZZZ'),
    formatCase(fromHex('0123456789'), '04HM-ASW9'),
    formatCase(sampleCode, sampleText),
  ],
  parse: [
    parseCase(sampleText, sampleCode),
    parseCase(sampleText.toLowerCase(), sampleCode),
    parseCase(sampleText.replace('-', ''), sampleCode),
    parseCase(` ${sampleText.replace('-', ' ')} `, sampleCode),
    parseCase('ILOO-oiLl', fromHex('0840000421')),
    parseCase('0000-000', null),
    parseCase('0000-00000', null),
    parseCase('0000-000U', null),
    parseCase('0000_0000', null),
    parseCase('0000-000Ð', null),
    parseCase('', null),
    parseCase(`${'0'.repeat(8)}${' '.repeat(25)}`, null),
  ],
});

// ------------------------------------------------------------------------------------------------
// ceremony.json

interface Ceremony {
  creator: P.TestPhone;
  joiner: P.TestPhone;
  creatorNonce: Uint8Array;
  joinerNonce: Uint8Array;
  creatorReveal: Uint8Array;
  joinerReveal: Uint8Array;
  commit: Uint8Array;
  transcript: Uint8Array;
  safetyCode: string;
  pairId: Uint8Array;
}

function ceremony(creator: P.TestPhone, joiner: P.TestPhone): Ceremony {
  const creatorNonce = P.seeded(`ceremony ${creator.name}-${joiner.name} creator nonce`);
  const joinerNonce = P.seeded(`ceremony ${creator.name}-${joiner.name} joiner nonce`);
  const creatorReveal = P.encodeReveal(creator.bundle, creatorNonce);
  const joinerReveal = P.encodeReveal(joiner.bundle, joinerNonce);
  const a = P.decodeReveal(creatorReveal);
  const b = P.decodeReveal(joinerReveal);
  assert(a.ok && b.ok, 'reveals decode');
  const transcript = P.transcript(a.value, b.value);
  const commit = P.commitment(joinerReveal);
  assert(P.matchesCommitment(joinerReveal, commit), 'commitment matches');
  const safetyCode = P.safetyCode(transcript);
  assert(/^[0-9]{6}$/.test(safetyCode), 'safety code is six digits');
  return {
    creator,
    joiner,
    creatorNonce,
    joinerNonce,
    creatorReveal,
    joinerReveal,
    commit,
    transcript,
    safetyCode,
    pairId: P.pairId(transcript),
  };
}

// A guards B, and so does C: the pairings the message vectors use.
const AB = ceremony(A, B);
const CB = ceremony(C, B);

const flippedNonce = AB.joinerReveal.slice();
flippedNonce[flippedNonce.length - 1]! ^= 0x01;
assert(!P.matchesCommitment(flippedNonce, AB.commit), 'a changed reveal must not match the commitment');
const badVersion = AB.joinerReveal.slice();
badVersion[0] = 2;
assert(!P.decodeReveal(badVersion).ok, 'bundle version 2 must be refused');
const offCurve = AB.joinerReveal.slice();
offCurve[64]! ^= 0x01;
assert(!P.decodeReveal(offCurve).ok, 'a signing key off the curve must be refused');
const swappedEncKey = P.decodeReveal(P.encodeReveal({ ...B.bundle, encPk: C.encPk }, AB.joinerNonce));
assert(swappedEncKey.ok && !P.verifyBundle(swappedEncKey.value.bundle), 'encSig must not cover another encryption key');

write('ceremony.json', {
  description:
    'The pairing ceremony (SPEC.md §6.3, §6.4). commit is over joinerReveal; transcript is ' +
    'bundle_A ‖ bundle_B ‖ n_A ‖ n_B; safetyCode is shown as safetyCodeDisplay.',
  ceremonies: [AB, CB].map((c) => ({
    creator: c.creator.name,
    joiner: c.joiner.name,
    creatorNonce: c.creatorNonce,
    joinerNonce: c.joinerNonce,
    creatorReveal: c.creatorReveal,
    joinerReveal: c.joinerReveal,
    commit: c.commit,
    transcript: c.transcript,
    safetyCode: c.safetyCode,
    safetyCodeDisplay: P.formatSafetyCode(c.safetyCode),
    pairId: c.pairId,
  })),
  rejections: [
    { name: 'joiner reveal that does not match the commitment', ceremony: 0, joinerReveal: flippedNonce, check: 'commitment' },
    { name: 'bundle version 2', reveal: badVersion, check: 'decode' },
    { name: 'signing key off the curve', reveal: offCurve, check: 'decode' },
    { name: 'reveal one byte short', reveal: AB.joinerReveal.slice(0, -1), check: 'decode' },
    { name: 'encSig over another encryption key', reveal: P.encodeReveal({ ...B.bundle, encPk: C.encPk }, AB.joinerNonce), check: 'encSig' },
  ],
});

// ------------------------------------------------------------------------------------------------
// hpke.json

// RFC 9180 Appendix A.1.1 and A.1.1.1, sequence number 0: values from the RFC itself.
const rfc = {
  info: fromHex('4f6465206f6e2061204772656369616e2055726e'),
  ikmE: fromHex('7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234'),
  pkEm: fromHex('37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431'),
  skEm: fromHex('52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736'),
  ikmR: fromHex('6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037'),
  pkRm: fromHex('3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d'),
  skRm: fromHex('4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8'),
  plaintext: fromHex('4265617574792069732074727574682c20747275746820626561757479'),
  aad: fromHex('436f756e742d30'),
  ciphertext: fromHex(
    'f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a',
  ),
};
const rfcEphemeral = P.deriveKeyPair(rfc.ikmE);
const rfcRecipient = P.deriveKeyPair(rfc.ikmR);
assert(P.equalBytes(rfcEphemeral.publicKey, rfc.pkEm), 'RFC 9180 pkEm');
assert(P.equalBytes(rfcRecipient.publicKey, rfc.pkRm), 'RFC 9180 pkRm');
const rfcSealed = P.hpkeSeal(rfc.pkRm, rfc.info, rfc.aad, rfc.plaintext, rfcEphemeral);
assert(P.equalBytes(rfcSealed, P.concat(rfc.pkEm, rfc.ciphertext)), 'RFC 9180 A.1.1.1 sequence 0 ciphertext');

const killitIkmE = P.seeded('hpke example ephemeral');
const killitInfo = P.envelopeInfo(A.fp, B.fp);
const killitPlaintext = utf8('Killit HPKE example');
const killitSealed = P.hpkeSeal(B.encPk, killitInfo, new Uint8Array(0), killitPlaintext, P.deriveKeyPair(killitIkmE));
assert(P.equalBytes(P.hpkeOpen(B.encKey, killitInfo, new Uint8Array(0), killitSealed), killitPlaintext), 'Killit HPKE example opens');

write('hpke.json', {
  description:
    'HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM (SPEC.md §2). sealed is enc ‖ ciphertext ‖ tag, ' +
    'the layout of Tink\'s HybridEncrypt without an output prefix. The ephemeral key is DeriveKeyPair(ikmE).',
  rfc9180: { ...rfc, sealed: rfcSealed, sequenceNumber: 0, source: 'RFC 9180 Appendix A.1.1 and A.1.1.1' },
  killit: [
    {
      name: 'envelope info from A to B, empty AAD',
      recipient: 'B',
      ikmE: killitIkmE,
      info: killitInfo,
      aad: new Uint8Array(0),
      plaintext: killitPlaintext,
      sealed: killitSealed,
    },
  ],
});

// ------------------------------------------------------------------------------------------------
// messages.json

const tiktok: P.AppRef = { packageName: 'com.zhiliaoapp.musically', certDigest: P.seeded('TikTok signing certificate') };

/** A deterministic 32 × 32 RGBA test pattern: a diagonal gradient, opaque. */
function testIcon(): Uint8Array {
  const pixels = new Uint8Array(P.ICON_BYTES);
  for (let y = 0; y < P.ICON_SIDE; y++) {
    for (let x = 0; x < P.ICON_SIDE; x++) {
      const i = (y * P.ICON_SIDE + x) * 4;
      pixels[i] = x * 8;
      pixels[i + 1] = y * 8;
      pixels[i + 2] = (x + y) * 4;
      pixels[i + 3] = 0xff;
    }
  }
  return pixels;
}

const tiktokInfo: P.AppInfo = {
  ...tiktok,
  label: 'TikTok',
  installer: 'com.android.vending',
  firstInstalled: 1_789_990_000_000,
  icon: testIcon(),
};

const unblockRequestId = P.seeded('request unblock TikTok', 16);
const unlockRequestId = P.seeded('request unlock', 16);
const unlockSession = P.seeded('unlock session nonce');
const unpairRequestId = P.seeded('request unpair C', 16);

interface MessageCase {
  name: string;
  from: P.TestPhone;
  to: P.TestPhone;
  pairing: Ceremony;
  kind: number;
  body: P.MessageBody | null;
  /** For a kind this implementation doesn't know: the raw body. */
  rawBody?: Uint8Array;
}

const messageCases: MessageCase[] = [
  {
    name: 'PAIR_OFFER from the guardian',
    from: A,
    to: B,
    pairing: AB,
    kind: P.Kind.PAIR_OFFER,
    body: { kind: P.Kind.PAIR_OFFER, senderRole: P.Role.GUARDIAN, selfName: 'Mom', deviceModel: 'Google Pixel 9', appManagement: false },
  },
  {
    name: 'PAIR_ANSWER accepting, from the protected phone',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.PAIR_ANSWER,
    body: {
      kind: P.Kind.PAIR_ANSWER,
      answer: P.Answer.ACCEPT,
      reason: P.DeclineReason.NONE,
      selfName: 'Ali',
      deviceModel: 'samsung SM-S911B',
      appManagement: true,
    },
  },
  {
    name: 'PAIR_ANSWER declining over a role conflict',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.PAIR_ANSWER,
    body: {
      kind: P.Kind.PAIR_ANSWER,
      answer: P.Answer.DECLINE,
      reason: P.DeclineReason.ROLE_CONFLICT,
      selfName: '',
      deviceModel: '',
      appManagement: false,
    },
  },
  {
    name: 'UNBLOCK_APP with an icon',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.UNBLOCK_APP,
    body: {
      kind: P.Kind.UNBLOCK_APP,
      requestId: unblockRequestId,
      app: tiktokInfo,
      explanation: 'My school club posts announcements only on TikTok.',
      chancesLeft: 3,
      guardianCount: 2,
    },
  },
  {
    name: 'UNLOCK without an explanation',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.UNLOCK,
    body: { kind: P.Kind.UNLOCK, requestId: unlockRequestId, sessionNonce: unlockSession, explanation: '', guardianCount: 2 },
  },
  {
    name: 'UNPAIR asking to remove guardian C',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.UNPAIR,
    body: {
      kind: P.Kind.UNPAIR,
      requestId: unpairRequestId,
      targetPairId: CB.pairId,
      targetFp: C.fp,
      explanation: 'Dad gave me this phone back and no longer uses Killit.',
      chancesLeft: 3,
      guardianCount: 2,
      timerEndsAt: 1_792_592_000_000,
    },
  },
  {
    name: 'DECISION approving the UNBLOCK_APP',
    from: A,
    to: B,
    pairing: AB,
    kind: P.Kind.DECISION,
    body: {
      kind: P.Kind.DECISION,
      requestId: unblockRequestId,
      target: { requestKind: P.Kind.UNBLOCK_APP, app: tiktok },
      decision: P.Verdict.APPROVE,
      note: '',
    },
  },
  {
    name: 'DECISION denying the UNLOCK, with a note',
    from: A,
    to: B,
    pairing: AB,
    kind: P.Kind.DECISION,
    body: {
      kind: P.Kind.DECISION,
      requestId: unlockRequestId,
      target: { requestKind: P.Kind.UNLOCK, sessionNonce: unlockSession },
      decision: P.Verdict.DENY,
      note: 'Not now.\nCall me first.',
    },
  },
  {
    name: 'DECISION approving the UNPAIR',
    from: A,
    to: B,
    pairing: AB,
    kind: P.Kind.DECISION,
    body: {
      kind: P.Kind.DECISION,
      requestId: unpairRequestId,
      target: { requestKind: P.Kind.UNPAIR, targetPairId: CB.pairId },
      decision: P.Verdict.APPROVE,
      note: '',
    },
  },
  {
    name: 'STATUS of the UNBLOCK_APP: one approval, one waiting',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.STATUS,
    body: {
      kind: P.Kind.STATUS,
      requestId: unblockRequestId,
      requestKind: P.Kind.UNBLOCK_APP,
      outcome: P.Outcome.OPEN,
      reason: P.CancelReason.NONE,
      guardians: [
        { guardianFp: A.fp, guardianName: 'Mom', state: P.GuardianState.APPROVED },
        { guardianFp: C.fp, guardianName: 'Dad', state: P.GuardianState.WAITING },
      ],
    },
  },
  {
    name: 'STATUS cancelling the UNLOCK: the protected user left the screen',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.STATUS,
    body: {
      kind: P.Kind.STATUS,
      requestId: unlockRequestId,
      requestKind: P.Kind.UNLOCK,
      outcome: P.Outcome.CANCELLED,
      reason: P.CancelReason.WITHDRAWN,
      guardians: [],
    },
  },
  { name: 'LEAVE', from: A, to: B, pairing: AB, kind: P.Kind.LEAVE, body: { kind: P.Kind.LEAVE } },
  {
    name: 'UNPAIRED telling C it was removed',
    from: B,
    to: C,
    pairing: CB,
    kind: P.Kind.UNPAIRED,
    body: { kind: P.Kind.UNPAIRED, how: P.UnpairedHow.ALL_APPROVED },
  },
  {
    name: 'NOTICE APP_INSTALLED without an icon',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.NOTICE,
    body: {
      kind: P.Kind.NOTICE,
      notice: { code: P.NoticeCode.APP_INSTALLED, app: { ...tiktokInfo, icon: null }, blocked: true },
    },
  },
  {
    name: 'NOTICE GUARDIAN_ADDED',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.NOTICE,
    body: { kind: P.Kind.NOTICE, notice: { code: P.NoticeCode.GUARDIAN_ADDED, guardianFp: C.fp, guardianName: 'Dad' } },
  },
  {
    name: 'NOTICE GUARDIAN_REMOVED',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.NOTICE,
    body: {
      kind: P.Kind.NOTICE,
      notice: { code: P.NoticeCode.GUARDIAN_REMOVED, guardianFp: C.fp, guardianName: 'Dad', how: P.RemovedHow.UNPAIRED },
    },
  },
  {
    name: 'NOTICE RELEASE_STARTED',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.NOTICE,
    body: { kind: P.Kind.NOTICE, notice: { code: P.NoticeCode.RELEASE_STARTED, completesAt: 1_791_209_600_000 } },
  },
  {
    name: 'NOTICE RELEASE_CANCELLED',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.NOTICE,
    body: { kind: P.Kind.NOTICE, notice: { code: P.NoticeCode.RELEASE_CANCELLED } },
  },
  {
    name: 'NOTICE PROTECTION_CHANGED',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.NOTICE,
    body: {
      kind: P.Kind.NOTICE,
      notice: { code: P.NoticeCode.PROTECTION_CHANGED, option: P.ProtectionOption.APPS_CONTROL, enabled: false },
    },
  },
  {
    name: 'NOTICE MANAGEMENT_CHANGED',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.NOTICE,
    body: { kind: P.Kind.NOTICE, notice: { code: P.NoticeCode.MANAGEMENT_CHANGED, enabled: false } },
  },
  {
    name: 'NOTICE with a code this version does not know',
    from: B,
    to: A,
    pairing: AB,
    kind: P.Kind.NOTICE,
    body: { kind: P.Kind.NOTICE, notice: { code: 0x0100, unknown: true, params: fromHex('0102') } },
    rawBody: fromHex('01000102'),
  },
  {
    name: 'a reserved kind this version does not know',
    from: B,
    to: A,
    pairing: AB,
    kind: 0x30,
    body: null,
    rawBody: fromHex('00'),
  },
];

interface BuiltMessage {
  readonly c: MessageCase;
  readonly header: P.MessageHeader;
  readonly body: Uint8Array;
  readonly inner: Uint8Array;
  readonly signedBytes: Uint8Array;
  readonly signature: Uint8Array;
  readonly ikmE: Uint8Array;
  readonly envelope: Uint8Array;
}

function seal(header: P.MessageHeader, inner: Uint8Array, signature: Uint8Array, recipient: P.TestPhone, ikmE: Uint8Array): Uint8Array {
  const plaintext = P.padPlaintext(inner, signature);
  const info = P.envelopeInfo(header.senderFp, header.recipientFp);
  return P.hpkeSeal(recipient.encPk, info, new Uint8Array(0), plaintext, P.deriveKeyPair(ikmE));
}

function build(c: MessageCase, index: number): BuiltMessage {
  const header: P.MessageHeader = {
    version: P.MESSAGE_VERSION,
    kind: c.kind,
    messageId: P.seeded(`message ${index} id`, 16),
    pairId: c.pairing.pairId,
    senderFp: c.from.fp,
    recipientFp: c.to.fp,
    createdAt: 1_790_000_000_000 + index * 60_000,
  };
  const body = c.rawBody ?? P.encodeBody(c.body as P.MessageBody);
  const inner = P.encodeInner(header, body);
  const signedBytes = P.messageSignedBytes(inner);
  const signature = sign(c.from.signKey, signedBytes);
  const ikmE = P.seeded(`message ${index} ephemeral`);
  const envelope = seal(header, inner, signature, c.to, ikmE);
  assert(envelope.length === P.ENVELOPE_BYTES, 'envelope size');

  const opened = P.openEnvelope(envelope, c.to.encKey, c.to.fp, c.from.fp);
  assert(opened.ok && P.verifyInner(c.from.signPk, opened.value.inner, opened.value.signature), `message "${c.name}" opens and verifies`);
  if (c.body !== null) {
    const decoded = P.decodeBody(c.kind, body);
    assert(decoded.ok && isDeepStrictEqual(toJson(decoded.value), toJson(c.body)), `message "${c.name}" decodes to its fields`);
  } else {
    assert(!P.isKnownKind(c.kind), `message "${c.name}" uses an unknown kind`);
  }
  return { c, header, body, inner, signedBytes, signature, ikmE, envelope };
}

const built = messageCases.map(build);
const byName = (name: string): BuiltMessage => {
  const message = built.find((m) => m.c.name === name);
  assert(message !== undefined, `no message called "${name}"`);
  return message;
};

// Envelopes that must be refused, each broken in one way.
const unblock = byName('UNBLOCK_APP with an icon');
const flipped = (bytes: Uint8Array, index: number): Uint8Array => {
  const copy = bytes.slice();
  copy[index]! ^= 0x01;
  return copy;
};
const paddedWrong = P.padPlaintext(unblock.inner, unblock.signature);
paddedWrong[P.PLAINTEXT_BYTES - 1] = 0x01;
const shortInner = P.padPlaintext(unblock.inner, unblock.signature);
shortInner.set(P.u16(P.HEADER_BYTES - 1), 0);
const toCInner = P.encodeInner({ ...unblock.header, recipientFp: C.fp }, unblock.body);
const toCSignature = sign(B.signKey, P.messageSignedBytes(toCInner));
const info = P.envelopeInfo(B.fp, A.fp);
const sealPlain = (plaintext: Uint8Array, seed: string) =>
  P.hpkeSeal(A.encPk, info, new Uint8Array(0), plaintext, P.deriveKeyPair(P.seeded(seed)));
const signedByC = sign(C.signKey, unblock.signedBytes);

const rejectedEnvelopes = [
  { name: 'one ciphertext byte flipped', envelope: flipped(unblock.envelope, 100), stage: 'open' },
  { name: 'one byte of enc flipped', envelope: flipped(unblock.envelope, 3), stage: 'open' },
  { name: 'one byte short', envelope: unblock.envelope.slice(0, -1), stage: 'open' },
  { name: 'non-zero padding', envelope: sealPlain(paddedWrong, 'rejected padding'), stage: 'open' },
  { name: 'innerLength below the header size', envelope: sealPlain(shortInner, 'rejected inner length'), stage: 'open' },
  {
    name: 'header names another recipient',
    envelope: sealPlain(P.padPlaintext(toCInner, toCSignature), 'rejected recipient'),
    stage: 'open',
    signedBytes: P.messageSignedBytes(toCInner),
    signature: toCSignature,
  },
  {
    name: 'signed by another phone than the sender',
    envelope: seal(unblock.header, unblock.inner, signedByC, A, P.seeded('rejected signature')),
    stage: 'signature',
    signedBytes: unblock.signedBytes,
    signature: signedByC,
  },
].map((r) => ({ ...r, from: 'B', recipient: 'A' }));

for (const r of rejectedEnvelopes) {
  const opened = P.openEnvelope(r.envelope, A.encKey, A.fp, B.fp);
  if (r.stage === 'open') {
    assert(!opened.ok, `envelope "${r.name}" must not open`);
  } else {
    assert(opened.ok && !P.verifyInner(B.signPk, opened.value.inner, opened.value.signature), `envelope "${r.name}" must fail its signature`);
  }
}
// The same envelope, named as coming from C: the HPKE info no longer matches.
assert(!P.openEnvelope(unblock.envelope, A.encKey, A.fp, C.fp).ok, 'an envelope must not open under another sender');
rejectedEnvelopes.push({ name: 'opened as if sent by C', envelope: unblock.envelope, stage: 'open', from: 'C', recipient: 'A' });

// Bodies that must be refused, each written by hand around one defect.
function body(kind: number, write: (w: P.ByteWriter) => void) {
  const writer = new P.ByteWriter();
  write(writer);
  return { kind, body: writer.finish() };
}
const nameBytes = (text: string): Uint8Array => utf8(text);
const appRef = (w: P.ByteWriter, packageName = tiktok.packageName) => w.blob16(utf8(packageName)).fixed(tiktok.certDigest, 32);
const appInfoNoIcon = (w: P.ByteWriter, iconFormat = 0) =>
  appRef(w).blob16(utf8('TikTok')).blob16(utf8('com.android.vending')).u64(tiktokInfo.firstInstalled).u8(iconFormat);
const explanation = utf8('My school club posts announcements only on TikTok.');

const rejectedBodies = [
  { name: 'PAIR_OFFER with role 3', ...body(P.Kind.PAIR_OFFER, (w) => w.u8(3).blob16(nameBytes('Mom')).blob16(new Uint8Array(0)).u8(0)) },
  {
    name: 'PAIR_OFFER from a guardian claiming app management',
    ...body(P.Kind.PAIR_OFFER, (w) => w.u8(1).blob16(nameBytes('Mom')).blob16(new Uint8Array(0)).u8(1)),
  },
  { name: 'PAIR_OFFER with bool 2', ...body(P.Kind.PAIR_OFFER, (w) => w.u8(2).blob16(nameBytes('Ali')).blob16(new Uint8Array(0)).u8(2)) },
  {
    name: 'PAIR_ANSWER accepting with a decline reason',
    ...body(P.Kind.PAIR_ANSWER, (w) => w.u8(1).u8(1).blob16(nameBytes('Ali')).blob16(new Uint8Array(0)).u8(0)),
  },
  {
    name: 'PAIR_ANSWER declining with a name',
    ...body(P.Kind.PAIR_ANSWER, (w) => w.u8(2).u8(1).blob16(nameBytes('Ali')).blob16(new Uint8Array(0)).u8(0)),
  },
  {
    name: 'UNBLOCK_APP with a trailing byte',
    ...body(P.Kind.UNBLOCK_APP, (w) => appInfoNoIcon(w.fixed(unblockRequestId, 16)).blob16(explanation).u8(3).u8(2).u8(0)),
  },
  {
    name: 'UNBLOCK_APP with a nine-code-point explanation',
    ...body(P.Kind.UNBLOCK_APP, (w) => appInfoNoIcon(w.fixed(unblockRequestId, 16)).blob16(utf8('too short')).u8(3).u8(2)),
  },
  {
    name: 'UNBLOCK_APP with no chances left',
    ...body(P.Kind.UNBLOCK_APP, (w) => appInfoNoIcon(w.fixed(unblockRequestId, 16)).blob16(explanation).u8(0).u8(2)),
  },
  {
    name: 'UNBLOCK_APP with icon format 2',
    ...body(P.Kind.UNBLOCK_APP, (w) => appInfoNoIcon(w.fixed(unblockRequestId, 16), 2).blob16(explanation).u8(3).u8(2)),
  },
  {
    name: 'UNBLOCK_APP with an invalid package name',
    ...body(P.Kind.UNBLOCK_APP, (w) =>
      appRef(w.fixed(unblockRequestId, 16), 'com..example')
        .blob16(utf8('TikTok'))
        .blob16(new Uint8Array(0))
        .u64(0)
        .u8(0)
        .blob16(explanation)
        .u8(3)
        .u8(2),
    ),
  },
  {
    name: 'UNBLOCK_APP with an icon cut short',
    ...body(P.Kind.UNBLOCK_APP, (w) => appInfoNoIcon(w.fixed(unblockRequestId, 16), 1).raw(new Uint8Array(100))),
  },
  {
    name: 'DECISION for a kind that is not a request',
    ...body(P.Kind.DECISION, (w) => w.fixed(unblockRequestId, 16).u8(P.Kind.DECISION).fixed(new Uint8Array(32), 32).u8(1).blob16(new Uint8Array(0))),
  },
  {
    name: 'DECISION with a control character in the note',
    ...body(P.Kind.DECISION, (w) => w.fixed(unlockRequestId, 16).u8(P.Kind.UNLOCK).fixed(unlockSession, 32).u8(2).blob16(utf8('no\u0007'))),
  },
  {
    name: 'STATUS that is open but gives a cancel reason',
    ...body(P.Kind.STATUS, (w) => w.fixed(unblockRequestId, 16).u8(P.Kind.UNBLOCK_APP).u8(0).u8(1).u8(0)),
  },
  {
    name: 'STATUS listing 41 guardians',
    ...body(P.Kind.STATUS, (w) => {
      w.fixed(unblockRequestId, 16).u8(P.Kind.UNBLOCK_APP).u8(0).u8(0).u8(41);
      for (let i = 0; i < 41; i++) w.fixed(A.fp, 32).blob16(utf8('Mom')).u8(0);
    }),
  },
  { name: 'LEAVE with a body', ...body(P.Kind.LEAVE, (w) => w.u8(0)) },
  { name: 'UNPAIRED with how 4', ...body(P.Kind.UNPAIRED, (w) => w.u8(4)) },
  { name: 'NOTICE PROTECTION_CHANGED with option 7', ...body(P.Kind.NOTICE, (w) => w.u16(P.NoticeCode.PROTECTION_CHANGED).u8(7).u8(0)) },
];

for (const r of rejectedBodies) assert(!P.decodeBody(r.kind, r.body).ok, `body "${r.name}" must be refused`);

// DECISION checks against stored requests (SPEC.md §11.6).
const approveUnblock = byName('DECISION approving the UNBLOCK_APP');
const denyUnlock = byName('DECISION denying the UNLOCK, with a note');
const approveUnpair = byName('DECISION approving the UNPAIR');

interface DecisionCheck {
  name: string;
  message: BuiltMessage;
  stored: P.StoredRequest;
  guardian: P.TestPhone;
  valid: boolean;
}

const storedUnblock: P.StoredRequest = {
  requestId: unblockRequestId,
  target: { requestKind: P.Kind.UNBLOCK_APP, app: tiktok },
  pairId: AB.pairId,
  guardianFp: A.fp,
  guardianSignPk: A.signPk,
  ownFp: B.fp,
};
const storedUnlock: P.StoredRequest = { ...storedUnblock, requestId: unlockRequestId, target: { requestKind: P.Kind.UNLOCK, sessionNonce: unlockSession } };
const storedUnpair: P.StoredRequest = { ...storedUnblock, requestId: unpairRequestId, target: { requestKind: P.Kind.UNPAIR, targetPairId: CB.pairId } };

const decisionChecks: DecisionCheck[] = [
  { name: 'approval matching its UNBLOCK_APP request', message: approveUnblock, stored: storedUnblock, guardian: A, valid: true },
  { name: 'denial matching its UNLOCK request', message: denyUnlock, stored: storedUnlock, guardian: A, valid: true },
  { name: 'approval matching its UNPAIR request', message: approveUnpair, stored: storedUnpair, guardian: A, valid: true },
  {
    name: 'approval checked against a request for another certificate',
    message: approveUnblock,
    stored: { ...storedUnblock, target: { requestKind: P.Kind.UNBLOCK_APP, app: { ...tiktok, certDigest: P.seeded('another certificate') } } },
    guardian: A,
    valid: false,
  },
  {
    name: 'approval checked against a request for another package',
    message: approveUnblock,
    stored: { ...storedUnblock, target: { requestKind: P.Kind.UNBLOCK_APP, app: { ...tiktok, packageName: 'com.instagram.android' } } },
    guardian: A,
    valid: false,
  },
  {
    name: 'denial checked against another unlock session',
    message: denyUnlock,
    stored: { ...storedUnlock, target: { requestKind: P.Kind.UNLOCK, sessionNonce: P.seeded('a later unlock session') } },
    guardian: A,
    valid: false,
  },
  { name: 'approval checked against another request id', message: approveUnblock, stored: { ...storedUnblock, requestId: unlockRequestId }, guardian: A, valid: false },
  { name: 'approval checked against another pairing', message: approveUnblock, stored: { ...storedUnblock, pairId: CB.pairId }, guardian: A, valid: false },
  {
    name: 'approval attributed to another guardian',
    message: approveUnblock,
    stored: { ...storedUnblock, guardianFp: C.fp, guardianSignPk: C.signPk },
    guardian: C,
    valid: false,
  },
];

for (const check of decisionChecks) {
  const opened = P.openEnvelope(check.message.envelope, B.encKey, B.fp, A.fp);
  assert(opened.ok, `decision "${check.name}" opens`);
  const result = P.verifyDecision(check.stored, opened.value);
  assert(result.ok === check.valid, `decision check "${check.name}" should be ${check.valid ? 'valid' : 'invalid'}`);
}

write('messages.json', {
  description:
    'End-to-end messages (SPEC.md §10, §11). For each message: fields is the decoded body; body, inner and signedBytes ' +
    'are exact; envelope is HPKE-sealed to the recipient with the ephemeral key DeriveKeyPair(ikmE). ' +
    'Bodies of an unknown kind or notice code are kept as received. rejectedEnvelopes must fail at stage "open" ' +
    '(SPEC.md §10.3 steps 1-4) or "signature" (step 6); rejectedBodies must fail to decode; decisionChecks verify a ' +
    'DECISION against a stored request (§11.6).',
  pairings: [
    { name: 'AB', guardian: 'A', protected: 'B', pairId: AB.pairId },
    { name: 'CB', guardian: 'C', protected: 'B', pairId: CB.pairId },
  ],
  messages: built.map((m) => ({
    name: m.c.name,
    from: m.c.from.name,
    to: m.c.to.name,
    kind: m.c.kind,
    known: P.isKnownKind(m.c.kind),
    messageId: m.header.messageId,
    pairId: m.header.pairId,
    createdAt: m.header.createdAt,
    fields: m.c.body,
    body: m.body,
    inner: m.inner,
    signedBytes: m.signedBytes,
    signature: m.signature,
    ikmE: m.ikmE,
    envelope: m.envelope,
  })),
  rejectedEnvelopes,
  rejectedBodies,
  decisionChecks: decisionChecks.map((check) => ({
    name: check.name,
    message: check.message.c.name,
    storedRequest: { ...check.stored, guardianSignPk: undefined, guardian: check.guardian.name },
    valid: check.valid,
  })),
});
