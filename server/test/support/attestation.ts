/**
 * Forged attestation chains for tests: a test root, intermediate and attestation certificates,
 * and a leaf for a test phone's key carrying a key description built field by field.
 *
 * Every rejection SPEC.md §5.2 lists can be provoked by an option here, so each check in
 * `verify.ts` is shown to fire, not just to pass.
 */
import { X509Certificate, createHash, createPublicKey, webcrypto } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import type { TestPhone } from '@tamodak/protocol/e2e';
import type { TrustAnchor } from '../../src/attestation/roots.ts';

// No DOM library here: WebCrypto's types come from Node's namespace.
type CryptoKey = webcrypto.CryptoKey;
type CryptoKeyPair = webcrypto.CryptoKeyPair;
const subtle = webcrypto.subtle;
const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const DAY = 24 * 60 * 60 * 1000;

/** Killit's test signing-certificate digest, as the test config allows it. */
export const TEST_CERT_DIGEST = new Uint8Array(createHash('sha256').update('killit test signing certificate').digest());
export const KILLIT_PACKAGE = 'org.tamodak.killit';

export interface AuthorizationListSpec {
  // `| undefined` throughout: tests remove a field by setting it to undefined.
  purpose?: number[] | undefined;
  algorithm?: number | undefined;
  keySize?: number | undefined;
  digest?: number[] | undefined;
  ecCurve?: number | undefined;
  origin?: number | undefined;
  rootOfTrust?: { deviceLocked: boolean; verifiedBootState: number } | undefined;
  osVersion?: number | undefined;
  osPatchLevel?: number | undefined;
  /** Packages and digests, or raw bytes for a malformed id. */
  applicationId?: { packages: { name: string; version: number }[]; digests: Uint8Array[] } | Uint8Array | undefined;
  /** Extra `[tag] EXPLICIT INTEGER` entries, e.g. a repeated tag. */
  extra?: { tag: number; value: number }[] | undefined;
}

export interface KeyDescriptionSpec {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keyMintVersion: number;
  keyMintSecurityLevel: number;
  challenge: Uint8Array;
  softwareEnforced: AuthorizationListSpec;
  hardwareEnforced: AuthorizationListSpec;
}

/** A key description a real TEE would give Killit's signing key. */
export function validDescription(challenge: Uint8Array): KeyDescriptionSpec {
  return {
    attestationVersion: 200,
    attestationSecurityLevel: 1,
    keyMintVersion: 200,
    keyMintSecurityLevel: 1,
    challenge,
    softwareEnforced: {
      applicationId: { packages: [{ name: KILLIT_PACKAGE, version: 1 }], digests: [TEST_CERT_DIGEST] },
    },
    hardwareEnforced: {
      purpose: [2],
      algorithm: 3,
      keySize: 256,
      digest: [4],
      ecCurve: 1,
      origin: 0,
      rootOfTrust: { deviceLocked: true, verifiedBootState: 0 },
      osVersion: 150000,
      osPatchLevel: 202609,
    },
  };
}

function tagged(tag: number, value: asn1js.BaseBlock): asn1js.Constructed {
  return new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: tag }, value: [value] });
}

const integer = (value: number): asn1js.Integer => new asn1js.Integer({ value });
const integerSet = (values: number[]): asn1js.Set => new asn1js.Set({ value: values.map(integer) });
const octets = (bytes: Uint8Array): asn1js.OctetString => new asn1js.OctetString({ valueHex: bytes });

export function encodeApplicationId(spec: { packages: { name: string; version: number }[]; digests: Uint8Array[] }): Uint8Array {
  const packages = spec.packages.map(
    (p) => new asn1js.Sequence({ value: [octets(new TextEncoder().encode(p.name)), integer(p.version)] }),
  );
  return new Uint8Array(
    new asn1js.Sequence({ value: [new asn1js.Set({ value: packages }), new asn1js.Set({ value: spec.digests.map(octets) })] }).toBER(),
  );
}

function authorizationList(spec: AuthorizationListSpec): asn1js.Sequence {
  const entries: asn1js.BaseBlock[] = [];
  if (spec.purpose) entries.push(tagged(1, integerSet(spec.purpose)));
  if (spec.algorithm !== undefined) entries.push(tagged(2, integer(spec.algorithm)));
  if (spec.keySize !== undefined) entries.push(tagged(3, integer(spec.keySize)));
  if (spec.digest) entries.push(tagged(5, integerSet(spec.digest)));
  if (spec.ecCurve !== undefined) entries.push(tagged(10, integer(spec.ecCurve)));
  if (spec.origin !== undefined) entries.push(tagged(702, integer(spec.origin)));
  if (spec.rootOfTrust) {
    entries.push(
      tagged(
        704,
        new asn1js.Sequence({
          value: [
            octets(new Uint8Array(32).fill(7)),
            new asn1js.Boolean({ value: spec.rootOfTrust.deviceLocked }),
            new asn1js.Enumerated({ value: spec.rootOfTrust.verifiedBootState }),
            octets(new Uint8Array(32).fill(9)),
          ],
        }),
      ),
    );
  }
  if (spec.osVersion !== undefined) entries.push(tagged(705, integer(spec.osVersion)));
  if (spec.osPatchLevel !== undefined) entries.push(tagged(706, integer(spec.osPatchLevel)));
  if (spec.applicationId) {
    const raw = spec.applicationId instanceof Uint8Array ? spec.applicationId : encodeApplicationId(spec.applicationId);
    entries.push(tagged(709, octets(raw)));
  }
  for (const extra of spec.extra ?? []) entries.push(tagged(extra.tag, integer(extra.value)));
  return new asn1js.Sequence({ value: entries });
}

/** Encodes a key description as the extension's DER. */
export function encodeKeyDescription(spec: KeyDescriptionSpec): Uint8Array {
  return new Uint8Array(
    new asn1js.Sequence({
      value: [
        integer(spec.attestationVersion),
        new asn1js.Enumerated({ value: spec.attestationSecurityLevel }),
        integer(spec.keyMintVersion),
        new asn1js.Enumerated({ value: spec.keyMintSecurityLevel }),
        octets(spec.challenge),
        octets(new Uint8Array(0)),
        authorizationList(spec.softwareEnforced),
        authorizationList(spec.hardwareEnforced),
      ],
    }).toBER(),
  );
}

let nextSerial = 1000;

interface CertificateSpec {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  publicKey: CryptoKey;
  signingKey: CryptoKey;
  notBefore: Date;
  notAfter: Date;
  serial?: number;
  keyDescription?: Uint8Array;
}

function name(attributes: Record<string, string>): pkijs.AttributeTypeAndValue[] {
  return Object.entries(attributes).map(
    ([type, value]) => new pkijs.AttributeTypeAndValue({ type, value: new asn1js.Utf8String({ value }) }),
  );
}

async function certificate(spec: CertificateSpec): Promise<Uint8Array> {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: spec.serial ?? nextSerial++ });
  cert.issuer.typesAndValues.push(...name(spec.issuer));
  cert.subject.typesAndValues.push(...name(spec.subject));
  cert.notBefore.value = spec.notBefore;
  cert.notAfter.value = spec.notAfter;
  if (spec.keyDescription) {
    cert.extensions = [
      new pkijs.Extension({ extnID: '1.3.6.1.4.1.11129.2.1.17', critical: false, extnValue: spec.keyDescription.slice().buffer }),
    ];
  }
  await cert.subjectPublicKeyInfo.importKey(spec.publicKey);
  await cert.sign(spec.signingKey, 'SHA-256');
  return new Uint8Array(cert.toSchema(true).toBER(false));
}

const CN = '2.5.4.3';
const SERIAL_NUMBER = '2.5.4.5';

export interface TestRoot {
  readonly anchor: TrustAnchor;
  readonly der: Uint8Array;
  readonly keys: CryptoKeyPair;
  readonly subject: Record<string, string>;
}

/** A self-signed root standing in for Google's. */
export async function createTestRoot(commonName = 'Killit Test Attestation Root'): Promise<TestRoot> {
  const keys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const subject = { [CN]: commonName };
  const now = Date.now();
  const der = await certificate({
    subject,
    issuer: subject,
    publicKey: keys.publicKey,
    signingKey: keys.privateKey,
    notBefore: new Date(now - 365 * DAY),
    notAfter: new Date(now + 10 * 365 * DAY),
  });
  const x509 = new X509Certificate(der);
  const spki = x509.publicKey.export({ type: 'spki', format: 'der' });
  return {
    anchor: { name: commonName, pem: x509.toString(), spkiSha256: createHash('sha256').update(spki).digest('hex') },
    der,
    keys,
    subject,
  };
}

/** The phone's signing key as a WebCrypto key, for the leaf certificate. */
async function phoneKeys(phone: TestPhone): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  const publicJwk = createPublicKey(phone.signKey).export({ format: 'jwk' });
  const privateJwk = phone.signKey.export({ format: 'jwk' });
  return {
    publicKey: await subtle.importKey('jwk', publicJwk, EC, true, ['verify']),
    privateKey: await subtle.importKey('jwk', privateJwk, EC, true, ['sign']),
  };
}

export interface ChainOptions {
  readonly phone: TestPhone;
  readonly challenge: Uint8Array;
  /** Edits the valid key description; return the changed copy. */
  readonly description?: (valid: KeyDescriptionSpec) => KeyDescriptionSpec;
  /** Raw extension bytes, overriding `description`. */
  readonly rawExtension?: Uint8Array;
  readonly omitExtension?: boolean;
  /** Also put a key description in the intermediate certificate. */
  readonly extensionOnIntermediate?: boolean;
  /** Mark the chain factory-provisioned: a serialNumber attribute below the root. */
  readonly factory?: boolean;
  readonly intermediateValidity?: { notBefore: Date; notAfter: Date };
  readonly leafValidity?: { notBefore: Date; notAfter: Date };
  readonly attestationSerial?: number;
  /** Name the leaf's issuer wrongly, breaking name chaining. */
  readonly breakNameChain?: boolean;
  /** Sign the leaf with the intermediate's key instead of the attestation key. */
  readonly misSignLeaf?: boolean;
  /** Certify this key in the leaf instead of the phone's. */
  readonly leafPublicKey?: CryptoKey;
  /** Append a fake leaf signed by the phone's attested key (the chain-extension attack). */
  readonly extendWithFakeLeaf?: boolean;
}

/**
 * Builds a four-certificate chain, leaf first: leaf → attestation → intermediate → root, the
 * shape of a factory-provisioned chain.
 */
export async function buildChain(root: TestRoot, options: ChainOptions): Promise<Uint8Array[]> {
  const now = Date.now();
  const valid = { notBefore: new Date(now - DAY), notAfter: new Date(now + 365 * DAY) };
  const intermediateKeys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const attestationKeys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const intermediateSubject = options.factory
    ? { [SERIAL_NUMBER]: 'c6047571d8f0d17c', [CN]: 'Test Intermediate' }
    : { [CN]: 'Test Intermediate' };
  const attestationSubject = { [CN]: 'Test Attestation Key' };

  const description = options.description ? options.description(validDescription(options.challenge)) : validDescription(options.challenge);
  const extension = options.omitExtension ? undefined : (options.rawExtension ?? encodeKeyDescription(description));

  const intermediate = await certificate({
    subject: intermediateSubject,
    issuer: root.subject,
    publicKey: intermediateKeys.publicKey,
    signingKey: root.keys.privateKey,
    ...(options.intermediateValidity ?? valid),
    ...(options.extensionOnIntermediate ? { keyDescription: encodeKeyDescription(description) } : {}),
  });
  const attestation = await certificate({
    subject: attestationSubject,
    issuer: intermediateSubject,
    publicKey: attestationKeys.publicKey,
    signingKey: intermediateKeys.privateKey,
    ...valid,
    ...(options.attestationSerial === undefined ? {} : { serial: options.attestationSerial }),
  });
  const phone = await phoneKeys(options.phone);
  const leaf = await certificate({
    subject: { [CN]: 'Android Keystore Key' },
    issuer: options.breakNameChain ? { [CN]: 'Somebody Else' } : attestationSubject,
    publicKey: options.leafPublicKey ?? phone.publicKey,
    signingKey: options.misSignLeaf ? intermediateKeys.privateKey : attestationKeys.privateKey,
    ...(options.leafValidity ?? valid),
    ...(extension === undefined ? {} : { keyDescription: extension }),
  });
  const chain = [leaf, attestation, intermediate, root.der];
  if (!options.extendWithFakeLeaf) return chain;

  // The attested key signs a new leaf for a key it controls, with a description it made up.
  const forgedKeys = (await subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair;
  const fake = await certificate({
    subject: { [CN]: 'Forged' },
    issuer: { [CN]: 'Android Keystore Key' },
    publicKey: forgedKeys.publicKey,
    signingKey: phone.privateKey,
    ...valid,
    keyDescription: encodeKeyDescription(validDescription(options.challenge)),
  });
  return [fake, ...chain];
}

/** An RSA key, to certify something other than P-256 in the leaf. */
export async function rsaPublicKey(): Promise<CryptoKey> {
  const keys = (await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  return keys.publicKey;
}
