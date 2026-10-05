/**
 * Key-attestation chain verification (SPEC.md §5.2), modelled on developer.android.com's
 * "Verify hardware-backed key pairs with key attestation" and Google's `android/keyattestation`
 * verifier (its `KeyAttestationCertPathValidator` and default constraints).
 *
 * What a successful result proves: a key generated inside a TEE or StrongBox, by an app the
 * platform identified as `org.tamodak.killit` signed with one of our certificates, in answer to a
 * challenge this server issued. That is what keeps scripts and emulators off the production API
 * (PLAN.md §6.1, "Fake clients").
 */
import { X509Certificate, createHash, type KeyObject } from 'node:crypto';
import * as pkijs from 'pkijs';
import { P256_POINT_BYTES, concat, constantTimeEqual, fromBase64Url, toHex } from '@tamodak/protocol/api';
import {
  KEY_DESCRIPTION_OID,
  KeyMint,
  SecurityLevel,
  parseApplicationId,
  parseKeyDescription,
  type AuthorizationList,
  type KeyDescription,
} from './keyDescription.ts';
import type { TrustAnchor } from './roots.ts';
import type { AttestationSummary } from '../db/schema.ts';

/** Why a chain was refused; sent to the phone as `reason` (SPEC.md §5.2). */
export type RejectionReason =
  | 'chain_invalid'
  | 'untrusted_root'
  | 'revoked'
  | 'extension_missing'
  | 'extension_misplaced'
  | 'extension_invalid'
  | 'security_level'
  | 'key_properties'
  | 'application_id'
  | 'key_mismatch';

export class AttestationError extends Error {
  override readonly name = 'AttestationError';
  readonly reason: RejectionReason;

  constructor(reason: RejectionReason, detail: string) {
    super(`${reason}: ${detail}`);
    this.reason = reason;
  }
}

export interface AttestationPolicy {
  readonly trustAnchors: readonly TrustAnchor[];
  /** Development only (SPEC.md §5.2 step 2): accept a self-signed root we don't know, and software keys. */
  readonly acceptAnyRoot: boolean;
  readonly packageName: string;
  readonly certDigests: readonly Uint8Array[];
  readonly isRevoked: (serialHex: string) => boolean;
  readonly now: Date;
}

export interface VerifiedAttestation {
  /** The attested key as an uncompressed P-256 point. */
  readonly signPk: Uint8Array;
  /** The challenge the key description carries; the caller checks it was issued and unused. */
  readonly challenge: Uint8Array;
  readonly securityLevel: number;
  readonly summary: AttestationSummary;
}

/** OID of the X.520 `serialNumber` attribute; its presence marks a factory-provisioned chain. */
const SERIAL_NUMBER_ATTRIBUTE = '2.5.4.5';

interface ParsedCertificate {
  readonly node: X509Certificate;
  readonly pkijs: pkijs.Certificate;
}

function parse(der: Uint8Array): ParsedCertificate {
  try {
    return { node: new X509Certificate(der), pkijs: pkijs.Certificate.fromBER(der) };
  } catch {
    throw new AttestationError('chain_invalid', 'a certificate does not parse');
  }
}

function spkiSha256(key: KeyObject): string {
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}

/** The DER inside the key-description extension of one certificate, or null when it has none. */
function keyDescriptionExtension(certificate: pkijs.Certificate): Uint8Array | null {
  const found = (certificate.extensions ?? []).filter((extension) => extension.extnID === KEY_DESCRIPTION_OID);
  if (found.length > 1) throw new AttestationError('extension_misplaced', 'the key description appears twice in one certificate');
  return found.length === 1 ? new Uint8Array(found[0]!.extnValue.getValue()) : null;
}

function hasSerialNumberAttribute(certificate: pkijs.Certificate): boolean {
  return certificate.subject.typesAndValues.some((attribute) => attribute.type === SERIAL_NUMBER_ATTRIBUTE);
}

/** The leaf's key as an uncompressed P-256 point, or a refusal for any other kind of key. */
function p256Point(key: KeyObject): Uint8Array {
  const jwk = key.export({ format: 'jwk' });
  if (key.asymmetricKeyType !== 'ec' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new AttestationError('key_mismatch', 'the attested key is not P-256');
  }
  const point = concat(Uint8Array.of(0x04), fromBase64Url(jwk.x), fromBase64Url(jwk.y));
  if (point.length !== P256_POINT_BYTES) throw new AttestationError('key_mismatch', 'the attested key is malformed');
  return point;
}

/**
 * Verifies an attestation chain, leaf first.
 *
 * @throws AttestationError with the reason to report.
 */
export function verifyAttestationChain(chainDer: readonly Uint8Array[], policy: AttestationPolicy): VerifiedAttestation {
  if (chainDer.length < 3 || chainDer.length > 6) throw new AttestationError('chain_invalid', `${chainDer.length} certificates`);
  const chain = chainDer.map(parse);
  const root = chain[chain.length - 1]!;
  const leaf = chain[0]!;

  // Trust anchor, by public key: Google publishes several certificates of one RSA key.
  const anchor = policy.trustAnchors.find((candidate) => candidate.spkiSha256 === spkiSha256(root.node.publicKey));
  let untrustedRoot = false;
  if (anchor === undefined) {
    if (!policy.acceptAnyRoot || !root.node.verify(root.node.publicKey)) {
      throw new AttestationError('untrusted_root', 'the chain does not end in a Google root');
    }
    untrustedRoot = true;
  }

  // Name chaining and signatures, from the root down. The anchor's own signature and dates don't
  // matter: what is trusted is its key.
  for (let i = chain.length - 2; i >= 0; i--) {
    const child = chain[i]!;
    const issuer = chain[i + 1]!;
    if (child.node.issuer !== issuer.node.subject) throw new AttestationError('chain_invalid', 'issuer and subject names do not chain');
    if (!child.node.verify(issuer.node.publicKey)) throw new AttestationError('chain_invalid', 'a certificate signature does not verify');
  }

  // Validity of the certificates between leaf and root. The leaf's dates are set by the phone
  // itself, so Google doesn't check them; expired factory certificates stay valid because
  // factory keys can't be rotated.
  const factoryProvisioned = hasSerialNumberAttribute(chain[chain.length - 2]!.pkijs);
  for (let i = 1; i < chain.length - 1; i++) {
    const certificate = chain[i]!.node;
    if (policy.now < certificate.validFromDate) throw new AttestationError('chain_invalid', 'a certificate is not valid yet');
    if (policy.now > certificate.validToDate && !factoryProvisioned) throw new AttestationError('chain_invalid', 'a certificate has expired');
  }

  for (const certificate of chain) {
    if (policy.isRevoked(certificate.node.serialNumber)) throw new AttestationError('revoked', 'a certificate in the chain is revoked');
  }

  // The key description must be in the leaf and nowhere else: an attested key signing a fake leaf
  // with a forged description is the chain-extension attack.
  for (let i = 1; i < chain.length; i++) {
    if (keyDescriptionExtension(chain[i]!.pkijs) !== null) throw new AttestationError('extension_misplaced', 'a key description above the leaf');
  }
  const extension = keyDescriptionExtension(leaf.pkijs);
  if (extension === null) throw new AttestationError('extension_missing', 'the leaf has no key description');
  let description: KeyDescription;
  try {
    description = parseKeyDescription(extension);
  } catch (error) {
    throw new AttestationError('extension_invalid', (error as Error).message);
  }

  const levels = [description.attestationSecurityLevel, description.keyMintSecurityLevel];
  const hardware = levels.every((level) => level === SecurityLevel.TRUSTED_ENVIRONMENT || level === SecurityLevel.STRONG_BOX);
  const allowedSoftware = untrustedRoot && levels.every((level) => level === SecurityLevel.SOFTWARE);
  if (!hardware && !allowedSoftware) throw new AttestationError('security_level', `levels ${levels.join(', ')}`);

  // A software key (development only) carries its properties in softwareEnforced.
  const enforced: AuthorizationList = hardware ? description.hardwareEnforced : description.softwareEnforced;
  checkKeyProperties(enforced, hardware);
  checkApplicationId(description, policy);

  const signPk = p256Point(leaf.node.publicKey);

  const rootOfTrust = description.hardwareEnforced.rootOfTrust ?? description.softwareEnforced.rootOfTrust;
  return {
    signPk,
    challenge: description.attestationChallenge,
    securityLevel: Math.min(...levels),
    summary: {
      attestationVersion: description.attestationVersion,
      attestationSecurityLevel: description.attestationSecurityLevel,
      keyMintSecurityLevel: description.keyMintSecurityLevel,
      verifiedBootState: rootOfTrust?.verifiedBootState ?? null,
      deviceLocked: rootOfTrust?.deviceLocked ?? null,
      osVersion: description.hardwareEnforced.osVersion ?? description.softwareEnforced.osVersion ?? null,
      osPatchLevel: description.hardwareEnforced.osPatchLevel ?? description.softwareEnforced.osPatchLevel ?? null,
      untrustedRoot,
    },
  };
}

/** SPEC.md §5.2 step 7, `key_properties`: a generated P-256 signing key, with a root of trust. */
function checkKeyProperties(enforced: AuthorizationList, hardware: boolean): void {
  const problems: string[] = [];
  if (enforced.origin !== KeyMint.ORIGIN_GENERATED) problems.push('not generated on the device');
  if (!(enforced.purpose ?? []).includes(KeyMint.PURPOSE_SIGN)) problems.push('not a signing key');
  if (enforced.algorithm !== KeyMint.ALGORITHM_EC) problems.push('not an EC key');
  // Keymaster 2 and 3 (Android 8 and 9) may leave the curve out; the size then names it.
  const p256 = enforced.ecCurve === KeyMint.EC_CURVE_P_256 || (enforced.ecCurve === undefined && enforced.keySize === 256);
  if (!p256) problems.push('not P-256');
  if (hardware && enforced.rootOfTrust === undefined) problems.push('no root of trust');
  if (problems.length > 0) throw new AttestationError('key_properties', problems.join(', '));
}

/** SPEC.md §5.2 step 7, `application_id`: exactly Killit, signed with one of our certificates. */
function checkApplicationId(description: KeyDescription, policy: AttestationPolicy): void {
  const raw = description.softwareEnforced.attestationApplicationId ?? description.hardwareEnforced.attestationApplicationId;
  if (raw === undefined) throw new AttestationError('application_id', 'no application id');
  let applicationId;
  try {
    applicationId = parseApplicationId(raw);
  } catch (error) {
    throw new AttestationError('application_id', (error as Error).message);
  }
  const [only, ...others] = applicationId.packages;
  if (only === undefined || others.length > 0 || only.name !== policy.packageName) {
    throw new AttestationError('application_id', 'the key does not belong to Killit alone');
  }
  const signed = applicationId.signatureDigests.some((digest) =>
    policy.certDigests.some((allowed) => constantTimeEqual(digest, allowed)),
  );
  if (!signed) throw new AttestationError('application_id', `unknown signing certificate ${applicationId.signatureDigests.map(toHex).join(', ')}`);
}
