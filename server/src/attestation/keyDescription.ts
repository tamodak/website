/**
 * Parsing of Android's key-attestation extension (OID 1.3.6.1.4.1.11129.2.1.17), following the
 * schema on source.android.com ("Key and ID attestation", attestation version 500).
 *
 * Only the fields registration checks or records are read. Unknown authorization tags are skipped,
 * because every KeyMint version adds some; a tag that appears twice is refused, because then
 * which value counts would be a guess. Devices in the wild don't always produce strict DER (Google's
 * verifier notes non-DER booleans), so the parser is BER-lenient in encoding but strict in
 * structure, and bounded in depth and size before it looks at anything.
 */
import * as asn1js from 'asn1js';

/** The extension's OID. */
export const KEY_DESCRIPTION_OID = '1.3.6.1.4.1.11129.2.1.17';

/** `SecurityLevel` values. */
export const SecurityLevel = { SOFTWARE: 0, TRUSTED_ENVIRONMENT: 1, STRONG_BOX: 2 } as const;

/** KeyMint enumeration values used in the checks (hardware/interfaces/security/keymint). */
export const KeyMint = {
  PURPOSE_SIGN: 2,
  ALGORITHM_EC: 3,
  EC_CURVE_P_256: 1,
  ORIGIN_GENERATED: 0,
} as const;

/** Authorization tags read here. */
const Tag = {
  PURPOSE: 1,
  ALGORITHM: 2,
  KEY_SIZE: 3,
  DIGEST: 5,
  EC_CURVE: 10,
  ORIGIN: 702,
  ROOT_OF_TRUST: 704,
  OS_VERSION: 705,
  OS_PATCH_LEVEL: 706,
  ATTESTATION_APPLICATION_ID: 709,
} as const;

/** `RootOfTrust`. `verifiedBootHash` only exists from attestation version 3. */
export interface RootOfTrust {
  readonly verifiedBootKey: Uint8Array;
  readonly deviceLocked: boolean;
  readonly verifiedBootState: number;
}

/** The parts of an `AuthorizationList` that registration uses. */
export interface AuthorizationList {
  readonly purpose?: readonly number[];
  readonly algorithm?: number;
  readonly keySize?: number;
  readonly digest?: readonly number[];
  readonly ecCurve?: number;
  readonly origin?: number;
  readonly rootOfTrust?: RootOfTrust;
  readonly osVersion?: number;
  readonly osPatchLevel?: number;
  /** The DER of `AttestationApplicationId`, still wrapped; see {@link parseApplicationId}. */
  readonly attestationApplicationId?: Uint8Array;
}

export interface KeyDescription {
  readonly attestationVersion: number;
  readonly attestationSecurityLevel: number;
  readonly keyMintVersion: number;
  readonly keyMintSecurityLevel: number;
  readonly attestationChallenge: Uint8Array;
  readonly softwareEnforced: AuthorizationList;
  readonly hardwareEnforced: AuthorizationList;
}

/** `AttestationApplicationId`: who the platform says asked for the key. */
export interface ApplicationId {
  readonly packages: readonly { readonly name: string; readonly version: bigint }[];
  readonly signatureDigests: readonly Uint8Array[];
}

/** Thrown for anything that isn't a well-formed key description. */
export class KeyDescriptionError extends Error {
  override readonly name = 'KeyDescriptionError';
}

/** Google's verifier allows 32 packages and 10 signature digests; so do we. */
const MAX_PACKAGES = 32;
const MAX_SIGNATURES = 10;

/** Parses BER with bounds, refusing trailing bytes. */
function parseBer(bytes: Uint8Array): asn1js.AsnType {
  const parsed = asn1js.fromBER(bytes, { maxDepth: 16, maxNodes: 4096 });
  if (parsed.offset === -1 || parsed.offset !== bytes.length) throw new KeyDescriptionError('malformed ASN.1');
  return parsed.result;
}

function children(node: unknown, what: string): asn1js.BaseBlock[] {
  if (!(node instanceof asn1js.Sequence) && !(node instanceof asn1js.Set)) throw new KeyDescriptionError(`${what} is not a sequence`);
  return node.valueBlock.value;
}

function sequence(node: unknown, what: string): asn1js.BaseBlock[] {
  if (!(node instanceof asn1js.Sequence)) throw new KeyDescriptionError(`${what} is not a sequence`);
  return node.valueBlock.value;
}

function set(node: unknown, what: string): asn1js.BaseBlock[] {
  if (!(node instanceof asn1js.Set)) throw new KeyDescriptionError(`${what} is not a set`);
  return node.valueBlock.value;
}

/** Reads an INTEGER or ENUMERATED that must fit a safe integer and be non-negative. */
function smallInteger(node: unknown, what: string): number {
  if (!(node instanceof asn1js.Integer)) throw new KeyDescriptionError(`${what} is not an integer`);
  const value = node.toBigInt();
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new KeyDescriptionError(`${what} out of range`);
  return Number(value);
}

function bigInteger(node: unknown, what: string): bigint {
  if (!(node instanceof asn1js.Integer)) throw new KeyDescriptionError(`${what} is not an integer`);
  return node.toBigInt();
}

function octets(node: unknown, what: string): Uint8Array {
  if (!(node instanceof asn1js.OctetString)) throw new KeyDescriptionError(`${what} is not an octet string`);
  return new Uint8Array(node.getValue());
}

function boolean(node: unknown, what: string): boolean {
  if (!(node instanceof asn1js.Boolean)) throw new KeyDescriptionError(`${what} is not a boolean`);
  return node.getValue();
}

function integerSet(node: unknown, what: string): number[] {
  return set(node, what).map((item) => smallInteger(item, what));
}

/** Reads `[tag] EXPLICIT` entries of an `AuthorizationList`. */
function authorizationList(node: unknown, what: string): AuthorizationList {
  const seen = new Set<number>();
  const list: { -readonly [K in keyof AuthorizationList]: AuthorizationList[K] } = {};
  for (const entry of sequence(node, what)) {
    const { tagClass, tagNumber } = entry.idBlock;
    if (tagClass !== 3 || !(entry instanceof asn1js.Constructed)) throw new KeyDescriptionError(`${what} holds an untagged value`);
    if (seen.has(tagNumber)) throw new KeyDescriptionError(`${what} repeats tag ${tagNumber}`);
    seen.add(tagNumber);
    const inner = entry.valueBlock.value;
    if (inner.length !== 1) throw new KeyDescriptionError(`${what} tag ${tagNumber} is not explicit`);
    const value = inner[0];
    switch (tagNumber) {
      case Tag.PURPOSE:
        list.purpose = integerSet(value, 'purpose');
        break;
      case Tag.ALGORITHM:
        list.algorithm = smallInteger(value, 'algorithm');
        break;
      case Tag.KEY_SIZE:
        list.keySize = smallInteger(value, 'keySize');
        break;
      case Tag.DIGEST:
        list.digest = integerSet(value, 'digest');
        break;
      case Tag.EC_CURVE:
        list.ecCurve = smallInteger(value, 'ecCurve');
        break;
      case Tag.ORIGIN:
        list.origin = smallInteger(value, 'origin');
        break;
      case Tag.ROOT_OF_TRUST: {
        const fields = sequence(value, 'rootOfTrust');
        if (fields.length < 3) throw new KeyDescriptionError('rootOfTrust is too short');
        list.rootOfTrust = {
          verifiedBootKey: octets(fields[0], 'verifiedBootKey'),
          deviceLocked: boolean(fields[1], 'deviceLocked'),
          verifiedBootState: smallInteger(fields[2], 'verifiedBootState'),
        };
        break;
      }
      case Tag.OS_VERSION:
        list.osVersion = smallInteger(value, 'osVersion');
        break;
      case Tag.OS_PATCH_LEVEL:
        list.osPatchLevel = smallInteger(value, 'osPatchLevel');
        break;
      case Tag.ATTESTATION_APPLICATION_ID:
        list.attestationApplicationId = octets(value, 'attestationApplicationId');
        break;
      default:
        // A tag this version doesn't use. It is still checked to be a single explicit value above.
        break;
    }
  }
  return list;
}

/**
 * Parses the extension value (the DER inside the extension's OCTET STRING).
 *
 * @throws KeyDescriptionError for anything malformed.
 */
export function parseKeyDescription(extensionValue: Uint8Array): KeyDescription {
  const fields = sequence(parseBer(extensionValue), 'KeyDescription');
  if (fields.length !== 8) throw new KeyDescriptionError('KeyDescription must have 8 fields');
  // fields[5] is uniqueId. It is unused, but it must still be an OCTET STRING.
  octets(fields[5], 'uniqueId');
  return {
    attestationVersion: smallInteger(fields[0], 'attestationVersion'),
    attestationSecurityLevel: smallInteger(fields[1], 'attestationSecurityLevel'),
    keyMintVersion: smallInteger(fields[2], 'keyMintVersion'),
    keyMintSecurityLevel: smallInteger(fields[3], 'keyMintSecurityLevel'),
    attestationChallenge: octets(fields[4], 'attestationChallenge'),
    softwareEnforced: authorizationList(fields[6], 'softwareEnforced'),
    hardwareEnforced: authorizationList(fields[7], 'hardwareEnforced'),
  };
}

/**
 * Parses an `AttestationApplicationId`.
 *
 * @throws KeyDescriptionError for anything malformed, or more packages or digests than any real
 *   phone would report.
 */
export function parseApplicationId(der: Uint8Array): ApplicationId {
  const fields = sequence(parseBer(der), 'AttestationApplicationId');
  if (fields.length !== 2) throw new KeyDescriptionError('AttestationApplicationId must have 2 fields');
  const packageNodes = set(fields[0], 'package_infos');
  const digestNodes = set(fields[1], 'signature_digests');
  if (packageNodes.length > MAX_PACKAGES || digestNodes.length > MAX_SIGNATURES) {
    throw new KeyDescriptionError('too many packages or signature digests');
  }
  const packages = packageNodes.map((node) => {
    const info = children(node, 'AttestationPackageInfo');
    if (info.length !== 2) throw new KeyDescriptionError('AttestationPackageInfo must have 2 fields');
    const name = Buffer.from(octets(info[0], 'package_name')).toString('utf8');
    return { name, version: bigInteger(info[1], 'version') };
  });
  return { packages, signatureDigests: digestNodes.map((node) => octets(node, 'signature digest')) };
}
