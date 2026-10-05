/**
 * The verifier against chains real phones produced (see fixtures/attestation/README.md): factory
 * and remotely provisioned, TEE and StrongBox, both Google roots, Android 8.1 to 17.
 */
import { X509Certificate } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { GOOGLE_ROOTS } from '../src/attestation/roots.ts';
import { KEY_DESCRIPTION_OID, parseKeyDescription } from '../src/attestation/keyDescription.ts';
import { AttestationError, verifyAttestationChain } from '../src/attestation/verify.ts';
import * as pkijs from 'pkijs';

const DIR = new URL('fixtures/attestation/', import.meta.url);

interface Expected {
  attestationVersion: string;
  attestationSecurityLevel: string;
  keyMintSecurityLevel: string;
  attestationChallenge: string;
  softwareEnforced: { attestationApplicationId?: { packages: { name: string }[]; signatures: string[] } };
  hardwareEnforced: {
    purposes?: string[];
    keySize?: string;
    ecCurve?: string;
    origin?: string;
    osVersion?: string;
    osPatchLevel?: string;
    rootOfTrust?: { deviceLocked: boolean; verifiedBootState: string };
  };
}

const LEVELS: Record<string, number> = { SOFTWARE: 0, TRUSTED_ENVIRONMENT: 1, STRONG_BOX: 2 };
const BOOT_STATES: Record<string, number> = { VERIFIED: 0, SELF_SIGNED: 1, UNVERIFIED: 2, FAILED: 3 };

function load(name: string): { chain: Uint8Array[]; expected: Expected } {
  const pem = readFileSync(new URL(`${name}.pem`, DIR), 'utf8');
  const chain = (pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []).map(
    (block) => new Uint8Array(new X509Certificate(block).raw),
  );
  // One file starts with a // comment line.
  const json = readFileSync(new URL(`${name}.json`, DIR), 'utf8').replace(/^\s*\/\/.*$/gm, '');
  return { chain, expected: JSON.parse(json) as Expected };
}

/** A moment when every certificate between leaf and root was valid: RKP certificates last days. */
function validMoment(chain: Uint8Array[]): Date {
  const middle = chain.slice(1, -1).map((der) => new X509Certificate(der));
  const from = Math.max(...middle.map((c) => c.validFromDate.getTime()));
  const to = Math.min(...middle.map((c) => c.validToDate.getTime()));
  return new Date(from < to ? from + 60_000 : from);
}

const names = readdirSync(DIR)
  .filter((file) => file.endsWith('.pem'))
  .map((file) => file.slice(0, -4))
  .sort();
const hardwareChains = names.filter((name) => !name.startsWith('marlin'));

describe('real attestation chains', () => {
  it('include every case the README lists', () => {
    expect(names).toHaveLength(10);
  });

  it.each(hardwareChains)('%s verifies against Google\'s roots', (name) => {
    const { chain, expected } = load(name);
    const applicationId = expected.softwareEnforced.attestationApplicationId!;
    const result = verifyAttestationChain(chain, {
      trustAnchors: GOOGLE_ROOTS,
      acceptAnyRoot: false,
      packageName: applicationId.packages[0]!.name,
      certDigests: applicationId.signatures.map((digest) => new Uint8Array(Buffer.from(digest, 'base64'))),
      isRevoked: () => false,
      now: validMoment(chain),
    });
    expect(Buffer.from(result.challenge).toString('base64')).toBe(expected.attestationChallenge);
    expect(result.securityLevel).toBe(LEVELS[expected.attestationSecurityLevel]);
    expect(result.summary.untrustedRoot).toBe(false);
    expect(result.summary.osVersion).toBe(Number(expected.hardwareEnforced.osVersion));
    const leafKey = new X509Certificate(chain[0]!).publicKey.export({ format: 'jwk' });
    expect(Buffer.from(result.signPk.subarray(1, 33)).toString('base64url')).toBe(leafKey.x);
  });

  it.each(hardwareChains)('%s parses to the key description Google recorded', (name) => {
    const { chain, expected } = load(name);
    const extension = pkijs.Certificate.fromBER(chain[0]!).extensions!.find((e) => e.extnID === KEY_DESCRIPTION_OID)!;
    const description = parseKeyDescription(new Uint8Array(extension.extnValue.getValue()));
    expect(description.attestationVersion).toBe(Number(expected.attestationVersion));
    expect(description.keyMintSecurityLevel).toBe(LEVELS[expected.keyMintSecurityLevel]);
    const hw = description.hardwareEnforced;
    expect(hw.purpose).toEqual(expected.hardwareEnforced.purposes!.map(Number));
    expect(hw.keySize).toBe(Number(expected.hardwareEnforced.keySize));
    if (expected.hardwareEnforced.ecCurve !== undefined) expect(hw.ecCurve).toBe(Number(expected.hardwareEnforced.ecCurve));
    expect(hw.origin).toBe(0);
    expect(hw.osPatchLevel).toBe(Number(expected.hardwareEnforced.osPatchLevel));
    expect(hw.rootOfTrust?.deviceLocked).toBe(expected.hardwareEnforced.rootOfTrust!.deviceLocked);
    expect(hw.rootOfTrust?.verifiedBootState).toBe(BOOT_STATES[expected.hardwareEnforced.rootOfTrust!.verifiedBootState]);
  });

  it('refuses another app\'s key', () => {
    const { chain } = load('caiman_sdk36_TEE_EC_RKP');
    expect(() =>
      verifyAttestationChain(chain, {
        trustAnchors: GOOGLE_ROOTS,
        acceptAnyRoot: false,
        packageName: 'org.tamodak.killit',
        certDigests: [new Uint8Array(32)],
        isRevoked: () => false,
        now: validMoment(chain),
      }),
    ).toThrow(expect.objectContaining({ reason: 'application_id' }));
  });

  it('refuses an RKP chain once its short-lived certificates expire', () => {
    const { chain, expected } = load('caiman_sdk36_TEE_EC_RKP');
    const applicationId = expected.softwareEnforced.attestationApplicationId!;
    const error = captureError(() =>
      verifyAttestationChain(chain, {
        trustAnchors: GOOGLE_ROOTS,
        acceptAnyRoot: false,
        packageName: applicationId.packages[0]!.name,
        certDigests: applicationId.signatures.map((digest) => new Uint8Array(Buffer.from(digest, 'base64'))),
        isRevoked: () => false,
        now: new Date('2026-10-05T00:00:00Z'),
      }),
    );
    expect(error?.reason).toBe('chain_invalid');
  });

  it('refuses a software attestation root in production', () => {
    const { chain } = load('marlin_sdk29_TEE_EC_NONE');
    const error = captureError(() =>
      verifyAttestationChain(chain, {
        trustAnchors: GOOGLE_ROOTS,
        acceptAnyRoot: false,
        packageName: 'com.google.wireless.android.security.attestationverifier.collector',
        certDigests: [],
        isRevoked: () => false,
        now: validMoment(chain),
      }),
    );
    expect(error?.reason).toBe('untrusted_root');
  });
});

function captureError(run: () => unknown): AttestationError | undefined {
  try {
    run();
  } catch (error) {
    if (error instanceof AttestationError) return error;
    throw error;
  }
  return undefined;
}
