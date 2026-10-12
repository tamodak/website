/**
 * Every rejection of SPEC.md §5.2, provoked with a forged chain. The real chains in
 * `realChains.test.ts` show that genuine phones pass; these show that each check bites.
 */
import { X509Certificate } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { testPhone } from '@tamodak/protocol/e2e';
import { AttestationError, verifyAttestationChain, type AttestationPolicy } from '../src/attestation/verify.ts';
import { GOOGLE_ROOTS } from '../src/attestation/roots.ts';
import {
  KILLIT_PACKAGE,
  TEST_CERT_DIGEST,
  buildChain,
  createTestRoot,
  encodeApplicationId,
  rsaPublicKey,
  type ChainOptions,
  type TestRoot,
} from './support/attestation.ts';

const phone = testPhone('A');
const challenge = new Uint8Array(32).fill(0x42);
const DAY = 24 * 60 * 60 * 1000;
let root: TestRoot;

beforeAll(async () => {
  root = await createTestRoot();
});

function policy(overrides: Partial<AttestationPolicy> = {}): AttestationPolicy {
  return {
    trustAnchors: [root.anchor],
    acceptAnyRoot: false,
    packageName: KILLIT_PACKAGE,
    certDigests: [TEST_CERT_DIGEST],
    isRevoked: () => false,
    now: new Date(),
    ...overrides,
  };
}

async function reasonFor(options: Partial<ChainOptions>, overrides: Partial<AttestationPolicy> = {}): Promise<string | 'ok'> {
  const chain = await buildChain(root, { phone, challenge, ...options });
  try {
    verifyAttestationChain(chain, policy(overrides));
    return 'ok';
  } catch (error) {
    if (error instanceof AttestationError) return error.reason;
    throw error;
  }
}

describe('a valid chain', () => {
  it('yields the phone\'s key, the challenge and the security level', async () => {
    const chain = await buildChain(root, { phone, challenge });
    const result = verifyAttestationChain(chain, policy());
    expect(Buffer.from(result.signPk).equals(Buffer.from(phone.signPk))).toBe(true);
    expect(Buffer.from(result.challenge).equals(Buffer.from(challenge))).toBe(true);
    expect(result.securityLevel).toBe(1);
    expect(result.summary).toMatchObject({ attestationVersion: 200, verifiedBootState: 0, deviceLocked: true, untrustedRoot: false });
  });

  it('reports StrongBox', async () => {
    const chain = await buildChain(root, {
      phone,
      challenge,
      description: (d) => ({ ...d, attestationSecurityLevel: 2, keyMintSecurityLevel: 2 }),
    });
    expect(verifyAttestationChain(chain, policy()).securityLevel).toBe(2);
  });

  it('accepts Keymaster 3, which names the curve by key size only', async () => {
    expect(await reasonFor({ description: (d) => ({ ...d, hardwareEnforced: { ...d.hardwareEnforced, ecCurve: undefined } }) })).toBe('ok');
  });

  it('ignores authorization tags it does not use', async () => {
    expect(await reasonFor({ description: (d) => ({ ...d, hardwareEnforced: { ...d.hardwareEnforced, extra: [{ tag: 724, value: 1 }] } }) })).toBe('ok');
  });

  it('ignores the leaf\'s own dates, which the phone sets', async () => {
    expect(await reasonFor({ leafValidity: { notBefore: new Date(Date.now() - 3 * DAY), notAfter: new Date(Date.now() - 2 * DAY) } })).toBe('ok');
  });
});

describe('the chain itself', () => {
  it('needs 3 to 6 certificates', async () => {
    const chain = await buildChain(root, { phone, challenge });
    expect(() => verifyAttestationChain(chain.slice(2), policy())).toThrow(expect.objectContaining({ reason: 'chain_invalid' }));
    const tooLong = [chain[0]!, chain[1]!, chain[1]!, chain[1]!, chain[1]!, chain[2]!, chain[3]!];
    expect(() => verifyAttestationChain(tooLong, policy())).toThrow(expect.objectContaining({ reason: 'chain_invalid' }));
  });

  it('must end in a trusted root', async () => {
    expect(await reasonFor({}, { trustAnchors: GOOGLE_ROOTS })).toBe('untrusted_root');
  });

  it('must chain by name', async () => {
    expect(await reasonFor({ breakNameChain: true })).toBe('chain_invalid');
  });

  it('must chain by signature', async () => {
    expect(await reasonFor({ misSignLeaf: true })).toBe('chain_invalid');
  });

  it('refuses garbage', () => {
    expect(() => verifyAttestationChain([new Uint8Array(10), new Uint8Array(10), root.der], policy())).toThrow(
      expect.objectContaining({ reason: 'chain_invalid' }),
    );
  });

  it('refuses an expired intermediate', async () => {
    const expired = { notBefore: new Date(Date.now() - 10 * DAY), notAfter: new Date(Date.now() - DAY) };
    expect(await reasonFor({ intermediateValidity: expired })).toBe('chain_invalid');
  });

  it('accepts an expired intermediate in a factory-provisioned chain', async () => {
    const expired = { notBefore: new Date(Date.now() - 10 * DAY), notAfter: new Date(Date.now() - DAY) };
    expect(await reasonFor({ intermediateValidity: expired, factory: true })).toBe('ok');
  });

  it('refuses an intermediate that is not valid yet, even in a factory chain', async () => {
    const future = { notBefore: new Date(Date.now() + DAY), notAfter: new Date(Date.now() + 10 * DAY) };
    expect(await reasonFor({ intermediateValidity: future, factory: true })).toBe('chain_invalid');
  });

  it('refuses a revoked certificate, listed in hex or in decimal', async () => {
    const serial = 0x1234abcd;
    expect(await reasonFor({ attestationSerial: serial }, { isRevoked: (s) => s.toLowerCase().replace(/^0+/, '') === '1234abcd' })).toBe('revoked');
    const chain = await buildChain(root, { phone, challenge, attestationSerial: serial });
    expect(new X509Certificate(chain[1]!).serialNumber.toLowerCase()).toContain('1234abcd');
  });
});

describe('the key description', () => {
  it('must be present in the leaf', async () => {
    expect(await reasonFor({ omitExtension: true })).toBe('extension_missing');
  });

  it('must not appear above the leaf', async () => {
    expect(await reasonFor({ extensionOnIntermediate: true })).toBe('extension_misplaced');
  });

  it('can\'t be forged by an attested key signing a fake leaf', async () => {
    expect(await reasonFor({ extendWithFakeLeaf: true })).toBe('extension_misplaced');
  });

  it('must parse', async () => {
    expect(await reasonFor({ rawExtension: Uint8Array.of(0x30, 0x03, 0x02, 0x01) })).toBe('extension_invalid');
  });

  it('may not repeat a tag', async () => {
    expect(
      await reasonFor({ description: (d) => ({ ...d, hardwareEnforced: { ...d.hardwareEnforced, extra: [{ tag: 2, value: 3 }] } }) }),
    ).toBe('extension_invalid');
  });

  it('must carry the challenge it was asked for (checked by the caller)', async () => {
    const chain = await buildChain(root, { phone, challenge: new Uint8Array(32).fill(1) });
    expect(Buffer.from(verifyAttestationChain(chain, policy()).challenge).equals(Buffer.from(challenge))).toBe(false);
  });
});

describe('the key and its owner', () => {
  it.each([
    ['software attestation', { attestationSecurityLevel: 0 }],
    ['a software KeyMint', { keyMintSecurityLevel: 0 }],
  ])('refuses %s', async (_, change) => {
    expect(await reasonFor({ description: (d) => ({ ...d, ...change }) })).toBe('security_level');
  });

  it.each([
    ['an imported key', { origin: 2 }],
    ['a verify-only key', { purpose: [3] }],
    ['an RSA key', { algorithm: 1 }],
    ['a P-384 key', { ecCurve: 2 }],
    ['a key without root of trust', { rootOfTrust: undefined }],
  ])('refuses %s', async (_, change) => {
    expect(await reasonFor({ description: (d) => ({ ...d, hardwareEnforced: { ...d.hardwareEnforced, ...change } }) })).toBe('key_properties');
  });

  it.each([
    ['another app', { packages: [{ name: 'com.example.evil', version: 1 }], digests: [TEST_CERT_DIGEST] }],
    ['Killit sharing a uid with another app', { packages: [{ name: KILLIT_PACKAGE, version: 1 }, { name: 'com.example.other', version: 1 }], digests: [TEST_CERT_DIGEST] }],
    ['Killit signed with another key', { packages: [{ name: KILLIT_PACKAGE, version: 1 }], digests: [new Uint8Array(32)] }],
  ])('refuses %s', async (_, applicationId) => {
    expect(await reasonFor({ description: (d) => ({ ...d, softwareEnforced: { applicationId } }) })).toBe('application_id');
  });

  it('refuses a key without an application id, or with a malformed one', async () => {
    expect(await reasonFor({ description: (d) => ({ ...d, softwareEnforced: {} }) })).toBe('application_id');
    expect(await reasonFor({ description: (d) => ({ ...d, softwareEnforced: { applicationId: Uint8Array.of(1, 2, 3) } }) })).toBe('application_id');
  });

  it('refuses more packages than any phone reports', async () => {
    const packages = Array.from({ length: 33 }, (_, i) => ({ name: `p${i}.x`, version: 1 }));
    const raw = encodeApplicationId({ packages, digests: [TEST_CERT_DIGEST] });
    expect(await reasonFor({ description: (d) => ({ ...d, softwareEnforced: { applicationId: raw } }) })).toBe('application_id');
  });

  it('refuses a leaf that certifies an RSA key', async () => {
    expect(await reasonFor({ leafPublicKey: await rsaPublicKey() })).toBe('key_mismatch');
  });
});

describe('development mode', () => {
  it('accepts an unknown root and a software key, and says so', async () => {
    const chain = await buildChain(root, {
      phone,
      challenge,
      description: (d) => ({
        ...d,
        attestationSecurityLevel: 0,
        keyMintSecurityLevel: 0,
        softwareEnforced: { ...d.hardwareEnforced, rootOfTrust: undefined, applicationId: d.softwareEnforced.applicationId! },
        hardwareEnforced: {},
      }),
    });
    const result = verifyAttestationChain(chain, policy({ trustAnchors: GOOGLE_ROOTS, acceptAnyRoot: true }));
    expect(result.securityLevel).toBe(0);
    expect(result.summary.untrustedRoot).toBe(true);
  });

  it('ignores the dates of a chain that ends in an unknown root', async () => {
    // Older emulator images ship software-attestation certificates that have since expired.
    const expired = { notBefore: new Date(Date.now() - 10 * DAY), notAfter: new Date(Date.now() - DAY) };
    const chain = await buildChain(root, { phone, challenge, intermediateValidity: expired });
    const result = verifyAttestationChain(chain, policy({ trustAnchors: GOOGLE_ROOTS, acceptAnyRoot: true }));
    expect(result.summary.untrustedRoot).toBe(true);
  });

  it('still refuses an expired intermediate under a trusted root', async () => {
    const expired = { notBefore: new Date(Date.now() - 10 * DAY), notAfter: new Date(Date.now() - DAY) };
    expect(await reasonFor({ intermediateValidity: expired }, { acceptAnyRoot: true })).toBe('chain_invalid');
  });

  it('still refuses a software key under a trusted root', async () => {
    expect(await reasonFor({ description: (d) => ({ ...d, attestationSecurityLevel: 0, keyMintSecurityLevel: 0 }) }, { acceptAnyRoot: true })).toBe(
      'security_level',
    );
  });
});
