/**
 * Pins the trust anchors: a changed certificate must come with a changed, reviewed key digest.
 */
import { X509Certificate, createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { GOOGLE_ROOTS } from '../src/attestation/roots.ts';

describe('Google attestation roots', () => {
  it.each(GOOGLE_ROOTS)('$name matches its recorded key digest and is self-signed', (root) => {
    const certificate = new X509Certificate(root.pem);
    const spki = certificate.publicKey.export({ type: 'spki', format: 'der' });
    expect(createHash('sha256').update(spki).digest('hex')).toBe(root.spkiSha256);
    expect(certificate.verify(certificate.publicKey)).toBe(true);
  });

  it('are exactly the RSA key and the 2026 ECDSA key', () => {
    expect(GOOGLE_ROOTS.map((root) => root.spkiSha256)).toEqual([
      'feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae',
      '3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec',
    ]);
  });
});
