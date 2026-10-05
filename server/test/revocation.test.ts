/**
 * Google's revocation list (src/attestation/revocation.ts): parsing, both serial formats it uses,
 * and failing closed.
 */
import { describe, expect, it } from 'vitest';
import { RevocationList, parseStatusList } from '../src/attestation/revocation.ts';

const list = JSON.stringify({
  entries: {
    c35747a084470c3135aeefe2b8d40cd6: { status: 'REVOKED', reason: 'KEY_COMPROMISE' },
    // A 64-bit serial written in decimal, as most of the real list is.
    '6681152659205225093': { status: 'REVOKED', reason: 'KEY_COMPROMISE' },
    '2c8cdddfd5e03bfc': { status: 'SUSPENDED', reason: 'SOFTWARE_FLAW' },
    abc: { status: 'SOMETHING_ELSE' },
  },
});

function respond(body: string, status = 200): typeof fetch {
  return (async () => new Response(body, { status, headers: { 'content-type': 'application/json' } })) as typeof fetch;
}

describe('the status list', () => {
  it('refuses REVOKED and SUSPENDED serials, in hex and in decimal', async () => {
    const revocation = new RevocationList({ url: 'https://example.invalid/status', fetch: respond(list) });
    await revocation.refresh();
    expect(revocation.isRevoked('C35747A084470C3135AEEFE2B8D40CD6')).toBe(true);
    expect(revocation.isRevoked('00c35747a084470c3135aeefe2b8d40cd6')).toBe(true);
    expect(revocation.isRevoked(BigInt('6681152659205225093').toString(16))).toBe(true);
    expect(revocation.isRevoked('2C8CDDDFD5E03BFC')).toBe(true);
    expect(revocation.isRevoked('abc')).toBe(false);
    expect(revocation.isRevoked('1234')).toBe(false);
  });

  it('is fresh for 24 hours after a good fetch, and not before one', async () => {
    let now = 0;
    const revocation = new RevocationList({ url: 'https://example.invalid/status', fetch: respond(list), now: () => now });
    expect(revocation.isFresh()).toBe(false);
    await revocation.refresh();
    now += 24 * 60 * 60 * 1000;
    expect(revocation.isFresh()).toBe(true);
    now += 1;
    expect(revocation.isFresh()).toBe(false);
  });

  it('keeps the previous list when a refresh fails', async () => {
    let body = list;
    let status = 200;
    const revocation = new RevocationList({
      url: 'https://example.invalid/status',
      fetch: (async () => new Response(body, { status })) as typeof fetch,
    });
    await revocation.refresh();
    status = 500;
    await expect(revocation.refresh()).rejects.toThrow();
    status = 200;
    body = '{"entries":{"NOT HEX":{"status":"REVOKED"}}}';
    await expect(revocation.refresh()).rejects.toThrow();
    expect(revocation.isRevoked('c35747a084470c3135aeefe2b8d40cd6')).toBe(true);
  });

  it.each([
    ['no entries', '{}'],
    ['entries that aren\'t an object', '{"entries":[]}'],
    ['an entry without a status', '{"entries":{"ab":{}}}'],
    ['a serial that isn\'t hex', '{"entries":{"xyz":{"status":"REVOKED"}}}'],
    ['not JSON at all', '<html>'],
  ])('refuses a list with %s', (_, body) => {
    expect(() => parseStatusList(body)).toThrow();
  });
});
