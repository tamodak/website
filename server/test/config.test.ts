/**
 * Configuration (src/config.ts): required values, secrets from files, and the guard that keeps
 * development-only attestation out of production.
 */
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config.ts';

const KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const DIGEST = '9C:D7:62:73:A6:9F:F2:00:86:33:EC:22:E5:96:0A:95:DB:5E:C1:C3:68:95:04:AC:7D:8E:F3:90:B8:4A:05:C4';
const base = {
  DATABASE_URL: 'postgres://killit_app:secret@db/killit',
  API_AUDIENCE: 'api.test.tamodak.org',
  INVITE_CODE_KEY: KEY,
  ATTESTATION_CERT_DIGESTS: DIGEST,
};

describe('loadConfig', () => {
  it('reads a complete production configuration with safe defaults', () => {
    const config = loadConfig(base);
    expect(config.environment).toBe('production');
    expect(config.port).toBe(8080);
    expect(config.attestation.devAcceptAnyRoot).toBe(false);
    expect(config.attestation.packageName).toBe('org.tamodak.killit');
    // apksigner and keytool print digests with colons and in uppercase; both are accepted.
    expect(Buffer.from(config.attestation.certDigests[0]!).toString('hex')).toBe(DIGEST.replace(/:/g, '').toLowerCase());
    expect(config.fcmCredentialsFile).toBeNull();
    expect(config.trustProxy).toBe(false);
  });

  it('lists every problem at once', () => {
    let error: unknown;
    try {
      loadConfig({});
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(ConfigError);
    const message = (error as Error).message;
    for (const name of ['DATABASE_URL', 'API_AUDIENCE', 'INVITE_CODE_KEY', 'ATTESTATION_CERT_DIGESTS']) expect(message).toContain(name);
  });

  it('reads secrets from files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'killit-config-'));
    writeFileSync(join(dir, 'db'), 'postgres://from-file\n');
    writeFileSync(join(dir, 'key'), `${KEY}\n`);
    const config = loadConfig({
      ...base,
      DATABASE_URL: undefined,
      INVITE_CODE_KEY: undefined,
      DATABASE_URL_FILE: join(dir, 'db'),
      INVITE_CODE_KEY_FILE: join(dir, 'key'),
    });
    expect(config.databaseUrl).toBe('postgres://from-file');
    expect(config.inviteCodeKey).toHaveLength(32);
  });

  it.each([
    ['a short invite key', { INVITE_CODE_KEY: 'AAECAwQFBgcICQoLDA0ODw' }],
    ['a malformed digest', { ATTESTATION_CERT_DIGESTS: 'abcd' }],
    ['an audience with a path', { API_AUDIENCE: 'api.tamodak.org/v1' }],
    ['an unknown environment', { KILLIT_ENV: 'staging' }],
    ['a secret given twice', { DATABASE_URL_FILE: '/nonexistent' }],
    ['the development root bypass in production', { ATTESTATION_DEV_ACCEPT_ANY_ROOT: 'true' }],
    ['the development root bypass on the test server', { KILLIT_ENV: 'test', ATTESTATION_DEV_ACCEPT_ANY_ROOT: 'true' }],
    ['another revocation list in production', { ATTESTATION_REVOCATION_URL: 'https://evil.example/status' }],
    ['a flag that is neither true nor false', { ATTESTATION_DEV_ACCEPT_ANY_ROOT: 'yes' }],
  ])('refuses %s', (_, change) => {
    expect(() => loadConfig({ ...base, ...change })).toThrow(ConfigError);
  });

  it('allows the root bypass only in development', () => {
    expect(loadConfig({ ...base, KILLIT_ENV: 'development', ATTESTATION_DEV_ACCEPT_ANY_ROOT: 'true' }).attestation.devAcceptAnyRoot).toBe(true);
  });
});
