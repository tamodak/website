/**
 * Server configuration, read once from the environment at startup (PLAN.md §6.6: secrets live in
 * an env file outside git).
 *
 * Every value is validated here, and a bad configuration stops the server before it listens, with
 * every problem listed at once. Secrets may be given inline (`NAME`) or as a file path
 * (`NAME_FILE`), so a deployment can keep them out of the process environment.
 */
import { readFileSync } from 'node:fs';
import { fromBase64Url } from '@tamodak/protocol/api';

/** Where the server runs. Development is the only place the attestation root check can be skipped. */
export type Environment = 'production' | 'test' | 'development';

/** Request-rate limits. Counts are per window; see `rateLimits.ts` for where each applies. */
export interface RateLimits {
  /** Every request, per IP address, per minute. */
  readonly ipPerMinute: number;
  /** `POST /v1/register/challenge` and `POST /v1/devices`, per IP address, per hour. */
  readonly registrationsPerIpPerHour: number;
  /** Invites created, per device, per hour. */
  readonly invitesPerDevicePerHour: number;
  /** Join attempts, per device and per IP address, per hour: the code-guessing budget. */
  readonly joinsPerHour: number;
  /** Envelopes sent, per device, per hour. */
  readonly envelopesPerDevicePerHour: number;
  /** Signed requests of any kind, per device, per minute. */
  readonly requestsPerDevicePerMinute: number;
}

export interface Config {
  readonly environment: Environment;
  readonly host: string;
  readonly port: number;
  /** The application role's connection string: data access only, no DDL (PLAN.md §6.6). */
  readonly databaseUrl: string;
  /** The API host requests must be signed for (SPEC.md §4.2). */
  readonly audience: string;
  /** HMAC key for invite-code hashes (SPEC.md §6.1). */
  readonly inviteCodeKey: Uint8Array;
  readonly attestation: {
    readonly packageName: string;
    /** SHA-256 digests of the signing certificates Killit may be signed with here. */
    readonly certDigests: readonly Uint8Array[];
    /** Development only: accept any root and software-level keys, so emulators can register. */
    readonly devAcceptAnyRoot: boolean;
    readonly revocationListUrl: string;
  };
  /** The FCM service-account file, or null to run without push (SPEC.md §9). */
  readonly fcmCredentialsFile: string | null;
  /** Fastify's `trustProxy`: which hops may set `X-Forwarded-For`. */
  readonly trustProxy: boolean | string;
  readonly logLevel: string;
  readonly mailbox: { readonly perRecipient: number; readonly perSender: number };
  readonly rateLimits: RateLimits;
}

type Env = Readonly<Record<string, string | undefined>>;

/** Thrown with every configuration problem found, one per line. */
export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}

export const GOOGLE_REVOCATION_LIST_URL = 'https://android.googleapis.com/attestation/status';

/** Parses and validates the configuration. */
export function loadConfig(env: Env = process.env): Config {
  const problems: string[] = [];
  const problem = (message: string): void => {
    problems.push(message);
  };

  const text = (name: string, fallback?: string): string => {
    const value = env[name]?.trim();
    if (value !== undefined && value !== '') return value;
    if (fallback !== undefined) return fallback;
    problem(`${name} is required`);
    return '';
  };

  /** A secret from `NAME` or from the file named by `NAME_FILE`, never both. */
  const secret = (name: string): string => {
    const inline = env[name]?.trim();
    const file = env[`${name}_FILE`]?.trim();
    if (inline && file) problem(`set ${name} or ${name}_FILE, not both`);
    if (file) {
      try {
        return readFileSync(file, 'utf8').trim();
      } catch {
        problem(`${name}_FILE (${file}) can't be read`);
        return '';
      }
    }
    if (inline) return inline;
    problem(`${name} or ${name}_FILE is required`);
    return '';
  };

  const integer = (name: string, fallback: number, min: number, max: number): number => {
    const raw = env[name]?.trim();
    if (raw === undefined || raw === '') return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < min || value > max) {
      problem(`${name} must be an integer from ${min} to ${max}`);
      return fallback;
    }
    return value;
  };

  const flag = (name: string): boolean => {
    const raw = env[name]?.trim();
    if (raw === undefined || raw === '' || raw === 'false') return false;
    if (raw === 'true') return true;
    problem(`${name} must be true or false`);
    return false;
  };

  const environment = text('KILLIT_ENV', 'production');
  if (environment !== 'production' && environment !== 'test' && environment !== 'development') {
    problem('KILLIT_ENV must be production, test or development');
  }

  const audience = text('API_AUDIENCE');
  if (audience && !/^[a-z0-9.-]+(:[0-9]{1,5})?$/.test(audience)) problem('API_AUDIENCE must be a host, optionally with a port');

  let inviteCodeKey: Uint8Array = new Uint8Array(0);
  const inviteKeyText = secret('INVITE_CODE_KEY');
  if (inviteKeyText) {
    try {
      inviteCodeKey = fromBase64Url(inviteKeyText);
    } catch {
      problem('INVITE_CODE_KEY must be base64url without padding');
    }
    if (inviteCodeKey.length > 0 && inviteCodeKey.length < 32) problem('INVITE_CODE_KEY must hold at least 32 bytes');
  }

  const certDigests: Uint8Array[] = [];
  for (const digest of text('ATTESTATION_CERT_DIGESTS').split(',')) {
    const normalized = digest.trim().replace(/:/g, '').toLowerCase();
    if (normalized === '') continue;
    if (!/^[0-9a-f]{64}$/.test(normalized)) {
      problem(`ATTESTATION_CERT_DIGESTS entry "${digest.trim()}" is not a SHA-256 in hex`);
      continue;
    }
    certDigests.push(Uint8Array.from(Buffer.from(normalized, 'hex')));
  }
  if (certDigests.length === 0) problem('ATTESTATION_CERT_DIGESTS must list at least one certificate digest');

  const devAcceptAnyRoot = flag('ATTESTATION_DEV_ACCEPT_ANY_ROOT');
  if (devAcceptAnyRoot && environment !== 'development') {
    problem('ATTESTATION_DEV_ACCEPT_ANY_ROOT is only allowed with KILLIT_ENV=development');
  }
  const revocationListUrl = text('ATTESTATION_REVOCATION_URL', GOOGLE_REVOCATION_LIST_URL);
  if (revocationListUrl !== GOOGLE_REVOCATION_LIST_URL && environment === 'production') {
    problem('ATTESTATION_REVOCATION_URL can only be changed outside production');
  }

  const trustProxyText = text('TRUST_PROXY', 'false');
  const trustProxy = trustProxyText === 'true' ? true : trustProxyText === 'false' ? false : trustProxyText;

  const fcmFile = env['FCM_CREDENTIALS_FILE']?.trim();

  const config: Config = {
    environment: environment as Environment,
    host: text('HOST', '0.0.0.0'),
    port: integer('PORT', 8080, 1, 65535),
    databaseUrl: secret('DATABASE_URL'),
    audience,
    inviteCodeKey,
    attestation: {
      packageName: text('ATTESTATION_PACKAGE', 'org.tamodak.killit'),
      certDigests,
      devAcceptAnyRoot,
      revocationListUrl,
    },
    fcmCredentialsFile: fcmFile ? fcmFile : null,
    trustProxy,
    logLevel: text('LOG_LEVEL', 'info'),
    mailbox: {
      perRecipient: integer('MAILBOX_PER_RECIPIENT', 1000, 1, 100_000),
      perSender: integer('MAILBOX_PER_SENDER', 200, 1, 100_000),
    },
    rateLimits: {
      ipPerMinute: integer('RATE_IP_PER_MINUTE', 600, 1, 1_000_000),
      registrationsPerIpPerHour: integer('RATE_REGISTRATIONS_PER_IP_PER_HOUR', 20, 1, 1_000_000),
      invitesPerDevicePerHour: integer('RATE_INVITES_PER_DEVICE_PER_HOUR', 20, 1, 1_000_000),
      joinsPerHour: integer('RATE_JOINS_PER_HOUR', 20, 1, 1_000_000),
      envelopesPerDevicePerHour: integer('RATE_ENVELOPES_PER_DEVICE_PER_HOUR', 1000, 1, 1_000_000),
      requestsPerDevicePerMinute: integer('RATE_REQUESTS_PER_DEVICE_PER_MINUTE', 120, 1, 1_000_000),
    },
  };

  if (problems.length > 0) throw new ConfigError(`invalid configuration:\n- ${problems.join('\n- ')}`);
  return config;
}
