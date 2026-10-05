/**
 * Row types for Kysely, mirroring `migrations/` (SPEC.md §12).
 *
 * `bytea` columns arrive as `Buffer`, `timestamptz` as `Date`, and `date` as a `YYYY-MM-DD`
 * string (see the type parser in `database.ts`).
 */
import type { ColumnType, Generated, Insertable, Selectable } from 'kysely';

/** A column the database fills in on insert and that is never written afterwards. */
type Defaulted<T> = ColumnType<T, T | undefined, never>;

export interface DevicesTable {
  id: Generated<string>;
  fingerprint: ColumnType<Buffer, Uint8Array, never>;
  sign_pk: ColumnType<Buffer, Uint8Array, never>;
  security_level: number;
  attestation: ColumnType<AttestationSummary, string, string>;
  fcm_token: string | null;
  created_at: Defaulted<Date>;
  last_seen_on: ColumnType<string, string | undefined, string>;
}

/** What registration records about a phone's attestation (SPEC.md §5.2). Never used to reject. */
export interface AttestationSummary {
  readonly attestationVersion: number;
  readonly attestationSecurityLevel: number;
  readonly keyMintSecurityLevel: number;
  readonly verifiedBootState: number | null;
  readonly deviceLocked: boolean | null;
  readonly osVersion: number | null;
  readonly osPatchLevel: number | null;
  /** True when the development-only "any root" setting let the chain through. */
  readonly untrustedRoot: boolean;
}

export interface AttestationChallengesTable {
  challenge: ColumnType<Buffer, Uint8Array, never>;
  expires_at: Date;
}

export interface SeenNoncesTable {
  device: string;
  nonce: ColumnType<Buffer, Uint8Array, never>;
  expires_at: Date;
}

export type InviteState = 'open' | 'joined' | 'creator_revealed' | 'revealed' | 'linked' | 'cancelled';

export interface InvitesTable {
  id: Generated<string>;
  code_hash: ColumnType<Buffer, Uint8Array, never>;
  creator: string;
  joiner: string | null;
  state: InviteState;
  joiner_commit: ColumnType<Buffer | null, Uint8Array | null | undefined, Uint8Array | null>;
  creator_reveal: ColumnType<Buffer | null, Uint8Array | null | undefined, Uint8Array | null>;
  joiner_reveal: ColumnType<Buffer | null, Uint8Array | null | undefined, Uint8Array | null>;
  creator_confirmed: Generated<boolean>;
  joiner_confirmed: Generated<boolean>;
  created_at: Defaulted<Date>;
  expires_at: Date;
  finished_at: Date | null;
}

export interface LinksTable {
  device_lo: string;
  device_hi: string;
  created_at: Defaulted<Date>;
}

export interface MessagesTable {
  id: Generated<string>;
  /** Delivery order; never leaves the server. `bigint` arrives as a string. */
  seq: Generated<string>;
  recipient: string;
  sender_fp: ColumnType<Buffer, Uint8Array, never>;
  envelope: ColumnType<Buffer, Uint8Array, never>;
  received_at: Defaulted<Date>;
}

export interface Database {
  devices: DevicesTable;
  attestation_challenges: AttestationChallengesTable;
  seen_nonces: SeenNoncesTable;
  invites: InvitesTable;
  links: LinksTable;
  messages: MessagesTable;
}

export type DeviceRow = Selectable<DevicesTable>;
export type NewDevice = Insertable<DevicesTable>;
export type InviteRow = Selectable<InvitesTable>;
