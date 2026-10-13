/**
 * Message bodies (SPEC.md §11): one strict encoder and decoder per kind, and the DECISION check
 * that rebuilds signed bytes from the protected phone's own stored request (SPEC.md §11.6).
 *
 * End-to-end code: the server never imports it.
 */
import type { KeyObject } from 'node:crypto';
import { ByteReader, ByteWriter, DecodeError, decodeWith, toHex, type Result } from './bytes.ts';
import { PAIR_ID_BYTES } from './ceremony.ts';
import { MESSAGE_VERSION, encodeInner, verifyInner, type MessageHeader, type OpenedMessage } from './envelope.ts';
import { FINGERPRINT_BYTES, encodeBundle, readBundle, type Bundle } from './identity.ts';
import { TEXT, readPackageName, readText, writePackageName, writeText } from './text.ts';

/** Message kinds (SPEC.md §11). */
export const Kind = {
  PAIR_OFFER: 0x01,
  PAIR_ANSWER: 0x02,
  UNBLOCK_APP: 0x10,
  UNLOCK: 0x11,
  UNPAIR: 0x12,
  DECISION: 0x13,
  STATUS: 0x14,
  LEAVE: 0x15,
  UNPAIRED: 0x16,
  NOTICE: 0x20,
  LIST_REQUEST: 0x30,
  APP_LIST: 0x31,
  MANAGE: 0x32,
  GUARDIAN_UNBLOCK: 0x33,
  HANDOVER: 0x34,
  MOVE_REQUEST: 0x35,
  MOVE_STATE: 0x36,
  MOVE_ANSWER: 0x37,
  MOVE_DONE: 0x38,
} as const;
export type Kind = (typeof Kind)[keyof typeof Kind];

/**
 * Who may send each kind (SPEC.md §10.3 step 8): by role in the pairing named in the header, or,
 * for the ceremony kinds, by part in the ceremony.
 */
export const SENDER: Readonly<Record<Kind, 'creator' | 'joiner' | 'guardian' | 'protected' | 'either'>> = {
  [Kind.PAIR_OFFER]: 'creator',
  [Kind.PAIR_ANSWER]: 'joiner',
  [Kind.UNBLOCK_APP]: 'protected',
  [Kind.UNLOCK]: 'protected',
  [Kind.UNPAIR]: 'protected',
  [Kind.DECISION]: 'guardian',
  [Kind.STATUS]: 'protected',
  [Kind.LEAVE]: 'guardian',
  [Kind.UNPAIRED]: 'protected',
  [Kind.NOTICE]: 'either',
  [Kind.LIST_REQUEST]: 'guardian',
  [Kind.APP_LIST]: 'protected',
  [Kind.MANAGE]: 'guardian',
  [Kind.GUARDIAN_UNBLOCK]: 'protected',
  [Kind.HANDOVER]: 'either',
  [Kind.MOVE_REQUEST]: 'creator',
  [Kind.MOVE_STATE]: 'joiner',
  [Kind.MOVE_ANSWER]: 'creator',
  [Kind.MOVE_DONE]: 'joiner',
};

/** True for a kind this implementation understands. Anything else is shown as "Update Killit". */
export function isKnownKind(kind: number): kind is Kind {
  return Object.values(Kind).includes(kind as Kind);
}

/**
 * True for the kinds two phones exchange in a ceremony, before any pairing exists between them:
 * their header names the ceremony's pair id (SPEC.md §10.3 step 5).
 */
export function isCeremonyKind(kind: number): boolean {
  return SENDER[kind as Kind] === 'creator' || SENDER[kind as Kind] === 'joiner';
}

/** The requests a guardian decides on. */
export type RequestKind = typeof Kind.UNBLOCK_APP | typeof Kind.UNLOCK | typeof Kind.UNPAIR | typeof Kind.GUARDIAN_UNBLOCK;
const REQUEST_KINDS: readonly number[] = [Kind.UNBLOCK_APP, Kind.UNLOCK, Kind.UNPAIR, Kind.GUARDIAN_UNBLOCK];

export const Role = { GUARDIAN: 1, PROTECTED: 2 } as const;
export type Role = (typeof Role)[keyof typeof Role];

export const Answer = { ACCEPT: 1, DECLINE: 2 } as const;
export type Answer = (typeof Answer)[keyof typeof Answer];

export const DeclineReason = { NONE: 0, USER: 1, ROLE_CONFLICT: 2 } as const;
export type DeclineReason = (typeof DeclineReason)[keyof typeof DeclineReason];

export const Verdict = { APPROVE: 1, DENY: 2 } as const;
export type Verdict = (typeof Verdict)[keyof typeof Verdict];

export const Outcome = { OPEN: 0, APPROVED: 1, DENIED: 2, CANCELLED: 3 } as const;
export type Outcome = (typeof Outcome)[keyof typeof Outcome];

export const CancelReason = { NONE: 0, WITHDRAWN: 1, APP_UNINSTALLED: 2, RESOLVED_BY_UNLOCK: 3, GUARDIAN_REMOVED: 4 } as const;
export type CancelReason = (typeof CancelReason)[keyof typeof CancelReason];

export const GuardianState = { WAITING: 0, APPROVED: 1, DENIED: 2 } as const;
export type GuardianState = (typeof GuardianState)[keyof typeof GuardianState];

export const UnpairedHow = { ALL_APPROVED: 1, TIMER: 2, RELEASED: 3 } as const;
export type UnpairedHow = (typeof UnpairedHow)[keyof typeof UnpairedHow];

export const NoticeCode = {
  APP_INSTALLED: 0x0001,
  GUARDIAN_ADDED: 0x0002,
  GUARDIAN_REMOVED: 0x0003,
  RELEASE_STARTED: 0x0004,
  RELEASE_CANCELLED: 0x0005,
  PROTECTION_CHANGED: 0x0006,
  MANAGEMENT_CHANGED: 0x0007,
  APP_MANAGED: 0x0008,
  GUARDIAN_MOVED: 0x0009,
} as const;

export const RemovedHow = { LEFT: 1, UNPAIRED: 2 } as const;
export type RemovedHow = (typeof RemovedHow)[keyof typeof RemovedHow];

/** The protection options of NOTICE PROTECTION_CHANGED, in Killit's HardeningConfig order. */
export const ProtectionOption = {
  UNINSTALL: 1,
  FORCE_STOP: 2,
  SAFE_BOOT: 3,
  FACTORY_RESET: 4,
  APPS_CONTROL: 5,
  DATE_TIME: 6,
} as const;
export type ProtectionOption = (typeof ProtectionOption)[keyof typeof ProtectionOption];

/** An app's state in an APP_LIST or a MOVE_STATE (SPEC.md §11.10, §11.14). */
export const AppState = { ALLOWED: 1, BLOCKED: 2, NEW: 3 } as const;
export type AppState = (typeof AppState)[keyof typeof AppState];

/** What a MANAGE asks for one app (SPEC.md §11.11). */
export const Desired = { ALLOWED: 1, BLOCKED: 2 } as const;
export type Desired = (typeof Desired)[keyof typeof Desired];

/** What NOTICE APP_MANAGED reports (SPEC.md §11.9). */
export const AppChange = { BLOCKED: 1, UNBLOCKED: 2, REFUSED: 3 } as const;
export type AppChange = (typeof AppChange)[keyof typeof AppChange];

export const MoveAnswerCode = { READY: 1, DECLINE: 2 } as const;
export type MoveAnswerCode = (typeof MoveAnswerCode)[keyof typeof MoveAnswerCode];

/** Why a MOVE_ANSWER declines; NONE exactly when it is READY. */
export const MoveDeclineReason = { NONE: 0, USER: 1, NOT_DEVICE_OWNER: 2, HAS_PAIRINGS: 3, INVALID: 4 } as const;
export type MoveDeclineReason = (typeof MoveDeclineReason)[keyof typeof MoveDeclineReason];

export const MoveOutcome = { COMMITTED: 1, ABANDONED: 2 } as const;
export type MoveOutcome = (typeof MoveOutcome)[keyof typeof MoveOutcome];

/** Sizes fixed by SPEC.md §11. */
export const REQUEST_ID_BYTES = 16;
export const SESSION_NONCE_BYTES = 32;
export const CERT_DIGEST_BYTES = 32;
export const ICON_SIDE = 32;
export const ICON_BYTES = ICON_SIDE * ICON_SIDE * 4;
export const MAX_GUARDIANS = 50;
export const MAX_STATUS_ENTRIES = 40;
/** An APP_LIST icon: 16 × 16 RGBA8888 (SPEC.md §11.10). */
export const LIST_ICON_SIDE = 16;
export const LIST_ICON_BYTES = LIST_ICON_SIDE * LIST_ICON_SIDE * 4;
/** The `iconFormat` codes: 1 for a request's 32 × 32 icon, 2 for a list's 16 × 16 one. */
export const ICON_FORMAT_REQUEST = 1;
export const ICON_FORMAT_LIST = 2;
/** Length of an APP_LIST's `listId` and of a move's `moveId`. */
export const LIST_ID_BYTES = 16;
export const MOVE_ID_BYTES = 16;
/** Apps in one MANAGE: 25 of the longest still fit in one body. */
export const MAX_MANAGE_APPS = 25;
/** The longest app list, and the most apps and pairings one move carries (SPEC.md §13). */
export const MAX_LISTED_APPS = 1000;
export const MAX_MOVED_PAIRINGS = 100;
export const MAX_MOVED_APPS = 4000;
/** The protection options are bits 0–5 of MOVE_STATE's `protection`. */
export const PROTECTION_BITS = 0b0011_1111;

/** An app, as a request binds it: its package and signing-certificate digest. */
export interface AppRef {
  readonly packageName: string;
  readonly certDigest: Uint8Array;
}

/** An app with what a guardian sees of it (PLAN.md §5.4). */
export interface AppInfo extends AppRef {
  readonly label: string;
  /** The installer's package name, or empty when unknown or sideloaded. */
  readonly installer: string;
  readonly firstInstalled: number;
  /** 32 × 32 RGBA8888 pixels, rows top to bottom, not premultiplied; null when there's none. */
  readonly icon: Uint8Array | null;
}

export interface PairOffer {
  readonly kind: typeof Kind.PAIR_OFFER;
  readonly senderRole: Role;
  readonly selfName: string;
  readonly deviceModel: string;
  readonly appManagement: boolean;
}

export interface PairAnswer {
  readonly kind: typeof Kind.PAIR_ANSWER;
  readonly answer: Answer;
  readonly reason: DeclineReason;
  readonly selfName: string;
  readonly deviceModel: string;
  readonly appManagement: boolean;
}

export interface UnblockApp {
  readonly kind: typeof Kind.UNBLOCK_APP;
  readonly requestId: Uint8Array;
  readonly app: AppInfo;
  readonly explanation: string;
  readonly chancesLeft: number;
  readonly guardianCount: number;
}

export interface Unlock {
  readonly kind: typeof Kind.UNLOCK;
  readonly requestId: Uint8Array;
  readonly sessionNonce: Uint8Array;
  readonly explanation: string;
  readonly guardianCount: number;
}

export interface Unpair {
  readonly kind: typeof Kind.UNPAIR;
  readonly requestId: Uint8Array;
  readonly targetPairId: Uint8Array;
  readonly targetFp: Uint8Array;
  readonly explanation: string;
  readonly chancesLeft: number;
  readonly guardianCount: number;
  readonly timerEndsAt: number;
}

/** What a DECISION binds: the request's own target, by kind (SPEC.md §11.6). */
export type DecisionTarget =
  | { readonly requestKind: typeof Kind.UNBLOCK_APP; readonly app: AppRef }
  | { readonly requestKind: typeof Kind.UNLOCK; readonly sessionNonce: Uint8Array }
  | { readonly requestKind: typeof Kind.UNPAIR; readonly targetPairId: Uint8Array }
  | { readonly requestKind: typeof Kind.GUARDIAN_UNBLOCK; readonly app: AppRef };

export interface Decision {
  readonly kind: typeof Kind.DECISION;
  readonly requestId: Uint8Array;
  readonly target: DecisionTarget;
  readonly decision: Verdict;
  readonly note: string;
}

export interface StatusEntry {
  readonly guardianFp: Uint8Array;
  readonly guardianName: string;
  readonly state: GuardianState;
}

export interface Status {
  readonly kind: typeof Kind.STATUS;
  readonly requestId: Uint8Array;
  readonly requestKind: RequestKind;
  readonly outcome: Outcome;
  readonly reason: CancelReason;
  readonly guardians: readonly StatusEntry[];
}

export interface Leave {
  readonly kind: typeof Kind.LEAVE;
}

export interface Unpaired {
  readonly kind: typeof Kind.UNPAIRED;
  readonly how: UnpairedHow;
}

export type NoticeBody =
  | { readonly code: typeof NoticeCode.APP_INSTALLED; readonly app: AppInfo; readonly blocked: boolean }
  | { readonly code: typeof NoticeCode.GUARDIAN_ADDED; readonly guardianFp: Uint8Array; readonly guardianName: string }
  | {
      readonly code: typeof NoticeCode.GUARDIAN_REMOVED;
      readonly guardianFp: Uint8Array;
      readonly guardianName: string;
      readonly how: RemovedHow;
    }
  | { readonly code: typeof NoticeCode.RELEASE_STARTED; readonly completesAt: number }
  | { readonly code: typeof NoticeCode.RELEASE_CANCELLED }
  | { readonly code: typeof NoticeCode.PROTECTION_CHANGED; readonly option: ProtectionOption; readonly enabled: boolean }
  | { readonly code: typeof NoticeCode.MANAGEMENT_CHANGED; readonly enabled: boolean }
  | {
      readonly code: typeof NoticeCode.APP_MANAGED;
      readonly app: AppRef;
      readonly label: string;
      readonly change: AppChange;
      readonly guardianFp: Uint8Array;
      readonly guardianName: string;
    }
  | { readonly code: typeof NoticeCode.GUARDIAN_MOVED; readonly guardianFp: Uint8Array; readonly guardianName: string }
  /** A code this implementation doesn't know. Its parameters are kept, unparsed (SPEC.md §11.9). */
  | { readonly code: number; readonly unknown: true; readonly params: Uint8Array };

export interface Notice {
  readonly kind: typeof Kind.NOTICE;
  readonly notice: NoticeBody;
}

export interface ListRequest {
  readonly kind: typeof Kind.LIST_REQUEST;
  readonly listId: Uint8Array;
}

/** One app in an APP_LIST (SPEC.md §11.10). */
export interface ListedApp extends AppRef {
  readonly label: string;
  /** The installer's package name, or empty when unknown or sideloaded. */
  readonly installer: string;
  readonly firstInstalled: number;
  readonly state: AppState;
  /** 16 × 16 RGBA8888 pixels, rows top to bottom, not premultiplied; null when there's none. */
  readonly icon: Uint8Array | null;
}

/** One page of the list answering a LIST_REQUEST. */
export interface AppList {
  readonly kind: typeof Kind.APP_LIST;
  readonly listId: Uint8Array;
  readonly page: number;
  readonly pageCount: number;
  readonly apps: readonly ListedApp[];
}

/** One app a MANAGE changes, and what it should be. */
export interface ManageEntry extends AppRef {
  readonly desired: Desired;
}

export interface Manage {
  readonly kind: typeof Kind.MANAGE;
  readonly seq: number;
  readonly entries: readonly ManageEntry[];
}

export interface GuardianUnblock {
  readonly kind: typeof Kind.GUARDIAN_UNBLOCK;
  readonly requestId: Uint8Array;
  readonly app: AppInfo;
  readonly proposerFp: Uint8Array;
  readonly proposerName: string;
  readonly guardianCount: number;
}

export interface Handover {
  readonly kind: typeof Kind.HANDOVER;
  readonly newBundle: Bundle;
  readonly deviceModel: string;
}

export interface MoveRequest {
  readonly kind: typeof Kind.MOVE_REQUEST;
  readonly deviceModel: string;
  readonly deviceOwner: boolean;
}

/** One pairing a move hands over, as the old phone holds it (SPEC.md §11.14). */
export interface MovedPairing {
  readonly pairId: Uint8Array;
  /** The old phone's side of it. */
  readonly role: Role;
  readonly peer: Bundle;
  readonly peerName: string;
  readonly nickname: string;
  readonly peerModel: string;
  /** GUARDIAN: the peer's setting as last heard; PROTECTED: always false. */
  readonly appManagement: boolean;
  /** PROTECTED: 0–3; GUARDIAN: always 0. */
  readonly unpairChances: number;
  readonly createdAt: number;
}

/** One decision about an app a move hands over, with the app's chances (D4). */
export interface MovedApp extends AppRef {
  readonly state: AppState;
  readonly chancesLeft: number;
}

/** One page of a move's state. */
export interface MoveState {
  readonly kind: typeof Kind.MOVE_STATE;
  readonly moveId: Uint8Array;
  readonly page: number;
  readonly pageCount: number;
  readonly appManagement: boolean;
  /** The protection options, bit (option − 1) for each one that is on. */
  readonly protection: number;
  readonly pairings: readonly MovedPairing[];
  readonly apps: readonly MovedApp[];
}

export interface MoveAnswer {
  readonly kind: typeof Kind.MOVE_ANSWER;
  readonly moveId: Uint8Array;
  readonly answer: MoveAnswerCode;
  readonly reason: MoveDeclineReason;
}

export interface MoveDone {
  readonly kind: typeof Kind.MOVE_DONE;
  readonly moveId: Uint8Array;
  readonly outcome: MoveOutcome;
}

export type MessageBody =
  | PairOffer
  | PairAnswer
  | UnblockApp
  | Unlock
  | Unpair
  | Decision
  | Status
  | Leave
  | Unpaired
  | Notice
  | ListRequest
  | AppList
  | Manage
  | GuardianUnblock
  | Handover
  | MoveRequest
  | MoveState
  | MoveAnswer
  | MoveDone;

// ------------------------------------------------------------------------------------------------
// Shared structures

/** Reads a `u8` and refuses anything outside `allowed`. */
function readEnum<T extends number>(reader: ByteReader, allowed: readonly T[], what: string): T {
  const value = reader.u8();
  if (!allowed.includes(value as T)) throw new DecodeError(`invalid ${what}`);
  return value as T;
}

/** Reads a `u8` in `[min, max]`. */
function readRange(reader: ByteReader, min: number, max: number, what: string): number {
  const value = reader.u8();
  if (value < min || value > max) throw new DecodeError(`${what} out of range`);
  return value;
}

function writeAppRef(writer: ByteWriter, app: AppRef): void {
  writePackageName(writer, app.packageName);
  writer.fixed(app.certDigest, CERT_DIGEST_BYTES);
}

function readAppRef(reader: ByteReader): AppRef {
  return { packageName: readPackageName(reader), certDigest: reader.fixed(CERT_DIGEST_BYTES) };
}

function writeAppInfo(writer: ByteWriter, app: AppInfo): void {
  writeAppRef(writer, app);
  writeText(writer, app.label, TEXT.appLabel);
  writePackageName(writer, app.installer, true);
  writer.u64(app.firstInstalled);
  if (app.icon === null) {
    writer.u8(0);
  } else {
    writer.u8(1).fixed(app.icon, ICON_BYTES);
  }
}

function readAppInfo(reader: ByteReader): AppInfo {
  const { packageName, certDigest } = readAppRef(reader);
  const label = readText(reader, TEXT.appLabel);
  const installer = readPackageName(reader, true);
  const firstInstalled = reader.u64();
  const iconFormat = readEnum(reader, [0, 1], 'icon format');
  const icon = iconFormat === 1 ? reader.fixed(ICON_BYTES) : null;
  return { packageName, certDigest, label, installer, firstInstalled, icon };
}

function checkCount(value: number, min: number, max: number, what: string): void {
  if (!Number.isInteger(value) || value < min || value > max) throw new RangeError(`${what} out of range`);
}

function writeListedApp(writer: ByteWriter, app: ListedApp): void {
  writeAppRef(writer, app);
  writeText(writer, app.label, TEXT.appLabel);
  writePackageName(writer, app.installer, true);
  writer.u64(app.firstInstalled).u8(app.state);
  if (app.icon === null) {
    writer.u8(0);
  } else {
    writer.u8(ICON_FORMAT_LIST).fixed(app.icon, LIST_ICON_BYTES);
  }
}

function readListedApp(reader: ByteReader): ListedApp {
  const { packageName, certDigest } = readAppRef(reader);
  const label = readText(reader, TEXT.appLabel);
  const installer = readPackageName(reader, true);
  const firstInstalled = reader.u64();
  const state = readEnum<AppState>(reader, [AppState.ALLOWED, AppState.BLOCKED, AppState.NEW], 'app state');
  const iconFormat = readEnum(reader, [0, ICON_FORMAT_LIST], 'icon format');
  const icon = iconFormat === ICON_FORMAT_LIST ? reader.fixed(LIST_ICON_BYTES) : null;
  return { packageName, certDigest, label, installer, firstInstalled, state, icon };
}

function writeMovedPairing(writer: ByteWriter, pairing: MovedPairing): void {
  writer.fixed(pairing.pairId, PAIR_ID_BYTES).u8(pairing.role).raw(encodeBundle(pairing.peer));
  writeText(writer, pairing.peerName, TEXT.selfName);
  writeText(writer, pairing.nickname, TEXT.selfName);
  writeText(writer, pairing.peerModel, TEXT.deviceModel);
  writer.bool(pairing.appManagement).u8(pairing.unpairChances).u64(pairing.createdAt);
}

function readMovedPairing(reader: ByteReader): MovedPairing {
  const pairId = reader.fixed(PAIR_ID_BYTES);
  const role = readEnum<Role>(reader, [Role.GUARDIAN, Role.PROTECTED], 'role');
  const peer = readBundle(reader);
  const peerName = readText(reader, TEXT.selfName);
  const nickname = readText(reader, TEXT.selfName);
  const peerModel = readText(reader, TEXT.deviceModel);
  // Both fields belong to the protected side of the pairing: the setting is the peer's when the
  // old phone guards it, and the chances to remove a guardian are the old phone's when it is the
  // one guarded. Each is zero on the other side.
  const appManagement = reader.bool();
  if (role === Role.PROTECTED && appManagement) throw new DecodeError('the guarded side states no app-management setting');
  const unpairChances = readRange(reader, 0, role === Role.PROTECTED ? 3 : 0, 'unpairChances');
  const createdAt = reader.u64();
  return { pairId, role, peer, peerName, nickname, peerModel, appManagement, unpairChances, createdAt };
}

/** Refuses a list that names one package twice. */
function checkUniquePackages(apps: readonly AppRef[]): void {
  const seen = new Set<string>();
  for (const app of apps) {
    if (seen.has(app.packageName)) throw new DecodeError('a package appears twice');
    seen.add(app.packageName);
  }
}

// ------------------------------------------------------------------------------------------------
// Encoding

/** Encodes a message body (SPEC.md §11). Refuses values its decoder would refuse. */
export function encodeBody(body: MessageBody): Uint8Array {
  const writer = new ByteWriter();
  switch (body.kind) {
    case Kind.PAIR_OFFER:
      if (body.senderRole === Role.GUARDIAN && body.appManagement) throw new RangeError('a guardian has no app-management setting');
      writer.u8(body.senderRole);
      writeText(writer, body.selfName, TEXT.selfName);
      writeText(writer, body.deviceModel, TEXT.deviceModel);
      writer.bool(body.appManagement);
      break;
    case Kind.PAIR_ANSWER: {
      const accept = body.answer === Answer.ACCEPT;
      if (accept !== (body.reason === DeclineReason.NONE)) throw new RangeError('ACCEPT has no reason; DECLINE needs one');
      if (!accept && body.appManagement) throw new RangeError('a decline carries no app-management setting');
      writer.u8(body.answer).u8(body.reason);
      writeText(writer, body.selfName, accept ? TEXT.selfName : TEXT.empty);
      writeText(writer, body.deviceModel, accept ? TEXT.deviceModel : TEXT.empty);
      writer.bool(body.appManagement);
      break;
    }
    case Kind.UNBLOCK_APP:
      checkCount(body.chancesLeft, 1, 3, 'chancesLeft');
      checkCount(body.guardianCount, 1, MAX_GUARDIANS, 'guardianCount');
      writer.fixed(body.requestId, REQUEST_ID_BYTES);
      writeAppInfo(writer, body.app);
      writeText(writer, body.explanation, TEXT.requiredExplanation);
      writer.u8(body.chancesLeft).u8(body.guardianCount);
      break;
    case Kind.UNLOCK:
      checkCount(body.guardianCount, 1, MAX_GUARDIANS, 'guardianCount');
      writer.fixed(body.requestId, REQUEST_ID_BYTES).fixed(body.sessionNonce, SESSION_NONCE_BYTES);
      writeText(writer, body.explanation, TEXT.optionalExplanation);
      writer.u8(body.guardianCount);
      break;
    case Kind.UNPAIR:
      checkCount(body.chancesLeft, 1, 3, 'chancesLeft');
      checkCount(body.guardianCount, 1, MAX_GUARDIANS, 'guardianCount');
      writer
        .fixed(body.requestId, REQUEST_ID_BYTES)
        .fixed(body.targetPairId, PAIR_ID_BYTES)
        .fixed(body.targetFp, FINGERPRINT_BYTES);
      writeText(writer, body.explanation, TEXT.requiredExplanation);
      writer.u8(body.chancesLeft).u8(body.guardianCount).u64(body.timerEndsAt);
      break;
    case Kind.DECISION:
      writer.fixed(body.requestId, REQUEST_ID_BYTES);
      writeDecisionTarget(writer, body.target);
      writer.u8(body.decision);
      writeText(writer, body.note, TEXT.note);
      break;
    case Kind.STATUS:
      if ((body.outcome === Outcome.CANCELLED) !== (body.reason !== CancelReason.NONE)) {
        throw new RangeError('only CANCELLED carries a reason, and it always does');
      }
      checkCount(body.guardians.length, 0, MAX_STATUS_ENTRIES, 'guardian list');
      writer.fixed(body.requestId, REQUEST_ID_BYTES).u8(body.requestKind).u8(body.outcome).u8(body.reason);
      writer.u8(body.guardians.length);
      for (const entry of body.guardians) {
        writer.fixed(entry.guardianFp, FINGERPRINT_BYTES);
        writeText(writer, entry.guardianName, TEXT.selfName);
        writer.u8(entry.state);
      }
      break;
    case Kind.LEAVE:
      break;
    case Kind.UNPAIRED:
      writer.u8(body.how);
      break;
    case Kind.NOTICE:
      writeNotice(writer, body.notice);
      break;
    case Kind.LIST_REQUEST:
      writer.fixed(body.listId, LIST_ID_BYTES);
      break;
    case Kind.APP_LIST:
      checkCount(body.pageCount, 1, 255, 'pageCount');
      checkCount(body.page, 0, body.pageCount - 1, 'page');
      checkCount(body.apps.length, body.pageCount === 1 ? 0 : 1, 255, 'apps on a page');
      writer.fixed(body.listId, LIST_ID_BYTES).u8(body.page).u8(body.pageCount).u8(body.apps.length);
      for (const app of body.apps) writeListedApp(writer, app);
      break;
    case Kind.MANAGE:
      checkCount(body.seq, 1, Number.MAX_SAFE_INTEGER, 'seq');
      checkCount(body.entries.length, 1, MAX_MANAGE_APPS, 'apps in a MANAGE');
      writer.u64(body.seq).u8(body.entries.length);
      for (const entry of body.entries) {
        writeAppRef(writer, entry);
        writer.u8(entry.desired);
      }
      break;
    case Kind.GUARDIAN_UNBLOCK:
      checkCount(body.guardianCount, 1, MAX_GUARDIANS, 'guardianCount');
      writer.fixed(body.requestId, REQUEST_ID_BYTES);
      writeAppInfo(writer, body.app);
      writer.fixed(body.proposerFp, FINGERPRINT_BYTES);
      writeText(writer, body.proposerName, TEXT.selfName);
      writer.u8(body.guardianCount);
      break;
    case Kind.HANDOVER:
      writer.raw(encodeBundle(body.newBundle));
      writeText(writer, body.deviceModel, TEXT.deviceModel);
      break;
    case Kind.MOVE_REQUEST:
      writeText(writer, body.deviceModel, TEXT.deviceModel);
      writer.bool(body.deviceOwner);
      break;
    case Kind.MOVE_STATE:
      checkCount(body.pageCount, 1, 255, 'pageCount');
      checkCount(body.page, 0, body.pageCount - 1, 'page');
      checkCount(body.pairings.length, 0, 255, 'pairings on a page');
      checkCount(body.apps.length, 0, 0xffff, 'apps on a page');
      writer.fixed(body.moveId, MOVE_ID_BYTES).u8(body.page).u8(body.pageCount).bool(body.appManagement).u8(body.protection);
      writer.u8(body.pairings.length);
      for (const pairing of body.pairings) writeMovedPairing(writer, pairing);
      writer.u16(body.apps.length);
      for (const app of body.apps) {
        writeAppRef(writer, app);
        writer.u8(app.state).u8(app.chancesLeft);
      }
      break;
    case Kind.MOVE_ANSWER:
      if ((body.answer === MoveAnswerCode.READY) !== (body.reason === MoveDeclineReason.NONE)) {
        throw new RangeError('READY has no reason; DECLINE needs one');
      }
      writer.fixed(body.moveId, MOVE_ID_BYTES).u8(body.answer).u8(body.reason);
      break;
    case Kind.MOVE_DONE:
      writer.fixed(body.moveId, MOVE_ID_BYTES).u8(body.outcome);
      break;
  }
  const bytes = writer.finish();
  // Enumerations arrive as plain numbers at runtime (from JSON, say), so the decoder has the last
  // word: whatever it would refuse is never emitted.
  const check = decodeBody(body.kind, bytes);
  if (!check.ok) throw new RangeError(`body would be refused: ${check.error}`);
  return bytes;
}

function writeDecisionTarget(writer: ByteWriter, target: DecisionTarget): void {
  writer.u8(target.requestKind);
  switch (target.requestKind) {
    case Kind.UNBLOCK_APP:
    case Kind.GUARDIAN_UNBLOCK:
      writeAppRef(writer, target.app);
      break;
    case Kind.UNLOCK:
      writer.fixed(target.sessionNonce, SESSION_NONCE_BYTES);
      break;
    case Kind.UNPAIR:
      writer.fixed(target.targetPairId, PAIR_ID_BYTES);
      break;
  }
}

function writeNotice(writer: ByteWriter, notice: NoticeBody): void {
  writer.u16(notice.code);
  if ('unknown' in notice) throw new RangeError('unknown notices can be received but not sent');
  switch (notice.code) {
    case NoticeCode.APP_INSTALLED:
      writeAppInfo(writer, notice.app);
      writer.bool(notice.blocked);
      break;
    case NoticeCode.GUARDIAN_ADDED:
      writer.fixed(notice.guardianFp, FINGERPRINT_BYTES);
      writeText(writer, notice.guardianName, TEXT.selfName);
      break;
    case NoticeCode.GUARDIAN_REMOVED:
      writer.fixed(notice.guardianFp, FINGERPRINT_BYTES);
      writeText(writer, notice.guardianName, TEXT.selfName);
      writer.u8(notice.how);
      break;
    case NoticeCode.RELEASE_STARTED:
      writer.u64(notice.completesAt);
      break;
    case NoticeCode.RELEASE_CANCELLED:
      break;
    case NoticeCode.PROTECTION_CHANGED:
      writer.u8(notice.option).bool(notice.enabled);
      break;
    case NoticeCode.MANAGEMENT_CHANGED:
      writer.bool(notice.enabled);
      break;
    case NoticeCode.APP_MANAGED:
      writeAppRef(writer, notice.app);
      writeText(writer, notice.label, TEXT.appLabel);
      writer.u8(notice.change).fixed(notice.guardianFp, FINGERPRINT_BYTES);
      writeText(writer, notice.guardianName, TEXT.selfName);
      break;
    case NoticeCode.GUARDIAN_MOVED:
      writer.fixed(notice.guardianFp, FINGERPRINT_BYTES);
      writeText(writer, notice.guardianName, TEXT.selfName);
      break;
  }
}

// ------------------------------------------------------------------------------------------------
// Decoding

/**
 * Decodes the body of a known kind. Every field is validated; trailing bytes are refused. An
 * unknown kind is a rejection here: callers check {@link isKnownKind} first and keep unknown
 * messages for "Update Killit" (SPEC.md §10.3 step 9).
 */
export function decodeBody(kind: number, bytes: Uint8Array): Result<MessageBody> {
  return decodeWith(() => {
    const reader = new ByteReader(bytes);
    const body = readBody(kind, reader);
    reader.end();
    return body;
  });
}

function readBody(kind: number, reader: ByteReader): MessageBody {
  switch (kind) {
    case Kind.PAIR_OFFER: {
      const senderRole = readEnum<Role>(reader, [Role.GUARDIAN, Role.PROTECTED], 'role');
      const selfName = readText(reader, TEXT.selfName);
      const deviceModel = readText(reader, TEXT.deviceModel);
      const appManagement = reader.bool();
      if (senderRole === Role.GUARDIAN && appManagement) throw new DecodeError('a guardian has no app-management setting');
      return { kind: Kind.PAIR_OFFER, senderRole, selfName, deviceModel, appManagement };
    }
    case Kind.PAIR_ANSWER: {
      const answer = readEnum<Answer>(reader, [Answer.ACCEPT, Answer.DECLINE], 'answer');
      const accept = answer === Answer.ACCEPT;
      const reason = readEnum<DeclineReason>(
        reader,
        accept ? [DeclineReason.NONE] : [DeclineReason.USER, DeclineReason.ROLE_CONFLICT],
        'decline reason',
      );
      const selfName = readText(reader, accept ? TEXT.selfName : TEXT.empty);
      const deviceModel = readText(reader, accept ? TEXT.deviceModel : TEXT.empty);
      const appManagement = reader.bool();
      if (!accept && appManagement) throw new DecodeError('a decline carries no app-management setting');
      return { kind: Kind.PAIR_ANSWER, answer, reason, selfName, deviceModel, appManagement };
    }
    case Kind.UNBLOCK_APP:
      return {
        kind: Kind.UNBLOCK_APP,
        requestId: reader.fixed(REQUEST_ID_BYTES),
        app: readAppInfo(reader),
        explanation: readText(reader, TEXT.requiredExplanation),
        chancesLeft: readRange(reader, 1, 3, 'chancesLeft'),
        guardianCount: readRange(reader, 1, MAX_GUARDIANS, 'guardianCount'),
      };
    case Kind.UNLOCK:
      return {
        kind: Kind.UNLOCK,
        requestId: reader.fixed(REQUEST_ID_BYTES),
        sessionNonce: reader.fixed(SESSION_NONCE_BYTES),
        explanation: readText(reader, TEXT.optionalExplanation),
        guardianCount: readRange(reader, 1, MAX_GUARDIANS, 'guardianCount'),
      };
    case Kind.UNPAIR:
      return {
        kind: Kind.UNPAIR,
        requestId: reader.fixed(REQUEST_ID_BYTES),
        targetPairId: reader.fixed(PAIR_ID_BYTES),
        targetFp: reader.fixed(FINGERPRINT_BYTES),
        explanation: readText(reader, TEXT.requiredExplanation),
        chancesLeft: readRange(reader, 1, 3, 'chancesLeft'),
        guardianCount: readRange(reader, 1, MAX_GUARDIANS, 'guardianCount'),
        timerEndsAt: reader.u64(),
      };
    case Kind.DECISION:
      return {
        kind: Kind.DECISION,
        requestId: reader.fixed(REQUEST_ID_BYTES),
        target: readDecisionTarget(reader),
        decision: readEnum<Verdict>(reader, [Verdict.APPROVE, Verdict.DENY], 'decision'),
        note: readText(reader, TEXT.note),
      };
    case Kind.STATUS: {
      const requestId = reader.fixed(REQUEST_ID_BYTES);
      const requestKind = readEnum(reader, REQUEST_KINDS, 'request kind') as RequestKind;
      const outcome = readEnum<Outcome>(reader, [Outcome.OPEN, Outcome.APPROVED, Outcome.DENIED, Outcome.CANCELLED], 'outcome');
      const reason = readEnum<CancelReason>(
        reader,
        outcome === Outcome.CANCELLED
          ? [CancelReason.WITHDRAWN, CancelReason.APP_UNINSTALLED, CancelReason.RESOLVED_BY_UNLOCK, CancelReason.GUARDIAN_REMOVED]
          : [CancelReason.NONE],
        'cancel reason',
      );
      const count = readRange(reader, 0, MAX_STATUS_ENTRIES, 'guardian list');
      const guardians: StatusEntry[] = [];
      for (let i = 0; i < count; i++) {
        guardians.push({
          guardianFp: reader.fixed(FINGERPRINT_BYTES),
          guardianName: readText(reader, TEXT.selfName),
          state: readEnum<GuardianState>(reader, [GuardianState.WAITING, GuardianState.APPROVED, GuardianState.DENIED], 'state'),
        });
      }
      return { kind: Kind.STATUS, requestId, requestKind, outcome, reason, guardians };
    }
    case Kind.LEAVE:
      return { kind: Kind.LEAVE };
    case Kind.UNPAIRED:
      return {
        kind: Kind.UNPAIRED,
        how: readEnum<UnpairedHow>(reader, [UnpairedHow.ALL_APPROVED, UnpairedHow.TIMER, UnpairedHow.RELEASED], 'how'),
      };
    case Kind.NOTICE:
      return { kind: Kind.NOTICE, notice: readNotice(reader) };
    case Kind.LIST_REQUEST:
      return { kind: Kind.LIST_REQUEST, listId: reader.fixed(LIST_ID_BYTES) };
    case Kind.APP_LIST: {
      const listId = reader.fixed(LIST_ID_BYTES);
      const page = reader.u8();
      const pageCount = readRange(reader, 1, 255, 'pageCount');
      if (page >= pageCount) throw new DecodeError('page out of range');
      // An empty page only stands for an empty list, which has a single page.
      const count = readRange(reader, pageCount === 1 ? 0 : 1, 255, 'apps on a page');
      const apps: ListedApp[] = [];
      for (let i = 0; i < count; i++) apps.push(readListedApp(reader));
      checkUniquePackages(apps);
      return { kind: Kind.APP_LIST, listId, page, pageCount, apps };
    }
    case Kind.MANAGE: {
      const seq = reader.u64();
      if (seq < 1) throw new DecodeError('seq out of range');
      const count = readRange(reader, 1, MAX_MANAGE_APPS, 'apps in a MANAGE');
      const entries: ManageEntry[] = [];
      for (let i = 0; i < count; i++) {
        const app = readAppRef(reader);
        entries.push({ ...app, desired: readEnum<Desired>(reader, [Desired.ALLOWED, Desired.BLOCKED], 'desired') });
      }
      checkUniquePackages(entries);
      return { kind: Kind.MANAGE, seq, entries };
    }
    case Kind.GUARDIAN_UNBLOCK:
      return {
        kind: Kind.GUARDIAN_UNBLOCK,
        requestId: reader.fixed(REQUEST_ID_BYTES),
        app: readAppInfo(reader),
        proposerFp: reader.fixed(FINGERPRINT_BYTES),
        proposerName: readText(reader, TEXT.selfName),
        guardianCount: readRange(reader, 1, MAX_GUARDIANS, 'guardianCount'),
      };
    case Kind.HANDOVER:
      return { kind: Kind.HANDOVER, newBundle: readBundle(reader), deviceModel: readText(reader, TEXT.deviceModel) };
    case Kind.MOVE_REQUEST:
      return { kind: Kind.MOVE_REQUEST, deviceModel: readText(reader, TEXT.deviceModel), deviceOwner: reader.bool() };
    case Kind.MOVE_STATE: {
      const moveId = reader.fixed(MOVE_ID_BYTES);
      const page = reader.u8();
      const pageCount = readRange(reader, 1, 255, 'pageCount');
      if (page >= pageCount) throw new DecodeError('page out of range');
      const appManagement = reader.bool();
      const protection = reader.u8();
      if ((protection & ~PROTECTION_BITS) !== 0) throw new DecodeError('unknown protection option');
      const pairingCount = reader.u8();
      const pairings: MovedPairing[] = [];
      for (let i = 0; i < pairingCount; i++) pairings.push(readMovedPairing(reader));
      const appCount = reader.u16();
      const apps: MovedApp[] = [];
      for (let i = 0; i < appCount; i++) {
        const app = readAppRef(reader);
        const state = readEnum<AppState>(reader, [AppState.ALLOWED, AppState.BLOCKED, AppState.NEW], 'app state');
        apps.push({ ...app, state, chancesLeft: readRange(reader, 0, 3, 'chancesLeft') });
      }
      if (new Set(pairings.map((p) => toHex(p.pairId))).size !== pairings.length) throw new DecodeError('a pairing appears twice');
      checkUniquePackages(apps);
      return { kind: Kind.MOVE_STATE, moveId, page, pageCount, appManagement, protection, pairings, apps };
    }
    case Kind.MOVE_ANSWER: {
      const moveId = reader.fixed(MOVE_ID_BYTES);
      const answer = readEnum<MoveAnswerCode>(reader, [MoveAnswerCode.READY, MoveAnswerCode.DECLINE], 'answer');
      const reason = readEnum<MoveDeclineReason>(
        reader,
        answer === MoveAnswerCode.READY
          ? [MoveDeclineReason.NONE]
          : [MoveDeclineReason.USER, MoveDeclineReason.NOT_DEVICE_OWNER, MoveDeclineReason.HAS_PAIRINGS, MoveDeclineReason.INVALID],
        'decline reason',
      );
      return { kind: Kind.MOVE_ANSWER, moveId, answer, reason };
    }
    case Kind.MOVE_DONE:
      return {
        kind: Kind.MOVE_DONE,
        moveId: reader.fixed(MOVE_ID_BYTES),
        outcome: readEnum<MoveOutcome>(reader, [MoveOutcome.COMMITTED, MoveOutcome.ABANDONED], 'outcome'),
      };
    default:
      throw new DecodeError('unknown kind');
  }
}


function readDecisionTarget(reader: ByteReader): DecisionTarget {
  const requestKind = readEnum(reader, REQUEST_KINDS, 'request kind') as RequestKind;
  switch (requestKind) {
    case Kind.UNBLOCK_APP:
    case Kind.GUARDIAN_UNBLOCK:
      return { requestKind, app: readAppRef(reader) };
    case Kind.UNLOCK:
      return { requestKind, sessionNonce: reader.fixed(SESSION_NONCE_BYTES) };
    case Kind.UNPAIR:
      return { requestKind, targetPairId: reader.fixed(PAIR_ID_BYTES) };
  }
}

function readNotice(reader: ByteReader): NoticeBody {
  const code = reader.u16();
  switch (code) {
    case NoticeCode.APP_INSTALLED:
      return { code: NoticeCode.APP_INSTALLED, app: readAppInfo(reader), blocked: reader.bool() };
    case NoticeCode.GUARDIAN_ADDED:
      return { code: NoticeCode.GUARDIAN_ADDED, guardianFp: reader.fixed(FINGERPRINT_BYTES), guardianName: readText(reader, TEXT.selfName) };
    case NoticeCode.GUARDIAN_REMOVED:
      return {
        code: NoticeCode.GUARDIAN_REMOVED,
        guardianFp: reader.fixed(FINGERPRINT_BYTES),
        guardianName: readText(reader, TEXT.selfName),
        how: readEnum<RemovedHow>(reader, [RemovedHow.LEFT, RemovedHow.UNPAIRED], 'how'),
      };
    case NoticeCode.RELEASE_STARTED:
      return { code: NoticeCode.RELEASE_STARTED, completesAt: reader.u64() };
    case NoticeCode.RELEASE_CANCELLED:
      return { code: NoticeCode.RELEASE_CANCELLED };
    case NoticeCode.PROTECTION_CHANGED:
      return {
        code: NoticeCode.PROTECTION_CHANGED,
        option: readEnum<ProtectionOption>(reader, Object.values(ProtectionOption), 'protection option'),
        enabled: reader.bool(),
      };
    case NoticeCode.MANAGEMENT_CHANGED:
      return { code: NoticeCode.MANAGEMENT_CHANGED, enabled: reader.bool() };
    case NoticeCode.APP_MANAGED:
      return {
        code: NoticeCode.APP_MANAGED,
        app: readAppRef(reader),
        label: readText(reader, TEXT.appLabel),
        change: readEnum<AppChange>(reader, [AppChange.BLOCKED, AppChange.UNBLOCKED, AppChange.REFUSED], 'change'),
        guardianFp: reader.fixed(FINGERPRINT_BYTES),
        guardianName: readText(reader, TEXT.selfName),
      };
    case NoticeCode.GUARDIAN_MOVED:
      return { code: NoticeCode.GUARDIAN_MOVED, guardianFp: reader.fixed(FINGERPRINT_BYTES), guardianName: readText(reader, TEXT.selfName) };
    default:
      return { code, unknown: true, params: reader.rest() };
  }
}

// ------------------------------------------------------------------------------------------------
// DECISION verification (SPEC.md §11.6)

/** What the protected phone stored when it sent a request to one guardian. */
export interface StoredRequest {
  readonly requestId: Uint8Array;
  readonly target: DecisionTarget;
  /** The pairing with the guardian this copy went to. */
  readonly pairId: Uint8Array;
  readonly guardianFp: Uint8Array;
  readonly guardianSignPk: KeyObject | Uint8Array;
  /** The protected phone's own fingerprint. */
  readonly ownFp: Uint8Array;
}

/**
 * Verifies a DECISION against the request it claims to answer.
 *
 * Only the verdict and the note are taken from the received message. Everything the guardian
 * agreed to (which request, which app and certificate, which unlock session, which pairing, who
 * signed, for whom) is rebuilt from `stored`, so the signature can only verify if the guardian
 * signed exactly that.
 *
 * @param message a message that passed {@link openEnvelope} (header parties already checked).
 * @returns the verdict and note, or a rejection when anything differs or the signature fails.
 */
export function verifyDecision(stored: StoredRequest, message: OpenedMessage): Result<{ decision: Verdict; note: string }> {
  return decodeWith(() => {
    if (message.header.kind !== Kind.DECISION) throw new DecodeError('not a decision');
    const decoded = decodeBody(Kind.DECISION, message.body);
    if (!decoded.ok) throw new DecodeError(decoded.error);
    const { decision, note } = decoded.value as Decision;
    const rebuiltHeader: MessageHeader = {
      version: MESSAGE_VERSION,
      kind: Kind.DECISION,
      messageId: message.header.messageId,
      pairId: stored.pairId,
      senderFp: stored.guardianFp,
      recipientFp: stored.ownFp,
      createdAt: message.header.createdAt,
    };
    const rebuiltBody = encodeBody({ kind: Kind.DECISION, requestId: stored.requestId, target: stored.target, decision, note });
    const rebuilt = encodeInner(rebuiltHeader, rebuiltBody);
    if (!verifyInner(stored.guardianSignPk, rebuilt, message.signature)) throw new DecodeError('decision does not match the request');
    return { decision, note };
  });
}

