/**
 * Message bodies (SPEC.md §11): one strict encoder and decoder per kind, and the DECISION check
 * that rebuilds signed bytes from the protected phone's own stored request (SPEC.md §11.6).
 *
 * End-to-end code: the server never imports it.
 */
import type { KeyObject } from 'node:crypto';
import { ByteReader, ByteWriter, DecodeError, decodeWith, type Result } from './bytes.ts';
import { PAIR_ID_BYTES } from './ceremony.ts';
import { MESSAGE_VERSION, encodeInner, verifyInner, type MessageHeader, type OpenedMessage } from './envelope.ts';
import { FINGERPRINT_BYTES } from './identity.ts';
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
} as const;
export type Kind = (typeof Kind)[keyof typeof Kind];

/** Who may send each kind, by role in the pairing named in the header (SPEC.md §10.3 step 8). */
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
};

/** True for a kind this implementation understands. Anything else is shown as "Update Killit". */
export function isKnownKind(kind: number): kind is Kind {
  return Object.values(Kind).includes(kind as Kind);
}

/** The requests a guardian decides on. */
export type RequestKind = typeof Kind.UNBLOCK_APP | typeof Kind.UNLOCK | typeof Kind.UNPAIR;
const REQUEST_KINDS: readonly number[] = [Kind.UNBLOCK_APP, Kind.UNLOCK, Kind.UNPAIR];

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

/** Sizes fixed by SPEC.md §11. */
export const REQUEST_ID_BYTES = 16;
export const SESSION_NONCE_BYTES = 32;
export const CERT_DIGEST_BYTES = 32;
export const ICON_SIDE = 32;
export const ICON_BYTES = ICON_SIDE * ICON_SIDE * 4;
export const MAX_GUARDIANS = 50;
export const MAX_STATUS_ENTRIES = 40;

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
  | { readonly requestKind: typeof Kind.UNPAIR; readonly targetPairId: Uint8Array };

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
  /** A code this implementation doesn't know. Its parameters are kept, unparsed (SPEC.md §11.9). */
  | { readonly code: number; readonly unknown: true; readonly params: Uint8Array };

export interface Notice {
  readonly kind: typeof Kind.NOTICE;
  readonly notice: NoticeBody;
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
  | Notice;

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
    default:
      throw new DecodeError('unknown kind');
  }
}

function readDecisionTarget(reader: ByteReader): DecisionTarget {
  const requestKind = readEnum(reader, REQUEST_KINDS, 'request kind') as RequestKind;
  switch (requestKind) {
    case Kind.UNBLOCK_APP:
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

