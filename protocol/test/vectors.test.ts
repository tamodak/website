/**
 * Checks the committed vectors against the implementation, so neither can change without the
 * other. Killit's Kotlin tests run the same checks against its own implementation (SPEC.md §14).
 */
import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { describe, expect, it } from 'vitest';
import * as P from '../src/e2e.ts';

type Json = Record<string, any>;
const load = (name: string): Json => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), 'utf8'));
const hex = P.toHex;
const bytes = P.fromHex;

/** Byte strings as hex, recursively, to compare decoded values with the files. */
function toJson(value: unknown): unknown {
  if (value instanceof Uint8Array) return hex(value);
  if (Array.isArray(value)) return value.map(toJson);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, toJson(inner)]));
  }
  return value;
}

const identities = load('identities.json');
const phones = new Map<string, P.TestPhone>(
  identities.phones.map((p: Json) => [p.name, P.phoneFromKeys(p.name, bytes(p.signPrivate), bytes(p.encPrivate), bytes(p.encSig))]),
);
const phone = (name: string): P.TestPhone => {
  const found = phones.get(name);
  if (found === undefined) throw new Error(`no test phone ${name}`);
  return found;
};

describe('identities.json', () => {
  it.each(identities.phones as Json[])('phone $name derives every public value', (p) => {
    const derived = phone(p.name);
    expect(hex(derived.signPk)).toBe(p.signPk);
    expect(hex(derived.fp)).toBe(p.fp);
    expect(P.toBase64Url(derived.fp)).toBe(p.deviceId);
    expect(hex(derived.encPk)).toBe(p.encPk);
    expect(hex(P.encKeyBindingBytes(derived.encPk))).toBe(p.encKeySignedBytes);
    expect(hex(derived.bundleBytes)).toBe(p.bundle);
    const decoded = P.decodeBundle(bytes(p.bundle));
    expect(decoded.ok && P.verifyBundle(decoded.value)).toBe(true);
  });
});

describe('encoding.json', () => {
  const encoding = load('encoding.json');

  it.each(encoding.text as Json[])('text: $why', (c) => {
    const rule = encoding.rules[c.rule] as P.TextRule;
    let accepted = true;
    try {
      P.checkText(bytes(c.utf8), rule);
    } catch {
      accepted = false;
    }
    expect(accepted).toBe(c.valid);
  });

  it('lists the same rules as the implementation', () => {
    expect(encoding.rules).toEqual(P.TEXT);
  });

  it.each(encoding.packageNames as Json[])('package name "$name"', (c) => {
    expect(P.isPackageName(c.name)).toBe(c.valid);
  });

  it.each(encoding.base64url as Json[])('base64url "$text"', (c) => {
    if (c.valid) {
      expect(hex(P.fromBase64Url(c.text))).toBe(c.bytes);
      expect(P.toBase64Url(bytes(c.bytes))).toBe(c.text);
    } else {
      expect(() => P.fromBase64Url(c.text)).toThrow(P.DecodeError);
    }
  });
});

describe('api-auth.json', () => {
  it.each(load('api-auth.json').cases as Json[])('$name', (c) => {
    const request: P.ApiRequest = {
      audience: c.audience,
      method: c.method,
      target: c.target,
      timestamp: c.timestamp,
      nonce: bytes(c.nonce),
      body: bytes(c.body),
    };
    expect(hex(P.sha256(request.body))).toBe(c.bodySha256);
    expect(hex(P.apiSignedBytes(request))).toBe(c.signedBytes);
    expect(P.verifyRequest(phone(c.verifier).signPk, request, bytes(c.signature))).toBe(c.valid);
    if (c.valid) {
      const parsed = P.parseAuthHeaders(c.headers);
      expect(parsed.ok).toBe(true);
      if (parsed.ok) {
        expect(hex(parsed.value.fp)).toBe(hex(phone(c.signer).fp));
        expect(parsed.value.timestamp).toBe(c.timestamp);
        expect(hex(parsed.value.signature)).toBe(c.signature);
      }
    }
  });
});

describe('invite-code.json', () => {
  const codes = load('invite-code.json');

  it('uses the Crockford alphabet', () => {
    expect(codes.alphabet).toBe(P.CROCKFORD_ALPHABET);
  });

  it.each(codes.format as Json[])('formats $bytes as $code', (c) => {
    expect(P.formatInviteCode(bytes(c.bytes))).toBe(c.code);
  });

  it.each(codes.parse as Json[])('parses "$input"', (c) => {
    const parsed = P.parseInviteCode(c.input);
    expect(parsed.ok).toBe(c.valid);
    if (parsed.ok) expect(hex(parsed.value)).toBe(c.bytes);
  });
});

describe('ceremony.json', () => {
  const ceremony = load('ceremony.json');

  it.each(ceremony.ceremonies as Json[])('$creator creates, $joiner joins', (c) => {
    const creator = phone(c.creator);
    const joiner = phone(c.joiner);
    expect(hex(P.encodeReveal(creator.bundle, bytes(c.creatorNonce)))).toBe(c.creatorReveal);
    expect(hex(P.encodeReveal(joiner.bundle, bytes(c.joinerNonce)))).toBe(c.joinerReveal);
    expect(hex(P.commitment(bytes(c.joinerReveal)))).toBe(c.commit);
    expect(P.matchesCommitment(bytes(c.joinerReveal), bytes(c.commit))).toBe(true);
    const a = P.decodeReveal(bytes(c.creatorReveal));
    const b = P.decodeReveal(bytes(c.joinerReveal));
    if (!a.ok || !b.ok) throw new Error('reveals must decode');
    const transcript = P.transcript(a.value, b.value);
    expect(hex(transcript)).toBe(c.transcript);
    expect(P.safetyCode(transcript)).toBe(c.safetyCode);
    expect(P.formatSafetyCode(c.safetyCode)).toBe(c.safetyCodeDisplay);
    expect(hex(P.pairId(transcript))).toBe(c.pairId);
  });

  it.each(ceremony.rejections as Json[])('rejects: $name', (r) => {
    switch (r.check) {
      case 'commitment':
        expect(P.matchesCommitment(bytes(r.joinerReveal), bytes(ceremony.ceremonies[r.ceremony].commit))).toBe(false);
        break;
      case 'decode':
        expect(P.decodeReveal(bytes(r.reveal)).ok).toBe(false);
        break;
      case 'encSig': {
        const decoded = P.decodeReveal(bytes(r.reveal));
        expect(decoded.ok && P.verifyBundle(decoded.value.bundle)).toBe(false);
        break;
      }
      default:
        throw new Error(`unknown check ${r.check}`);
    }
  });
});

describe('hpke.json', () => {
  const hpke = load('hpke.json');

  it('reproduces RFC 9180 A.1.1, sequence 0', () => {
    const rfc = hpke.rfc9180;
    const ephemeral = P.deriveKeyPair(bytes(rfc.ikmE));
    const recipient = P.deriveKeyPair(bytes(rfc.ikmR));
    expect(hex(ephemeral.publicKey)).toBe(rfc.pkEm);
    expect(hex(recipient.publicKey)).toBe(rfc.pkRm);
    const sealed = P.hpkeSeal(bytes(rfc.pkRm), bytes(rfc.info), bytes(rfc.aad), bytes(rfc.plaintext), ephemeral);
    expect(hex(sealed)).toBe(rfc.sealed);
    expect(hex(sealed)).toBe(rfc.pkEm + rfc.ciphertext);
    expect(hex(P.hpkeOpen(recipient.privateKey, bytes(rfc.info), bytes(rfc.aad), sealed))).toBe(rfc.plaintext);
  });

  it.each(hpke.killit as Json[])('$name', (c) => {
    const recipient = phone(c.recipient);
    const sealed = P.hpkeSeal(recipient.encPk, bytes(c.info), bytes(c.aad), bytes(c.plaintext), P.deriveKeyPair(bytes(c.ikmE)));
    expect(hex(sealed)).toBe(c.sealed);
    expect(hex(P.hpkeOpen(recipient.encKey, bytes(c.info), bytes(c.aad), bytes(c.sealed)))).toBe(c.plaintext);
  });
});

describe('messages.json', () => {
  const messages = load('messages.json');
  const pairIds = new Map<string, string>(messages.pairings.map((p: Json) => [p.name, p.pairId]));

  it.each(messages.messages as Json[])('$name', (m) => {
    const from = phone(m.from);
    const to = phone(m.to);
    const header: P.MessageHeader = {
      version: P.MESSAGE_VERSION,
      kind: m.kind,
      messageId: bytes(m.messageId),
      pairId: bytes(m.pairId),
      senderFp: from.fp,
      recipientFp: to.fp,
      createdAt: m.createdAt,
    };
    expect([...pairIds.values()]).toContain(m.pairId);
    expect(hex(P.encodeInner(header, bytes(m.body)))).toBe(m.inner);
    expect(hex(P.messageSignedBytes(bytes(m.inner)))).toBe(m.signedBytes);
    expect(P.verifyInner(from.signPk, bytes(m.inner), bytes(m.signature))).toBe(true);

    const opened = P.openEnvelope(bytes(m.envelope), to.encKey, to.fp, from.fp);
    if (!opened.ok) throw new Error(opened.error);
    expect(hex(opened.value.inner)).toBe(m.inner);
    expect(hex(opened.value.signature)).toBe(m.signature);
    const plaintext = P.padPlaintext(bytes(m.inner), bytes(m.signature));
    const resealed = P.hpkeSeal(to.encPk, P.envelopeInfo(from.fp, to.fp), new Uint8Array(0), plaintext, P.deriveKeyPair(bytes(m.ikmE)));
    expect(hex(resealed)).toBe(m.envelope);

    expect(P.isKnownKind(m.kind)).toBe(m.known);
    if (m.known) {
      const decoded = P.decodeBody(m.kind, bytes(m.body));
      if (!decoded.ok) throw new Error(decoded.error);
      expect(isDeepStrictEqual(toJson(decoded.value), m.fields)).toBe(true);
      // Unknown notices can be received but never sent, so only known ones round-trip.
      if (!(m.kind === P.Kind.NOTICE && 'unknown' in (decoded.value as P.Notice).notice)) {
        expect(hex(P.encodeBody(decoded.value))).toBe(m.body);
      }
    }
  });

  it.each(messages.rejectedEnvelopes as Json[])('refuses envelope: $name', (r) => {
    const recipient = phone(r.recipient);
    const from = phone(r.from);
    const opened = P.openEnvelope(bytes(r.envelope), recipient.encKey, recipient.fp, from.fp);
    if (r.stage === 'open') {
      expect(opened.ok).toBe(false);
    } else {
      if (!opened.ok) throw new Error(`should open: ${opened.error}`);
      expect(P.verifyInner(from.signPk, opened.value.inner, opened.value.signature)).toBe(false);
    }
  });

  it.each(messages.rejectedBodies as Json[])('refuses body: $name', (r) => {
    expect(P.decodeBody(r.kind, bytes(r.body)).ok).toBe(false);
  });

  it.each(messages.decisionChecks as Json[])('decision: $name', (check) => {
    const message = (messages.messages as Json[]).find((m) => m.name === check.message);
    if (message === undefined) throw new Error(`no message ${check.message}`);
    const protectedPhone = phone(message.to);
    const opened = P.openEnvelope(bytes(message.envelope), protectedPhone.encKey, protectedPhone.fp, phone(message.from).fp);
    if (!opened.ok) throw new Error(opened.error);
    const s = check.storedRequest;
    const target = s.target;
    const stored: P.StoredRequest = {
      requestId: bytes(s.requestId),
      target:
        target.requestKind === P.Kind.UNBLOCK_APP
          ? { requestKind: P.Kind.UNBLOCK_APP, app: { packageName: target.app.packageName, certDigest: bytes(target.app.certDigest) } }
          : target.requestKind === P.Kind.UNLOCK
            ? { requestKind: P.Kind.UNLOCK, sessionNonce: bytes(target.sessionNonce) }
            : { requestKind: P.Kind.UNPAIR, targetPairId: bytes(target.targetPairId) },
      pairId: bytes(s.pairId),
      guardianFp: bytes(s.guardianFp),
      guardianSignPk: phone(s.guardian).signPk,
      ownFp: bytes(s.ownFp),
    };
    expect(P.verifyDecision(stored, opened.value).ok).toBe(check.valid);
  });
});
