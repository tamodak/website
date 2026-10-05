/**
 * The pairing ceremony as two phones run it against the server (SPEC.md §6), with the checks a
 * real phone makes on what the server relays.
 */
import { expect } from 'vitest';
import {
  commitment,
  decodeReveal,
  encodeReveal,
  fingerprint,
  matchesCommitment,
  pairId,
  randomBytes,
  safetyCode,
  toBase64Url,
  transcript,
  verifyBundle,
} from '@tamodak/protocol/e2e';
import type { PhoneClient } from './client.ts';

export interface Ceremony {
  readonly inviteId: string;
  readonly code: string;
  readonly creatorCode: string;
  readonly joinerCode: string;
  readonly pairId: Uint8Array;
}

/** Runs the whole ceremony to a link, asserting each step; returns what both phones computed. */
export async function pair(creator: PhoneClient, joiner: PhoneClient): Promise<Ceremony> {
  const created = await creator.call('POST', '/v1/invites');
  expect(created.status).toBe(201);
  const creatorNonce = randomBytes(32);
  const joinerNonce = randomBytes(32);
  const joinerReveal = encodeReveal(joiner.phone.bundle, joinerNonce);

  const joined = await joiner.call('POST', '/v1/invites/join', {
    code: created.body.code,
    commit: toBase64Url(commitment(joinerReveal)),
  });
  expect(joined.status).toBe(200);
  const id = created.body.id as string;

  // The creator learns of the commitment, keeps it, and only then reveals.
  const seen = await creator.call('GET', `/v1/invites/${id}`);
  expect(seen.body.state).toBe('joined');
  const keptCommit = new Uint8Array(Buffer.from(seen.body.commit, 'base64url'));
  const creatorReveal = encodeReveal(creator.phone.bundle, creatorNonce);
  expect((await creator.call('POST', `/v1/invites/${id}/reveal`, { reveal: toBase64Url(creatorReveal) })).status).toBe(200);

  // The joiner sees the creator's reveal, checks it, then reveals.
  const forJoiner = await joiner.call('GET', `/v1/invites/${id}`);
  const fromCreator = decodeReveal(new Uint8Array(Buffer.from(forJoiner.body.creatorReveal, 'base64url')));
  if (!fromCreator.ok) throw new Error(fromCreator.error);
  expect(verifyBundle(fromCreator.value.bundle)).toBe(true);
  expect((await joiner.call('POST', `/v1/invites/${id}/reveal`, { reveal: toBase64Url(joinerReveal) })).status).toBe(200);

  // The creator checks the joiner's reveal against the commitment it kept.
  const forCreator = await creator.call('GET', `/v1/invites/${id}`);
  const joinerRevealSeen = new Uint8Array(Buffer.from(forCreator.body.joinerReveal, 'base64url'));
  expect(matchesCommitment(joinerRevealSeen, keptCommit)).toBe(true);
  const fromJoiner = decodeReveal(joinerRevealSeen);
  if (!fromJoiner.ok) throw new Error(fromJoiner.error);
  expect(verifyBundle(fromJoiner.value.bundle)).toBe(true);

  // Each phone computes the transcript from what it holds.
  const ownCreator = decodeReveal(creatorReveal);
  const ownJoiner = decodeReveal(joinerReveal);
  if (!ownCreator.ok || !ownJoiner.ok) throw new Error('own reveals must decode');
  const creatorTranscript = transcript(ownCreator.value, fromJoiner.value);
  const joinerTranscript = transcript(fromCreator.value, ownJoiner.value);

  const creatorConfirm = await creator.call('POST', '/v1/links', { invite: id });
  expect(creatorConfirm.body).toEqual({ state: 'waiting', peer: toBase64Url(fingerprint(fromJoiner.value.bundle.signPk)) });
  const joinerConfirm = await joiner.call('POST', '/v1/links', { invite: id });
  expect(joinerConfirm.body).toEqual({ state: 'linked', peer: toBase64Url(fingerprint(fromCreator.value.bundle.signPk)) });

  return {
    inviteId: id,
    code: created.body.code,
    creatorCode: safetyCode(creatorTranscript),
    joinerCode: safetyCode(joinerTranscript),
    pairId: pairId(creatorTranscript),
  };
}
