/**
 * Periodic cleanup (PLAN.md §8.2): expired challenges and nonces, and invites an hour after they
 * finished or expired. Messages are never purged by age (SPEC.md §8): they wait for their
 * recipient.
 */
import { sql, type Kysely } from 'kysely';
import type { Database } from '../db/schema.ts';
import type { RateLimiter } from '../rateLimiter.ts';

export interface PurgeResult {
  readonly challenges: number;
  readonly nonces: number;
  readonly invites: number;
}

/** Runs one cleanup pass. */
export async function purge(db: Kysely<Database>, limiter: RateLimiter): Promise<PurgeResult> {
  const challenges = await db.deleteFrom('attestation_challenges').where('expires_at', '<', sql<Date>`now()`).executeTakeFirst();
  const nonces = await db.deleteFrom('seen_nonces').where('expires_at', '<', sql<Date>`now()`).executeTakeFirst();
  // Kept an hour after the end, so both phones can still read how it ended.
  const invites = await db
    .deleteFrom('invites')
    .where(sql<boolean>`coalesce(finished_at, expires_at) < now() - interval '1 hour'`)
    .executeTakeFirst();
  limiter.sweep();
  return {
    challenges: Number(challenges.numDeletedRows),
    nonces: Number(nonces.numDeletedRows),
    invites: Number(invites.numDeletedRows),
  };
}

/** Runs {@link purge} every `intervalMillis`; returns a function that stops it. */
export function startPurging(
  db: Kysely<Database>,
  limiter: RateLimiter,
  onError: (error: unknown) => void,
  intervalMillis = 60_000,
): () => void {
  const timer = setInterval(() => {
    purge(db, limiter).catch(onError);
  }, intervalMillis);
  timer.unref();
  return () => clearInterval(timer);
}
