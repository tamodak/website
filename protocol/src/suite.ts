/**
 * The HPKE suite identifiers (SPEC.md §2.1).
 *
 * They live apart from the HPKE implementation because the encryption-key binding (SPEC.md §3.2)
 * signs them, and the server's entry point must be able to read bundles without carrying any
 * decryption code (PLAN.md §8).
 */

/** DHKEM(X25519, HKDF-SHA256). */
export const HPKE_KEM_ID = 0x0020;
/** HKDF-SHA256. */
export const HPKE_KDF_ID = 0x0001;
/** AES-128-GCM. */
export const HPKE_AEAD_ID = 0x0001;
