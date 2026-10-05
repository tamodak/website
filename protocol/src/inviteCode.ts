/**
 * Invite codes (SPEC.md §6.1): 40 random bits written as 8 Crockford base32 symbols.
 *
 * Crockford's alphabet leaves out I, L, O and U, and parsing maps the look-alikes back, so a code
 * read aloud or copied by hand survives the usual mistakes. 40 bits against a 15-minute lifetime
 * and per-device rate limits is far out of a guesser's reach, and the safety code stops anyone
 * who gets in anyway.
 */
import { DecodeError, decodeWith, type Result } from './bytes.ts';

/** The symbols in value order. */
export const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/** A code is 5 random bytes. */
export const INVITE_CODE_BYTES = 5;
/** Anything longer than this can't be a code, even with separators, and is refused unread. */
const MAX_INPUT_LENGTH = 32;

/** Formats 5 bytes as `XXXX-XXXX`, most significant bits first. */
export function formatInviteCode(bytes: Uint8Array): string {
  if (bytes.length !== INVITE_CODE_BYTES) throw new RangeError('an invite code is 5 bytes');
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let symbols = '';
  for (let shift = 35n; shift >= 0n; shift -= 5n) symbols += CROCKFORD_ALPHABET[Number((value >> shift) & 31n)];
  return `${symbols.slice(0, 4)}-${symbols.slice(4)}`;
}

/**
 * Parses what a person typed: hyphens and spaces are dropped, case is ignored, and `I`/`L` read
 * as `1` and `O` as `0`. The result must be exactly 8 symbols.
 *
 * Only ASCII is accepted. Unicode case mapping differs between platforms (`ß` uppercases to `SS`
 * in JavaScript), so the phone maps its keyboard's input to ASCII before sending, and the phone
 * and the server then agree on every string.
 */
export function parseInviteCode(input: string): Result<Uint8Array> {
  return decodeWith(() => {
    if (input.length > MAX_INPUT_LENGTH) throw new DecodeError('invite code too long');
    if (!/^[\x20-\x7e]*$/.test(input)) throw new DecodeError('invite code is not ASCII');
    const symbols = input
      .replace(/[- ]/g, '')
      .replace(/[a-z]/g, (letter) => letter.toUpperCase())
      .replace(/[IL]/g, '1')
      .replace(/O/g, '0');
    if (symbols.length !== 8) throw new DecodeError('an invite code has 8 symbols');
    let value = 0n;
    for (const symbol of symbols) {
      const digit = CROCKFORD_ALPHABET.indexOf(symbol);
      if (digit < 0) throw new DecodeError('invalid invite code symbol');
      value = (value << 5n) | BigInt(digit);
    }
    const bytes = new Uint8Array(INVITE_CODE_BYTES);
    for (let i = INVITE_CODE_BYTES - 1; i >= 0; i--) {
      bytes[i] = Number(value & 0xffn);
      value >>= 8n;
    }
    return bytes;
  });
}
