/**
 * Text and package-name rules (SPEC.md §1.3, §1.4).
 *
 * Remote text is the one part of a message a person reads, so it is the part most worth
 * constraining: no control characters that could break a layout, no invisible leading or
 * trailing space, and limits in both code points (what the UI counts) and bytes (what fits in an
 * envelope). Kotlin and TypeScript disagree on what `trim()` removes, so "trimmed" here means a
 * fixed list of code points, and receivers reject untrimmed text instead of trimming it.
 */
import { ByteReader, ByteWriter, DecodeError } from './bytes.ts';

/** A line holds no line feed; a paragraph may. */
export type TextKind = 'line' | 'paragraph';

/** The limits for one text field. Both the code-point and the byte limits must hold. */
export interface TextRule {
  readonly kind: TextKind;
  readonly minCodePoints: number;
  readonly maxCodePoints: number;
  readonly maxBytes: number;
}

/** Every text field in the protocol, with its limits from SPEC.md §11. */
export const TEXT = {
  selfName: { kind: 'line', minCodePoints: 1, maxCodePoints: 40, maxBytes: 160 },
  deviceModel: { kind: 'line', minCodePoints: 0, maxCodePoints: 64, maxBytes: 256 },
  appLabel: { kind: 'line', minCodePoints: 0, maxCodePoints: 100, maxBytes: 400 },
  requiredExplanation: { kind: 'paragraph', minCodePoints: 10, maxCodePoints: 500, maxBytes: 2000 },
  optionalExplanation: { kind: 'paragraph', minCodePoints: 0, maxCodePoints: 500, maxBytes: 2000 },
  note: { kind: 'paragraph', minCodePoints: 0, maxCodePoints: 300, maxBytes: 1200 },
  empty: { kind: 'line', minCodePoints: 0, maxCodePoints: 0, maxBytes: 0 },
} as const satisfies Record<string, TextRule>;

/**
 * The white space a text field may not start or end with: the Unicode `White_Space` characters
 * that the control-character rule doesn't already forbid.
 */
export function isEdgeWhiteSpace(codePoint: number): boolean {
  return (
    codePoint === 0x0a ||
    codePoint === 0x20 ||
    codePoint === 0xa0 ||
    codePoint === 0x1680 ||
    (codePoint >= 0x2000 && codePoint <= 0x200a) ||
    codePoint === 0x202f ||
    codePoint === 0x205f ||
    codePoint === 0x3000
  );
}

/** True for the control characters no text field may contain, line feed aside. */
function isForbiddenControl(codePoint: number): boolean {
  return (
    (codePoint <= 0x1f && codePoint !== 0x0a) ||
    (codePoint >= 0x7f && codePoint <= 0x9f) ||
    codePoint === 0x2028 ||
    codePoint === 0x2029
  );
}

// fatal: malformed UTF-8 is an error, never U+FFFD. ignoreBOM: a leading U+FEFF stays in the
// text instead of being silently dropped, so both sides validate the same code points.
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const utf8 = new TextEncoder();

/**
 * Validates UTF-8 bytes against a rule and returns the text.
 *
 * @throws DecodeError naming the first rule broken.
 */
export function checkText(bytes: Uint8Array, rule: TextRule): string {
  if (bytes.length > rule.maxBytes) throw new DecodeError('text too long');
  let text: string;
  try {
    text = strictUtf8.decode(bytes);
  } catch {
    throw new DecodeError('invalid UTF-8');
  }
  let count = 0;
  let first = -1;
  let last = -1;
  for (const char of text) {
    const codePoint = char.codePointAt(0) as number;
    if (isForbiddenControl(codePoint)) throw new DecodeError('control character in text');
    if (codePoint === 0x0a && rule.kind === 'line') throw new DecodeError('line feed in a line field');
    if (first < 0) first = codePoint;
    last = codePoint;
    count++;
  }
  if (count < rule.minCodePoints) throw new DecodeError('text too short');
  if (count > rule.maxCodePoints) throw new DecodeError('text too long');
  if (count > 0 && (isEdgeWhiteSpace(first) || isEdgeWhiteSpace(last))) throw new DecodeError('text not trimmed');
  return text;
}

/**
 * Encodes text as UTF-8 after checking it against a rule.
 *
 * A JavaScript string can hold a lone surrogate, which `TextEncoder` would silently turn into
 * U+FFFD; such strings are refused instead, so what is signed is what the sender wrote.
 *
 * @throws RangeError when the text breaks the rule. Encoders fail loudly: it is the caller's bug.
 */
export function encodeText(text: string, rule: TextRule): Uint8Array {
  if (!text.isWellFormed()) throw new RangeError('text contains a lone surrogate');
  const bytes = utf8.encode(text);
  try {
    checkText(bytes, rule);
  } catch (error) {
    throw new RangeError(`text breaks its rule: ${(error as Error).message}`);
  }
  return bytes;
}

/**
 * Removes the edge white space of SPEC.md §1.3 from both ends. Senders call this before
 * {@link encodeText}; receivers never do.
 */
export function trimText(text: string): string {
  const codePoints = Array.from(text);
  let start = 0;
  let end = codePoints.length;
  while (start < end && isEdgeWhiteSpace(codePoints[start]!.codePointAt(0)!)) start++;
  while (end > start && isEdgeWhiteSpace(codePoints[end - 1]!.codePointAt(0)!)) end--;
  return codePoints.slice(start, end).join('');
}

const PACKAGE_NAME = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$/;

/** True when `name` is a package name under SPEC.md §1.4. */
export function isPackageName(name: string): boolean {
  return name.length >= 1 && name.length <= 255 && PACKAGE_NAME.test(name);
}

/** Writes a `text16` field after checking it against its rule. */
export function writeText(writer: ByteWriter, text: string, rule: TextRule): ByteWriter {
  return writer.blob16(encodeText(text, rule));
}

/** Reads a `text16` field and checks it against its rule. */
export function readText(reader: ByteReader, rule: TextRule): string {
  return checkText(reader.blob16(rule.maxBytes), rule);
}

/** Writes a package name as `text16`. With `allowEmpty`, an empty string stands for "unknown". */
export function writePackageName(writer: ByteWriter, name: string, allowEmpty = false): ByteWriter {
  if (!(isPackageName(name) || (allowEmpty && name === ''))) throw new RangeError(`not a package name: ${name}`);
  return writer.blob16(utf8.encode(name));
}

/** Reads a package name written by {@link writePackageName}. */
export function readPackageName(reader: ByteReader, allowEmpty = false): string {
  const bytes = reader.blob16(255);
  // The pattern is ASCII-only, so decoding as Latin-1 can't hide a multi-byte sequence from it.
  const name = Buffer.from(bytes).toString('latin1');
  if (!(isPackageName(name) || (allowEmpty && name === ''))) throw new DecodeError('invalid package name');
  return name;
}
