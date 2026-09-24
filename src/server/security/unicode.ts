/**
 * Well-formed UTF-16 for everything sent to the model provider. A lone surrogate (half of
 * an emoji, left behind by a cut at an arbitrary code-unit index) cannot be encoded as
 * UTF-8, and a request carrying one is rejected with 400 invalid_request_error.
 *
 * Implemented here rather than with String.prototype.toWellFormed/isWellFormed: the
 * project compiles to ES2017 with no polyfill and pins no Node version, so the built-ins
 * are not guaranteed at runtime. Pure, dependency-free and unit tested.
 */

/** U+FFFD REPLACEMENT CHARACTER, what toWellFormed() substitutes for a lone surrogate. */
export const REPLACEMENT_CHARACTER = "�";

const isHigh = (code: number): boolean => code >= 0xd800 && code <= 0xdbff;
const isLow = (code: number): boolean => code >= 0xdc00 && code <= 0xdfff;

/** UTF-16 offsets of every unpaired surrogate in `text`. */
export function loneSurrogateOffsets(text: string): number[] {
  const offsets: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (isHigh(code) && isLow(text.charCodeAt(i + 1))) {
      i++;
    } else if (isHigh(code) || isLow(code)) {
      offsets.push(i);
    }
  }
  return offsets;
}

/** True when `text` holds no unpaired surrogate. */
export function isWellFormedText(text: string): boolean {
  return loneSurrogateOffsets(text).length === 0;
}

/** `text` with every unpaired surrogate replaced by U+FFFD; unchanged when already well formed. */
export function toWellFormedText(text: string): string {
  const offsets = loneSurrogateOffsets(text);
  if (offsets.length === 0) return text;
  const chars = text.split("");
  for (const offset of offsets) chars[offset] = REPLACEMENT_CHARACTER;
  return chars.join("");
}

/**
 * The first `max` UTF-16 code units of `text`, one fewer when the cut would fall between
 * the two halves of a surrogate pair. Identical to text.slice(0, max) otherwise, so ASCII
 * and BMP-only text is cut exactly as before.
 */
export function sliceWithoutSplitting(text: string, max: number): string {
  if (max <= 0) return "";
  if (text.length <= max) return text;
  const end = isHigh(text.charCodeAt(max - 1)) && isLow(text.charCodeAt(max)) ? max - 1 : max;
  return text.slice(0, end);
}
