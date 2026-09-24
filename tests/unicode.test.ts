import { describe, expect, it } from "vitest";
import {
  REPLACEMENT_CHARACTER,
  isWellFormedText,
  loneSurrogateOffsets,
  sliceWithoutSplitting,
  toWellFormedText,
} from "@/server/security/unicode";

const EMOJI = "\u{1F600}"; // two UTF-16 code units
const HIGH = EMOJI.charAt(0);
const LOW = EMOJI.charAt(1);

describe("loneSurrogateOffsets / isWellFormedText", () => {
  it("finds lone high and low surrogates, and ignores proper pairs", () => {
    expect(loneSurrogateOffsets(`a${EMOJI}b`)).toEqual([]);
    expect(loneSurrogateOffsets(`a${HIGH}b${LOW}c`)).toEqual([1, 3]);
    expect(loneSurrogateOffsets(`${LOW}${HIGH}`)).toEqual([0, 1]); // reversed halves are not a pair
    expect(loneSurrogateOffsets(`${EMOJI}${HIGH}`)).toEqual([2]);
    expect(isWellFormedText(`ok ${EMOJI}`)).toBe(true);
    expect(isWellFormedText(`bad ${HIGH}`)).toBe(false);
  });

  it("agrees with the runtime's own isWellFormed where it exists", () => {
    const native = (String.prototype as { isWellFormed?: () => boolean }).isWellFormed;
    if (!native) return;
    for (const s of ["", "abc", EMOJI, HIGH, LOW, `${LOW}${HIGH}`, `x${EMOJI}${HIGH}y`]) {
      expect(isWellFormedText(s)).toBe(native.call(s));
    }
  });
});

describe("toWellFormedText", () => {
  it("replaces each lone surrogate with U+FFFD and nothing else", () => {
    expect(toWellFormedText(`a${HIGH}b${EMOJI}c${LOW}`)).toBe(
      `a${REPLACEMENT_CHARACTER}b${EMOJI}c${REPLACEMENT_CHARACTER}`,
    );
  });

  it("returns well-formed text unchanged (same string)", () => {
    const s = `plain ${EMOJI} text`;
    expect(toWellFormedText(s)).toBe(s);
  });
});

describe("sliceWithoutSplitting", () => {
  it("is exactly text.slice(0, max) for ASCII", () => {
    const s = "abcdefghij";
    for (let max = 0; max <= 12; max++) expect(sliceWithoutSplitting(s, max)).toBe(s.slice(0, max));
  });

  it("cutting immediately before an emoji keeps everything before it", () => {
    expect(sliceWithoutSplitting(`abc${EMOJI}def`, 3)).toBe("abc");
  });

  it("cutting inside an emoji drops the whole emoji instead of leaving half", () => {
    const out = sliceWithoutSplitting(`abc${EMOJI}def`, 4);
    expect(out).toBe("abc");
    expect(isWellFormedText(out)).toBe(true);
  });

  it("cutting just after an emoji keeps it whole", () => {
    expect(sliceWithoutSplitting(`abc${EMOJI}def`, 5)).toBe(`abc${EMOJI}`);
  });

  it("never leaves a lone surrogate for any cut through emoji-heavy text", () => {
    const s = `${EMOJI}a${EMOJI}${EMOJI}b`;
    for (let max = 0; max <= s.length + 1; max++) {
      expect(isWellFormedText(sliceWithoutSplitting(s, max))).toBe(true);
    }
  });
});
