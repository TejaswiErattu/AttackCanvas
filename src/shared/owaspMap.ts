import type { Owasp2025 } from "@/shared/schema";

/**
 * Maps OWASP Top 10:2021 tags, which is what most scanner rule packs still carry, onto
 * the 2025 categories AttackCanvas reports in.
 *
 * This is a data table, not a schema change: src/shared/schema is frozen (CLAUDE.md
 * rule 1) and already defines the 2025 codes. The 2021 side is a plain string key so a
 * scanner tag never has to be trusted to be well formed.
 *
 * Two 2021 categories land on A01:2025: A01 itself (Broken Access Control) and A10
 * (SSRF), which the 2025 list folds into it. The mapping is therefore many-to-one, and
 * nothing maps *to* A10:2025 (Mishandling of Exceptional Conditions), which is new.
 */
export const OWASP_2021_TO_2025 = {
  "A01:2021": "A01:2025",
  "A02:2021": "A04:2025",
  "A03:2021": "A05:2025",
  "A04:2021": "A06:2025",
  "A05:2021": "A02:2025",
  "A06:2021": "A03:2025",
  "A07:2021": "A07:2025",
  "A08:2021": "A08:2025",
  "A09:2021": "A09:2025",
  "A10:2021": "A01:2025",
} as const satisfies Record<string, Owasp2025>;

export type Owasp2021 = keyof typeof OWASP_2021_TO_2025;

/** A code in either year, anywhere in a tag: "A03:2021 - Injection" or "OWASP-A05:2025". */
const CODE = /\bA(0[1-9]|10):(2021|2025)\b/gi;

export function isOwasp2021(code: string): code is Owasp2021 {
  return Object.prototype.hasOwnProperty.call(OWASP_2021_TO_2025, code);
}

/** The 2025 category for a 2021 code, or undefined for anything else. */
export function mapOwasp2021(code: string): Owasp2025 | undefined {
  const normalized = code.trim().toUpperCase();
  return isOwasp2021(normalized) ? OWASP_2021_TO_2025[normalized] : undefined;
}

export type OwaspCodes = {
  /** 2021 codes found in the tags, in the order they first appeared. */
  y2021: Owasp2021[];
  /**
   * 2025 codes: every 2021 code mapped, plus any tag already written in 2025 terms.
   * De-duplicated and sorted, so the result does not depend on tag order.
   */
  y2025: Owasp2025[];
};

/**
 * Reads OWASP codes out of free-form scanner tags. Semgrep writes them as
 * "A03:2021 - Injection"; the year is required, because a bare "A03" is ambiguous
 * between editions and guessing would put a finding under the wrong category.
 */
export function owaspCodesIn(tags: readonly string[]): OwaspCodes {
  const y2021: Owasp2021[] = [];
  const y2025 = new Set<Owasp2025>();

  for (const tag of tags) {
    const pattern = new RegExp(CODE.source, CODE.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(tag)) !== null) {
      const code = `A${match[1]}:${match[2]}`;

      if (match[2] === "2025") {
        y2025.add(code as Owasp2025);
      } else if (isOwasp2021(code)) {
        if (!y2021.includes(code)) y2021.push(code);
        y2025.add(OWASP_2021_TO_2025[code]);
      }
    }
  }

  return { y2021, y2025: [...y2025].sort() };
}
