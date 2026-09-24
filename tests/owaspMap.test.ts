import { describe, expect, it } from "vitest";
import {
  OWASP_2021_TO_2025,
  isOwasp2021,
  mapOwasp2021,
  owaspCodesIn,
} from "@/shared/owaspMap";
import { OWASP_LABELS, Owasp2025Schema } from "@/shared/schema";

describe("OWASP_2021_TO_2025", () => {
  it.each([
    ["A01:2021", "A01:2025"],
    ["A02:2021", "A04:2025"],
    ["A03:2021", "A05:2025"],
    ["A04:2021", "A06:2025"],
    ["A05:2021", "A02:2025"],
    ["A06:2021", "A03:2025"],
    ["A07:2021", "A07:2025"],
    ["A08:2021", "A08:2025"],
    ["A09:2021", "A09:2025"],
    ["A10:2021", "A01:2025"],
  ])("maps %s to %s, as specified", (from, to) => {
    expect(OWASP_2021_TO_2025[from as keyof typeof OWASP_2021_TO_2025]).toBe(
      to,
    );
  });

  it("covers all ten 2021 categories and nothing else", () => {
    expect(Object.keys(OWASP_2021_TO_2025)).toEqual(
      Array.from(
        { length: 10 },
        (_, i) => `A${String(i + 1).padStart(2, "0")}:2021`,
      ),
    );
  });

  it("only ever maps to a real 2025 category", () => {
    for (const target of Object.values(OWASP_2021_TO_2025)) {
      expect(Owasp2025Schema.safeParse(target).success).toBe(true);
    }
  });

  it("is many-to-one onto A01:2025, which absorbs SSRF", () => {
    const toA01 = Object.entries(OWASP_2021_TO_2025)
      .filter(([, to]) => to === "A01:2025")
      .map(([from]) => from);

    expect(toA01).toEqual(["A01:2021", "A10:2021"]);
  });

  it("maps nothing onto A10:2025, which has no 2021 counterpart", () => {
    expect(Object.values(OWASP_2021_TO_2025)).not.toContain("A10:2025");
  });

  it("agrees with the official 2025 names for the categories it renames", () => {
    // A guard against a transposed row: the 2021 name should describe the 2025 target.
    expect(OWASP_LABELS[OWASP_2021_TO_2025["A03:2021"]]).toBe("Injection");
    expect(OWASP_LABELS[OWASP_2021_TO_2025["A02:2021"]]).toBe(
      "Cryptographic Failures",
    );
    expect(OWASP_LABELS[OWASP_2021_TO_2025["A05:2021"]]).toBe(
      "Security Misconfiguration",
    );
    expect(OWASP_LABELS[OWASP_2021_TO_2025["A06:2021"]]).toBe(
      "Software Supply Chain Failures",
    );
    expect(OWASP_LABELS[OWASP_2021_TO_2025["A04:2021"]]).toBe(
      "Insecure Design",
    );
  });
});

describe("mapOwasp2021 and isOwasp2021", () => {
  it("maps a code, ignoring case and whitespace", () => {
    expect(mapOwasp2021("A03:2021")).toBe("A05:2025");
    expect(mapOwasp2021("  a03:2021 ")).toBe("A05:2025");
  });

  it.each([
    "A03:2025",
    "A11:2021",
    "A00:2021",
    "A03",
    "Injection",
    "",
    "constructor",
  ])("returns undefined for %s", (input) => {
    expect(mapOwasp2021(input)).toBeUndefined();
  });

  it("does not treat an object prototype key as a code", () => {
    expect(isOwasp2021("toString")).toBe(false);
    expect(isOwasp2021("__proto__")).toBe(false);
    expect(isOwasp2021("A03:2021")).toBe(true);
  });
});

describe("owaspCodesIn", () => {
  it("reads the tag format Semgrep writes", () => {
    expect(owaspCodesIn(["A03:2021 - Injection"])).toEqual({
      y2021: ["A03:2021"],
      y2025: ["A05:2025"],
    });
  });

  it("reads the longer SSRF tag, and maps it onto A01:2025", () => {
    expect(
      owaspCodesIn(["A10:2021 - Server-Side Request Forgery (SSRF)"]),
    ).toEqual({
      y2021: ["A10:2021"],
      y2025: ["A01:2025"],
    });
  });

  it("finds a code anywhere in a tag", () => {
    expect(owaspCodesIn(["OWASP-A07:2021"]).y2025).toEqual(["A07:2025"]);
    expect(
      owaspCodesIn([
        "owasp a07:2021 - Identification and Authentication Failures",
      ]).y2025,
    ).toEqual(["A07:2025"]);
  });

  it("passes a tag already in 2025 terms through unchanged", () => {
    expect(owaspCodesIn(["A05:2025 - Injection"])).toEqual({
      y2021: [],
      y2025: ["A05:2025"],
    });
  });

  it("does not remap a 2025 code as if it were a 2021 one", () => {
    // A03:2025 is Supply Chain Failures; A03:2021 is Injection. Same digits, different
    // categories, which is exactly why the year is required.
    expect(owaspCodesIn(["A03:2025"]).y2025).toEqual(["A03:2025"]);
    expect(owaspCodesIn(["A03:2021"]).y2025).toEqual(["A05:2025"]);
  });

  it("collects several codes from several tags", () => {
    const { y2021, y2025 } = owaspCodesIn([
      "A07:2021 - Identification and Authentication Failures",
      "A02:2021 - Cryptographic Failures",
    ]);

    expect(y2021).toEqual(["A07:2021", "A02:2021"]); // in the order they appeared
    expect(y2025).toEqual(["A04:2025", "A07:2025"]); // sorted
  });

  it("finds two codes in one tag", () => {
    expect(owaspCodesIn(["A01:2021 and A03:2021"]).y2025).toEqual([
      "A01:2025",
      "A05:2025",
    ]);
  });

  it("de-duplicates, including two 2021 codes that land on the same 2025 one", () => {
    const { y2021, y2025 } = owaspCodesIn(["A01:2021", "A10:2021", "A01:2021"]);

    expect(y2021).toEqual(["A01:2021", "A10:2021"]);
    expect(y2025).toEqual(["A01:2025"]);
  });

  it("gives the same answer whatever order the tags arrive in", () => {
    const tags = ["A09:2021", "A02:2021", "A07:2021"];
    expect(owaspCodesIn(tags).y2025).toEqual(
      owaspCodesIn([...tags].reverse()).y2025,
    );
  });

  it("ignores a bare code with no year, which is ambiguous between editions", () => {
    expect(owaspCodesIn(["A03 - Injection", "OWASP A03"])).toEqual({
      y2021: [],
      y2025: [],
    });
  });

  it.each([
    ["an empty list", []],
    ["a tag with no code", ["Injection"]],
    ["an out-of-range code", ["A11:2021", "A00:2021"]],
    ["an older edition", ["A03:2017", "A1:2017"]],
    ["a code glued to other text", ["XA03:2021"]],
  ])("returns nothing for %s", (_label, tags) => {
    expect(owaspCodesIn(tags)).toEqual({ y2021: [], y2025: [] });
  });

  it("is safe to call repeatedly: the pattern keeps no state between calls", () => {
    const tags = ["A03:2021", "A01:2021"];
    expect(owaspCodesIn(tags)).toEqual(owaspCodesIn(tags));
  });
});
