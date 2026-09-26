/**
 * docs/coverage.md must agree with the code it describes. The page claims which gap kinds
 * and Semgrep rules sit under each OWASP 2025 category; this reads those facts from the
 * source and fails if the page omits one, files it under the wrong row, or a row is missing.
 *
 * The gap table (META in src/server/detect/gaps.ts) is not exported, so it is read from the
 * source text; the Semgrep rules are read from the rule pack, and their 2021 tags are mapped
 * to 2025 with the same table the pipeline uses.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { RULE_IDS } from "@/server/mcp/semgrepRules";
import { mapOwasp2021 } from "@/shared/owaspMap";
import { OWASP_LABELS } from "@/shared/schema";

const doc = readFileSync("docs/coverage.md", "utf8");
const gapsSource = readFileSync("src/server/detect/gaps.ts", "utf8");
const rulesSource = readFileSync("src/server/mcp/semgrepRules.ts", "utf8");

/** The matrix row for a category, e.g. "A05:2025" -> the line starting "| **A05**". */
function row(code: string): string {
  const short = code.slice(0, 3);
  const line = doc.split("\n").find((l) => l.startsWith(`| **${short}**`));
  if (line === undefined) throw new Error(`docs/coverage.md has no row for ${code}`);
  return line;
}

/** kind -> its 2025 categories, from the META table. */
function gapCategories(): Map<string, string[]> {
  const start = gapsSource.indexOf("const META: Record<GapKind, KindMeta> = {");
  expect(start, "META table not found in gaps.ts").toBeGreaterThan(-1);
  const body = gapsSource.slice(start, gapsSource.indexOf("\n};", start));
  const map = new Map<string, string[]>();
  for (const match of body.matchAll(/^  ([a-z_]+): \{[\s\S]*?owasp: \[([^\]]*)\]/gm)) {
    map.set(match[1], [...match[2].matchAll(/"(A\d\d:2025)"/g)].map((m) => m[1]));
  }
  return map;
}

/** rule id -> its 2025 categories, from the rule's 2021 tag. */
function ruleCategories(): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const block of rulesSource.split(/\n {2}- id: /).slice(1)) {
    const id = block.split("\n")[0].trim();
    const tag = /owasp: \["([^"]+)"\]/.exec(block)?.[1] ?? "";
    const code = /^(A\d\d:20\d\d)/.exec(tag)?.[1] ?? "";
    const mapped = mapOwasp2021(code);
    map.set(id, mapped ? [mapped] : []);
  }
  return map;
}

describe("docs/coverage.md", () => {
  it("guards the guard: the sources it is checked against were really read", () => {
    expect(gapCategories().size).toBe(13);
    expect(ruleCategories().size).toBe(RULE_IDS.length);
    for (const categories of [...gapCategories().values(), ...ruleCategories().values()]) {
      expect(categories.length).toBeGreaterThan(0);
    }
  });

  it("has one row for each of the ten OWASP 2025 categories, named as the schema names them", () => {
    for (const [code, label] of Object.entries(OWASP_LABELS)) {
      expect(row(code), code).toContain(label);
    }
    expect(doc.split("\n").filter((l) => /^\| \*\*A\d\d\*\*/.test(l))).toHaveLength(10);
  });

  it("puts every gap kind in the row of each category the detector tags it with", () => {
    for (const [kind, categories] of gapCategories()) {
      for (const code of categories) {
        expect(row(code), `${kind} under ${code}`).toContain(`\`${kind}\``);
      }
    }
  });

  it("puts every Semgrep rule in the row of the 2025 category its tag maps to", () => {
    for (const [id, categories] of ruleCategories()) {
      for (const code of categories) {
        expect(row(code), `${id} under ${code}`).toContain(`\`${id}\``);
      }
    }
  });

  it("names every gap kind and every rule id somewhere, and no rule that does not exist", () => {
    for (const kind of gapCategories().keys()) expect(doc).toContain(`\`${kind}\``);
    for (const id of RULE_IDS) expect(doc).toContain(`\`${id}\``);
    const named = [...doc.matchAll(/`(attackcanvas-[a-z0-9-]+)`/g)].map((m) => m[1]);
    for (const id of named) expect(RULE_IDS as readonly string[]).toContain(id);
  });

  it("links the adversarial review, and the file it links to exists", () => {
    expect(doc).toContain("(gap-adversarial-review.md)");
    expect(() => readFileSync("docs/gap-adversarial-review.md", "utf8")).not.toThrow();
  });

  it("has the 'What the tool cannot see' section with each named limit", () => {
    expect(doc).toContain("## What the tool cannot see");
    for (const limit of [
      "Runtime configuration",
      "Infrastructure outside the repository",
      "Private dependencies",
      "Languages the detectors do not parse",
      "Secrets in git history",
      "Files the loader skipped",
    ]) {
      expect(doc, limit).toContain(limit);
    }
  });
});
