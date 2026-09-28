import { describe, expect, it } from "vitest";
import { GAP_ASSERT_CERTAINTY } from "@/server/analysis/architecture";
import {
  ASSERTED_CERTAINTY,
  NOTES_MARKER,
  benchRow,
  checkMarkers,
  mergeReport,
  parseExpected,
  perOwasp,
  renderReport,
  scoreRepo,
  toFindings,
  totalCounts,
  withoutExpected,
  type BenchResult,
  type ExpectedRepo,
  type Finding,
} from "../scripts/eval/benchLib";

const EXPECTED: ExpectedRepo = {
  repo: "demo",
  issues: [
    { id: "i-authz", class: "IDOR", owasp: "A01:2025", file: "src/a.js", line: 3, gapKind: "authz_missing" },
    {
      id: "i-cmd",
      class: "command injection",
      owasp: "A05:2025",
      file: "src/b.js",
      line: 5,
      gapKind: "input_validation_missing",
      ruleId: "attackcanvas-command-injection",
    },
    { id: "i-jwt", class: "jwt none", owasp: "A04:2025", file: "src/t.js", line: 2, ruleId: "attackcanvas-jwt-verify-none" },
  ],
  controls: [
    { id: "c-owner", gapKind: "authz_missing", file: "src/c.js", how: "guard", type: "cross-package guard" },
    { id: "c-headers", gapKind: "security_headers_missing", file: "src/app.js", how: "helmet", type: "app-level middleware" },
  ],
};

const gap = (kind: string, file: string, line: number, extra: Partial<Finding> = {}): Finding => ({
  source: "gap",
  kind,
  file,
  line,
  scope: "route",
  certainty: 0.7,
  ...extra,
});
const semgrep = (kind: string, file: string, line: number): Finding => ({ source: "semgrep", kind, file, line });

describe("scoreRepo: matching", () => {
  it("matches by file and by either the gap kind or the rule id, ignoring the line", () => {
    const score = scoreRepo(
      EXPECTED,
      [gap("authz_missing", "src/a.js", 99), semgrep("attackcanvas-command-injection", "src/b.js", 6)],
      { semgrep: true },
    );
    expect(score.issues.map((i) => [i.id, i.status])).toEqual([
      ["i-authz", "TP"],
      ["i-cmd", "TP"],
      ["i-jwt", "FN"],
    ]);
    expect(score.counts).toMatchObject({ tp: 2, fp: 0, fn: 1, skipped: 0 });
  });

  it("does not match the right kind in the wrong file", () => {
    const score = scoreRepo(EXPECTED, [gap("authz_missing", "src/other.js", 3)], { semgrep: false });
    expect(score.issues[0].status).toBe("FN");
    expect(score.counts.fp).toBe(1);
  });

  it("counts a second finding for an already matched issue as a duplicate, not a false positive", () => {
    const score = scoreRepo(
      EXPECTED,
      [gap("input_validation_missing", "src/b.js", 4), semgrep("attackcanvas-command-injection", "src/b.js", 5)],
      { semgrep: true },
    );
    expect(score.counts).toMatchObject({ tp: 1, fp: 0, duplicates: 1 });
    expect(score.issues[1].matchedBy).toEqual(["gap:input_validation_missing@4", "semgrep:attackcanvas-command-injection@5"]);
  });

  it("skips an issue labelled only by a rule id when Semgrep did not run, and leaves it out of recall", () => {
    const score = scoreRepo(EXPECTED, [gap("authz_missing", "src/a.js", 3)], { semgrep: false });
    expect(score.issues.find((i) => i.id === "i-jwt")?.status).toBe("skipped");
    // i-cmd still has its gap kind, so it is scored (and missed) without Semgrep.
    expect(score.counts).toMatchObject({ tp: 1, fn: 1, skipped: 1 });
    expect(score.counts.recall).toBe(0.5);
  });

  it("does not let a Semgrep rule id match when Semgrep is off, even if a finding carries it", () => {
    const score = scoreRepo(EXPECTED, [semgrep("attackcanvas-command-injection", "src/b.js", 5)], { semgrep: false });
    expect(score.issues[1].status).toBe("FN");
    expect(score.counts.fp).toBe(1);
  });
});

describe("scoreRepo: metrics", () => {
  it("computes precision TP/(TP+FP) and recall TP/(TP+FN)", () => {
    const score = scoreRepo(
      EXPECTED,
      [
        gap("authz_missing", "src/a.js", 3),
        gap("transport_insecure", "src/x.js", 1, { scope: "file" }),
        gap("cors_permissive", "src/y.js", 1, { scope: "file" }),
      ],
      { semgrep: true },
    );
    expect(score.counts).toMatchObject({ tp: 1, fp: 2, fn: 2 });
    expect(score.counts.precision).toBeCloseTo(1 / 3);
    expect(score.counts.recall).toBeCloseTo(1 / 3);
  });

  it("reports null rates when there is nothing to divide by", () => {
    const score = scoreRepo({ ...EXPECTED, controls: [] }, [], { semgrep: false });
    expect(score.counts.precision).toBeNull();
    expect(score.counts.falseGapRate).toBeNull();
  });

  it("pools totals as sums across repositories, not an average of rates", () => {
    const a = scoreRepo(EXPECTED, [gap("authz_missing", "src/a.js", 3)], { semgrep: true });
    const b = scoreRepo({ ...EXPECTED, repo: "other" }, [], { semgrep: true });
    const total = totalCounts([a, b]);
    expect(total).toMatchObject({ tp: 1, fn: 5, controls: 4 });
    expect(total.recall).toBeCloseTo(1 / 6);
  });

  it("tallies planted, detected, missed and skipped per OWASP class", () => {
    const score = scoreRepo(EXPECTED, [gap("authz_missing", "src/a.js", 3)], { semgrep: false });
    expect(perOwasp([score])).toEqual([
      { owasp: "A01:2025", planted: 1, detected: 1, missed: 0, skipped: 0 },
      { owasp: "A04:2025", planted: 1, detected: 0, missed: 0, skipped: 1 },
      { owasp: "A05:2025", planted: 1, detected: 0, missed: 1, skipped: 0 },
    ]);
  });
});

describe("scoreRepo: false gaps", () => {
  it("counts a gap of the control's kind in the control's file as a false gap", () => {
    const score = scoreRepo(EXPECTED, [gap("authz_missing", "src/c.js", 8)], { semgrep: false });
    expect(score.controls[0]).toMatchObject({ id: "c-owner", falseGap: true, asserted: true });
    expect(score.counts.falseGapRate).toBe(0.5);
  });

  it("counts a repository-scoped gap of the control's kind as a false gap wherever it is anchored", () => {
    const score = scoreRepo(
      EXPECTED,
      [gap("security_headers_missing", "package.json", 7, { scope: "repository", certainty: 0.6 })],
      { semgrep: false },
    );
    expect(score.controls[1]).toMatchObject({ falseGap: true, asserted: false });
    expect(score.counts).toMatchObject({ falseGaps: 1, assertedFalseGaps: 0 });
  });

  it("does not count a route-scoped gap of the same kind in another file", () => {
    const score = scoreRepo(EXPECTED, [gap("authz_missing", "src/a.js", 3)], { semgrep: false });
    expect(score.controls[0].falseGap).toBe(false);
  });

  it("never lets a Semgrep finding falsify a control", () => {
    const score = scoreRepo(EXPECTED, [semgrep("authz_missing", "src/c.js", 1)], { semgrep: true });
    expect(score.controls[0].falseGap).toBe(false);
  });

  it("uses the product's assertion threshold", () => {
    expect(ASSERTED_CERTAINTY).toBe(GAP_ASSERT_CERTAINTY);
  });
});

describe("toFindings", () => {
  it("merges gaps and Semgrep evidence into one list sorted by file, line, source and kind", () => {
    const findings = toFindings(
      [
        {
          id: "gap-1",
          kind: "cors_permissive",
          scope: "file",
          control: "c",
          expectation: "e",
          file: "b.js",
          line: 2,
          basisFacts: [],
          certainty: 0.5,
          owasp: [],
          stride: [],
          cwe: [],
        },
      ],
      [{ id: "ev-semgrep-1", kind: "scanner", source: "semgrep", summary: "s", filePath: "a.js", lineStart: 9, ruleId: "r" }],
    );
    expect(findings).toEqual([
      { source: "semgrep", kind: "r", file: "a.js", line: 9 },
      { source: "gap", kind: "cors_permissive", file: "b.js", line: 2, scope: "file", certainty: 0.5 },
    ]);
  });
});

describe("parseExpected", () => {
  const valid = `repo: demo
issues:
  - { id: a-1, class: c, owasp: "A01:2025", file: src/a.js, line: 3, gapKind: authz_missing }
controls:
  - { id: c-1, gapKind: authn_missing, file: src/a.js, how: h, type: framework default }
`;

  it("accepts a well-formed label file", () => {
    expect(parseExpected(valid, "x").issues[0].id).toBe("a-1");
  });

  it.each([
    ["an issue with neither gapKind nor ruleId", valid.replace(", gapKind: authz_missing", "")],
    ["an unknown gap kind", valid.replace("gapKind: authz_missing", "gapKind: made_up")],
    ["an unknown rule id", valid.replace("gapKind: authz_missing", "ruleId: attackcanvas-nope")],
    ["an OWASP code outside 2025", valid.replace("A01:2025", "A01:2021")],
    ["an absolute path", valid.replace("file: src/a.js, line", "file: /etc/a.js, line")],
    ["a path with ..", valid.replace("file: src/a.js, line", "file: ../a.js, line")],
    ["an unknown control type", valid.replace("framework default", "magic")],
    ["a duplicate id", valid.replace("id: c-1", "id: a-1")],
    ["an unknown field", valid.replace("line: 3,", "line: 3, severity: high,")],
    ["invalid YAML", "repo: [unclosed"],
  ])("rejects %s", (_label, text) => {
    expect(() => parseExpected(text, "x")).toThrow(/^x: /);
  });
});

describe("checkMarkers", () => {
  const files = [
    { path: "src/a.js", content: "const a = 1;\n// SEEDED:i-authz\napp.get('/x/:id', h);\n" },
    { path: "src/b.js", content: "// SEEDED:i-cmd\n\n\n\nexec('x' + y);\n" },
    { path: "src/t.js", content: "// SEEDED:i-jwt\njwt.verify(t);\n" },
    { path: "src/guard.js", content: "// SEEDED:c-owner\n// SEEDED:c-headers\n" },
  ];

  it("passes when every issue marker is on its line or within the window above, and every control is marked", () => {
    expect(checkMarkers(files, EXPECTED)).toEqual([]);
  });

  it("reports an issue whose marker is too far above its line", () => {
    // Marker on line 1, issue on line 8: six lines apart, one more than the window allows.
    const far = files.map((f) => (f.path === "src/a.js" ? { ...f, content: `// SEEDED:i-authz${"\n".repeat(7)}app.get()\n` } : f));
    const expected = { ...EXPECTED, issues: [{ ...EXPECTED.issues[0], line: 8 }, ...EXPECTED.issues.slice(1)] };
    expect(checkMarkers(far, expected)).toEqual([expect.stringMatching(/^i-authz: no SEEDED:i-authz marker at src\/a.js:8 or the 5 lines above/)]);
    const near = { ...expected, issues: [{ ...EXPECTED.issues[0], line: 6 }, ...EXPECTED.issues.slice(1)] };
    expect(checkMarkers(far, near)).toEqual([]);
  });

  it("does not accept a marker for a longer id as the marker for a prefix", () => {
    const prefixed = files.map((f) => (f.path === "src/t.js" ? { ...f, content: "// SEEDED:i-jwt-extra\njwt.verify(t);\n" } : f));
    expect(checkMarkers(prefixed, EXPECTED)).toEqual([
      expect.stringMatching(/^i-jwt: no SEEDED:i-jwt marker/),
      "SEEDED:i-jwt-extra marks nothing in expected.yaml",
    ]);
  });

  it("reports an issue in a file that was not loaded, a line past the end, an unmarked control and an orphan marker", () => {
    const expected: ExpectedRepo = {
      ...EXPECTED,
      issues: [
        { ...EXPECTED.issues[0], file: "src/missing.js" },
        { ...EXPECTED.issues[1], line: 50 },
        EXPECTED.issues[2],
      ],
    };
    const broken = [
      ...files.filter((f) => f.path !== "src/guard.js"),
      { path: "src/guard.js", content: "// SEEDED:c-owner\n// SEEDED:stray-1\n" },
    ];
    expect(checkMarkers(broken, expected)).toEqual([
      "i-authz: file src/missing.js was not loaded",
      "i-cmd: line 50 is past the end of src/b.js",
      "c-headers: no SEEDED:c-headers marker in any file",
      "SEEDED:stray-1 marks nothing in expected.yaml",
    ]);
  });
});

describe("withoutExpected", () => {
  it("removes the label file so no detector reads it", () => {
    const loaded = [
      { path: "expected.yaml", content: "repo: x", tier: "low" as const, reason: "other" },
      { path: "src/a.js", content: "a", tier: "medium" as const, reason: "source" },
    ];
    const { files, expected } = withoutExpected(loaded);
    expect(files.map((f) => f.path)).toEqual(["src/a.js"]);
    expect(expected).toBe("repo: x");
  });

  it("fails when the label file is missing", () => {
    expect(() => withoutExpected([])).toThrow(/expected.yaml was not loaded/);
  });
});

describe("reporting", () => {
  const score = scoreRepo(EXPECTED, [gap("authz_missing", "src/a.js", 3), gap("authz_missing", "src/c.js", 8)], {
    semgrep: false,
  });
  const result: BenchResult = {
    run: { mode: "detectors", repos: [score], total: totalCounts([score]), perOwasp: perOwasp([score]) },
    hashes: ["a".repeat(64), "a".repeat(64), "a".repeat(64)],
    deterministic: true,
  };
  const meta = { date: "2026-09-25", commit: "abc1234", semgrep: "not on PATH, skipped" };

  it("renders a paste-ready bench row", () => {
    expect(benchRow(result, meta)).toBe("| 2026-09-25 | abc1234 | detectors | 1/1/1 | 50.0% | 50.0% | 1/2 (50.0%) | yes |");
  });

  it("lists every false positive and false gap and ends with the notes marker", () => {
    const report = renderReport([result], meta);
    expect(report).toContain("- demo: gap `authz_missing` at src/c.js:8, certainty 0.7, scope route, **falsifies c-owner**");
    expect(report).toContain("- demo: `c-owner` (authz_missing, cross-package guard): src/c.js:8 certainty 0.7");
    expect(report).toContain("- demo: `i-cmd` (A05:2025, src/b.js)");
    expect(report.trimEnd().endsWith(NOTES_MARKER)).toBe(true);
  });

  it("keeps hand-written notes below the marker across regenerations", () => {
    const first = mergeReport(renderReport([result], meta), undefined);
    const edited = `${first}\n## Notes\n\nc-owner is review entry 1d.\n`;
    const regenerated = mergeReport(renderReport([result], { ...meta, commit: "def5678" }), edited);
    expect(regenerated).toContain("def5678");
    expect(regenerated).not.toContain("abc1234");
    expect(regenerated).toContain("## Notes\n\nc-owner is review entry 1d.\n");
    expect(regenerated.split(NOTES_MARKER)).toHaveLength(2);
  });
});
