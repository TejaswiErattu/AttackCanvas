/**
 * The gap sheet, gap precision, per-class recall, second-labeler agreement and sampling in
 * scripts/eval/lib.ts. Every sheet and model here is a few rows written for the test; no
 * saved result is read and no model is called.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Evidence, Threat, ThreatModel } from "@/shared/schema";
import { validateThreatModel } from "@/shared/schema";
import {
  ExpectedFileSchema,
  GAP_COLUMNS,
  LABEL_COLUMNS,
  agreementOf,
  allocateStrata,
  blankSecondSheet,
  buildGapSheet,
  classesOf,
  compareLabelers,
  computeGapMetrics,
  computeRepoMetrics,
  gapOnlyEvidence,
  gapSheetProblems,
  gapSheetRows,
  gapSheetStarted,
  goldenProblems,
  parseCsv,
  parseGapLabels,
  parseLabels,
  parseSecondLabels,
  parseYamlWith,
  recallByClass,
  recalledIds,
  renderEvaluationReport,
  secondSheetProblems,
  seededRandom,
  stratifiedSample,
  strataKey,
  toCsv,
  visibleBases,
  type GapLabeled,
  type LabeledThreat,
} from "../scripts/eval/lib";
import demoJson from "../fixtures/demo-analysis.json";

const demo = validateThreatModel(demoJson);
if (!demo.ok) throw new Error("demo fixture invalid");
const base: ThreatModel = demo.data;

const evidence = (id: string, ruleId: string | undefined, filePath: string | undefined, line?: number): Evidence => ({
  id,
  kind: "code",
  source: "detector",
  summary: "s",
  ...(filePath ? { filePath } : {}),
  ...(line !== undefined ? { lineStart: line } : {}),
  ...(ruleId ? { ruleId } : {}),
});

const threat = (id: string, evidenceIds: string[], confidence: number, title = `Title ${id}`, basis: Threat["basis"] = "evidence_backed"): Threat => ({
  ...base.threats[0],
  id,
  title,
  evidenceIds,
  confidence,
  basis,
});

/** Gap evidence, a positive code observation, a Semgrep finding, and five threats over them. */
const model: ThreatModel = {
  ...base,
  evidence: [
    evidence("ev-gap-1", "gap:authz_missing", "app/a.js", 3),
    evidence("ev-gap-2", "gap:csrf_missing", "app/b.js", 7),
    evidence("ev-gap-3", "gap:authz_missing", "app/a.js", 3), // the same place as ev-gap-1
    evidence("ev-code-1", undefined, "app/c.js", 1),
    evidence("ev-semgrep-1", "attackcanvas-eval-user-input", "app/d.js", 2),
  ],
  threats: [
    threat("t1", ["ev-gap-1"], 0.4),
    threat("t2", ["ev-gap-2", "ev-gap-1", "ev-gap-3"], 0.1, "=HYPERLINK(1)"),
    threat("t3", ["ev-gap-1", "ev-code-1"], 0.9), // a gap and a positive observation: not gap-only
    threat("t4", [], 0.9), // cites nothing
    threat("t5", ["ev-semgrep-1"], 0.9), // a rule id that is not a gap
    threat("t6", ["ev-gap-2"], 0.25), // exactly the cutoff: visible
    threat("t7", ["ev-gap-2"], 0.2499), // just under it: hidden
  ],
};

describe("gapSheetRows", () => {
  const rows = gapSheetRows(model);

  it("keeps only threats whose every cited item is a control gap, in the model's order", () => {
    expect(rows.map((r) => r.threatId)).toEqual(["t1", "t2", "t6", "t7"]);
  });

  it("lists each distinct gap kind and location once, sorted", () => {
    expect(rows[1]).toMatchObject({ gapKinds: ["authz_missing", "csrf_missing"], files: ["app/a.js:3", "app/b.js:7"] });
  });

  it("marks a threat visible from the display cutoff, boundary included", () => {
    expect(rows.map((r) => [r.threatId, r.visible])).toEqual([["t1", true], ["t2", false], ["t6", true], ["t7", false]]);
  });

  it("does not count an evidence id that does not resolve as a gap", () => {
    const byId = new Map(model.evidence.map((e) => [e.id, e]));
    expect(gapOnlyEvidence(threat("x", ["ev-gap-1", "ev-missing"], 0.5), byId)).toBeNull();
    expect(gapOnlyEvidence(threat("x", ["ev-gap-1"], 0.5), byId)?.map((e) => e.id)).toEqual(["ev-gap-1"]);
  });
});

describe("buildGapSheet", () => {
  const rows = parseCsv(buildGapSheet(model));

  it("writes the columns, one row per gap-only threat, and leaves gapLabel and notes empty", () => {
    expect(rows[0]).toEqual([...GAP_COLUMNS]);
    expect(rows).toHaveLength(5);
    expect(rows[1]).toEqual(["t1", "Title t1", "authz_missing", "app/a.js:3", "0.40", "y", "", ""]);
    expect(rows.slice(1).every((r) => r[6] === "" && r[7] === "")).toBe(true);
  });

  it("joins several kinds with ; and locations with |, and defuses a formula in a title", () => {
    expect(rows[2].slice(1, 4)).toEqual(["'=HYPERLINK(1)", "authz_missing;csrf_missing", "app/a.js:3 | app/b.js:7"]);
    expect(rows[2][5]).toBe("n");
  });
});

const sheet = (...lines: string[]) => `${GAP_COLUMNS.join(",")}\n${lines.join("\n")}\n`;

describe("parseGapLabels", () => {
  it("reads the label, the kinds and the visible flag", () => {
    const labels = parseGapLabels(
      sheet("t1,A,authz_missing,f,0.4,y,predicted_correct,", "t2,B,authz_missing;csrf_missing,f,0.1,n,PREDICTED_WRONG,a note"),
    );
    expect(labels).toEqual([
      { threatId: "t1", gapKinds: ["authz_missing"], visible: true, label: "predicted_correct" },
      { threatId: "t2", gapKinds: ["authz_missing", "csrf_missing"], visible: false, label: "predicted_wrong" },
    ]);
  });

  it("refuses a partially filled sheet and says how many rows are blank", () => {
    const run = () => parseGapLabels(sheet("t1,A,authz_missing,f,0.4,y,predicted_correct,", "t2,B,csrf_missing,f,0.4,y,,", "t3,C,csrf_missing,f,0.4,y,,"));
    expect(run).toThrow(/not fully labeled \(2 of 3 row\(s\) have no gapLabel\)/);
    expect(run).toThrow(/row 3 \(t2\): gapLabel is blank/);
    expect(run).toThrow(/row 4 \(t3\): gapLabel is blank/);
  });

  it("refuses a sheet nobody has started", () => {
    expect(() => parseGapLabels(sheet("t1,A,authz_missing,f,0.4,y,,", "t2,B,csrf_missing,f,0.4,y,,"))).toThrow(/2 of 2 row\(s\) have no gapLabel/);
  });

  it("collects other problems: an unknown label, a bad visible flag, empty kinds, a duplicate", () => {
    const run = () =>
      parseGapLabels(
        sheet("t1,A,authz_missing,f,0.4,y,correct,", "t2,B,csrf_missing,f,0.4,maybe,predicted_correct,", "t3,C,,f,0.4,y,predicted_correct,", "t1,A,authz_missing,f,0.4,y,predicted_correct,"),
      );
    expect(run).toThrow(/gapLabel must be predicted_correct or predicted_wrong, got "correct"/);
    expect(run).toThrow(/visible must be y or n/);
    expect(run).toThrow(/gapKinds is empty/);
    expect(run).toThrow(/duplicate threatId/);
  });

  it("rejects an empty file, a missing column and a sheet with no rows", () => {
    expect(() => parseGapLabels("")).toThrow(/empty/);
    expect(() => parseGapLabels("threatId,title\nt1,A")).toThrow(/missing column/);
    expect(() => parseGapLabels(`${GAP_COLUMNS.join(",")}\n`)).toThrow(/no threat rows/);
  });
});

describe("gapSheetProblems", () => {
  const good: GapLabeled[] = gapSheetRows(model).map((r) => ({ threatId: r.threatId, gapKinds: r.gapKinds, visible: r.visible, label: "predicted_correct" }));

  it("accepts a sheet that matches the result", () => {
    expect(gapSheetProblems(good, model)).toEqual([]);
  });

  it("reports a missing gap-only threat, a row that is not gap-only, and a changed kind or visibility", () => {
    const problems = gapSheetProblems(
      [
        { ...good[0], visible: false },
        { ...good[1], gapKinds: ["csrf_missing"] },
        good[2],
        { threatId: "t3", gapKinds: ["authz_missing"], visible: true, label: "predicted_correct" },
      ],
      model,
    );
    expect(problems).toEqual([
      "t7 cites only gaps but is not in the sheet",
      "t1: visible is n but the result says y",
      "t2: gapKinds differ from the result (authz_missing;csrf_missing)",
      "t3 is not a gap-only threat of this result",
    ]);
  });
});

describe("computeGapMetrics", () => {
  const label = (threatId: string, kinds: string[], visible: boolean, correct: boolean): GapLabeled => ({
    threatId,
    gapKinds: kinds,
    visible,
    label: correct ? "predicted_correct" : "predicted_wrong",
  });
  const labels = [
    label("a", ["authz_missing"], true, true),
    label("b", ["authz_missing"], true, false),
    label("c", ["csrf_missing"], false, true),
    label("d", ["csrf_missing", "authz_missing"], false, false),
    label("e", ["rate_limit_missing"], true, true),
  ];
  const m = computeGapMetrics(labels);

  it("computes gap_precision = correct / (correct + wrong), overall and for visible rows only, with n", () => {
    expect(m.overall).toEqual({ correct: 3, wrong: 2, n: 5, precision: 0.6 });
    expect(m.visible).toEqual({ correct: 2, wrong: 1, n: 3, precision: 2 / 3 });
  });

  it("counts predicted_wrong under every kind a threat cites, most wrong first then by name", () => {
    expect(m.wrongByKind).toEqual([
      { kind: "authz_missing", wrong: 2, total: 3 },
      { kind: "csrf_missing", wrong: 1, total: 2 },
      { kind: "rate_limit_missing", wrong: 0, total: 1 },
    ]);
  });

  it("reports a null precision when there are no visible rows", () => {
    expect(computeGapMetrics([label("c", ["x"], false, true)]).visible).toEqual({ correct: 0, wrong: 0, n: 0, precision: null });
  });
});

describe("recallByClass", () => {
  const expected = ExpectedFileSchema.parse({
    expectedThreats: [
      { id: "E1", description: "x", owasp2013: "A1" },
      { id: "E2", description: "x", owasp2013: "A1" },
      { id: "E3", description: "x", owasp2013: "A2/A3/A5" },
      { id: "E4", description: "x", owasp2013: "A10" },
      { id: "E5", description: "x", owasp2013: "SSRF (tutorial ssrf.html)" },
      { id: "E6", description: "x" },
    ],
  });

  it("splits a multi-class note, drops a trailing parenthetical and defaults to unclassified", () => {
    expect(classesOf("A2/A3/A5")).toEqual(["A2", "A3", "A5"]);
    expect(classesOf("SSRF (tutorial ssrf.html)")).toEqual(["SSRF"]);
    expect(classesOf(undefined)).toEqual(["unclassified"]);
  });

  it("counts found and missed per class, A-classes in numeric order, then the rest", () => {
    const rows = recallByClass(expected, new Set(["E1", "E3", "E5"]));
    expect(rows.map((r) => [r.cls, r.expected, r.found, r.missed])).toEqual([
      ["A1", 2, 1, 1],
      ["A2", 1, 1, 0],
      ["A3", 1, 1, 0],
      ["A5", 1, 1, 0],
      ["A10", 1, 0, 1],
      ["SSRF", 1, 1, 0],
      ["unclassified", 1, 0, 1],
    ]);
    expect(rows[0].missedIds).toEqual(["E2"]);
  });
});

describe("agreementOf", () => {
  it("computes simple agreement and Cohen's kappa", () => {
    const a = ["y", "y", "y", "y", "y", "y", "n", "n", "n", "n"];
    const b = ["y", "y", "y", "y", "y", "n", "n", "n", "n", "y"];
    const result = agreementOf(a.map((x, i) => [x, b[i]] as const));
    expect(result).toMatchObject({ n: 10, agreed: 8, agreement: 0.8 });
    expect(result.kappa).toBeCloseTo(7 / 12); // (0.80 - 0.52) / (1 - 0.52)
  });

  it("gives kappa 1 for perfect agreement with variation and -1 for total disagreement on two even classes", () => {
    expect(agreementOf([["y", "y"], ["n", "n"]]).kappa).toBe(1);
    expect(agreementOf([["y", "n"], ["n", "y"]]).kappa).toBe(-1);
  });

  it("gives no kappa when nobody varied, or there is nothing to compare", () => {
    expect(agreementOf([["y", "y"], ["y", "y"]])).toMatchObject({ agreement: 1, kappa: null });
    expect(agreementOf([])).toEqual({ n: 0, agreed: 0, agreement: null, kappa: null });
  });
});

const label = (threatId: string, matches: string[], supported: boolean, correct = 1, total = 1): LabeledThreat => ({
  threatId,
  matches,
  supported,
  evidenceCorrect: correct,
  evidenceTotal: total,
});

describe("compareLabelers", () => {
  const primary = [label("t1", ["E1"], true), label("t2", [], true), label("t3", ["E2"], false), label("t4", [], false, 0, 0)];
  const second = [label("t1", ["E1"], true), label("t2", [], false), label("t4", ["E3"], false, 0, 0)];
  const c = compareLabelers(primary, second);

  it("compares only the threats both sheets hold", () => {
    expect(c.n).toBe(3);
  });

  it("reports agreement and kappa on supported, and lists the disagreements", () => {
    expect(c.supported).toMatchObject({ n: 3, agreed: 2 });
    expect(c.supported.kappa).toBeCloseTo(0.4); // po 2/3, pe 1/3*1/3 + 2/3*2/3 = 5/9
    expect(c.supportedDisagreements).toEqual(["t2"]);
  });

  it("reports whether a row matches anything, the exact match set, and the evidence cell", () => {
    expect(c.matchesAny).toMatchObject({ agreed: 2, n: 3 }); // t4 differs: none vs E3
    expect(c.matchesExact).toMatchObject({ agreed: 2, kappa: null });
    expect(c.evidence).toMatchObject({ agreed: 3, kappa: null });
  });

  it("flags a second-sheet threat the primary sheet does not have, and an empty second sheet", () => {
    expect(secondSheetProblems(primary, [label("t9", [], true)])).toEqual(["t9 is not a threat in the primary sheet"]);
    expect(secondSheetProblems(primary, [])).toEqual(["the second sheet has no rows"]);
    expect(secondSheetProblems(primary, second)).toEqual([]);
  });
});

describe("sampling", () => {
  it("seededRandom repeats for a seed and differs across seeds", () => {
    const draw = (seed: number) => Array.from({ length: 4 }, seededRandom(seed));
    expect(draw(7)).toEqual(draw(7));
    expect(draw(7)).not.toEqual(draw(8));
    expect(draw(7).every((x) => x >= 0 && x < 1)).toBe(true);
  });

  it("allocateStrata is proportional, sums to the size and gives every stratum at least one", () => {
    const counts = new Map([["a", 69], ["b", 35], ["c", 18], ["d", 14]]);
    expect([...allocateStrata(counts, 20)]).toEqual([["a", 10], ["b", 5], ["c", 3], ["d", 2]]);
    expect([...allocateStrata(new Map([["big", 100], ["rare", 1]]), 5)]).toEqual([["big", 4], ["rare", 1]]);
  });

  it("allocateStrata takes the minimum-one places from the largest stratum, never exceeds a stratum's size, and refuses an impossible request", () => {
    // Shares 0.2, 0.2 and 9.6 round to 1, 1 and 9 (11 in all), so the biggest gives one back.
    expect([...allocateStrata(new Map([["a", 2], ["b", 2], ["c", 96]]), 10)]).toEqual([["a", 1], ["b", 1], ["c", 8]]);
    expect([...allocateStrata(new Map([["a", 1], ["b", 1]]), 2)]).toEqual([["a", 1], ["b", 1]]);
    expect(() => allocateStrata(new Map([["a", 3]]), 4)).toThrow(/cannot sample 4 from 3/);
    expect(() => allocateStrata(new Map([["a", 3], ["b", 3], ["c", 3]]), 2)).toThrow(/3 strata/);
  });

  // 40 threats: 20 supported+match, 10 supported+nomatch, 6 unsupported+match, 4 unsupported+nomatch.
  const labels: LabeledThreat[] = [
    ...Array.from({ length: 20 }, (_, i) => label(`threat-${i + 1}`, ["E1"], true)),
    ...Array.from({ length: 10 }, (_, i) => label(`threat-${i + 21}`, [], true)),
    ...Array.from({ length: 6 }, (_, i) => label(`threat-${i + 31}`, ["E1"], false)),
    ...Array.from({ length: 4 }, (_, i) => label(`threat-${i + 37}`, [], false)),
  ];

  it("stratifiedSample draws the size asked, stratified, and returns it in threat-number order", () => {
    const ids = stratifiedSample(labels, 10, 1);
    expect(ids).toHaveLength(10);
    expect(new Set(ids).size).toBe(10);
    expect(ids).toEqual([...ids].sort((a, b) => Number(a.split("-")[1]) - Number(b.split("-")[1])));
    const byKey = new Map(labels.map((l) => [l.threatId, strataKey(l)]));
    const tally = ids.reduce((m, id) => m.set(byKey.get(id) as string, (m.get(byKey.get(id) as string) ?? 0) + 1), new Map<string, number>());
    // Shares 5, 2.5, 1.5, 1: the spare place goes to the first of the two tied 0.5 remainders by name.
    expect([...tally].sort()).toEqual([["supported/match", 5], ["supported/nomatch", 3], ["unsupported/match", 1], ["unsupported/nomatch", 1]]);
  });

  it("is the same for the same seed and different for another", () => {
    expect(stratifiedSample(labels, 10, 1)).toEqual(stratifiedSample(labels, 10, 1));
    expect(stratifiedSample(labels, 10, 1)).not.toEqual(stratifiedSample(labels, 10, 2));
  });
});

describe("blankSecondSheet", () => {
  const header = [...LABEL_COLUMNS];
  const primary = toCsv([
    header,
    ["t1", "Title 1", "Comp", "S", "high", "0.80", "ev-1: a.js:1", "E1;E2", "y", "2/3", "FIRST PERSON'S NOTE"],
    ["t2", "Title, with comma", "Comp", "T", "low", "0.10", "", "", "n", "0/0", "another note"],
    ["t3", "Title 3", "Comp", "I", "low", "0.10", "", "E3", "y", "1/1", ""],
  ]);
  const out = blankSecondSheet(primary, ["t1", "t3"]);

  it("keeps the header and only the sampled rows, with the model's columns intact", () => {
    const rows = parseCsv(out);
    expect(rows[0]).toEqual(header);
    expect(rows.map((r) => r[0])).toEqual(["threatId", "t1", "t3"]);
    expect(rows[1].slice(0, 7)).toEqual(["t1", "Title 1", "Comp", "S", "high", "0.80", "ev-1: a.js:1"]);
  });

  it("empties matchesExpected, supported, evidenceCorrect and notes, and leaks none of them", () => {
    for (const row of parseCsv(out).slice(1)) expect(row.slice(7)).toEqual(["", "", "", ""]);
    expect(out).not.toContain("FIRST PERSON");
    expect(out).not.toContain("E1;E2");
  });

  it("stays a sheet parseLabels reads once a person has filled it", () => {
    const filled = out.replace(/^(t1,.*),,,,$/m, "$1,E1,y,1/1,").replace(/^(t3,.*),,,,$/m, "$1,,n,0/0,");
    expect(parseLabels(filled, new Set(["E1", "E2", "E3"])).map((l) => [l.threatId, l.supported])).toEqual([["t1", true], ["t3", false]]);
  });
});

describe("renderEvaluationReport with extras", () => {
  const expected = ExpectedFileSchema.parse({
    expectedThreats: [
      { id: "E1", description: "x", owasp2013: "A1" },
      { id: "E2", description: "x", owasp2013: "A2" },
    ],
  });
  const labels = [label("t1", ["E1"], true)];
  const m = computeRepoMetrics("r", labels, expected, { totalUsd: 1, calls: 2 });
  const gaps = computeGapMetrics([
    { threatId: "g1", gapKinds: ["authz_missing"], visible: true, label: "predicted_correct" },
    { threatId: "g2", gapKinds: ["authz_missing"], visible: true, label: "predicted_wrong" },
  ]);
  const labelers = compareLabelers([label("t1", ["E1"], true), label("t2", [], false)], [label("t1", ["E1"], true), label("t2", [], true)]);
  const md = renderEvaluationReport([m], "2026-09-25", ["demo"], {
    r: { classes: recallByClass(expected, new Set(m.matched)), gaps, labelers },
  });

  it("adds the per-class table, gap precision with n, and second-labeler agreement", () => {
    expect(md).toContain("## Recall by class: r");
    expect(md).toContain("| A1 | 1 | 1 | 0 | none |");
    expect(md).toContain("| A2 | 1 | 0 | 1 | E2 |");
    expect(md).toContain("| All | 2 | 1 | 1 | 50.0% |");
    expect(md).toContain("| Visible only | 2 | 1 | 1 | 50.0% |");
    expect(md).toContain("| authz_missing | 1 | 2 |");
    expect(md).toContain("**supported (y/n)**: 1/2 agree (50.0%), Cohen's kappa 0.00");
    expect(md).toContain("**Supported disagreements**: t2");
  });

  it("puts the extra sections before the definitions, and adds nothing when there are no extras", () => {
    expect(md.indexOf("## Second labeler agreement: r")).toBeLessThan(md.indexOf("## Definitions"));
    const plain = renderEvaluationReport([m], "2026-09-25", ["demo"]);
    expect(plain).not.toContain("## Recall by class");
    expect(plain).not.toContain("Gap precision");
  });
});

describe("golden demo checks", () => {
  const withBases = (...bases: [number, Threat["basis"]][]): ThreatModel => ({
    ...base,
    threats: bases.map(([confidence, basis], i) => threat(`t${i}`, [], confidence, `T${i}`, basis)),
  });

  it("counts only visible threats, boundary included", () => {
    expect(visibleBases(withBases([0.25, "evidence_backed"], [0.24, "assumption_dependent"], [0.9, "assumption_dependent"]))).toEqual({
      evidenceBacked: 1,
      assumptionDependent: 1,
    });
  });

  it("names the basis that has no visible threat", () => {
    expect(goldenProblems(withBases([0.9, "evidence_backed"], [0.1, "assumption_dependent"]))).toEqual(["no visible assumption_dependent threat"]);
    expect(goldenProblems(withBases([0.9, "assumption_dependent"]))).toEqual(["no visible evidence_backed threat"]);
    expect(goldenProblems(withBases())).toHaveLength(2);
    expect(goldenProblems(withBases([0.9, "evidence_backed"], [0.9, "assumption_dependent"]))).toEqual([]);
  });
});

describe("recall requires a supported row (R1)", () => {
  const row = (threatId: string, matches: string[], supported: boolean): LabeledThreat => ({
    threatId,
    matches,
    supported,
    evidenceCorrect: 0,
    evidenceTotal: 0,
  });
  const expected = ExpectedFileSchema.parse({
    expectedThreats: [
      { id: "E1", description: "x", owasp2013: "A1" },
      { id: "E2", description: "x", owasp2013: "A9" },
    ],
  });

  it("does not recall an item whose only matching row is unsupported", () => {
    const labels = [row("t1", ["E1"], true), row("t2", ["E2"], false)];
    expect([...recalledIds(labels)]).toEqual(["E1"]);
    const m = computeRepoMetrics("r", labels, expected, { totalUsd: 0, calls: 0 });
    expect(m.matched).toEqual(["E1"]);
    expect(m.missed).toEqual(["E2"]);
    expect(m.unsupported).toBe(1); // the unsupported match still counts as unsupported
  });

  it("recalls the item once any matching row is supported, whatever the others say", () => {
    const labels = [row("t1", ["E2"], false), row("t2", ["E2"], true)];
    expect(computeRepoMetrics("r", labels, expected, { totalUsd: 0, calls: 0 }).matched).toEqual(["E2"]);
  });

  it("gives the per-class table the same answer as the recall figure", () => {
    const labels = [row("t1", ["E1"], true), row("t2", ["E2"], false)];
    const m = computeRepoMetrics("r", labels, expected, { totalUsd: 0, calls: 0 });
    const classes = recallByClass(expected, new Set(m.matched));
    expect(classes.reduce((sum, c) => sum + c.found, 0)).toBe(m.matched.length);
    expect(classes.find((c) => c.cls === "A9")).toMatchObject({ found: 0, missed: 1, missedIds: ["E2"] });
  });

  // Pinned to the reviewed labels: eval/review/nodegoat-a3118b6-report.md reports 17/19.
  it("reproduces the reviewed nodegoat-a3118b6 recall of 17/19, with NG-VULNERABLE-DEPS missed", () => {
    const key = parseYamlWith(readFileSync("eval/expected/nodegoat-a3118b6.yaml", "utf8"), ExpectedFileSchema, "key");
    const labels = parseLabels(readFileSync("eval/labels/nodegoat-a3118b6.csv", "utf8"), new Set(key.expectedThreats.map((t) => t.id)));
    const deps = labels.filter((l) => l.matches.includes("NG-VULNERABLE-DEPS"));
    expect(deps.map((l) => [l.threatId, l.supported])).toEqual([["threat-70", false]]);

    const m = computeRepoMetrics("nodegoat-a3118b6", labels, key, { totalUsd: 0, calls: 0 });
    expect(`${m.matched.length}/${m.expected}`).toBe("17/19");
    expect(m.missed).toEqual(["NG-WEAK-PASSWORD-POLICY", "NG-VULNERABLE-DEPS"]);

    const a9 = recallByClass(key, new Set(m.matched)).find((c) => c.cls === "A9");
    expect(a9).toMatchObject({ expected: 1, found: 0, missed: 1, missedIds: ["NG-VULNERABLE-DEPS"] });
  });
});

describe("gapSheetStarted", () => {
  const header = GAP_COLUMNS.join(",");

  it("is false for a freshly generated sheet, so the scorer skips it", () => {
    expect(gapSheetStarted(buildGapSheet(model))).toBe(false);
    expect(gapSheetStarted(`${header}\n`)).toBe(false);
    expect(gapSheetStarted("")).toBe(false);
  });

  it("is true once any row has a gapLabel, so a partial sheet is parsed and refused", () => {
    const partial = `${header}\nt1,A,authz_missing,f,0.4,y,predicted_wrong,\nt2,B,csrf_missing,f,0.4,y,,\n`;
    expect(gapSheetStarted(partial)).toBe(true);
    expect(() => parseGapLabels(partial)).toThrow(/1 of 2 row\(s\) have no gapLabel/);
  });

  it("ignores notes: a note without a label does not start the sheet", () => {
    expect(gapSheetStarted(`${header}\nt1,A,authz_missing,f,0.4,y,,thinking about it\n`)).toBe(false);
  });
});

describe("second sheet: matchesExpected not labelled", () => {
  const ids = new Set(["E1", "E2"]);
  // The columns of the real second sheet: the primary's, then the second labeller's own.
  const second = (...rows: string[]) => `${LABEL_COLUMNS.join(",")},label,reason\n${rows.join("\n")}\n`;
  const blankMatches = second(
    "t1,A,c,S,High,0.8,loc,,y,1/1,n1,confirmed_useful,r1",
    "t2,B,c,S,High,0.8,loc,,n,0/0,n2,confirmed_wrong,r2",
    "t3,C,c,S,High,0.8,loc,,y,0/0,n3,confirmed_useful,r3",
  );

  it("reports an entirely blank column as not labelled, and still reads supported and evidence", () => {
    const sheet = parseSecondLabels(blankMatches, ids);
    expect(sheet.matchesLabelled).toBe(false);
    expect(sheet.labels.map((l) => [l.threatId, l.supported, l.evidenceCorrect, l.evidenceTotal])).toEqual([
      ["t1", true, 1, 1],
      ["t2", false, 0, 0],
      ["t3", true, 0, 0],
    ]);
  });

  it("omits match agreement and kappa but keeps supported and evidence agreement", () => {
    const primary = [label("t1", ["E1"], true), label("t2", [], false, 0, 0), label("t3", ["E2"], true, 0, 0)];
    const s = parseSecondLabels(blankMatches, ids);
    const c = compareLabelers(primary, s.labels, { matchesLabelled: s.matchesLabelled });
    expect(c.matchesLabelled).toBe(false);
    expect(c.matchesAny).toBeNull();
    expect(c.matchesExact).toBeNull();
    expect(c.supported).toMatchObject({ n: 3, agreed: 3, agreement: 1 });
    expect(c.evidence).toMatchObject({ n: 3, agreed: 3 });
  });

  it("does not score a blank as 'matches nothing': a primary match would otherwise read as disagreement", () => {
    const primary = [label("t1", ["E1"], true), label("t2", ["E2"], false), label("t3", ["E1"], true, 0, 0)];
    const s = parseSecondLabels(blankMatches, ids);
    const blindly = compareLabelers(primary, s.labels); // the old behaviour, matchesLabelled defaults to true
    expect(blindly.matchesAny).toMatchObject({ agreed: 0, n: 3 });
    const honest = compareLabelers(primary, s.labels, { matchesLabelled: false });
    expect(honest.matchesAny).toBeNull();
  });

  it("rejects a partly filled column instead of treating the blank rows as matching nothing", () => {
    const partial = second(
      "t1,A,c,S,High,0.8,loc,E1,y,1/1,,,",
      "t2,B,c,S,High,0.8,loc,,n,0/0,,,",
      "t3,C,c,S,High,0.8,loc,,y,0/0,,,",
    );
    const run = () => parseSecondLabels(partial, ids);
    expect(run).toThrow(/filled on 1 of 3 rows and blank on t2, t3/);
    expect(run).toThrow(/write "none" for a threat that matches no expected item/);
  });

  it("accepts a fully filled column, where none marks a row that matches nothing", () => {
    const filled = second(
      "t1,A,c,S,High,0.8,loc,E1;E2,y,1/1,,,",
      "t2,B,c,S,High,0.8,loc,none,n,0/0,,,",
      "t3,C,c,S,High,0.8,loc,NONE,y,0/0,,,",
    );
    const s = parseSecondLabels(filled, ids);
    expect(s.matchesLabelled).toBe(true);
    expect(s.labels.map((l) => l.matches)).toEqual([["E1", "E2"], [], []]);
    const primary = [label("t1", ["E1", "E2"], true), label("t2", [], false), label("t3", ["E1"], true, 0, 0)];
    const c = compareLabelers(primary, s.labels);
    expect(c.matchesAny).toMatchObject({ agreed: 2, n: 3 });
    expect(c.matchesExact).toMatchObject({ agreed: 2, n: 3, kappa: null });
  });

  it("still rejects an unknown id in a filled column", () => {
    const bad = second("t1,A,c,S,High,0.8,loc,E9,y,1/1,,,");
    expect(() => parseSecondLabels(bad, ids)).toThrow(/unknown id\(s\) E9/);
  });

  it("does not loosen the rest of the sheet: a blank supported or evidenceCorrect is still refused", () => {
    const halfDone = second("t1,A,c,S,High,0.8,loc,,,,,,", "t2,B,c,S,High,0.8,loc,,y,1/1,,,");
    const run = () => parseSecondLabels(halfDone, ids);
    expect(run).toThrow(/supported must be y or n/);
    expect(run).toThrow(/evidenceCorrect must look like 2\/3/);
  });

  it("gives an empty or column-less sheet parseLabels' own message", () => {
    expect(() => parseSecondLabels("", ids)).toThrow(/label sheet is empty/);
    expect(() => parseSecondLabels("threatId,title\nt1,A", ids)).toThrow(/missing column/);
  });

  it("leaves the primary sheet's rule alone: a blank matchesExpected there still means matches nothing", () => {
    const primaryText = `${LABEL_COLUMNS.join(",")}\nt1,A,c,S,High,0.8,loc,E1,y,1/1,\nt2,B,c,S,High,0.8,loc,,y,0/0,\n`;
    expect(parseLabels(primaryText, ids).map((l) => l.matches)).toEqual([["E1"], []]);
  });

  it("tells the report so, and says nothing about match agreement", () => {
    const expected = ExpectedFileSchema.parse({ expectedThreats: [{ id: "E1", description: "x", owasp2013: "A1" }] });
    const primary = [label("t1", ["E1"], true), label("t2", [], false, 0, 0)];
    const s = parseSecondLabels(second("t1,A,c,S,High,0.8,loc,,y,1/1,,,", "t2,B,c,S,High,0.8,loc,,n,0/0,,,"), ids);
    const labelers = compareLabelers(primary, s.labels, { matchesLabelled: false });
    const m = computeRepoMetrics("r", primary, expected, { totalUsd: 0, calls: 0 });
    const md = renderEvaluationReport([m], "2026-09-25", ["demo"], { r: { labelers } });
    expect(md).toContain("**supported (y/n)**: 2/2 agree (100.0%)");
    expect(md).toContain("**evidenceCorrect, exact cell**: 2/2 agree");
    expect(md).toContain("**matchesExpected**: not labelled by the second labeller");
    expect(md).not.toContain("matches any expected item");
    expect(md).not.toContain("exact set");
  });
});
