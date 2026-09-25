import { describe, expect, it } from "vitest";
import { validateThreatModel, type ThreatModel } from "@/shared/schema";
import {
  ExpectedFileSchema,
  LABEL_COLUMNS,
  ReposFileSchema,
  buildLabelSheet,
  combineMetrics,
  computeRepoMetrics,
  csvCell,
  parseCsv,
  parseLabels,
  parseYamlWith,
  renderEvaluationReport,
  requireRepoUrl,
  revisionMismatch,
  selectRepos,
  toCsv,
} from "../scripts/eval/lib";
import demoJson from "../fixtures/demo-analysis.json";

const parsed = validateThreatModel(demoJson);
if (!parsed.ok) throw new Error("demo fixture invalid");
const model: ThreatModel = parsed.data;

describe("csv", () => {
  it("round-trips commas, quotes and newlines", () => {
    const rows = [["a", 'he said "hi"', "x,y", "line1\nline2"], ["", "z", "", ""]];
    expect(parseCsv(toCsv(rows))).toEqual(rows);
  });

  it("tolerates a BOM, LF endings, a missing final newline and blank lines", () => {
    expect(parseCsv("﻿a,b\n1,2\n\n3,4")).toEqual([["a", "b"], ["1", "2"], ["3", "4"]]);
  });

  it("defuses spreadsheet formulas", () => {
    expect(csvCell("=HYPERLINK(1)")).toBe("'=HYPERLINK(1)");
    expect(csvCell("@x")).toBe("'@x");
    expect(csvCell("plain")).toBe("plain");
  });
});

describe("buildLabelSheet", () => {
  const rows = parseCsv(buildLabelSheet(model));

  it("has the header and one row per threat, hand columns empty", () => {
    expect(rows[0]).toEqual([...LABEL_COLUMNS]);
    expect(rows).toHaveLength(model.threats.length + 1);
    for (const row of rows.slice(1)) {
      expect(row).toHaveLength(LABEL_COLUMNS.length);
      expect(row.slice(7)).toEqual(["", "", "", ""]);
    }
  });

  it("fills id, title, severity and confidence from the model", () => {
    const threat = model.threats[0];
    const row = rows[1];
    expect(row[0]).toBe(threat.id);
    expect(row[1]).toBe(threat.title);
    expect(row[3]).toBe(threat.stride.join(""));
    expect(row[4]).toBe(threat.severity);
    expect(row[5]).toBe(threat.confidence.toFixed(2));
  });

  it("lists exactly one location entry per cited evidence item", () => {
    model.threats.forEach((threat, i) => {
      const cell = rows[i + 1][6];
      const entries = cell === "" ? [] : cell.split(" | ");
      expect(entries).toHaveLength(threat.evidenceIds.length);
    });
  });
});

const expected = ExpectedFileSchema.parse({
  expectedThreats: [
    { id: "E1", description: "one" },
    { id: "E2", description: "two" },
    { id: "E3", description: "three" },
  ],
});
const expectedIds = new Set(expected.expectedThreats.map((t) => t.id));
const header = LABEL_COLUMNS.join(",");
const sheet = (...rows: string[]) => [header, ...rows].join("\n");

describe("parseLabels", () => {
  it("reads matches, y/n and correct/total", () => {
    const labels = parseLabels(
      sheet("t1,A,c,S,High,0.8,loc,E1;E2,y,2/3,", "t2,B,c,T,Low,0.3,loc,,N,0/0,note"),
      expectedIds,
    );
    expect(labels).toEqual([
      { threatId: "t1", matches: ["E1", "E2"], supported: true, evidenceCorrect: 2, evidenceTotal: 3 },
      { threatId: "t2", matches: [], supported: false, evidenceCorrect: 0, evidenceTotal: 0 },
    ]);
  });

  it("collects every problem: unlabeled, unknown expected id, impossible ratio, duplicates", () => {
    const run = () =>
      parseLabels(
        sheet("t1,A,c,S,High,0.8,loc,E9,y,1/1,", "t2,B,c,S,High,0.8,loc,,,1/1,", "t3,C,c,S,High,0.8,loc,,y,4/3,", "t3,C,c,S,High,0.8,loc,,y,1/1,"),
        expectedIds,
      );
    expect(run).toThrow(/unknown id\(s\) E9/);
    expect(run).toThrow(/supported must be y or n/);
    expect(run).toThrow(/more correct than total/);
    expect(run).toThrow(/duplicate threatId/);
  });

  it("rejects an unfilled evidenceCorrect and a missing column", () => {
    expect(() => parseLabels(sheet("t1,A,c,S,High,0.8,loc,,y,,"), expectedIds)).toThrow(/evidenceCorrect/);
    expect(() => parseLabels("threatId,title\nt1,A", expectedIds)).toThrow(/missing column/);
  });
});

describe("metrics", () => {
  const labels = parseLabels(
    sheet(
      "t1,A,c,S,High,0.8,loc,E1,y,2/2,",
      "t2,B,c,S,High,0.8,loc,E1;E2,y,1/2,",
      "t3,C,c,S,High,0.8,loc,,n,0/1,",
      "t4,D,c,S,High,0.8,loc,,y,0/0,",
    ),
    expectedIds,
  );
  const m = computeRepoMetrics("r", labels, expected, { totalUsd: 1.5, calls: 7 });

  it("computes recall from distinct expected ids matched", () => {
    expect(m.matched).toEqual(["E1", "E2"]);
    expect(m.missed).toEqual(["E3"]);
    expect(m.recall).toBeCloseTo(2 / 3);
  });

  it("computes unsupported rate and evidence accuracy", () => {
    expect(m.unsupported).toBe(1);
    expect(m.unsupportedRate).toBe(0.25);
    expect(m.evidenceCorrect).toBe(3);
    expect(m.evidenceTotal).toBe(5);
    expect(m.evidenceAccuracy).toBeCloseTo(0.6);
    expect(m.costUsd).toBe(1.5);
  });

  it("reports n/a evidence accuracy when nothing cites evidence", () => {
    const none = parseLabels(sheet("t1,A,c,S,High,0.8,,,y,0/0,"), expectedIds);
    expect(computeRepoMetrics("r", none, expected, { totalUsd: 0, calls: 0 }).evidenceAccuracy).toBeNull();
  });

  it("pools counts across repos", () => {
    const other = computeRepoMetrics("s", labels.slice(0, 1), expected, { totalUsd: 0.5, calls: 3 });
    const all = combineMetrics([m, other]);
    expect(all.threats).toBe(5);
    expect(all.expected).toBe(6);
    expect(all.recall).toBeCloseTo(3 / 6);
    expect(all.costUsd).toBe(2);
    expect(all.evidenceTotal).toBe(7);
  });

  it("renders a report with the table, misses and a pooled row", () => {
    const other = computeRepoMetrics("s", labels, expected, { totalUsd: 0.5, calls: 3 });
    const md = renderEvaluationReport([m, other], "2026-09-24", ["demo"]);
    expect(md).toContain("| r | 4 | 2/3 (66.7%) | 1/4 (25.0%) | 3/5 (60.0%) | $1.5000 (7 calls) |");
    expect(md).toContain("| all repos |");
    expect(md).toContain("- **r**: E3");
    expect(md).toContain("Model profile: demo");
  });
});

describe("config", () => {
  it("parses repos.yaml and rejects duplicate or unsafe names", () => {
    const ok = parseYamlWith("repos:\n  - {name: testbed, url: ''}\n  - {name: nodegoat, url: ''}", ReposFileSchema, "f");
    expect(ok.repos.map((r) => r.name)).toEqual(["testbed", "nodegoat"]);
    expect(() => parseYamlWith("repos:\n  - {name: a, url: ''}\n  - {name: a, url: ''}", ReposFileSchema, "f")).toThrow(/duplicate/);
    expect(() => parseYamlWith("repos:\n  - {name: ../x, url: ''}", ReposFileSchema, "f")).toThrow();
  });

  it("selects named repos and rejects unknown ones", () => {
    const repos = [{ name: "a", url: "" }, { name: "b", url: "" }];
    expect(selectRepos(repos, [])).toHaveLength(2);
    expect(selectRepos(repos, ["b"])).toEqual([repos[1]]);
    expect(() => selectRepos(repos, ["c"])).toThrow(/not in eval\/repos.yaml: c/);
  });

  it("requires a GitHub URL before a paid run", () => {
    expect(() => requireRepoUrl({ name: "a", url: "" })).toThrow(/needs a/);
    expect(requireRepoUrl({ name: "a", url: " https://github.com/OWASP/NodeGoat " })).toBe("https://github.com/OWASP/NodeGoat");
  });

  it("rejects expected ids that cannot be typed into a cell", () => {
    expect(() => parseYamlWith("expectedThreats:\n  - {id: 'a b', description: x}", ExpectedFileSchema, "f")).toThrow();
    expect(() => parseYamlWith("expectedThreats:\n  - {id: a, description: x}\n  - {id: a, description: y}", ExpectedFileSchema, "f")).toThrow(/duplicate/);
  });
});

describe("revision pinning", () => {
  const key = ExpectedFileSchema.parse({ revision: "abc123", mode: "guided", expectedThreats: [{ id: "E1", description: "x" }] });

  it("accepts the pinned ref and rejects a branch or other commit", () => {
    expect(revisionMismatch(key, "abc123")).toBeNull();
    expect(revisionMismatch(key, "master")).toMatch(/tree\/abc123/);
    expect(revisionMismatch({ expectedThreats: key.expectedThreats }, "master")).toBeNull();
  });

  it("flags a guided repo in the report", () => {
    const labels = parseLabels(sheet("t1,A,c,S,High,0.8,loc,E1,y,1/1,"), new Set(["E1"]));
    const md = renderEvaluationReport([computeRepoMetrics("ng", labels, key, { totalUsd: 0, calls: 0 })], "d", ["demo"]);
    expect(md).toContain("**Guided evaluation:** ng");
    expect(md).toContain("| ng (guided) |");
  });
});
