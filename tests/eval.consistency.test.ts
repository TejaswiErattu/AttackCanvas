import { describe, expect, it } from "vitest";
import type { ThreatModel } from "@/shared/schema";
import {
  analyseConsistency,
  compareEvidence,
  componentKeys,
  flowKeys,
  jaccard,
  pairwiseOverlap,
  renderConsistencyReport,
  scoreAgreement,
  statOf,
  threatPresence,
  visibleThreats,
} from "../scripts/eval/consistencyLib";
import { DEFAULT_LEVEL, parseRunArgs, type EvalResult } from "../scripts/eval/lib";

type T = { title: string; comps?: string[]; owasp?: string[]; conf?: number; severity?: string; priority?: string };
type E = { source?: string; ruleId: string; file?: string; line?: number; id?: string };

/** A minimal hand-built model; only the fields the consistency logic reads. */
function model(opts: { comps?: [string, string][]; flows?: [string, string, string][]; threats?: T[]; evidence?: E[] }): ThreatModel {
  const comps = opts.comps ?? [["Web", "web_app"], ["DB", "database"]];
  return {
    components: comps.map(([name, type], i) => ({ id: `c${i}`, name, type })),
    dataFlows: (opts.flows ?? []).map(([s, t, label], i) => ({
      id: `f${i}`,
      sourceId: `c${comps.findIndex(([n]) => n === s)}`,
      targetId: `c${comps.findIndex(([n]) => n === t)}`,
      label,
    })),
    threats: (opts.threats ?? []).map((t, i) => ({
      id: `t${i}`,
      title: t.title,
      componentIds: (t.comps ?? ["Web"]).map((n) => `c${comps.findIndex(([x]) => x === n)}`),
      owasp: t.owasp ?? ["A01:2025"],
      confidence: t.conf ?? 0.6,
      severity: t.severity ?? "High",
      priority: t.priority ?? "fix_soon",
    })),
    evidence: (opts.evidence ?? []).map((e, i) => ({
      id: e.id ?? `e${i}`,
      kind: "code",
      source: e.source ?? "detector",
      summary: "s",
      ruleId: e.ruleId,
      filePath: e.file,
      lineStart: e.line,
    })),
  } as unknown as ThreatModel;
}

function result(name: string, m: ThreatModel, extra: Partial<EvalResult> = {}): EvalResult {
  return { repo: name, repoUrl: "u", modelProfile: "demo", ranAt: "2026-01-01T00:00:00Z", cost: { calls: 10, totalUsd: 3 }, threatModel: m, ...extra };
}

describe("jaccard", () => {
  it("is 1 for two empty sets, 0 for disjoint, and |A n B| / |A u B| otherwise", () => {
    expect(jaccard(new Set(), new Set())).toBe(1);
    expect(jaccard(new Set(["a"]), new Set(["b"]))).toBe(0);
    expect(jaccard(new Set(["a", "b", "c"]), new Set(["b", "c", "d"]))).toBe(0.5);
    expect(jaccard(new Set(["a"]), new Set())).toBe(0);
  });

  it("averages every unordered pair, and has no mean for a single run", () => {
    const o = pairwiseOverlap([
      { name: "r1", keys: new Set(["a", "b"]) },
      { name: "r2", keys: new Set(["a", "b"]) },
      { name: "r3", keys: new Set(["a"]) },
    ]);
    expect(o.pairs.map((p) => p.jaccard)).toEqual([1, 0.5, 0.5]);
    expect(o.mean).toBeCloseTo(2 / 3);
    expect(pairwiseOverlap([{ name: "r1", keys: new Set() }]).mean).toBeNull();
  });
});

describe("keys", () => {
  it("match components by normalised name and type, not id", () => {
    expect(componentKeys(model({ comps: [["Web  App", "web_app"]] }))).toEqual(componentKeys(model({ comps: [["web app", "web_app"]] })));
    expect(componentKeys(model({ comps: [["Web", "web_app"]] }))).not.toEqual(componentKeys(model({ comps: [["Web", "api"]] })));
  });

  it("match flows by source name, target name and label", () => {
    const a = flowKeys(model({ flows: [["Web", "DB", "queries"]] }));
    const swapped = flowKeys(model({ comps: [["DB", "database"], ["Web", "web_app"]], flows: [["Web", "DB", "Queries"]] }));
    expect(swapped).toEqual(a);
    expect(flowKeys(model({ flows: [["DB", "Web", "queries"]] }))).not.toEqual(a);
  });
});

describe("threats", () => {
  it("visibleThreats drops hidden ones and collapses duplicate keys", () => {
    const v = visibleThreats(model({ threats: [{ title: "XSS" }, { title: "xss!" }, { title: "Low", conf: 0.2 }] }));
    expect(v.size).toBe(1);
  });

  it("the key ignores component and OWASP order but not their content", () => {
    const a = visibleThreats(model({ threats: [{ title: "T", comps: ["Web", "DB"], owasp: ["A01:2025", "A02:2025"] }] }));
    const b = visibleThreats(model({ threats: [{ title: "T", comps: ["DB", "Web"], owasp: ["A02:2025", "A01:2025"] }] }));
    const c = visibleThreats(model({ threats: [{ title: "T", comps: ["DB", "Web"], owasp: ["A02:2025"] }] }));
    expect([...a.keys()]).toEqual([...b.keys()]);
    expect([...a.keys()]).not.toEqual([...c.keys()]);
  });

  it("counts presence in all, some and one run", () => {
    const runs = [
      new Map([["a", 1], ["b", 1], ["c", 1]]),
      new Map([["a", 1], ["b", 1]]),
      new Map([["a", 1], ["d", 1]]),
    ];
    expect(threatPresence(runs)).toEqual({ total: 4, inAll: 1, inSome: 1, inOne: 2 });
  });

  it("has zeros, not NaN, when no run has a visible threat", () => {
    expect(threatPresence([new Map(), new Map()])).toEqual({ total: 0, inAll: 0, inSome: 0, inOne: 0 });
  });

  it("severity and priority agreement only look at threats present in every run", () => {
    const mk = (severity: string, priority: string, extra: T[] = []) =>
      visibleThreats(model({ threats: [{ title: "Shared", severity, priority }, ...extra] }));
    const a = scoreAgreement([mk("High", "fix_now"), mk("High", "fix_soon", [{ title: "Only here" }]), mk("Medium", "fix_soon")]);
    expect(a).toEqual({ matched: 1, severity: 0, priority: 0 });
    const b = scoreAgreement([mk("High", "fix_now"), mk("High", "fix_now")]);
    expect(b).toEqual({ matched: 1, severity: 1, priority: 1 });
  });
});

describe("deterministic evidence", () => {
  const items: E[] = [
    { ruleId: "gap:csrf", file: "a.js", line: 3 },
    { source: "semgrep", ruleId: "r1", file: "b.js", line: 9 },
  ];

  it("is identical when only ids and order differ, and ignores model-written evidence", () => {
    const a = model({ evidence: items });
    const b = model({ evidence: [{ ...items[1], id: "zz" }, { ...items[0], id: "yy" }, { source: "ai", ruleId: "x" }] });
    expect(compareEvidence([a, b])).toEqual({ identical: true, counts: [2, 2], differing: 0 });
  });

  it("reports a missing or changed item", () => {
    const changed = model({ evidence: [items[0], { ...items[1], line: 10 }] });
    expect(compareEvidence([model({ evidence: items }), changed])).toMatchObject({ identical: false, differing: 2 });
    expect(compareEvidence([model({ evidence: items }), model({ evidence: [items[0]] })])).toMatchObject({ identical: false, differing: 1 });
  });

  it("counts a repeated item as different from a single one", () => {
    const twice = model({ evidence: [items[0], items[0]] });
    expect(compareEvidence([model({ evidence: [items[0]] }), twice]).identical).toBe(false);
  });
});

describe("analyseConsistency", () => {
  const shared: T = { title: "Shared" };
  const runs = [
    result("r1", model({ threats: [shared, { title: "A", owasp: ["A02:2025"] }], evidence: [{ ruleId: "gap:x" }] }), { level: 2, durationMs: 60000 }),
    result("r2", model({ threats: [shared], evidence: [{ ruleId: "gap:x" }] }), { level: 2, durationMs: 180000, cost: { calls: 20, totalUsd: 5 } }),
  ];
  const c = analyseConsistency(runs);

  it("summarises the three-run-style inputs end to end", () => {
    expect(c.components.mean).toBe(1);
    expect(c.threats.visiblePerRun).toEqual([2, 1]);
    expect(c.threats.presence).toEqual({ total: 2, inAll: 1, inSome: 0, inOne: 1 });
    expect(c.owasp).toEqual([{ code: "A01:2025", counts: [1, 1] }, { code: "A02:2025", counts: [1, 0] }]);
    expect(c.evidence.identical).toBe(true);
    expect(c.calls).toEqual({ min: 10, max: 20, mean: 15 });
    expect(c.costUsd).toEqual({ min: 3, max: 5, mean: 4 });
    expect(c.durationMs).toEqual({ min: 60000, max: 180000, mean: 120000 });
  });

  it("leaves duration out when any run lacks it, and statOf handles no values", () => {
    expect(analyseConsistency([runs[0], result("old", model({}))]).durationMs).toBeNull();
    expect(statOf([])).toBeNull();
  });

  it("renders a report that names the runs and flags non-identical evidence", () => {
    const md = renderConsistencyReport(c, "2026-01-01");
    expect(md).toContain("r1, r2");
    expect(md).toContain("Identical across all runs");
    const bad = analyseConsistency([runs[0], result("r3", model({}))]);
    expect(renderConsistencyReport(bad, "x")).toContain("NOT identical");
  });
});

describe("run.ts --level", () => {
  const parse = (argv: string[]) => parseRunArgs(argv, 600000, 2147483647);

  it("defaults to 2 and reads 0 to 4 anywhere in the arguments", () => {
    expect(DEFAULT_LEVEL).toBe(2);
    expect(parse(["a"])).toMatchObject({ ok: true, value: { level: 2 } });
    expect(parse(["--level", "0", "a"])).toMatchObject({ ok: true, value: { names: ["a"], level: 0 } });
    expect(parse(["a", "--level", "4", "--timeout", "1000"])).toMatchObject({ ok: true, value: { level: 4, timeoutMs: 1000 } });
  });

  it.each([["5"], ["-1"], ["1.5"], ["two"], [""], ["01"]])("rejects --level %j", (raw) => {
    expect(parse(["a", "--level", raw]).ok).toBe(false);
  });

  it("rejects a missing or repeated --level", () => {
    expect(parse(["--level"])).toMatchObject({ ok: false, message: /needs a value/ });
    expect(parse(["--level", "1", "--level", "2"])).toMatchObject({ ok: false, message: /more than once/ });
  });
});
