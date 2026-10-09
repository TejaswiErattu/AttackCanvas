/**
 * scripts/eval/miniLib.ts on the committed NodeGoat result, labels and answer key. The
 * threat engine is a fake: no model, GitHub or filesystem write is reached.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { parse as parseYaml } from "yaml";
import {
  deserializeArchitecture,
  serializeArchitecture,
} from "@/server/analysis/checkpoints";
import type { MergedArchitecture } from "@/server/analysis/architecture";
import { batchElements, type ThreatEngineInput, type ThreatEngineResult } from "@/server/analysis/threats";
import { EvalResultSchema, parseLabels } from "../scripts/eval/lib";
import {
  componentsByFiles,
  componentsByLabels,
  evidenceInRange,
  expectedSources,
  formatMiniReport,
  labelledRecall,
  parseMiniArgs,
  parseSourceRanges,
  planMini,
  proxyRecall,
  runMini,
  selectBatches,
  type MiniArgs,
} from "../scripts/eval/miniLib";

const NAME = "nodegoat-a3118b6";
const result = EvalResultSchema.parse(JSON.parse(readFileSync(`eval/results/${NAME}.json`, "utf8")));
const model = result.threatModel;
const expectedText = readFileSync(`eval/expected/${NAME}.yaml`, "utf8");
const expectedIds = new Set<string>(
  (parseYaml(expectedText) as { expectedThreats: { id: string }[] }).expectedThreats.map((t) => t.id),
);
const labels = parseLabels(readFileSync(`eval/labels/${NAME}.csv`, "utf8"), expectedIds);
const sources = expectedSources(parseYaml(expectedText));

/** The saved model's architecture, enough for batching and selection (no engine reads the Maps here). */
const architecture: MergedArchitecture = {
  components: model.components,
  dataFlows: model.dataFlows,
  trustBoundaries: model.trustBoundaries,
  unknowns: model.unknowns,
  evidence: model.evidence,
  limitations: [],
  gapBindings: new Map([["gap-1", ["express-app"]]]),
  componentEvidence: new Map([["express-app", ["ev-gap-1"]]]),
  flowEvidence: new Map(),
  issues: [],
};

const ARGS: MiniArgs = {
  name: NAME,
  ids: ["NG-NOSQL-WHERE"],
  byFiles: false,
  dryRun: false,
  allowUncached: false,
};

describe("parseMiniArgs", () => {
  it("reads a name, ids split on commas or spaces, and the flags", () => {
    expect(parseMiniArgs([NAME, "NG-A,NG-B", "NG-C", "--dry-run", "--by-files", "--level", "0"])).toEqual({
      name: NAME,
      ids: ["NG-A", "NG-B", "NG-C"],
      byFiles: true,
      dryRun: true,
      allowUncached: false,
      level: 0,
    });
  });

  it("rejects a missing id list, an unknown flag, a bad name and a bad level", () => {
    expect(() => parseMiniArgs([NAME])).toThrow(/usage/);
    expect(() => parseMiniArgs([NAME, "NG-A", "--fast"])).toThrow(/unknown option --fast/);
    expect(() => parseMiniArgs(["../x", "NG-A"])).toThrow(/not a result name/);
    expect(() => parseMiniArgs([NAME, "NG-A", "--level", "7"])).toThrow(/--level/);
  });
});

describe("answer-key locations", () => {
  it("parses a source link with and without lines, and ignores what is not a blob URL", () => {
    expect(
      parseSourceRanges(
        "https://github.com/o/r/blob/abc/server.js#L72-L96 ; https://github.com/o/r/blob/abc/config/env/all.js ; https://example.com/x",
      ),
    ).toEqual([
      { path: "server.js", start: 72, end: 96 },
      { path: "config/env/all.js" },
    ]);
    expect(parseSourceRanges("https://github.com/o/r/blob/abc/a.js#L5")).toEqual([{ path: "a.js", start: 5, end: 5 }]);
  });

  it("reads the committed answer key's ranges", () => {
    expect(sources.get("NG-NOSQL-WHERE")).toEqual([{ path: "app/data/allocations-dao.js", start: 57, end: 79 }]);
  });

  it("matches evidence by file and overlapping lines", () => {
    const range = { path: "a.js", start: 10, end: 20 };
    const at = (lineStart?: number, lineEnd?: number, filePath = "a.js") =>
      ({ id: "e", filePath, lineStart, lineEnd }) as Parameters<typeof evidenceInRange>[0];
    expect(evidenceInRange(at(15), range)).toBe(true);
    expect(evidenceInRange(at(5, 10), range)).toBe(true);
    expect(evidenceInRange(at(21), range)).toBe(false);
    expect(evidenceInRange(at(15, undefined, "b.js"), range)).toBe(false);
    expect(evidenceInRange(at(undefined), range)).toBe(true); // file-level evidence, line-ranged key
    expect(evidenceInRange(at(1), { path: "a.js" })).toBe(true); // whole-file key
  });
});

describe("choosing components and batches", () => {
  it("takes the components of supported threats the labels tie to the id", () => {
    expect(componentsByLabels(model, labels, ["NG-NOSQL-WHERE"])).toEqual(["allocations-handler", "mongodb"]);
  });

  it("ignores a threat labelled unsupported", () => {
    const unsupported = labels.map((l) => (l.matches.includes("NG-NOSQL-WHERE") ? { ...l, supported: false } : l));
    expect(componentsByLabels(model, unsupported, ["NG-NOSQL-WHERE"])).toEqual([]);
  });

  it("can instead take components whose files hold the key's source file", () => {
    expect(componentsByFiles(architecture, sources, ["NG-NOSQL-WHERE"])).toContain("allocations-handler");
  });

  it("selects whole batches from the full batching, never re-cut, in run order", () => {
    const { all, selected } = selectBatches(architecture, ["allocations-handler", "mongodb"]);
    const full = batchElements(architecture);
    expect(all).toBe(full.length);
    expect(selected.length).toBeGreaterThan(0);
    expect(selected.length).toBeLessThan(all);
    for (const batch of selected) expect(full).toContainEqual(batch);
    expect(selected.map((b) => full.indexOf(b))).toEqual([...selected.map((b) => full.indexOf(b))].sort((a, b) => a - b));
    for (const id of ["allocations-handler", "mongodb"]) expect(selected.flat()).toContain(id);
  });
});

describe("planMini", () => {
  it("plans a subset of the batches for the chosen ids", () => {
    const plan = planMini({ args: ARGS, model, labels, sources, architecture });
    expect(plan.componentIds).toEqual(["allocations-handler", "mongodb"]);
    expect(plan.selected.length).toBeLessThan(plan.all);
  });

  it("refuses a checkpoint whose architecture lacks a component the result's threats name", () => {
    const other = { ...architecture, components: architecture.components.filter((c) => c.id !== "mongodb") };
    expect(() => planMini({ args: ARGS, model, labels, sources, architecture: other })).toThrow(
      /no component mongodb.*--by-files/,
    );
  });

  it("refuses when no labelled threat matches, and suggests --by-files", () => {
    expect(() => planMini({ args: { ...ARGS, ids: ["NG-NOT-LABELLED"] }, model, labels, sources, architecture })).toThrow(
      /--by-files/,
    );
  });

  it("works from the key's source files alone with --by-files", () => {
    const plan = planMini({ args: { ...ARGS, byFiles: true }, model, labels: [], sources, architecture });
    expect(plan.componentIds).toContain("allocations-handler");
  });
});

describe("recall", () => {
  it("counts an id as found when a threat cites evidence inside the key's range", () => {
    const evidence = [
      { id: "ev-in", filePath: "app/data/allocations-dao.js", lineStart: 77 },
      { id: "ev-out", filePath: "app/data/allocations-dao.js", lineStart: 5 },
    ] as unknown as Parameters<typeof proxyRecall>[1];
    expect(proxyRecall([{ evidenceIds: ["ev-in"] }], evidence, sources, ["NG-NOSQL-WHERE"]).found).toEqual(["NG-NOSQL-WHERE"]);
    expect(proxyRecall([{ evidenceIds: ["ev-out"] }], evidence, sources, ["NG-NOSQL-WHERE"]).found).toEqual([]);
    expect(proxyRecall([], evidence, new Map(), ["NG-X"]).unlocatable).toEqual(["NG-X"]);
  });

  it("reproduces the hand-labelled recall on the saved run for ids the labels recall", () => {
    expect(labelledRecall(labels, ["NG-NOSQL-WHERE", "NG-SSJS-EVAL", "NG-NOT-LABELLED"])).toEqual([
      "NG-NOSQL-WHERE",
      "NG-SSJS-EVAL",
    ]);
  });

  it("finds NG-NOSQL-WHERE by location on the saved run, as the labels do", () => {
    const found = proxyRecall(model.threats, model.evidence, sources, ["NG-NOSQL-WHERE"]).found;
    expect(found).toEqual(["NG-NOSQL-WHERE"]);
  });
});

describe("runMini", () => {
  function fakeEngine(threats: ThreatEngineResult["threats"] = []) {
    return vi.fn(
      async (input: ThreatEngineInput): Promise<ThreatEngineResult> => ({
        threats,
        evidence: [],
        limitations: [],
        batches: (input.batches ?? []).map((elementIds, index) => ({ index, elementIds: [...elementIds], returned: 0 })),
        usage: [],
        promptId: "threats.test",
      }),
    );
  }

  it("runs only the selected batches, as one engine call, and reports the cost it is given", async () => {
    const generateThreats = fakeEngine([
      { id: "threat-1", evidenceIds: ["ev-semgrep-1"] } as ThreatEngineResult["threats"][number],
    ]);
    const report = await runMini(
      {
        args: ARGS,
        model,
        labels,
        sources,
        architecture,
        engine: { gaps: [], files: [] },
        analysisId: "mini-test",
      },
      { generateThreats, cost: () => ({ totalUsd: 0.4321, calls: 4, cachedCalls: 1 }) },
    );

    expect(generateThreats).toHaveBeenCalledTimes(1);
    const sent = generateThreats.mock.calls[0][0];
    const plan = planMini({ args: ARGS, model, labels, sources, architecture });
    expect(sent.batches).toEqual(plan.selected);
    expect(sent.analysisId).toBe("mini-test");
    expect(sent.architecture).toBe(architecture);

    expect(report).toMatchObject({
      ids: ["NG-NOSQL-WHERE"],
      batches: { run: plan.selected.length, of: plan.all },
      newThreats: 1,
      labelledSaved: ["NG-NOSQL-WHERE"],
      proxySaved: ["NG-NOSQL-WHERE"],
      proxyNew: ["NG-NOSQL-WHERE"],
      costUsd: 0.4321,
      calls: 4,
      cachedCalls: 1,
    });
    const text = formatMiniReport(report).join("\n");
    expect(text).toContain("this run, location proxy:      1/1 (NG-NOSQL-WHERE)");
    expect(text).toContain("cost: $0.4321 (4 response(s), 1 from the model cache)");
    expect(text).toContain("not hand-labelled recall");
  });

  it("reports a miss when the new threats cite nothing in range", async () => {
    const report = await runMini(
      { args: ARGS, model, labels, sources, architecture, engine: { gaps: [], files: [] }, analysisId: "mini-test" },
      { generateThreats: fakeEngine(), cost: () => ({ totalUsd: 0, calls: 0, cachedCalls: 0 }) },
    );
    expect(report.proxyNew).toEqual([]);
    expect(formatMiniReport(report).join("\n")).toContain("this run, location proxy:      0/1");
  });

  it("makes no engine call when the plan fails", async () => {
    const generateThreats = fakeEngine();
    await expect(
      runMini(
        { args: { ...ARGS, ids: ["NG-NOT-LABELLED"] }, model, labels, sources, architecture, engine: { gaps: [], files: [] }, analysisId: "x" },
        { generateThreats, cost: () => ({ totalUsd: 0, calls: 0, cachedCalls: 0 }) },
      ),
    ).rejects.toThrow();
    expect(generateThreats).not.toHaveBeenCalled();
  });
});

describe("architecture checkpoint serialisation", () => {
  it("round-trips the Maps through JSON", () => {
    const back = deserializeArchitecture(JSON.parse(JSON.stringify(serializeArchitecture(architecture))));
    expect(back.gapBindings).toEqual(architecture.gapBindings);
    expect(back.componentEvidence.get("express-app")).toEqual(["ev-gap-1"]);
    expect(back.components).toEqual(architecture.components);
    expect(back.flowEvidence).toBeInstanceOf(Map);
  });
});
