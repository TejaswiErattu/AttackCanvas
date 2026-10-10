import { afterEach, describe, expect, it } from "vitest";
import {
  MAX_TIMEOUT_MS,
  PIPELINE_TIMEOUT_MS,
  createAnalysis,
  getAnalysis,
  resetStore,
  type AnalysisState,
} from "@/server/analysis/pipeline";
import { validateThreatModel, type AnalysisStage, type ThreatModel } from "@/shared/schema";
import { analyseRepo, type PipelineApi } from "../scripts/eval/analyse";
import {
  DEFAULT_RUN_PROFILE,
  StageTracker,
  existingResultPaths,
  formatRunFailure,
  parseRunArgs,
  resolveRunProfile,
  stageBefore,
} from "../scripts/eval/lib";
import { MODELS, activeProfile } from "@/server/ai/models";
import { planFor } from "@/server/ai/levels";
import demoJson from "../fixtures/demo-analysis.json";

const parsed = validateThreatModel(demoJson);
if (!parsed.ok) throw new Error("demo fixture invalid");
const model: ThreatModel = parsed.data;
const repo = { name: "nodegoat", url: "https://github.com/OWASP/NodeGoat/tree/abc" };

afterEach(() => resetStore());

describe("parseRunArgs", () => {
  const parse = (argv: string[]) => parseRunArgs(argv, PIPELINE_TIMEOUT_MS, MAX_TIMEOUT_MS);

  it("defaults to the pipeline timeout when the flag is absent", () => {
    expect(parse(["nodegoat"])).toEqual({ ok: true, value: { names: ["nodegoat"], timeoutMs: PIPELINE_TIMEOUT_MS, level: 2 } });
    expect(parse([])).toEqual({ ok: true, value: { names: [], timeoutMs: PIPELINE_TIMEOUT_MS, level: 2 } });
  });

  it("accepts --timeout before or after repo names", () => {
    expect(parse(["nodegoat", "--timeout", "1200000"])).toEqual({ ok: true, value: { names: ["nodegoat"], timeoutMs: 1_200_000, level: 2 } });
    expect(parse(["--timeout", "1200000", "a", "b"])).toEqual({ ok: true, value: { names: ["a", "b"], timeoutMs: 1_200_000, level: 2 } });
  });

  it.each([["0"], ["-5"], ["1.5"], ["1e6"], ["abc"], [" 100"], [String(MAX_TIMEOUT_MS + 1)]])(
    "rejects --timeout %j",
    (raw) => {
      const r = parse(["nodegoat", "--timeout", raw]);
      expect(r.ok).toBe(false);
    },
  );

  it("rejects a missing value, a repeated flag and unknown options", () => {
    expect(parse(["nodegoat", "--timeout"])).toMatchObject({ ok: false, message: /needs a value/ });
    expect(parse(["--timeout", "--force"])).toMatchObject({ ok: false, message: /needs a value/ });
    expect(parse(["--timeout", "1000", "--timeout", "2000"])).toMatchObject({ ok: false, message: /more than once/ });
    expect(parse(["--timout", "1000"])).toMatchObject({ ok: false, message: /unknown option --timout/ });
  });
});

describe("parseRunArgs --profile", () => {
  const parse = (argv: string[]) => parseRunArgs(argv, PIPELINE_TIMEOUT_MS, MAX_TIMEOUT_MS);

  it("accepts dev and demo, with other flags in any order", () => {
    expect(parse(["juice-shop-l1-r1", "--profile", "dev", "--level", "1"])).toEqual({
      ok: true,
      value: { names: ["juice-shop-l1-r1"], timeoutMs: PIPELINE_TIMEOUT_MS, level: 1, profile: "dev" },
    });
    expect(parse(["--profile", "demo", "--timeout", "1200000", "a"])).toEqual({
      ok: true,
      value: { names: ["a"], timeoutMs: 1_200_000, level: 2, profile: "demo" },
    });
  });

  it("leaves profile unset when the flag is absent", () => {
    const r = parse(["nodegoat"]);
    expect(r.ok && "profile" in r.value).toBe(false);
  });

  it.each([["prod"], ["DEV"], [""], ["dev "]])("rejects --profile %j before any work", (raw) => {
    expect(parse(["a", "--profile", raw])).toMatchObject({ ok: false, message: /--profile must be one of dev, demo/ });
  });

  it("rejects a missing value and a repeated flag", () => {
    expect(parse(["a", "--profile"])).toMatchObject({ ok: false, message: /--profile needs a value/ });
    expect(parse(["--profile", "--level", "1"])).toMatchObject({ ok: false, message: /--profile needs a value/ });
    expect(parse(["--profile", "dev", "--profile", "demo"])).toMatchObject({ ok: false, message: /more than once/ });
  });
});

describe("resolveRunProfile", () => {
  it("keeps the demo default when nothing is requested", () => {
    expect(DEFAULT_RUN_PROFILE).toBe("demo");
    expect(resolveRunProfile(undefined, undefined)).toEqual({ profile: "demo" });
    expect(resolveRunProfile(undefined, "demo")).toEqual({ profile: "demo" });
  });

  it("uses --profile and says so when the shell asked for something else", () => {
    expect(resolveRunProfile("dev", undefined)).toEqual({ profile: "dev" });
    expect(resolveRunProfile("dev", "demo")).toEqual({
      profile: "dev",
      notice: expect.stringMatching(/"demo" from the environment is ignored; using "dev" from --profile/),
    });
  });

  it("never replaces a different shell value silently", () => {
    const r = resolveRunProfile(undefined, "dev");
    expect(r.profile).toBe("demo");
    expect(r.notice).toMatch(/"dev" from the environment is ignored; using "demo" from the eval default/);
  });
});

describe("the profile the runner sets is the one the pipeline plans with", () => {
  const saved = process.env.ATTACKCANVAS_MODEL_PROFILE;
  afterEach(() => {
    if (saved === undefined) delete process.env.ATTACKCANVAS_MODEL_PROFILE;
    else process.env.ATTACKCANVAS_MODEL_PROFILE = saved;
  });

  it.each(["dev", "demo"] as const)("%s reaches planFor through ATTACKCANVAS_MODEL_PROFILE", (requested) => {
    process.env.ATTACKCANVAS_MODEL_PROFILE = resolveRunProfile(requested, "dev").profile;
    expect(activeProfile()).toBe(requested);
    expect(planFor(2, activeProfile()).models).toEqual(MODELS[requested]);
  });

  it("level 1 runs Sonnet on every reasoning stage under either profile", () => {
    expect(planFor(1, "dev").models).toEqual(planFor(1, "demo").models);
  });
});

describe("StageTracker", () => {
  it("keeps the furthest non-terminal stage and ignores failed and regressions", () => {
    const t = new StageTracker();
    t.record("scanning");
    t.record("generating_threats");
    t.record("scanning");
    t.record("failed");
    expect(t.lastSeen).toBe("generating_threats");
    expect(stageBefore("generating_threats")).toBe("mapping_architecture");
    expect(stageBefore("queued")).toBeNull();
  });
});

/** A fake pipeline on the real store: `run`/`resume` walk the given stages, then finish. */
function fakePipeline(opts: {
  runStages: AnalysisStage[];
  runEnd: "awaiting_answers" | "complete" | "failed";
  resumeEnd?: "complete" | "failed";
  cost: { calls: number; totalUsd: number };
}): PipelineApi & { answered: unknown[]; timeouts: number[] } {
  const answered: unknown[] = [];
  const timeouts: number[] = [];
  const tick = () => new Promise((r) => setTimeout(r, 150)); // longer than STAGE_POLL_MS
  const failState = (s: AnalysisState) => {
    s.stage = "failed";
    s.error = { code: "TIMEOUT", message: "safe timeout message" };
    s.threatModel = undefined;
    s.cost = opts.cost;
  };
  return {
    answered,
    timeouts,
    createAnalysis: (url, level, o) => {
      timeouts.push(o.timeoutMs);
      return createAnalysis(url, level, o);
    },
    getAnalysis,
    runAnalysis: async (id) => {
      const s = getAnalysis(id)!;
      for (const stage of opts.runStages) {
        s.stage = stage;
        await tick();
      }
      if (opts.runEnd === "failed") failState(s);
      else if (opts.runEnd === "awaiting_answers") {
        s.stage = "awaiting_answers";
        s.questions = [{ id: "q1" } as never];
        s.threatModel = model;
      } else {
        s.stage = "complete";
        s.threatModel = model;
        s.cost = opts.cost;
      }
      return s;
    },
    resumeWithAnswers: async (id, answers) => {
      answered.push(...answers);
      const s = getAnalysis(id)!;
      s.stage = "finalizing";
      await tick();
      if (opts.resumeEnd === "failed") failState(s);
      else {
        s.stage = "complete";
        s.cost = opts.cost;
      }
      return s;
    },
  };
}

describe("analyseRepo", () => {
  it("passes the timeout through to createAnalysis", async () => {
    const api = fakePipeline({ runStages: [], runEnd: "complete", cost: { calls: 1, totalUsd: 0.1 } });
    await analyseRepo(api, repo, { timeoutMs: 1_200_000, profile: "demo" });
    expect(api.timeouts).toEqual([1_200_000]);
  });

  it("reports a failure mid-run with the stage, the pipeline's cost and no result", async () => {
    const api = fakePipeline({
      runStages: ["loading_repo", "scanning", "mapping_architecture", "generating_threats"],
      runEnd: "failed",
      cost: { calls: 9, totalUsd: 2.3456 },
    });
    let clock = 1_000;
    const out = await analyseRepo(api, repo, { timeoutMs: 600_000, profile: "demo", now: () => (clock += 5_000) });
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out).not.toHaveProperty("result");
    expect(out.failure).toMatchObject({
      failedDuring: "generating_threats",
      phase: "analysis",
      error: { code: "TIMEOUT" },
      cost: { calls: 9, totalUsd: 2.3456 },
      timeoutMs: 600_000,
      elapsedMs: 5_000,
    });
    const lines = formatRunFailure(out.failure).join("\n");
    expect(lines).toContain("FAILED [TIMEOUT] safe timeout message");
    expect(lines).toContain("failed during: generating_threats (last completed: mapping_architecture; phase: analysis)");
    expect(lines).toContain("9 provider response(s), $2.3456");
    expect(lines).toContain("no result written");
  });

  it("attributes a failure after answering to the resume phase", async () => {
    const api = fakePipeline({
      runStages: ["generating_threats"],
      runEnd: "awaiting_answers",
      resumeEnd: "failed",
      cost: { calls: 15, totalUsd: 4 },
    });
    const out = await analyseRepo(api, repo, { timeoutMs: 600_000, profile: "demo" });
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.failure.phase).toBe("resume");
    expect(out.failure.failedDuring).toBe("finalizing");
    expect(api.answered).toEqual([{ questionId: "q1", status: "skipped" }]);
  });

  it("returns a result with the pipeline's cost only when the job completes", async () => {
    const api = fakePipeline({ runStages: ["scanning"], runEnd: "awaiting_answers", resumeEnd: "complete", cost: { calls: 16, totalUsd: 5.5 } });
    const out = await analyseRepo(api, repo, { timeoutMs: 600_000, profile: "demo" });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.result.cost).toEqual({ calls: 16, totalUsd: 5.5 });
    expect(out.result.threatModel.threats.length).toBe(model.threats.length);
  });
});

describe("analyseRepo: a failure within one poll of a stage change", () => {
  /**
   * The juice-shop-l1-r1 case: the architecture stage is polled, the job enters
   * generating_threats, and the first threat batch is refused before the next poll.
   */
  function failsRightAfter(entered: AnalysisStage, recordsFailedStage: boolean): PipelineApi {
    return {
      createAnalysis: (url, level, o) => createAnalysis(url, level, o),
      getAnalysis,
      runAnalysis: async (id) => {
        const s = getAnalysis(id)!;
        for (const stage of ["loading_repo", "scanning", "mapping_architecture"] as const) {
          s.stage = stage;
          await new Promise((r) => setTimeout(r, 150)); // longer than STAGE_POLL_MS
        }
        s.stage = entered; // no await: the poll never sees it
        if (recordsFailedStage) s.failedStage = s.stage; // as pipeline.ts fail() does
        s.stage = "failed";
        s.error = { code: "SECRET_BLOCKED", message: "safe message" };
        s.cost = { calls: 1, totalUsd: 0.28 };
        return s;
      },
      resumeWithAnswers: async () => {
        throw new Error("not reached");
      },
    };
  }

  it("reports the stage the pipeline recorded, not the last one polled", async () => {
    const out = await analyseRepo(failsRightAfter("generating_threats", true), repo, { timeoutMs: 600_000, profile: "dev" });
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.failure.failedDuring).toBe("generating_threats");
    expect(formatRunFailure(out.failure).join("\n")).toContain(
      "failed during: generating_threats (last completed: mapping_architecture; phase: analysis)",
    );
  });

  it("falls back to the last polled stage when the state carries none", async () => {
    const out = await analyseRepo(failsRightAfter("generating_threats", false), repo, { timeoutMs: 600_000, profile: "dev" });
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.failure.failedDuring).toBe("mapping_architecture");
  });
});

describe("existingResultPaths (overwrite guard)", () => {
  const root = "/repo";
  const repos = [
    { name: "nodegoat", url: "u" },
    { name: "nodegoat-after-fix", url: "u" },
  ];

  it("reports an existing result so run.ts refuses", () => {
    const exists = (p: string) => p === "/repo/eval/results/nodegoat.json";
    expect(existingResultPaths(repos, root, exists)).toEqual(["eval/results/nodegoat.json"]);
  });

  it("allows a new result path", () => {
    const exists = (p: string) => p === "/repo/eval/results/nodegoat.json";
    expect(existingResultPaths([repos[1]], root, exists)).toEqual([]);
  });
});
