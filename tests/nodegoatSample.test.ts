/**
 * fixtures/samples/nodegoat-a3118b6.json, the saved NodeGoat threat model kept as an offline
 * sample (scripts/export-nodegoat-sample.ts), and the guarantee that the demo path does not
 * serve it: a real repository URL must never silently return a canned result.
 */

import { existsSync, readFileSync } from "node:fs";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAnalysis, getAnalysis, resetStore } from "@/server/analysis/pipeline";
import { DEMO_STAGES_BEFORE_QUESTIONS, DEMO_STAGES_NO_QUESTIONS, seedDemoAnalysis } from "@/server/analysis/demo";
import { ThreatModelSchema, validateThreatModel } from "@/shared/schema";
import { goldenProblems, visibleBases } from "../scripts/eval/lib";

const SAMPLE = "fixtures/samples/nodegoat-a3118b6.json";
const fixture: unknown = JSON.parse(readFileSync(SAMPLE, "utf8"));

describe("fixtures/samples/nodegoat-a3118b6.json", () => {
  it("validates against the ThreatModel schema", () => {
    const result = validateThreatModel(fixture);
    expect(result.ok, result.ok ? "" : JSON.stringify(result.issues.slice(0, 3))).toBe(true);
  });

  it("is the NodeGoat model pinned to the commit the answer key was written for", () => {
    expect(ThreatModelSchema.parse(fixture).repo).toMatchObject({
      owner: "OWASP",
      name: "NodeGoat",
      ref: "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
    });
  });

  it("has both bases among visible threats: an evidence_backed and an assumption_dependent one", () => {
    const model = ThreatModelSchema.parse(fixture);
    const bases = visibleBases(model);
    expect(bases.evidenceBacked).toBeGreaterThan(0);
    expect(bases.assumptionDependent).toBeGreaterThan(0);
    expect(goldenProblems(model)).toEqual([]);
  });

  it("is exactly what the export script writes from the saved a3118b6 result", () => {
    const saved = JSON.parse(readFileSync("eval/results/nodegoat-a3118b6.json", "utf8")) as { threatModel: unknown };
    expect(fixture).toEqual(JSON.parse(JSON.stringify(ThreatModelSchema.parse(saved.threatModel))));
  });

  it("carries no local path or credential-shaped string", () => {
    const text = readFileSync(SAMPLE, "utf8");
    expect(text).not.toMatch(/\/Users\/|\/home\/[a-z]/);
    expect(text).not.toMatch(/sk-ant-|ghp_[A-Za-z0-9]|github_pat_|AKIA[0-9A-Z]{12}|BEGIN (?:RSA |EC )?PRIVATE KEY/);
  });
});

describe("the demo does not serve the NodeGoat sample", () => {
  const fast = (stages: typeof DEMO_STAGES_BEFORE_QUESTIONS) => stages.map((s) => ({ ...s, delayMs: 0 }));

  beforeEach(() => resetStore());

  it("keeps no fixtures/golden-demo.json, the file demo.ts would serve for any GOLDEN_REPO_URL", () => {
    expect(existsSync("fixtures/golden-demo.json")).toBe(false);
  });

  it("serves the synthetic acme/acme-notes model, not NodeGoat", async () => {
    const state = createAnalysis("https://github.com/acme/acme-notes", 2, { isDemo: true });
    await seedDemoAnalysis(state.id, fast(DEMO_STAGES_BEFORE_QUESTIONS), fast(DEMO_STAGES_NO_QUESTIONS));
    expect(getAnalysis(state.id)?.threatModel?.repo).toMatchObject({ owner: "acme", name: "acme-notes" });
  });
});

describe("POST /api/analyze with the demo switch on", () => {
  const saved = { golden: process.env.GOLDEN_REPO_URL, fallback: process.env.DEMO_FALLBACK };

  beforeEach(() => {
    resetStore();
    process.env.GOLDEN_REPO_URL = "https://github.com/acme/acme-notes";
    process.env.DEMO_FALLBACK = "1";
  });
  afterEach(() => {
    vi.restoreAllMocks();
    for (const [key, value] of [["GOLDEN_REPO_URL", saved.golden], ["DEMO_FALLBACK", saved.fallback]] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("does not create a demo job for the real NodeGoat URL", async () => {
    const pipeline = await import("@/server/analysis/pipeline");
    const demo = await import("@/server/analysis/demo");
    const run = vi.spyOn(pipeline, "runAnalysis").mockResolvedValue(undefined as never);
    const seed = vi.spyOn(demo, "seedDemoAnalysis").mockResolvedValue(undefined);
    const { POST } = await import("@/app/api/analyze/route");

    const response = await POST(
      new NextRequest("http://localhost/api/analyze", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": "10.9.8.7" },
        body: JSON.stringify({ repoUrl: "https://github.com/OWASP/NodeGoat", analysisLevel: 2 }),
      }),
    );

    expect(response.status).toBe(202);
    const { analysisId } = (await response.json()) as { analysisId: string };
    expect(getAnalysis(analysisId)?.isDemo).toBe(false);
    expect(seed).not.toHaveBeenCalled();
    expect(run).toHaveBeenCalled();
  });
});
