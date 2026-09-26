/**
 * POST /api/analyze. src/server/analysis/pipeline.ts and src/server/analysis/demo.ts are
 * mocked: the route's own job is validation against the frozen AnalysisRequestSchema,
 * rate limiting and choosing which of runAnalysis / seedDemoAnalysis to start, not what
 * those do -- that is tests/pipeline.test.ts's job.
 */

import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  resetRateLimiter,
  MAX_CONCURRENT_ANALYSES,
  RATE_LIMIT_MAX,
} from "@/server/http/rateLimit";

vi.mock("@/server/analysis/pipeline", () => ({
  countActiveAnalyses: vi.fn(),
  createAnalysis: vi.fn(),
  findActiveAnalysis: vi.fn(),
  getAnalysis: vi.fn(),
  runAnalysis: vi.fn(),
}));
vi.mock("@/server/analysis/demo", () => ({
  seedDemoAnalysis: vi.fn(),
}));
vi.mock("@/server/log", () => ({ log: vi.fn() }));

import { POST } from "@/app/api/analyze/route";
import {
  countActiveAnalyses,
  createAnalysis,
  findActiveAnalysis,
  getAnalysis,
  runAnalysis,
} from "@/server/analysis/pipeline";
import { seedDemoAnalysis } from "@/server/analysis/demo";
import { resetAllowlistWarning } from "@/server/http/ownerAllowlist";

const VALID_URL = "https://github.com/acme/canary";

function postRequest(body: unknown, ip = "9.9.9.9"): NextRequest {
  return new NextRequest("http://localhost/api/analyze", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const originalGolden = process.env.GOLDEN_REPO_URL;
const originalFallback = process.env.DEMO_FALLBACK;
const originalOwners = process.env.ATTACKCANVAS_ALLOWED_OWNERS;

beforeEach(() => {
  resetRateLimiter();
  vi.mocked(countActiveAnalyses).mockReset().mockReturnValue(0); // room to spare, by default
  vi.mocked(createAnalysis).mockReset();
  vi.mocked(findActiveAnalysis).mockReset().mockReturnValue(undefined); // nothing running, by default
  vi.mocked(getAnalysis).mockReset();
  vi.mocked(runAnalysis).mockReset();
  vi.mocked(seedDemoAnalysis).mockReset();
  delete process.env.GOLDEN_REPO_URL;
  delete process.env.DEMO_FALLBACK;
  delete process.env.ATTACKCANVAS_ALLOWED_OWNERS;
  resetAllowlistWarning();
});

afterEach(() => {
  if (originalOwners === undefined) delete process.env.ATTACKCANVAS_ALLOWED_OWNERS;
  else process.env.ATTACKCANVAS_ALLOWED_OWNERS = originalOwners;
  if (originalGolden === undefined) delete process.env.GOLDEN_REPO_URL;
  else process.env.GOLDEN_REPO_URL = originalGolden;
  if (originalFallback === undefined) delete process.env.DEMO_FALLBACK;
  else process.env.DEMO_FALLBACK = originalFallback;
});

describe("POST /api/analyze", () => {
  it("400s on a body that is not JSON", async () => {
    const request = new NextRequest("http://localhost/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "not json",
    });
    const response = await POST(request);
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error.code).toBe("INVALID_REQUEST");
    expect(json.error.title).toBe("Invalid request");
    expect(json.error.message).toBe("Request body must be JSON.");
    expect(createAnalysis).not.toHaveBeenCalled();
  });

  it("400s with INVALID_URL when repoUrl is missing, before creating a job", async () => {
    const response = await POST(postRequest({ analysisLevel: 2 }));
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error.code).toBe("INVALID_URL");
    expect(createAnalysis).not.toHaveBeenCalled();
  });

  it("400s with INVALID_REQUEST when both repoUrl and analysisLevel are wrong", async () => {
    const response = await POST(postRequest({ repoUrl: "nope", analysisLevel: 9 }));
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error.code).toBe("INVALID_REQUEST");
    expect(json.error.message).toContain("analysisLevel must be 0, 1, 2, 3, or 4");
    expect(createAnalysis).not.toHaveBeenCalled();
  });

  it("400s when analysisLevel is missing (the contract requires it), before creating a job", async () => {
    const response = await POST(postRequest({ repoUrl: VALID_URL }));
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error.code).toBe("INVALID_REQUEST");
    expect(createAnalysis).not.toHaveBeenCalled();
  });

  it("400s when analysisLevel is out of range, before creating a job", async () => {
    const response = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 7 }));
    expect(response.status).toBe(400);
    expect(createAnalysis).not.toHaveBeenCalled();
    expect(runAnalysis).not.toHaveBeenCalled();
  });

  it("rejects the shorthand owner/repo form -- the public contract requires a full URL", async () => {
    const response = await POST(postRequest({ repoUrl: "acme/canary", analysisLevel: 2 }));
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error.code).toBe("INVALID_URL");
    expect(createAnalysis).not.toHaveBeenCalled();
  });

  it("400s on a URL AnalysisRequestSchema accepts but parseGitHubUrl rejects (not github.com), without calling runAnalysis", async () => {
    const response = await POST(
      postRequest({ repoUrl: "https://example.com/acme/canary", analysisLevel: 2 }),
    );
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error.code).toBe("INVALID_URL");
    expect(runAnalysis).not.toHaveBeenCalled();
    expect(createAnalysis).not.toHaveBeenCalled();
  });

  // ---------------------------------------------------------------------------
  // Prompt U, Part 2: the public route must never accept a fixture: repo URL, in any
  // environment. src/server/ingest/fixtureLoader.ts's environment gate protects the
  // pipeline dispatch, but this route never calls that dispatch at all -- it validates
  // with the plain, fixture-unaware parseGitHubUrl (see the route's own header comment) --
  // so a fixture: URL is rejected here unconditionally, before createAnalysis exists.
  // ---------------------------------------------------------------------------

  it.each(["development", "test", "production", undefined])(
    "400s on a fixture: repoUrl regardless of NODE_ENV (%s), without creating a job",
    async (nodeEnv) => {
      vi.stubEnv("NODE_ENV", nodeEnv);
      try {
        const response = await POST(
          postRequest({ repoUrl: "fixture:canary-repo", analysisLevel: 2 }),
        );
        expect(response.status).toBe(400);
        const json = await response.json();
        expect(json.error.code).toBe("INVALID_URL");
        expect(createAnalysis).not.toHaveBeenCalled();
        expect(runAnalysis).not.toHaveBeenCalled();
      } finally {
        vi.unstubAllEnvs();
      }
    },
  );

  it("400s on a fixture: URL using the double-slash / shorthand-like variants too", async () => {
    for (const repoUrl of [
      "fixture://canary-repo",
      "FIXTURE:canary-repo",
      " fixture:canary-repo",
      "fixture:../secrets",
    ]) {
      const response = await POST(postRequest({ repoUrl, analysisLevel: 2 }));
      expect(response.status, repoUrl).toBe(400);
      const json = await response.json();
      expect(json.error.code, repoUrl).toBe("INVALID_URL");
    }
    expect(createAnalysis).not.toHaveBeenCalled();
  });

  it("accepts a full github.com URL and starts runAnalysis with an explicit isDemo: false", async () => {
    vi.mocked(createAnalysis).mockReturnValue({ id: "job-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-1", stage: "loading_repo" } as never);

    const response = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }));

    expect(response.status).toBe(202);
    const json = await response.json();
    expect(json).toEqual({ analysisId: "job-1", status: "loading_repo" });
    expect(createAnalysis).toHaveBeenCalledWith(VALID_URL, 2, { isDemo: false });
    expect(runAnalysis).toHaveBeenCalledWith("job-1");
    expect(seedDemoAnalysis).not.toHaveBeenCalled();
  });

  it("coalesces a duplicate of a running analysis instead of starting a second one (bug bash case 10)", async () => {
    const running = {
      id: "job-running",
      stage: "generating_threats",
      repoUrl: "https://github.com/Acme/Canary.git",
      analysisLevel: 2,
      isDemo: false,
    };
    vi.mocked(findActiveAnalysis).mockImplementation((matches) =>
      matches(running as never) ? (running as never) : undefined,
    );
    vi.mocked(countActiveAnalyses).mockReturnValue(MAX_CONCURRENT_ANALYSES); // cap full: the duplicate must not care

    const response = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }));

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ analysisId: "job-running", status: "generating_threats" });
    expect(createAnalysis).not.toHaveBeenCalled();
    expect(runAnalysis).not.toHaveBeenCalled();
  });

  it("does not coalesce across a different ref or analysisLevel", async () => {
    const running = {
      id: "job-running",
      stage: "scanning",
      repoUrl: "https://github.com/acme/canary/tree/feature/x",
      analysisLevel: 2,
      isDemo: false,
    };
    vi.mocked(findActiveAnalysis).mockImplementation((matches) =>
      matches(running as never) ? (running as never) : undefined,
    );
    vi.mocked(createAnalysis).mockReturnValue({ id: "job-new", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-new", stage: "loading_repo" } as never);

    const byRef = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }));
    expect((await byRef.json()).analysisId).toBe("job-new");

    const byLevel = await POST(
      postRequest({ repoUrl: `${VALID_URL}/tree/feature/x`, analysisLevel: 3 }, "9.9.9.10"),
    );
    expect((await byLevel.json()).analysisId).toBe("job-new");
    expect(createAnalysis).toHaveBeenCalledTimes(2);
  });

  it("refuses level 4 with the friendly message, before any job, cap or rate-limit spend", async () => {
    const response = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 4 }, "7.7.7.7"));
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error.code).toBe("INVALID_REQUEST");
    expect(body.error.message).toMatch(/pick a level from 0 to 3/);
    expect(createAnalysis).not.toHaveBeenCalled();
    expect(runAnalysis).not.toHaveBeenCalled();
  });

  it("passes every unlocked analysisLevel (0-3) through unchanged", async () => {
    for (const level of [0, 1, 2, 3] as const) {
      vi.mocked(createAnalysis).mockReturnValue({ id: `job-${level}`, stage: "queued" } as never);
      vi.mocked(getAnalysis).mockReturnValue({ id: `job-${level}`, stage: "loading_repo" } as never);

      const response = await POST(
        postRequest({ repoUrl: VALID_URL, analysisLevel: level }, `1.1.1.${level}`),
      );

      expect(response.status).toBe(202);
      expect(createAnalysis).toHaveBeenLastCalledWith(VALID_URL, level, { isDemo: false });
    }
  });

  it("429s once the rate limit is exceeded, before creating a job", async () => {
    vi.mocked(createAnalysis).mockReturnValue({ id: "job-x", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-x", stage: "loading_repo" } as never);

    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      const ok = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }, "5.5.5.5"));
      expect(ok.status).toBe(202);
    }
    const limited = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }, "5.5.5.5"));
    expect(limited.status).toBe(429);
    const json = await limited.json();
    expect(json.error.code).toBe("RATE_LIMITED");
    expect(json.error.message).toContain(`You've started ${RATE_LIMIT_MAX} analyses within an hour`);
    expect(json.error.canRetry).toBe(true);
    expect(createAnalysis).toHaveBeenCalledTimes(RATE_LIMIT_MAX);
  });

  // ---------------------------------------------------------------------------
  // Prompt U, Part 2: the global concurrency cap
  // ---------------------------------------------------------------------------

  it("429s with SERVER_BUSY when countActiveAnalyses is already at the cap, without creating a job", async () => {
    vi.mocked(countActiveAnalyses).mockReturnValue(MAX_CONCURRENT_ANALYSES);

    const response = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }));

    expect(response.status).toBe(429);
    const json = await response.json();
    expect(json.error.code).toBe("SERVER_BUSY");
    expect(json.error.title).toBe("AttackCanvas is busy");
    expect(json.error.message).toContain(
      `already running ${MAX_CONCURRENT_ANALYSES} analyses`,
    );
    expect(createAnalysis).not.toHaveBeenCalled();
    expect(runAnalysis).not.toHaveBeenCalled();
  });

  it("accepts the request when countActiveAnalyses is just below the cap", async () => {
    vi.mocked(countActiveAnalyses).mockReturnValue(MAX_CONCURRENT_ANALYSES - 1);
    vi.mocked(createAnalysis).mockReturnValue({ id: "job-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-1", stage: "loading_repo" } as never);

    const response = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }));

    expect(response.status).toBe(202);
    expect(createAnalysis).toHaveBeenCalledTimes(1);
  });

  it("admits only ONE of two simultaneous requests for the last free slot", async () => {
    // The property under test is that nothing `await`s between the concurrency check
    // and createAnalysis. Node runs one request at a time, but both POST calls DO
    // interleave at `await request.json()` near the top -- so if the check and the
    // create were separated by any further await, both would resume, both would read
    // the same stale count of 1, and both would be admitted under a cap of 2.
    //
    // Stateful mocks make that observable: createAnalysis is what advances the count,
    // exactly as the real store does.
    let active = MAX_CONCURRENT_ANALYSES - 1; // one slot left
    vi.mocked(countActiveAnalyses).mockImplementation(() => active);
    vi.mocked(createAnalysis).mockImplementation(() => {
      active += 1;
      return { id: `job-${active}`, stage: "queued" } as never;
    });
    vi.mocked(getAnalysis).mockImplementation(
      () => ({ id: "job-x", stage: "loading_repo" }) as never,
    );

    const [first, second] = await Promise.all([
      POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 })),
      POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 })),
    ]);

    const statuses = [first.status, second.status].sort();
    expect(statuses).toEqual([202, 429]);
    expect(createAnalysis).toHaveBeenCalledTimes(1); // the loser never created a job
    expect(active).toBe(MAX_CONCURRENT_ANALYSES); // never overshot the cap
  });

  it("does NOT apply the concurrency cap to the golden-demo path, even when at the cap", async () => {
    process.env.GOLDEN_REPO_URL = "https://github.com/acme/golden";
    process.env.DEMO_FALLBACK = "1";
    vi.mocked(countActiveAnalyses).mockReturnValue(MAX_CONCURRENT_ANALYSES); // at the cap
    vi.mocked(createAnalysis).mockReturnValue({ id: "demo-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "demo-1", stage: "loading_repo" } as never);

    const response = await POST(
      postRequest({ repoUrl: "https://github.com/acme/golden", analysisLevel: 2 }),
    );

    expect(response.status).toBe(202);
    expect(seedDemoAnalysis).toHaveBeenCalledWith("demo-1");
  });

  it("checks the concurrency cap before the rate limit: a 'server busy' 429 does not spend the caller's hourly quota", async () => {
    vi.mocked(createAnalysis).mockReturnValue({ id: "job-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-1", stage: "loading_repo" } as never);

    // Server busy: more refused attempts than the whole hourly quota.
    vi.mocked(countActiveAnalyses).mockReturnValue(MAX_CONCURRENT_ANALYSES);
    for (let i = 0; i < RATE_LIMIT_MAX + 2; i++) {
      const busy = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }, "7.7.7.7"));
      expect(busy.status).toBe(429);
      expect((await busy.json()).error.code).toBe("SERVER_BUSY");
    }
    expect(createAnalysis).not.toHaveBeenCalled();

    // A slot frees up: the caller still has every one of its attempts.
    vi.mocked(countActiveAnalyses).mockReturnValue(0);
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      const ok = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }, "7.7.7.7"));
      expect(ok.status, `attempt ${i + 1}`).toBe(202);
    }
    // ...and the rate limit itself still holds after that.
    const limited = await POST(postRequest({ repoUrl: VALID_URL, analysisLevel: 2 }, "7.7.7.7"));
    expect(limited.status).toBe(429);
    expect((await limited.json()).error.code).toBe("RATE_LIMITED");
    expect(createAnalysis).toHaveBeenCalledTimes(RATE_LIMIT_MAX);
  });

  it("still rate-limits the golden-demo path, which is exempt only from the concurrency cap", async () => {
    process.env.GOLDEN_REPO_URL = "https://github.com/acme/golden";
    process.env.DEMO_FALLBACK = "1";
    vi.mocked(countActiveAnalyses).mockReturnValue(MAX_CONCURRENT_ANALYSES);
    vi.mocked(createAnalysis).mockReturnValue({ id: "demo-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "demo-1", stage: "loading_repo" } as never);
    const demo = () =>
      POST(postRequest({ repoUrl: "https://github.com/acme/golden", analysisLevel: 2 }, "8.8.4.4"));

    for (let i = 0; i < RATE_LIMIT_MAX; i++) expect((await demo()).status).toBe(202);
    expect((await demo()).status).toBe(429);
  });

  it("routes the golden-demo repo to seedDemoAnalysis with isDemo: true, instead of runAnalysis", async () => {
    process.env.GOLDEN_REPO_URL = "https://github.com/acme/golden";
    process.env.DEMO_FALLBACK = "1";
    vi.mocked(createAnalysis).mockReturnValue({ id: "demo-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "demo-1", stage: "loading_repo" } as never);

    const response = await POST(
      postRequest({ repoUrl: "https://github.com/acme/golden", analysisLevel: 2 }),
    );

    expect(response.status).toBe(202);
    expect(createAnalysis).toHaveBeenCalledWith("https://github.com/acme/golden", 2, {
      isDemo: true,
    });
    expect(seedDemoAnalysis).toHaveBeenCalledWith("demo-1");
    expect(runAnalysis).not.toHaveBeenCalled();
  });

  it.each([
    ["a trailing slash", "https://github.com/acme/golden/"],
    ["surrounding whitespace", "https://github.com/acme/golden "],
    ["http://", "http://github.com/acme/golden"],
    ["www.", "https://www.github.com/acme/golden"],
    ["a .git suffix", "https://github.com/acme/golden.git"],
    ["different casing", "https://GitHub.com/Acme/Golden"],
  ])("routes the golden-demo repo to the demo path even with %s", async (_label, repoUrl) => {
    process.env.GOLDEN_REPO_URL = "https://github.com/acme/golden";
    process.env.DEMO_FALLBACK = "1";
    vi.mocked(createAnalysis).mockReturnValue({ id: "demo-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "demo-1", stage: "loading_repo" } as never);

    const response = await POST(postRequest({ repoUrl, analysisLevel: 2 }));

    expect(response.status).toBe(202);
    // AnalysisRequestSchema trims repoUrl before the route sees it.
    expect(createAnalysis).toHaveBeenCalledWith(repoUrl.trim(), 2, { isDemo: true });
    expect(seedDemoAnalysis).toHaveBeenCalledWith("demo-1");
    expect(runAnalysis).not.toHaveBeenCalled();
  });

  it("does not use the demo path for a different repo that merely shares a prefix with the golden one", async () => {
    process.env.GOLDEN_REPO_URL = "https://github.com/acme/golden";
    process.env.DEMO_FALLBACK = "1";
    vi.mocked(createAnalysis).mockReturnValue({ id: "real-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "real-1", stage: "loading_repo" } as never);

    await POST(postRequest({ repoUrl: "https://github.com/acme/golden-demo", analysisLevel: 2 }));

    expect(createAnalysis).toHaveBeenCalledWith("https://github.com/acme/golden-demo", 2, {
      isDemo: false,
    });
    expect(runAnalysis).toHaveBeenCalledWith("real-1");
    expect(seedDemoAnalysis).not.toHaveBeenCalled();
  });

  it("does not use the demo path when DEMO_FALLBACK is unset, even for the golden URL", async () => {
    process.env.GOLDEN_REPO_URL = "https://github.com/acme/golden";
    vi.mocked(createAnalysis).mockReturnValue({ id: "real-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "real-1", stage: "loading_repo" } as never);

    await POST(postRequest({ repoUrl: "https://github.com/acme/golden", analysisLevel: 2 }));

    expect(createAnalysis).toHaveBeenCalledWith("https://github.com/acme/golden", 2, {
      isDemo: false,
    });
    expect(runAnalysis).toHaveBeenCalledWith("real-1");
    expect(seedDemoAnalysis).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// The optional owner allowlist (ATTACKCANVAS_ALLOWED_OWNERS)
// ---------------------------------------------------------------------------

describe("POST /api/analyze: owner allowlist", () => {
  function accept(): void {
    vi.mocked(createAnalysis).mockReturnValue({ id: "job-1", stage: "queued" } as never);
    vi.mocked(getAnalysis).mockReturnValue({ id: "job-1", stage: "loading_repo" } as never);
  }
  const post = (repoUrl: string, ip = "9.9.9.9") => POST(postRequest({ repoUrl, analysisLevel: 2 }, ip));

  it("unset: every owner is analysed, exactly as before", async () => {
    accept();
    for (const url of ["https://github.com/acme/canary", "https://github.com/anyone/anything"]) {
      const response = await post(url);
      expect(response.status, url).toBe(202);
    }
    expect(runAnalysis).toHaveBeenCalledTimes(2);
  });

  it("empty or blank counts as unset", async () => {
    accept();
    for (const value of ["", "  ", ",,"]) {
      process.env.ATTACKCANVAS_ALLOWED_OWNERS = value;
      expect((await post(VALID_URL)).status, JSON.stringify(value)).toBe(202);
    }
  });

  it("allowed: a listed owner is analysed, whatever the casing of the URL or the list", async () => {
    accept();
    process.env.ATTACKCANVAS_ALLOWED_OWNERS = "Widgets, ACME";
    expect((await post("https://github.com/acme/canary")).status).toBe(202);
    expect((await post("https://github.com/WIDGETS/thing")).status).toBe(202);
    expect(runAnalysis).toHaveBeenCalledTimes(2);
  });

  it("blocked: another owner gets 403 OWNER_NOT_ALLOWED, and nothing is started", async () => {
    process.env.ATTACKCANVAS_ALLOWED_OWNERS = "widgets";
    const response = await post("https://github.com/acme/canary");

    expect(response.status).toBe(403);
    const json = await response.json();
    expect(json.error).toMatchObject({
      code: "OWNER_NOT_ALLOWED",
      title: "Owner not allowed on this deployment",
      canRetry: false,
    });
    expect(json.error.message).not.toContain("widgets"); // the list is not disclosed
    expect(createAnalysis).not.toHaveBeenCalled();
    expect(runAnalysis).not.toHaveBeenCalled();
  });

  it("blocked: costs nothing, spending no job slot check and no rate-limit attempt", async () => {
    accept();
    process.env.ATTACKCANVAS_ALLOWED_OWNERS = "widgets";
    for (let i = 0; i < RATE_LIMIT_MAX + 3; i++) {
      expect((await post("https://github.com/acme/canary", "7.7.7.7")).status).toBe(403);
    }
    expect(countActiveAnalyses).not.toHaveBeenCalled();
    // The same address still has its whole hourly budget for an allowed owner.
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      expect((await post("https://github.com/widgets/thing", "7.7.7.7")).status).toBe(202);
    }
  });

  it("blocked: does not match a prefix or a longer name", async () => {
    process.env.ATTACKCANVAS_ALLOWED_OWNERS = "acme";
    for (const url of ["https://github.com/acme2/x", "https://github.com/my-acme/x", "https://github.com/acm/x"]) {
      expect((await post(url)).status, url).toBe(403);
    }
  });

  it("malformed setting: entries that are not owner names are dropped, the valid ones still work", async () => {
    accept();
    process.env.ATTACKCANVAS_ALLOWED_OWNERS = "acme, acme/shop, @bad";
    expect((await post("https://github.com/acme/canary")).status).toBe(202);
    expect((await post("https://github.com/shop/x")).status).toBe(403);
  });

  it("malformed setting with nothing valid: every owner is refused, never everyone allowed", async () => {
    process.env.ATTACKCANVAS_ALLOWED_OWNERS = "acme/shop, https://github.com/acme, -x";
    for (const url of ["https://github.com/acme/canary", "https://github.com/shop/x"]) {
      const response = await post(url);
      expect(response.status, url).toBe(403);
      expect((await response.json()).error.code).toBe("OWNER_NOT_ALLOWED");
    }
    expect(createAnalysis).not.toHaveBeenCalled();
  });

  it("a malformed URL is still INVALID_URL, decided before the allowlist", async () => {
    process.env.ATTACKCANVAS_ALLOWED_OWNERS = "acme";
    const response = await post("https://example.com/acme/canary");
    expect(response.status).toBe(400);
    expect((await response.json()).error.code).toBe("INVALID_URL");
  });

  it("the golden demo is exempt: it reads nothing and calls no model", async () => {
    accept();
    process.env.DEMO_FALLBACK = "1";
    process.env.GOLDEN_REPO_URL = "https://github.com/acme/golden";
    process.env.ATTACKCANVAS_ALLOWED_OWNERS = "widgets";

    expect((await post("https://github.com/acme/golden")).status).toBe(202);
    expect(seedDemoAnalysis).toHaveBeenCalledTimes(1);
    // Only that one repo: another acme repo is still refused.
    expect((await post("https://github.com/acme/other")).status).toBe(403);
  });
});
