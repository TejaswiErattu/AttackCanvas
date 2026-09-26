/**
 * POST /api/analyze -- starts an analysis and returns immediately.
 *
 * Body: validated with the frozen AnalysisRequestSchema (src/shared/schema/request.ts) --
 * { repoUrl: url, analysisLevel: 0|1|2|3|4 }, both required. The public API therefore
 * accepts a full GitHub URL only, not the shorthand "owner/repo" form parseGitHubUrl also
 * accepts; scripts (scripts/try-pipeline.ts) may keep accepting shorthand and normalizing
 * it themselves before calling into the pipeline, but this route -- the contract's own
 * boundary -- validates against the contract as written, unchanged.
 *
 * Order, per Prompt V Part 2 (and Prompt U Part 2's addition of the concurrency cap):
 * validate the body against the contract, run the deeper github.com-specific check
 * (host, credentials, length) with parseGitHubUrl, cap global real-analysis concurrency
 * at 2 (skipped for the demo path -- see below), THEN rate-limit per IP (5/hour), create
 * the job, start runAnalysis WITHOUT awaiting it (a full run takes minutes; the route
 * returns the id to poll). Concurrency comes before the rate limit because checking the
 * rate limit spends one of the caller's attempts: a "server busy" 429 must not burn the
 * hourly quota of a caller who never got an analysis. Nothing between the two checks
 * awaits, so no request can slip in between them.
 *
 * A duplicate submission (the same owner/repo/ref and analysisLevel while that analysis is
 * still in flight, a double-click or a retried request) is coalesced: the route answers
 * with the running job's id instead of creating a second one. Checked first, before the
 * concurrency and rate-limit checks, so the duplicate costs its caller nothing and
 * cannot fill the concurrency cap with copies of one run.
 *
 * When ATTACKCANVAS_ALLOWED_OWNERS is set, a repository whose owner is not on the list gets
 * 403 OWNER_NOT_ALLOWED before anything else is checked (src/server/http/ownerAllowlist.ts).
 * Unset, nothing changes.
 *
 * The one exception is the golden-demo repo: when repoUrl
 * matches GOLDEN_REPO_URL and DEMO_FALLBACK=1, the job is created with isDemo: true and
 * seeded from a fixture instead of running the real pipeline (see
 * src/server/analysis/demo.ts) -- isDemo is set explicitly at creation, not inferred
 * later from anything about how the job turns out, and a demo job never competes for
 * (or is throttled by) the concurrency cap, since it never calls a paid model.
 */

import { NextResponse, type NextRequest } from "next/server";
import { AnalysisRequestSchema } from "@/shared/schema";
import { parseGitHubUrl } from "@/server/ingest/urlParser";
import {
  countActiveAnalyses,
  createAnalysis,
  findActiveAnalysis,
  getAnalysis,
  runAnalysis,
} from "@/server/analysis/pipeline";
import { seedDemoAnalysis } from "@/server/analysis/demo";
import { checkOwner } from "@/server/http/ownerAllowlist";
import {
  MAX_CONCURRENT_ANALYSES,
  RATE_LIMIT_MAX,
  checkConcurrency,
  checkRateLimit,
  clientKey,
} from "@/server/http/rateLimit";
import { errorResponse } from "@/server/http/errors";
import type { ErrorCode } from "@/shared/schema";

export const runtime = "nodejs";

/**
 * Compares canonical owner/repo, not raw strings: parseGitHubUrl already accepts a
 * trailing slash, surrounding whitespace, ".git", "http://", "www." and any casing as the
 * same repo, so the demo switch must too -- otherwise such a spelling of the golden URL
 * falls through to the real pipeline and fails with REPO_NOT_FOUND. Case-insensitive
 * because GitHub owner and repo names are.
 */
function isGoldenDemo(submitted: { owner: string; repo: string }): boolean {
  const golden = process.env.GOLDEN_REPO_URL;
  if (process.env.DEMO_FALLBACK !== "1" || !golden) return false;
  const parsedGolden = parseGitHubUrl(golden);
  if (!parsedGolden.ok) return false;
  return (
    parsedGolden.owner.toLowerCase() === submitted.owner.toLowerCase() &&
    parsedGolden.repo.toLowerCase() === submitted.repo.toLowerCase()
  );
}

/** True when `state` analyses the same repository, ref and level as this request. */
function sameAnalysis(
  state: { repoUrl: string; analysisLevel: number },
  submitted: { owner: string; repo: string; ref?: string },
  analysisLevel: number,
): boolean {
  if (state.analysisLevel !== analysisLevel) return false;
  const stored = parseGitHubUrl(state.repoUrl);
  return (
    stored.ok &&
    stored.owner.toLowerCase() === submitted.owner.toLowerCase() &&
    stored.repo.toLowerCase() === submitted.repo.toLowerCase() &&
    (stored.ref ?? "") === (submitted.ref ?? "")
  );
}

/**
 * A safe, generic description of which contract field failed -- never echoes the value --
 * and the code for it: INVALID_URL only when the URL is the sole problem, INVALID_REQUEST
 * for anything else in the body.
 */
function describeRequestIssues(
  issues: readonly { path: ReadonlyArray<string | number | symbol> }[],
): { code: ErrorCode; message: string } {
  const paths = new Set(issues.map((issue) => String(issue.path[0] ?? "")));
  const badUrl = paths.has("repoUrl");
  const badLevel = paths.has("analysisLevel");
  if (badUrl && badLevel) {
    return {
      code: "INVALID_REQUEST",
      message:
        "repoUrl must be a full https://github.com/<owner>/<repo> URL, and analysisLevel must be 0, 1, 2, 3, or 4.",
    };
  }
  if (badUrl) {
    return {
      code: "INVALID_URL",
      message: "repoUrl must be a full https://github.com/<owner>/<repo> URL.",
    };
  }
  if (badLevel) {
    return { code: "INVALID_REQUEST", message: "analysisLevel must be 0, 1, 2, 3, or 4." };
  }
  return { code: "INVALID_REQUEST", message: "Request body did not match the expected shape." };
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, "INVALID_REQUEST", "Request body must be JSON.");
  }

  const parsedBody = AnalysisRequestSchema.safeParse(body);
  if (!parsedBody.success) {
    const { code, message } = describeRequestIssues(parsedBody.error.issues);
    return errorResponse(400, code, message);
  }
  const { repoUrl, analysisLevel } = parsedBody.data;

  // AnalysisRequestSchema only checks repoUrl is *a* URL; parseGitHubUrl does the
  // github.com-specific validation (host, no embedded credentials, length) on top.
  const parsedUrl = parseGitHubUrl(repoUrl);
  if (!parsedUrl.ok) {
    return errorResponse(400, parsedUrl.code, parsedUrl.message);
  }

  const isDemo = isGoldenDemo(parsedUrl);

  // Optional owner allowlist (ATTACKCANVAS_ALLOWED_OWNERS). Checked right after the URL is
  // understood and before anything that counts or spends: a refused owner takes no job
  // slot, no rate-limit attempt, and reaches no GitHub or model. The golden demo is exempt:
  // it serves a canned result and reads nothing.
  if (!isDemo && !checkOwner(parsedUrl.owner)) {
    return errorResponse(403, "OWNER_NOT_ALLOWED");
  }

  // Coalesce a duplicate of an analysis that is still running (see the module header).
  const running = isDemo ? undefined : findActiveAnalysis((state) => sameAnalysis(state, parsedUrl, analysisLevel));
  if (running) {
    return NextResponse.json({ analysisId: running.id, status: running.stage }, { status: 202 });
  }

  // Global concurrency cap, real analyses only (Prompt U Part 2: cost-abuse controls).
  // A demo job never calls a paid model (src/server/analysis/demo.ts), so it neither
  // competes for this budget nor is blocked by it -- checked before createAnalysis so
  // a rejected request never occupies a job slot, and before the rate limit so it never
  // spends one of the caller's hourly attempts either.
  if (!isDemo && !checkConcurrency(countActiveAnalyses())) {
    return errorResponse(
      429,
      "SERVER_BUSY",
      `AttackCanvas is already running ${MAX_CONCURRENT_ANALYSES} analyses, the most it runs at once. Wait a few minutes and try again.`,
    );
  }

  // Per-IP rate limit, demo included. Last of the checks: it records an attempt.
  if (!checkRateLimit(clientKey(request.headers))) {
    return errorResponse(
      429,
      "RATE_LIMITED",
      `You've started ${RATE_LIMIT_MAX} analyses within an hour, the most allowed from one address. Try again later.`,
    );
  }

  const state = createAnalysis(repoUrl, analysisLevel, { isDemo });

  if (isDemo) {
    void seedDemoAnalysis(state.id);
  } else {
    void runAnalysis(state.id);
  }

  // Read the state back rather than assume "queued": runAnalysis's synchronous prefix
  // (up to its first await) already ran by the time control returns here.
  const current = getAnalysis(state.id);
  return NextResponse.json(
    { analysisId: state.id, status: current?.stage ?? state.stage },
    { status: 202 },
  );
}
