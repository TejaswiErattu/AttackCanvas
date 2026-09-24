/**
 * POST /api/analyze/[id]/answers -- submits developer answers and resumes the analysis.
 *
 * Only valid when the job is at "awaiting_answers"; anything else is a 409. Body:
 * { answers: { questionId, status: "answered"|"skipped"|"unsure", optionIndex? }[] }.
 * resumeWithAnswers (src/server/analysis/pipeline.ts) is started WITHOUT awaiting, same
 * as POST /api/analyze -- it is pure/synchronous today (applyAnswers does no I/O), but
 * not awaiting keeps this route correct if that ever changes.
 *
 * `state.isDemo` (set explicitly at createAnalysis time, never inferred) picks between
 * resumeWithAnswers for a real job and resumeDemoAnalysis for the golden-demo path
 * (src/server/analysis/demo.ts), which has no QuestionEffects to re-score with since
 * nothing real ran. `answers` is still Zod-validated either way -- a malformed body is
 * rejected before either function is called. A second POST for the same id 409s: the
 * stage is checked once up front and AGAIN after the body has been read (that read is
 * this handler's only await), and both resumeWithAnswers and resumeDemoAnalysis move the
 * job off "awaiting_answers" synchronously. So a duplicate whose body was still arriving
 * when the first one resumed the job finds it gone at the second check, instead of
 * getting a 202 for answers that were silently never applied.
 *
 * The body is capped (MAX_ANSWERS entries, MAX_QUESTION_ID_LENGTH per id): there are at
 * most 3 questions, and an unbounded array let a single request pin the event loop.
 */

import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { getAnalysis, resumeWithAnswers } from "@/server/analysis/pipeline";
import { resumeDemoAnalysis } from "@/server/analysis/demo";
import { errorResponse, notFoundResponse } from "@/server/http/errors";

export const runtime = "nodejs";

/** Room for the at most 3 questions (MAX_QUESTIONS in src/server/questions) plus a few repeats. */
const MAX_ANSWERS = 10;

/** Question ids are short kebab-case ("question-1"); 64 is generous. */
const MAX_QUESTION_ID_LENGTH = 64;

const AnswersRequestSchema = z.object({
  answers: z
    .array(
      z.object({
        questionId: z.string().min(1).max(MAX_QUESTION_ID_LENGTH),
        status: z.enum(["answered", "skipped", "unsure"]),
        optionIndex: z.number().int().min(0).optional(),
      }),
    )
    .min(1)
    .max(MAX_ANSWERS),
});

/** ERROR_COPY's own message says why and what to do (reload to see where it stands). */
function notAwaitingAnswers(): NextResponse {
  return errorResponse(409, "NOT_AWAITING_ANSWERS");
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
  const { id } = await params;
  const initial = getAnalysis(id);
  if (!initial) return notFoundResponse();
  if (initial.stage !== "awaiting_answers") return notAwaitingAnswers();

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, "INVALID_REQUEST", "Request body must be JSON.");
  }
  const parsedBody = AnswersRequestSchema.safeParse(body);
  if (!parsedBody.success) {
    return errorResponse(
      400,
      "INVALID_REQUEST",
      `answers must be a non-empty array of at most ${MAX_ANSWERS} entries, each with a ` +
        `questionId of at most ${MAX_QUESTION_ID_LENGTH} characters, a status of ` +
        `"answered", "skipped" or "unsure", and an optional whole-number optionIndex.`,
    );
  }

  // Re-read after the await: a concurrent POST may have resumed (or the TTL expired) the
  // job while this body was arriving. Nothing below awaits, so this check holds through
  // the synchronous resume call.
  const state = getAnalysis(id);
  if (!state) return notFoundResponse();
  if (state.stage !== "awaiting_answers") return notAwaitingAnswers();

  if (state.isDemo) {
    void resumeDemoAnalysis(id);
  } else {
    void resumeWithAnswers(id, parsedBody.data.answers);
  }

  const current = getAnalysis(id);
  return NextResponse.json({ status: current?.stage ?? state.stage }, { status: 202 });
}
