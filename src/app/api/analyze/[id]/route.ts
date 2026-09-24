/**
 * GET /api/analyze/[id] -- polls one analysis.
 *
 * Response: { stage, stageLabel, stageIndex, stageCount, questions?, threatModel?,
 * basisCounts?, hiddenSummary?, error? } or a 404 when the id is unknown or has expired.
 *
 * `threatModel` is the adapted DashboardViewModel (src/client/adapter.ts), not the raw
 * schema ThreatModel: the raw model's internal evidence graph and un-laid-out ids are not
 * what a React Flow dashboard renders, which is exactly why toDashboardViewModel exists.
 * It is included whenever the state carries a threatModel, which is true from
 * "awaiting_answers" onward, not only at "complete" -- a client can show partial results
 * while questions are pending.
 *
 * `basisCounts` (Prompt V Part 1: a derived count, never a new schema field) is sent under
 * the same condition but is NOT counted over that view: it tallies ALL scored threats in
 * the raw model, including the ones below 0.25 confidence the view hides. The dashboard
 * labels it accordingly ("Across all scored threats", src/components/SeveritySummary.tsx).
 * `hiddenSummary` is derived the same way, so the empty state can say how many threats
 * were scored and hidden, and why, instead of "no threats".
 */

import { NextResponse, type NextRequest } from "next/server";
import {
  toAnalysisError,
  toAnalysisStatus,
  toDashboardViewModel,
  toQuestionData,
} from "@/client/adapter";
import { countByBasis, getAnalysis, summarizeHidden } from "@/server/analysis/pipeline";
import { notFoundResponse } from "@/server/http/errors";

export const runtime = "nodejs";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
): Promise<NextResponse> {
  const { id } = await params;
  const state = getAnalysis(id);
  if (!state) return notFoundResponse();

  const status = toAnalysisStatus(state.stage);

  return NextResponse.json({
    ...status,
    questions: state.questions ? toQuestionData(state.questions) : undefined,
    threatModel: state.threatModel ? toDashboardViewModel(state.threatModel) : undefined,
    basisCounts: state.threatModel ? countByBasis(state.threatModel.threats) : undefined,
    hiddenSummary: state.threatModel ? summarizeHidden(state.threatModel.threats) : undefined,
    error: state.error ? toAnalysisError(state.error.code, state.error.message) : undefined,
  });
}
