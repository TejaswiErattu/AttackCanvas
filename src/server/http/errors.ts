/**
 * A single shape for every JSON error body the analyze routes return, built from
 * ERROR_COPY (src/shared/labels.ts) so an error message is always the same safe copy
 * shown anywhere else in the app (CLAUDE.md rule 8: never a raw upstream message).
 */

import { NextResponse } from "next/server";
import { toAnalysisError } from "@/client/adapter";
import type { ErrorCode } from "@/shared/schema";

/** `message` overrides the default ERROR_COPY text; only pass text safe to show a user. */
export function errorResponse(status: number, code: ErrorCode, message?: string): NextResponse {
  return NextResponse.json({ error: toAnalysisError(code, message) }, { status });
}

/** For an id that does not name a stored analysis -- not a schema ErrorCode, an HTTP 404. */
export function notFoundResponse(): NextResponse {
  return NextResponse.json(
    {
      error: {
        code: "NOT_FOUND",
        title: "Analysis not found",
        message: "No analysis exists with that id, or it has expired.",
        canRetry: false,
      },
    },
    { status: 404 },
  );
}
