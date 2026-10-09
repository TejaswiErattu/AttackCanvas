/**
 * Replay mode: serve a saved ThreatModel for a repository instead of analysing it.
 *
 * When ATTACKCANVAS_REPLAY_DIR is set and NODE_ENV is not "production", POST /api/analyze
 * looks for <dir>/<owner>__<repo>.json before touching GitHub or a model. A file that
 * exists and validates as a ThreatModel completes the job at once, marked `replayed`;
 * anything else (no file, unreadable, invalid) falls through to a normal run. It exists so
 * the dashboard can be worked on against a real result without paying for one.
 *
 * In production the variable is ignored and a warning is logged once: a deployed instance
 * must never answer a real repository URL with a canned result.
 *
 * The file is matched case-insensitively, because GitHub owner and repo names are. The
 * owner and repo have already passed parseGitHubUrl, and a name holding anything but
 * letters, digits, ".", "_" and "-" is refused here anyway, so no path can escape `dir`.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { validateThreatModel, type ThreatModel } from "@/shared/schema";
import { log } from "@/server/log";
import type { AnalysisState } from "@/server/analysis/pipeline";

export const REPLAY_DIR_ENV = "ATTACKCANVAS_REPLAY_DIR";

/** The diagnostic line a replayed job carries. */
export const REPLAYED_DIAGNOSTIC = "replayed: true (served from ATTACKCANVAS_REPLAY_DIR)";

const SAFE_NAME = /^[A-Za-z0-9._-]{1,100}$/;

let warned = false;

/** Test seam: forget that the production warning was already logged. */
export function resetReplayWarning(): void {
  warned = false;
}

/**
 * The replay directory, or undefined when replay is off: unset, blank, or production. In
 * production a set variable is logged once (the name only, never the value).
 */
export function replayDir(
  env: Record<string, string | undefined> = process.env,
): string | undefined {
  const dir = env[REPLAY_DIR_ENV]?.trim();
  if (!dir) return undefined;
  if (env.NODE_ENV === "production") {
    if (!warned) {
      warned = true;
      try {
        log("warn", `${REPLAY_DIR_ENV} is set but ignored in production`);
      } catch {
        // A warning must never fail a request.
      }
    }
    return undefined;
  }
  return dir;
}

/** `<owner>__<repo>.json`, or undefined for a name that could not be a file name here. */
export function replayFileName(owner: string, repo: string): string | undefined {
  if (!SAFE_NAME.test(owner) || !SAFE_NAME.test(repo)) return undefined;
  return `${owner}__${repo}.json`;
}

/**
 * The saved ThreatModel for owner/repo, or undefined when there is none or it does not
 * validate. Never throws: every failure means "run normally".
 */
export function loadReplay(dir: string, owner: string, repo: string): ThreatModel | undefined {
  const wanted = replayFileName(owner, repo)?.toLowerCase();
  if (!wanted) return undefined;
  try {
    const match = readdirSync(dir).find((name) => name.toLowerCase() === wanted);
    if (!match) return undefined;
    const validated = validateThreatModel(JSON.parse(readFileSync(join(dir, match), "utf8")));
    return validated.ok ? validated.data : undefined;
  } catch {
    return undefined;
  }
}

/** Moves a freshly created job straight to "complete" with the replayed model. */
export function completeReplayed(state: AnalysisState, model: ThreatModel): void {
  state.threatModel = model;
  state.replayed = true;
  state.diagnostics = [...state.diagnostics, REPLAYED_DIAGNOSTIC];
  state.stage = "complete";
  state.updatedAt = Date.now();
}
