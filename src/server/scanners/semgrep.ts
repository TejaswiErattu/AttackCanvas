import type { Evidence } from "@/shared/schema";
import { owaspCodesIn } from "@/shared/owaspMap";
import { redact } from "@/server/security/redactor";
import type { RawSemgrepFinding } from "@/server/mcp/semgrepClient";

/**
 * Turns raw Semgrep findings into Evidence.
 *
 * The result is plain, schema-valid `Evidence`: parsing it with EvidenceSchema returns it
 * unchanged. The OWASP mapping rides in `metadata.owasp2025`, a typed field of the
 * schema, so it survives validation and reaches the analysis prompt. Only the 2025 codes
 * are stored: the 2021 tags on a rule are converted by src/shared/owaspMap.ts.
 *
 * What is deliberately not carried: the rule's CWE list, its original 2021 tags and
 * Semgrep's own severity. The schema has no field for them, and severity in particular is
 * computed in scoring, never taken from a scanner (CLAUDE.md rule 2).
 */

/** Six lines is context, not the file. Matches the Semgrep client's own cap. */
export const SNIPPET_MAX_LINES = 6;

/** A summary is one line of context. Longer than this is a rule doc, not a summary. */
export const SUMMARY_MAX_CHARS = 240;

/** Findings are the same finding when these three agree. */
export function dedupeKey(finding: RawSemgrepFinding): string {
  return `${finding.ruleId}\u0000${finding.path}\u0000${finding.startLine}`;
}

function compare(a: RawSemgrepFinding, b: RawSemgrepFinding): number {
  return (
    a.path.localeCompare(b.path) ||
    a.startLine - b.startLine ||
    a.ruleId.localeCompare(b.ruleId) ||
    // Of two findings that dedupe together, keep the one covering more lines.
    b.endLine - a.endLine ||
    a.message.localeCompare(b.message)
  );
}

function oneLine(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`;
}

/**
 * Redacted, capped, and null when there is nothing to show. Semgrep messages can
 * interpolate matched source ("Found $X passed to eval"), so the message is redacted
 * exactly like the snippet is: both are repository content (CLAUDE.md rule 3).
 */
function cleanSnippet(
  snippet: string | undefined,
  path: string,
): string | undefined {
  if (!snippet) return undefined;

  const lines = snippet.split("\n").slice(0, SNIPPET_MAX_LINES).join("\n");
  const redacted = redact(lines, path).content;
  return redacted.trim() === "" ? undefined : redacted;
}

function summaryFor(finding: RawSemgrepFinding): string {
  const redacted = oneLine(redact(finding.message, finding.path).content);
  return truncate(
    redacted || `Semgrep rule ${finding.ruleId} matched`,
    SUMMARY_MAX_CHARS,
  );
}

/**
 * Semgrep findings as Evidence, sorted by file then line so ids are stable
 * ("ev-semgrep-3" means the same finding on every run) and de-duplicated by
 * ruleId + path + startLine.
 */
export function normalizeSemgrep(
  raw: readonly RawSemgrepFinding[],
): Evidence[] {
  const seen = new Set<string>();
  const evidence: Evidence[] = [];

  for (const finding of [...raw].sort(compare)) {
    const key = dedupeKey(finding);
    if (seen.has(key)) continue;
    seen.add(key);

    const { y2025 } = owaspCodesIn(finding.owasp);
    const snippet = cleanSnippet(finding.snippet, finding.path);
    const lineEnd = Math.max(finding.endLine, finding.startLine);

    evidence.push({
      id: `ev-semgrep-${evidence.length + 1}`,
      kind: "scanner",
      source: "semgrep",
      summary: summaryFor(finding),
      filePath: finding.path,
      lineStart: finding.startLine,
      lineEnd,
      ...(snippet !== undefined ? { snippet } : {}),
      ruleId: finding.ruleId,
      // Omitted, not empty, when the rule carries no OWASP tag: there is nothing to say.
      ...(y2025.length > 0 ? { metadata: { owasp2025: y2025 } } : {}),
    });
  }

  return evidence;
}
