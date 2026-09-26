/**
 * Builds a GitHub issue for one finding: a title, a Markdown body and the
 * https://github.com/<owner>/<repo>/issues/new link that pre-fills both.
 *
 * Pure and DOM-free. Everything read from the finding is untrusted repository- or
 * model-derived text (CLAUDE.md rule 3). It leaves this module in two ways only: URL-encoded
 * inside the link's query string, and as Markdown text in the body, where HTML-significant
 * characters are escaped. Nothing here produces HTML, and the UI renders the link as an
 * anchor whose href is this URL, never as markup built from these strings.
 *
 * Only what the finding already carries is used: severity, confidence label and basis are
 * copied as the server computed them, never recomputed (CLAUDE.md rule 2).
 */

import type { EvidenceItem, ThreatCardData } from "@/shared/viewModel";

/** Body cap in characters, before URL encoding. */
export const ISSUE_BODY_LIMIT = 6000;

export type IssueRepo = { fullName: string; ref: string };

/**
 * Longest pre-filled link offered. GitHub refuses very long request URLs (roughly 8 KB), and
 * a 6,000-character body can encode to well over that, so a longer link is not offered and
 * the reader is sent to "Copy as Markdown" instead. Deliberately below the real limit.
 */
export const ISSUE_URL_LIMIT = 7000;

export type IssueDraft = {
  title: string;
  body: string;
  /** Empty when the repository name is not "owner/repo", or when the link is too long. */
  url: string;
  /** True when a valid link exists but exceeds ISSUE_URL_LIMIT; the body still works. */
  tooLong: boolean;
};

const CONFIDENCE_TEXT: Record<string, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

function capitalise(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** One line of inline text: whitespace collapsed, and HTML-significant characters escaped. */
function inline(text: string): string {
  return text
    .replace(/\s+/g, " ")
    .trim()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/** Multi-line prose: line breaks kept, HTML-significant characters escaped. */
function prose(text: string): string {
  return text
    .trim()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

/**
 * "src/a.ts:12-20" -> { path: "src/a.ts", start: 12, end: 20 }; a location with no line
 * numbers yields just the path.
 */
export function parseLocation(
  location: string,
): { path: string; start?: number; end?: number } {
  const match = /^(.*):(\d+)(?:-(\d+))?$/.exec(location);
  if (!match) return { path: location };
  const start = Number(match[2]);
  const end = match[3] === undefined ? undefined : Number(match[3]);
  return { path: match[1], start, end };
}

/** GitHub blob link at the analysed ref, with a line anchor when the location has one. */
export function blobUrl(repo: IssueRepo, location: string): string {
  const { path, start, end } = parseLocation(location);
  const anchor =
    start === undefined ? "" : end === undefined || end === start ? `#L${start}` : `#L${start}-L${end}`;
  return `https://github.com/${encodePath(repo.fullName)}/blob/${encodePath(repo.ref)}/${encodePath(path)}${anchor}`;
}

function evidenceLine(repo: IssueRepo, item: EvidenceItem): string {
  const summary = inline(item.summary);
  if (item.location === null) return `- ${summary}`;
  // Backticks in a path would end the code span early; a path never legitimately has them.
  const label = item.location.replace(/`/g, "'");
  return `- [\`${label}\`](${blobUrl(repo, item.location)}) — ${summary}`;
}

function list(items: readonly string[]): string {
  return items.map(inline).join(", ");
}

function assemble(parts: {
  head: string[];
  evidence: string[];
  omitted: number;
  tail: string[];
}): string {
  const evidence =
    parts.evidence.length === 0 && parts.omitted === 0
      ? []
      : [
          "## Evidence",
          ...(parts.evidence.length ? parts.evidence : []),
          ...(parts.omitted > 0
            ? [`_${parts.omitted} more evidence item${parts.omitted === 1 ? "" : "s"} omitted to fit the issue size limit._`]
            : []),
          "",
        ];
  return [...parts.head, ...evidence, ...parts.tail].join("\n").trimEnd() + "\n";
}

/** The Markdown body, at most ISSUE_BODY_LIMIT characters, trimming evidence first. */
export function buildIssueBody(threat: ThreatCardData, repo: IssueRepo): string {
  const stride = (threat.stride ?? []).map((s) => `${s.code} ${s.label}`);
  const owasp = (threat.owasp ?? []).map((o) => `${o.code} ${o.label}`);
  const affected = threat.affectedNames ?? threat.componentNames ?? [];
  const confidenceLabel = CONFIDENCE_TEXT[threat.confidenceLabel] ?? threat.confidenceLabel;

  const head = [
    `**Severity:** ${capitalise(threat.severity)}`,
    `**Confidence:** ${confidenceLabel} (${threat.confidence}%)`,
    `**Basis:** ${inline(threat.basisLabel)}`,
    `**STRIDE:** ${stride.length ? list(stride) : "None"}`,
    `**OWASP Top 10:2025:** ${owasp.length ? list(owasp) : "None"}`,
    `**CWE:** ${threat.cwe?.length ? list(threat.cwe) : "None"}`,
    `**Affected components:** ${affected.length ? list(affected) : "None"}`,
    "",
    "## Attack scenario",
    prose(threat.attackScenario ?? ""),
    "",
  ];

  const mitigation = threat.mitigation;
  const tail = [
    "## Mitigation",
    prose(mitigation?.summary ?? ""),
    ...(mitigation?.steps?.length
      ? ["", ...mitigation.steps.map((step, i) => `${i + 1}. ${inline(step)}`)]
      : []),
    ...(mitigation?.codeLocation ? ["", `Where: \`${inline(mitigation.codeLocation).replace(/`/g, "'")}\``] : []),
    "",
    `_Generated by AttackCanvas for ${inline(repo.fullName)} at \`${inline(repo.ref).replace(/`/g, "'")}\`._`,
  ];

  const lines = (threat.evidence ?? []).map((item) => evidenceLine(repo, item));
  // Trim evidence first: drop items from the end until the body fits.
  for (let keep = lines.length; keep >= 0; keep -= 1) {
    const body = assemble({ head, evidence: lines.slice(0, keep), omitted: lines.length - keep, tail });
    if (body.length <= ISSUE_BODY_LIMIT) return body;
  }
  // Even with no evidence it is too long: hard-cut, the one place text is truncated.
  const bare = assemble({ head, evidence: [], omitted: lines.length, tail });
  return `${bare.slice(0, ISSUE_BODY_LIMIT - 1)}…`;
}

/** Title, body and the pre-filled "new issue" link. */
export function buildIssue(threat: ThreatCardData, repo: IssueRepo): IssueDraft {
  // Issue titles are plain text on GitHub, so this is not HTML-escaped; it only ever
  // reaches the page URL-encoded inside the link.
  const title = (threat.title ?? "").replace(/\s+/g, " ").trim().slice(0, 200);
  const body = buildIssueBody(threat, repo);
  const parts = repo.fullName.split("/");
  const valid = parts.length === 2 && parts[0] !== "" && parts[1] !== "";
  const full = valid
    ? `https://github.com/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}/issues/new` +
      `?title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}`
    : "";
  const tooLong = full.length > ISSUE_URL_LIMIT;
  return { title, body, url: tooLong ? "" : full, tooLong };
}
