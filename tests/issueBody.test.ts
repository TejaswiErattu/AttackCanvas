/**
 * issueBody: the GitHub issue link and Markdown body for one finding. Plain Node.
 */

import { describe, expect, it } from "vitest";
import {
  ISSUE_BODY_LIMIT,
  blobUrl,
  buildIssue,
  buildIssueBody,
  parseLocation,
} from "@/client/issueBody";
import type { ThreatCardData } from "@/shared/viewModel";
import { deepFreeze } from "./helpers";

const REPO = { fullName: "acme/shop", ref: "main" };

function threat(overrides: Partial<ThreatCardData> = {}): ThreatCardData {
  return {
    id: "t1",
    title: "SQL injection in login",
    severity: "high",
    confidence: 82,
    confidenceLabel: "high",
    priority: "fix_now",
    priorityLabel: "Fix now",
    stride: [{ code: "T", label: "Tampering" }],
    owasp: [{ code: "A05:2025", label: "Injection" }],
    cwe: ["CWE-89"],
    basis: "evidence_backed",
    basisLabel: "Confirmed by evidence",
    componentNames: ["API", "Database"],
    affectedNames: ["API", "Database", "API → Database"],
    componentIds: ["api", "db"],
    dataFlowIds: ["f1"],
    confidenceReasons: [],
    attackScenario: "An attacker sends a crafted username.",
    evidence: [
      {
        kind: "code",
        kindLabel: "Code",
        summary: "Query built by string concatenation",
        location: "src/auth/login.ts:12-20",
        snippet: null,
        sourceLabel: "Code analysis",
      },
    ],
    mitigation: { summary: "Use parameterised queries.", steps: ["Switch to placeholders"], codeLocation: "src/auth/login.ts" },
    assumptions: [],
    ...overrides,
  };
}

describe("buildIssueBody", () => {
  it("includes every requested field", () => {
    const body = buildIssueBody(threat(), REPO);
    expect(body).toContain("**Severity:** High");
    expect(body).toContain("**Confidence:** High (82%)");
    expect(body).toContain("**Basis:** Confirmed by evidence");
    expect(body).toContain("**STRIDE:** T Tampering");
    expect(body).toContain("**OWASP Top 10:2025:** A05:2025 Injection");
    expect(body).toContain("**CWE:** CWE-89");
    expect(body).toContain("**Affected components:** API, Database, API → Database");
    expect(body).toContain("An attacker sends a crafted username.");
    expect(body).toContain(
      "[`src/auth/login.ts:12-20`](https://github.com/acme/shop/blob/main/src/auth/login.ts#L12-L20) — Query built by string concatenation",
    );
    expect(body).toContain("Use parameterised queries.");
    expect(body).toContain("1. Switch to placeholders");
  });

  it("lists evidence without a file as a plain summary", () => {
    const body = buildIssueBody(
      threat({ evidence: [{ kind: "inference", kindLabel: "Inference", summary: "No auth check seen", location: null, snippet: null, sourceLabel: "AI analysis" }] }),
      REPO,
    );
    expect(body).toContain("- No auth check seen");
  });

  it("escapes HTML in repository-derived text", () => {
    const body = buildIssueBody(threat({ attackScenario: "<img src=x onerror=alert(1)>" }), REPO);
    expect(body).not.toContain("<img");
    expect(body).toContain("&lt;img");
  });

  it("never mutates its input", () => {
    expect(() => buildIssueBody(deepFreeze(threat()), deepFreeze({ ...REPO }))).not.toThrow();
  });
});

describe("6,000 character cap", () => {
  const manyEvidence = Array.from({ length: 80 }, (_, i) => ({
    kind: "code" as const,
    kindLabel: "Code",
    summary: `Finding number ${i} with a reasonably long description of what was found`,
    location: `src/module${i}/file.ts:${i + 1}`,
    snippet: null,
    sourceLabel: "Code analysis",
  }));

  it("trims evidence first and says so", () => {
    const body = buildIssueBody(threat({ evidence: manyEvidence }), REPO);
    expect(body.length).toBeLessThanOrEqual(ISSUE_BODY_LIMIT);
    expect(body).toContain("more evidence items omitted");
    expect(body).toContain("Finding number 0 ");
    expect(body).not.toContain("Finding number 79 ");
    // Everything else survives the trim.
    expect(body).toContain("An attacker sends a crafted username.");
    expect(body).toContain("Use parameterised queries.");
  });

  it("truncates the text itself only when it is too long even without evidence", () => {
    const body = buildIssueBody(threat({ attackScenario: "x".repeat(20_000), evidence: manyEvidence }), REPO);
    expect(body.length).toBeLessThanOrEqual(ISSUE_BODY_LIMIT);
    expect(body.endsWith("…")).toBe(true);
  });

  it("does not touch a body that already fits", () => {
    expect(buildIssueBody(threat(), REPO)).not.toContain("omitted");
  });
});

describe("buildIssue", () => {
  it("builds the pre-filled new-issue link", () => {
    const issue = buildIssue(threat(), REPO);
    const url = new URL(issue.url);
    expect(url.origin + url.pathname).toBe("https://github.com/acme/shop/issues/new");
    expect(url.searchParams.get("title")).toBe("SQL injection in login");
    expect(url.searchParams.get("body")).toBe(issue.body);
  });

  it("URL-encodes a title containing <script> and never leaves it raw", () => {
    const issue = buildIssue(threat({ title: "XSS via <script>alert(1)</script>" }), REPO);
    expect(issue.url).toContain("%3Cscript%3E");
    expect(issue.url).not.toContain("<");
    expect(issue.url).not.toContain(">");
    // Decoded, it is still just text for GitHub to show as a plain title.
    expect(new URL(issue.url).searchParams.get("title")).toBe("XSS via <script>alert(1)</script>");
    // And it is not copied into the body as markup.
    expect(issue.body).not.toContain("<script>");
  });

  it("returns no link for a repository name that is not owner/repo", () => {
    expect(buildIssue(threat(), { fullName: "nonsense", ref: "main" }).url).toBe("");
  });
});

describe("blob links", () => {
  it("parses locations", () => {
    expect(parseLocation("a/b.ts:5")).toEqual({ path: "a/b.ts", start: 5, end: undefined });
    expect(parseLocation("a/b.ts:5-9")).toEqual({ path: "a/b.ts", start: 5, end: 9 });
    expect(parseLocation("a/b.ts")).toEqual({ path: "a/b.ts" });
  });

  it("anchors a single line, and encodes odd paths and refs", () => {
    expect(blobUrl({ fullName: "o/r", ref: "feature/x y" }, "src/a b.ts:7")).toBe(
      "https://github.com/o/r/blob/feature/x%20y/src/a%20b.ts#L7",
    );
    expect(blobUrl(REPO, "README.md")).toBe("https://github.com/acme/shop/blob/main/README.md");
  });
});
