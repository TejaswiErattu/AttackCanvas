// @vitest-environment jsdom

/**
 * ThreatCard: renders the server's scoring verbatim, and evidence in the server's order.
 *
 * The card is where a user reads severity, confidence, priority and basis, so the risk is
 * that the UI quietly "improves" one of them -- re-deriving a priority from a severity, or
 * re-sorting evidence so gaps no longer come last. Both are asserted against here.
 *
 * jsdom is needed for this one; cleanup is explicit because Vitest runs without globals,
 * so Testing Library cannot register its own afterEach hook.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import ThreatCard from "@/components/ThreatCard";
import type { EvidenceItem, ThreatCardData } from "@/shared/viewModel";

afterEach(cleanup);

const EVIDENCE: EvidenceItem[] = [
  {
    kind: "code",
    kindLabel: "Code",
    summary: "Route handler reads the id straight from the request.",
    location: "src/app/api/notes/route.ts:14-18",
    snippet: "const id = request.nextUrl.searchParams.get('id')",
    sourceLabel: "Code analysis",
  },
  {
    kind: "scanner",
    kindLabel: "Scanner finding",
    summary: "Semgrep flagged an unparameterised query.",
    location: "src/db/notes.ts:31",
    snippet: null,
    sourceLabel: "Semgrep",
  },
  {
    kind: "assumption",
    kindLabel: "Assumption",
    summary: "No authorisation middleware was found on this route.",
    location: null,
    snippet: null,
    sourceLabel: "Code analysis",
  },
];

const THREAT: ThreatCardData = {
  id: "broken-object-level-auth",
  title: "Any signed-in user can read another user's notes",
  severity: "critical",
  confidence: 82,
  confidenceLabel: "high",
  priority: "fix_now",
  priorityLabel: "Fix now",
  stride: [{ code: "E", label: "Elevation of privilege" }],
  owasp: [{ code: "A01:2025", label: "Broken Access Control" }],
  cwe: ["CWE-639"],
  basis: "evidence_backed",
  basisLabel: "Confirmed by evidence",
  componentNames: ["Notes API", "Postgres"],
  affectedNames: ["Notes API", "Postgres"],
  componentIds: ["notes-api", "postgres"],
  dataFlowIds: ["api-db"],
  confidenceReasons: ["+0.35 code evidence", "Confidence 82% (high)"],
  attackScenario: "A user changes the note id in the URL and reads someone else's note.",
  evidence: EVIDENCE,
  mitigation: {
    summary: "Check note ownership before returning it.",
    steps: ["Load the note", "Compare owner id to the session user", "Return 404 on mismatch"],
    codeLocation: "src/app/api/notes/route.ts",
  },
  assumptions: ["Sessions are cookie-based."],
};

function renderCard(overrides: Partial<ThreatCardData> = {}, selected = false) {
  const onSelect = vi.fn();
  render(
    <ThreatCard
      threat={{ ...THREAT, ...overrides }}
      selected={selected}
      onSelect={onSelect}
    />,
  );
  return { onSelect };
}

describe("ThreatCard rendering", () => {
  it("shows the server's severity, priority, confidence and basis unchanged", () => {
    renderCard();

    expect(screen.getByText("Critical")).toBeTruthy();
    expect(screen.getByText("Fix now")).toBeTruthy();
    expect(screen.getByText(/82%/)).toBeTruthy();
    expect(screen.getByText(/High confidence/)).toBeTruthy();
    expect(screen.getByText(/Confirmed by evidence/)).toBeTruthy();
  });

  it("renders the server's priority label even when it contradicts the severity", () => {
    // A "low" severity carrying "Fix now" is not something the scoring rules would
    // produce; the card must still display what the server sent rather than recompute.
    renderCard({ severity: "low", priority: "fix_now", priorityLabel: "Fix now" });

    expect(screen.getByText("Low")).toBeTruthy();
    expect(screen.getByText("Fix now")).toBeTruthy();
  });

  it("shows the title, components, STRIDE, OWASP and CWE", () => {
    renderCard();

    expect(screen.getByRole("heading", { name: THREAT.title })).toBeTruthy();
    expect(screen.getByText(/Notes API, Postgres/)).toBeTruthy();
    expect(screen.getByText(/Elevation of privilege/)).toBeTruthy();
    expect(screen.getByText(/A01:2025/)).toBeTruthy();
    expect(screen.getByText("CWE-639")).toBeTruthy();
  });
});

describe("ThreatCard confidence reasons", () => {
  function reasonLines(id = THREAT.id): string[] {
    const list = screen.getByTestId(`confidence-reasons-${id}`);
    return Array.from(list.querySelectorAll("li")).map((li) => li.textContent ?? "");
  }

  it("shows the lines as provided, in order, when the card is selected", () => {
    renderCard({}, true);

    expect(screen.getByRole("heading", { name: "Why this confidence" })).toBeTruthy();
    expect(reasonLines()).toEqual(["+0.35 code evidence", "Confidence 82% (high)"]);
  });

  it("shows qualitative gap wording untouched, adding no numbers or totals of its own", () => {
    const lines = [
      "Supported by a finding that a security control is missing; it counts for more the surer the code analysis is that the control is absent",
      "Confidence 40% (medium). These reasons explain the figure; they are not separate scores that add up to it.",
    ];
    renderCard({ confidenceReasons: lines }, true);

    expect(reasonLines()).toEqual(lines);
    expect(screen.getByTestId(`confidence-reasons-${THREAT.id}`).textContent).toBe(lines.join(""));
  });

  it("stays out of the collapsed card", () => {
    renderCard();
    expect(screen.queryByTestId(`confidence-reasons-${THREAT.id}`)).toBeNull();
  });

  it("omits the section rather than showing an empty one", () => {
    renderCard({ confidenceReasons: [] }, true);
    expect(screen.queryByRole("heading", { name: "Why this confidence" })).toBeNull();
  });
});

describe("ThreatCard selection", () => {
  it("reports its id when the header is activated", () => {
    const { onSelect } = renderCard();
    fireEvent.click(screen.getByRole("button"));

    expect(onSelect).toHaveBeenCalledWith("broken-object-level-auth");
  });

  it("exposes its expanded state to assistive technology", () => {
    renderCard();
    expect(screen.getByRole("button").getAttribute("aria-expanded")).toBe("false");

    cleanup();
    renderCard({}, true);
    expect(screen.getByRole("button").getAttribute("aria-expanded")).toBe("true");
  });

  it("keeps the detail panel collapsed until selected", () => {
    renderCard();

    expect(screen.queryByText(/Attack scenario/)).toBeNull();
    expect(screen.queryByText(EVIDENCE[0].summary)).toBeNull();
  });

  it("reveals scenario, evidence, mitigation and assumptions when selected", () => {
    renderCard({}, true);

    expect(screen.getByText(THREAT.attackScenario)).toBeTruthy();
    expect(screen.getByText(THREAT.mitigation.summary)).toBeTruthy();
    expect(screen.getByText("Sessions are cookie-based.")).toBeTruthy();
    expect(screen.getByText("src/app/api/notes/route.ts")).toBeTruthy();
  });
});

describe("ThreatCard evidence", () => {
  it("renders evidence in the order the server supplied, gaps last", () => {
    renderCard({}, true);

    const items = screen.getAllByRole("listitem");
    const evidenceText = items
      .map((item) => item.textContent ?? "")
      .filter((text) => EVIDENCE.some((entry) => text.includes(entry.summary)));

    // The adapter already sorts positive findings before gap reasoning. The card must not
    // re-sort, so the rendered order has to match the input array exactly.
    expect(evidenceText).toHaveLength(3);
    expect(evidenceText[0]).toContain(EVIDENCE[0].summary);
    expect(evidenceText[1]).toContain(EVIDENCE[1].summary);
    expect(evidenceText[2]).toContain(EVIDENCE[2].summary);
  });

  it("shows each item's kind, source and location", () => {
    renderCard({}, true);

    expect(screen.getByText("Scanner finding")).toBeTruthy();
    expect(screen.getByText(/via Semgrep/)).toBeTruthy();
    expect(screen.getByText("src/db/notes.ts:31")).toBeTruthy();
  });

  it("renders an untrusted snippet as text, never as markup", () => {
    renderCard(
      {
        evidence: [
          {
            ...EVIDENCE[0],
            snippet: "<img src=x onerror=alert(1)>",
          },
        ],
      },
      true,
    );

    // Present as visible text, and no element was created from it.
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });

  it("states plainly when a threat cites no evidence", () => {
    renderCard({ evidence: [] }, true);
    expect(screen.getByText(/No evidence was cited/)).toBeTruthy();
  });

  it("does not crash when optional fields are missing", () => {
    const partial = {
      ...THREAT,
      cwe: undefined,
      assumptions: undefined,
      evidence: undefined,
    } as unknown as ThreatCardData;

    expect(() =>
      render(<ThreatCard threat={partial} selected onSelect={vi.fn()} />),
    ).not.toThrow();
  });

  it("lists the mitigation steps in the order the server gave them", () => {
    renderCard({}, true);

    const steps = THREAT.mitigation.steps.map((step) => screen.getByText(step));
    // compareDocumentPosition tells us step N really does precede step N+1 in the DOM.
    steps.slice(1).forEach((step, index) => {
      const precedes =
        steps[index].compareDocumentPosition(step) & Node.DOCUMENT_POSITION_FOLLOWING;
      expect(precedes).toBeTruthy();
    });
  });
});
