// @vitest-environment jsdom

/**
 * The dashboard must not recompute the analysis.
 *
 * CLAUDE.md rule 2 puts severity, confidence, priority, basis and the visibility threshold
 * in src/server/scoring, and the threat ordering in src/client/adapter.ts. The dashboard is
 * a renderer. The failure mode this file exists to catch is a well-meaning UI that
 * "corrects" the backend -- re-deriving a priority from a severity, re-tallying the
 * severity counts from the visible list, re-sorting threats by severity, rebuilding the
 * Fix Now list, or re-applying the 0.25 confidence cut on the client.
 *
 * So the view model below is deliberately self-contradictory: its counts do not match its
 * threats, its Fix Now list does not match its priorities, its ordering is not by severity,
 * and one threat sits under the confidence threshold. Every assertion checks that the UI
 * reproduced the server's answer rather than a recomputed one.
 *
 * ArchitectureGraph is stubbed because React Flow needs layout APIs jsdom does not provide.
 * The stub still receives the real node data, highlight ids and selected node, so the "does
 * not re-derive node stats" and "passes highlight ids through" assertions remain
 * meaningful; the layout itself is covered by tests/layoutGraph.test.ts.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import type { DashboardViewModel, ThreatCardData } from "@/shared/viewModel";
import type { GraphNode } from "@/shared/viewModel";

vi.mock("@/components/ArchitectureGraph", () => ({
  default: ({
    nodes,
    highlightNodeIds,
    highlightEdgeIds,
    selectedNodeId,
    onSelectNode,
  }: {
    nodes: readonly GraphNode[];
    highlightNodeIds: readonly string[];
    highlightEdgeIds: readonly string[];
    selectedNodeId: string | null;
    onSelectNode: (id: string | null) => void;
  }) => (
    <div
      data-testid="graph"
      data-highlight-nodes={highlightNodeIds.join(",")}
      data-highlight-edges={highlightEdgeIds.join(",")}
      data-selected={selectedNodeId ?? ""}
    >
      {nodes.map((node) => (
        <button
          key={node.id}
          type="button"
          data-testid={`graph-node-${node.id}`}
          onClick={() => onSelectNode(node.id)}
        >
          {node.label}|{node.threatCount}|{String(node.maxSeverity)}
        </button>
      ))}
    </div>
  ),
}));

const { default: Dashboard } = await import("@/components/Dashboard");

afterEach(cleanup);

function threat(id: string, overrides: Partial<ThreatCardData>): ThreatCardData {
  return {
    id,
    title: `Title ${id}`,
    severity: "medium",
    confidence: 50,
    confidenceLabel: "medium",
    priority: "monitor",
    priorityLabel: "Monitor",
    stride: [{ code: "S", label: "Spoofing" }],
    owasp: [{ code: "A01:2025", label: "Broken Access Control" }],
    cwe: [],
    basis: "evidence_backed",
    basisLabel: "Confirmed by evidence",
    componentNames: ["API"],
    componentIds: ["api"],
    dataFlowIds: [],
    confidenceReasons: [],
    attackScenario: `Scenario ${id}`,
    evidence: [],
    mitigation: { summary: "Mitigate", steps: ["Step"], codeLocation: null },
    assumptions: [],
    ...overrides,
  };
}

/**
 * A "low severity / Fix now / 12% confidence" threat is impossible under the scoring rules,
 * and it sits below the 0.25 display threshold. It is here precisely because a client that
 * recomputes anything would change or drop it.
 */
const QUIET_GAP = threat("quiet-gap", {
  severity: "low",
  priority: "fix_now",
  priorityLabel: "Fix now",
  confidence: 12,
  confidenceLabel: "low",
  basis: "assumption_dependent",
  basisLabel: "Predicted from a missing control",
  componentIds: ["api"],
  dataFlowIds: ["api-db"],
});

/** Critical, but the server marked it Monitor. The card must say Monitor. */
const LOUD_CRITICAL = threat("loud-critical", {
  severity: "critical",
  priority: "monitor",
  priorityLabel: "Monitor",
  confidence: 95,
  confidenceLabel: "high",
  componentNames: ["Database"],
  componentIds: ["db"],
});

const MIDDLE = threat("middle", {
  severity: "medium",
  priority: "fix_soon",
  priorityLabel: "Fix soon",
});

const VIEW: DashboardViewModel = {
  analysisLevel: 2,
  analysisLevelLabel: "Standard",
  repo: {
    fullName: "acme/golden-demo",
    ref: "main",
    frameworks: ["Next.js"],
    fileCount: 42,
    analyzedAt: "2026-09-22T12:00:00.000Z",
  },
  // Deliberately not the tally of `threats` below.
  counts: { critical: 7, high: 4, medium: 2, low: 1 },
  // Deliberately omits QUIET_GAP even though its priority is fix_now.
  fixNow: [LOUD_CRITICAL],
  // Deliberately neither fixNow.length (1) nor the fix_now threats listed below (1).
  fixNowTotal: 3,
  nodes: [
    {
      id: "api",
      type: "api",
      label: "Notes API",
      position: { x: 0, y: 0 },
      threatCount: 9,
      maxSeverity: "critical",
      technologies: ["next"],
    },
    {
      id: "db",
      type: "database",
      label: "Postgres",
      position: { x: 0, y: 0 },
      threatCount: 1,
      maxSeverity: "low",
      technologies: ["postgres"],
    },
  ],
  edges: [],
  // Server order: low first, critical second. Not sorted by severity.
  threats: [QUIET_GAP, LOUD_CRITICAL, MIDDLE],
  assumptions: ["Sessions are cookie-based."],
  limitations: ["Only the default branch was analyzed."],
  filterOptions: {
    severities: ["critical", "medium", "low"],
    stride: [{ code: "S", label: "Spoofing" }],
    owasp: [{ code: "A01:2025", label: "Broken Access Control" }],
    components: [
      { id: "api", name: "Notes API" },
      { id: "db", name: "Postgres" },
    ],
    confidenceLabels: ["high", "medium", "low"],
  },
};

function renderDashboard() {
  return render(
    <Dashboard view={VIEW} basisCounts={{ evidence_backed: 11, assumption_dependent: 3 }} />,
  );
}

function threatListIds(): string[] {
  const region = screen.getByRole("region", { name: "Threats" });
  return within(region)
    .getAllByRole("article")
    .map((article) => article.getAttribute("data-testid") ?? "");
}

function severityCount(label: string): string {
  const term = screen.getByText(label, { selector: "dt" });
  return term.parentElement?.querySelector("dd")?.textContent ?? "";
}

describe("Dashboard does not recompute severity counts", () => {
  it("renders the server's counts even though they disagree with the threat list", () => {
    renderDashboard();

    // Three threats are listed, but the server said 7/4/2/1 and the server wins.
    expect(severityCount("Critical")).toBe("7");
    expect(severityCount("High")).toBe("4");
    expect(severityCount("Medium")).toBe("2");
    expect(severityCount("Low")).toBe("1");
  });

  it("does not re-tally the basis counts from the visible threats", () => {
    renderDashboard();
    expect(screen.getByText(/Across all scored threats: 11/)).toBeTruthy();
  });
});

describe("Dashboard keeps the server's Fix now order", () => {
  it("lists fixNow in the order given, never re-sorting it", () => {
    // Deliberately the reverse of severity-then-confidence: a client that re-sorted would swap them.
    const first = threat("first", { severity: "high", confidence: 55, priority: "fix_now", priorityLabel: "Fix now" });
    const second = threat("second", { severity: "critical", confidence: 99, priority: "fix_now", priorityLabel: "Fix now" });
    render(
      <Dashboard
        view={{ ...VIEW, fixNow: [first, second], fixNowTotal: 2 }}
        basisCounts={{ evidence_backed: 11, assumption_dependent: 3 }}
      />,
    );

    const region = screen.getByRole("region", { name: "Fix now" });
    const ids = within(region).getAllByRole("article").map((a) => a.getAttribute("data-testid"));
    expect(ids).toEqual(["threat-card-first", "threat-card-second"]);
  });
});

describe("Dashboard does not recompute priority", () => {
  it("shows the server's Fix Now list, not one derived from priority values", () => {
    renderDashboard();

    const region = screen.getByRole("region", { name: "Fix now" });
    const cards = within(region).getAllByRole("article");

    // QUIET_GAP has priority fix_now but is not in the server's fixNow array.
    expect(cards).toHaveLength(1);
    expect(cards[0].getAttribute("data-testid")).toBe("threat-card-loud-critical");
  });

  it("shows the server's fixNowTotal in the Fix now tile, not the length of the list", () => {
    renderDashboard();

    // fixNow is capped at 5 by the adapter, so its length undercounts; the tile must show
    // the server's total (3 here), not 1 from the list or 1 from counting priorities.
    expect(severityCount("Fix now")).toBe("3");
    expect(screen.getByText(/Showing the top 1 of 3/)).toBeTruthy();
  });

  it("renders a priority label that contradicts the severity, unchanged", () => {
    renderDashboard();

    const region = screen.getByRole("region", { name: "Threats" });
    const critical = within(region).getByTestId("threat-card-loud-critical");
    const quiet = within(region).getByTestId("threat-card-quiet-gap");

    expect(within(critical).getByText("Critical")).toBeTruthy();
    expect(within(critical).getByText("Monitor")).toBeTruthy();
    expect(within(quiet).getByText("Low")).toBeTruthy();
    expect(within(quiet).getByText("Fix now")).toBeTruthy();
  });

  it("renders the server's basis label verbatim", () => {
    renderDashboard();

    const quiet = within(screen.getByRole("region", { name: "Threats" })).getByTestId(
      "threat-card-quiet-gap",
    );
    expect(quiet.textContent).toContain("Predicted from a missing control");
  });
});

describe("Dashboard does not recompute confidence or visibility", () => {
  it("shows the server's confidence percentage and label unchanged", () => {
    renderDashboard();

    const quiet = within(screen.getByRole("region", { name: "Threats" })).getByTestId(
      "threat-card-quiet-gap",
    );
    expect(quiet.textContent).toContain("12%");
    expect(quiet.textContent).toContain("Low confidence");
  });

  it("does not re-apply the 0.25 confidence cut on the client", () => {
    renderDashboard();

    // The hide-below-0.25 rule belongs to the server adapter. If the server returned a
    // 12% threat, the dashboard renders it rather than second-guessing the threshold.
    expect(threatListIds()).toContain("threat-card-quiet-gap");
  });
});

describe("Dashboard does not reorder threats", () => {
  it("preserves the server's ordering even when severity disagrees with it", () => {
    renderDashboard();

    expect(threatListIds()).toEqual([
      "threat-card-quiet-gap",
      "threat-card-loud-critical",
      "threat-card-middle",
    ]);
  });

  it("keeps that ordering after filtering", () => {
    renderDashboard();

    // Scoped to the Severity fieldset: "Low" is also a Confidence option.
    const severity = screen.getByRole("group", { name: "Severity" });
    fireEvent.click(within(severity).getByLabelText("Critical"));
    fireEvent.click(within(severity).getByLabelText("Low"));

    // Filtering narrows the list; it must not promote the critical threat.
    expect(threatListIds()).toEqual([
      "threat-card-quiet-gap",
      "threat-card-loud-critical",
    ]);
  });
});

describe("Dashboard does not recompute graph statistics", () => {
  it("renders each node's threat count and max severity from the view model", () => {
    renderDashboard();

    // Only one listed threat touches "api", but the server said 9.
    expect(screen.getByTestId("graph-node-api").textContent).toBe("Notes API|9|critical");
    expect(screen.getByTestId("graph-node-db").textContent).toBe("Postgres|1|low");
  });
});

describe("Dashboard highlighting", () => {
  it("passes the selected threat's highlight ids through unchanged", () => {
    renderDashboard();

    expect(screen.getByTestId("graph").getAttribute("data-highlight-nodes")).toBe("");

    const quiet = within(screen.getByRole("region", { name: "Threats" })).getByTestId(
      "threat-card-quiet-gap",
    );
    fireEvent.click(within(quiet).getByRole("button"));

    // Exactly QUIET_GAP's component ids as nodes and its data-flow ids as edges.
    const graph = screen.getByTestId("graph");
    expect(graph.getAttribute("data-highlight-nodes")).toBe("api");
    expect(graph.getAttribute("data-highlight-edges")).toBe("api-db");
  });

  it("never highlights a node for a flow that shares its id", () => {
    // A flow may legally share an id with a component. Selecting a threat that touches
    // only the flow "db" must light up that edge, not the Postgres node "db".
    const flowOnly = threat("flow-only", { componentIds: ["api"], dataFlowIds: ["db"] });
    render(<Dashboard view={{ ...VIEW, threats: [flowOnly] }} basisCounts={null} />);

    const card = within(screen.getByRole("region", { name: "Threats" })).getByTestId(
      "threat-card-flow-only",
    );
    fireEvent.click(within(card).getByRole("button"));

    const graph = screen.getByTestId("graph");
    expect(graph.getAttribute("data-highlight-nodes")).toBe("api");
    expect(graph.getAttribute("data-highlight-edges")).toBe("db");
  });

  it("clears the highlight when the same threat is selected again", () => {
    renderDashboard();

    const quiet = within(screen.getByRole("region", { name: "Threats" })).getByTestId(
      "threat-card-quiet-gap",
    );
    fireEvent.click(within(quiet).getByRole("button"));
    fireEvent.click(within(quiet).getByRole("button"));

    expect(screen.getByTestId("graph").getAttribute("data-highlight-nodes")).toBe("");
    expect(screen.getByTestId("graph").getAttribute("data-highlight-edges")).toBe("");
  });

  it("filters the list to a component when its node is selected", () => {
    renderDashboard();

    fireEvent.click(screen.getByTestId("graph-node-db"));

    // Only LOUD_CRITICAL touches component "db".
    expect(threatListIds()).toEqual(["threat-card-loud-critical"]);
    expect(screen.getByTestId("graph").getAttribute("data-highlight-nodes")).toBe("db");
  });

  it("clears the selected node when Clear all removes it from the filter", () => {
    renderDashboard();

    fireEvent.click(screen.getByTestId("graph-node-db"));
    fireEvent.click(screen.getByRole("button", { name: "Clear all" }));

    // The list is unfiltered again, so the graph must not stay focused on "db".
    expect(threatListIds()).toHaveLength(3);
    const graph = screen.getByTestId("graph");
    expect(graph.getAttribute("data-selected")).toBe("");
    expect(graph.getAttribute("data-highlight-nodes")).toBe("");
  });

  it("clears the selected node when its component checkbox is unchecked", () => {
    renderDashboard();

    fireEvent.click(screen.getByTestId("graph-node-db"));
    const components = screen.getByRole("group", { name: "Component" });
    fireEvent.click(within(components).getByLabelText("Postgres"));

    expect(threatListIds()).toHaveLength(3);
    expect(screen.getByTestId("graph").getAttribute("data-selected")).toBe("");
  });

  it("keeps the selected node while the filter still includes it", () => {
    renderDashboard();

    fireEvent.click(screen.getByTestId("graph-node-db"));
    const components = screen.getByRole("group", { name: "Component" });
    fireEvent.click(within(components).getByLabelText("Notes API"));

    expect(screen.getByTestId("graph").getAttribute("data-selected")).toBe("db");
  });
});

describe("Dashboard renders the rest of the view model as given", () => {
  it("shows repository metadata, assumptions and limitations", () => {
    renderDashboard();

    expect(screen.getByRole("heading", { name: "acme/golden-demo" })).toBeTruthy();
    expect(screen.getByText(/Standard analysis/)).toBeTruthy();
    expect(screen.getByText(/42 files analyzed/)).toBeTruthy();
    expect(screen.getByText("Sessions are cookie-based.")).toBeTruthy();
    expect(screen.getByText("Only the default branch was analyzed.")).toBeTruthy();
  });

  it("does not crash when optional view-model fields are missing", () => {
    const partial = {
      analysisLevel: 2,
      analysisLevelLabel: "Standard",
      repo: VIEW.repo,
      counts: VIEW.counts,
      threats: [],
      nodes: [],
      edges: [],
      filterOptions: {
        severities: [],
        stride: [],
        owasp: [],
        components: [],
        confidenceLabels: [],
      },
    } as unknown as DashboardViewModel;

    expect(() =>
      render(<Dashboard view={partial} basisCounts={null} />),
    ).not.toThrow();
    expect(screen.getByText(/produced no threats/)).toBeTruthy();
  });
});
