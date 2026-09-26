// @vitest-environment jsdom

/**
 * The results page with real data: fixtures/demo-analysis.json (the fixture the server
 * demo serves) run through the real adapter, toDashboardViewModel, into the real Dashboard.
 *
 * Covers what the redesign added: keyboard-reachable component buttons under the map that
 * narrow the threat list to one component, a status line saying so, and a caveats panel
 * that keeps assumptions, limitations and hidden threats visible.
 *
 * ArchitectureGraph is stubbed only because React Flow needs layout APIs jsdom lacks.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { toDashboardViewModel } from "@/client/adapter";
import { validateThreatModel } from "@/shared/schema";
import demoJson from "../fixtures/demo-analysis.json";

vi.mock("@/components/ArchitectureGraph", () => ({
  default: ({
    selectedNodeId,
    nodes,
    edges,
  }: {
    selectedNodeId: string | null;
    nodes: { id: string }[];
    edges: { id: string }[];
  }) => (
    <div
      data-testid="graph"
      data-selected={selectedNodeId ?? ""}
      data-nodes={nodes.map((n) => n.id).join(",")}
      data-edges={edges.map((e) => e.id).join(",")}
    />
  ),
}));

const { default: Dashboard } = await import("@/components/Dashboard");

afterEach(cleanup);

function demoView() {
  const validated = validateThreatModel(demoJson);
  if (!validated.ok) throw new Error("demo fixture no longer validates");
  return toDashboardViewModel(validated.data);
}

const HIDDEN = { scored: 9, hidden: 3, topReason: "assumptions" as const, topReasonCount: 3 };

function renderDemo() {
  const view = demoView();
  render(
    <Dashboard
      view={view}
      basisCounts={{ evidence_backed: 7, assumption_dependent: 2 }}
      hiddenSummary={HIDDEN}
    />,
  );
  return view;
}

function listedIds(): string[] {
  const region = screen.getByRole("region", { name: "Threats" });
  return within(region)
    .getAllByRole("article")
    .map((article) => article.getAttribute("data-testid") ?? "");
}

describe("Dashboard with the demo fixture", () => {
  it("lists every visible threat from the adapter, in its order", () => {
    const view = renderDemo();
    expect(listedIds()).toEqual(view.threats.map((t) => `threat-card-${t.id}`));
  });

  it("narrows the list to one component from its button, and says so", () => {
    const view = renderDemo();
    const picker = screen.getByRole("list", { name: "Components" });
    const stripe = within(picker).getByRole("button", { name: /Stripe/ });

    fireEvent.click(stripe);

    const expected = view.threats
      .filter((t) => t.componentIds.includes("stripe"))
      .map((t) => `threat-card-${t.id}`);
    expect(expected.length).toBeGreaterThan(0);
    expect(listedIds()).toEqual(expected);
    expect(stripe.getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("status").textContent).toContain("Stripe");
    expect(screen.getByTestId("graph").getAttribute("data-selected")).toBe("stripe");
  });

  it("restores the full list when the same component is pressed again", () => {
    const view = renderDemo();
    const stripe = within(screen.getByRole("list", { name: "Components" })).getByRole("button", {
      name: /Stripe/,
    });

    fireEvent.click(stripe);
    fireEvent.click(stripe);

    expect(listedIds()).toHaveLength(view.threats.length);
    expect(stripe.getAttribute("aria-pressed")).toBe("false");
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("keeps limitations, assumptions and hidden threats visible", () => {
    const view = renderDemo();
    const caveats = screen.getByRole("region", { name: "Read this with care" });

    view.limitations.forEach((line) => expect(caveats.textContent).toContain(line));
    view.assumptions.forEach((line) => expect(caveats.textContent).toContain(line));
    expect(caveats.textContent).toContain("3 of 9 scored threats fell below 25% confidence");
  });

  it("reveals scenario, evidence, confidence reasons and mitigation when a card opens", () => {
    const view = renderDemo();
    const first = view.threats[0];
    const card = within(screen.getByRole("region", { name: "Threats" })).getByTestId(
      `threat-card-${first.id}`,
    );

    fireEvent.click(within(card).getByRole("button"));

    expect(within(card).getByText(first.attackScenario)).toBeTruthy();
    expect(within(card).getByText(first.mitigation.summary)).toBeTruthy();
    expect(within(card).getByTestId(`confidence-reasons-${first.id}`)).toBeTruthy();
    expect(within(card).getAllByText(first.evidence[0].summary).length).toBeGreaterThan(0);
  });
});

describe("Dashboard diagram sub-views", () => {
  it("re-selects the diagram's nodes and edges per view and leaves the threat list alone", async () => {
    const { selectDiagramView } = await import("@/client/diagramViews");
    const view = renderDemo();
    const graph = screen.getByTestId("graph");
    const before = listedIds();
    expect(graph.getAttribute("data-nodes")).toBe(view.nodes.map((n) => n.id).join(","));

    for (const [label, name] of [
      ["Identity and auth", "identity"],
      ["Data flows", "data_flows"],
      ["External systems", "external"],
    ] as const) {
      fireEvent.click(screen.getByRole("radio", { name: label }));
      expect(screen.getByRole("radio", { name: label }).getAttribute("aria-checked")).toBe("true");
      const expected = selectDiagramView(view, name);
      expect(screen.getByTestId("graph").getAttribute("data-nodes")).toBe(expected.nodeIds.join(","));
      expect(screen.getByTestId("graph").getAttribute("data-edges")).toBe(expected.edgeIds.join(","));
      expect(listedIds()).toEqual(before);
    }

    fireEvent.click(screen.getByRole("radio", { name: "Overall" }));
    expect(screen.getByTestId("graph").getAttribute("data-nodes")).toBe(view.nodes.map((n) => n.id).join(","));
  });
});
