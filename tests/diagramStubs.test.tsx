// @vitest-environment jsdom

/**
 * How Dashboard wires a view that has a stub: the diagram receives the stub (as a node, and
 * by id), while the legend and the boundary notes are built from the view's own components
 * only. No real view produces a stub today, so viewGraph is replaced to return one for the
 * demo fixture's only external service, Stripe. ArchitectureGraph is stubbed to record its
 * props; React Flow needs layout APIs jsdom lacks.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { toDashboardViewModel } from "@/client/adapter";
import { validateThreatModel } from "@/shared/schema";
import type { GraphEdge, GraphNode } from "@/shared/viewModel";
import demoJson from "../fixtures/demo-analysis.json";

const seen: { nodes: string[]; stubIds: string[]; edges: string[] }[] = [];

vi.mock("@/components/ArchitectureGraph", () => ({
  default: (props: { nodes: GraphNode[]; stubIds?: string[]; edges: GraphEdge[] }) => {
    seen.push({
      nodes: props.nodes.map((n) => n.id),
      stubIds: [...(props.stubIds ?? [])],
      edges: props.edges.map((e) => e.id),
    });
    return <div data-testid="graph" />;
  },
}));

vi.mock("@/client/diagramViews", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/client/diagramViews")>();
  return {
    ...original,
    viewGraph: (input: Parameters<typeof original.viewGraph>[0]) => {
      const all = original.viewGraph(input, "overall");
      return {
        nodes: all.nodes.filter((n) => n.id !== "stripe"),
        stubs: all.nodes.filter((n) => n.id === "stripe"),
        edges: all.edges,
      };
    },
  };
});

const { default: Dashboard } = await import("@/components/Dashboard");

afterEach(() => {
  cleanup();
  seen.length = 0;
});

function view() {
  const validated = validateThreatModel(demoJson);
  if (!validated.ok) throw new Error("demo fixture no longer validates");
  return toDashboardViewModel(validated.data);
}

describe("Dashboard with a stub in the view", () => {
  it("hands the diagram the stub as a node and by id, with the view's other nodes and edges", () => {
    const v = view();
    render(<Dashboard view={v} basisCounts={null} />);
    const last = seen.at(-1)!;
    expect(last.stubIds).toEqual(["stripe"]);
    expect(last.nodes).toContain("stripe");
    expect(last.nodes).toHaveLength(v.nodes.length);
    expect(last.edges).toEqual(v.edges.map((e) => e.id));
  });

  it("does not count the stub in the legend: External service is not listed, the others are", () => {
    render(<Dashboard view={view()} basisCounts={null} />);
    const legend = screen.getByRole("list", { name: "Component types" });
    expect(within(legend).queryByText("External service")).toBeNull();
    for (const label of ["Actor", "Frontend", "API", "Database", "Storage"]) {
      expect(within(legend).getByText(label)).toBeTruthy();
    }
  });
});
