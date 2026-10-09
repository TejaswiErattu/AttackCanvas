// @vitest-environment jsdom

/**
 * The unverified switch: one setting drives the diagram's node counts, the severity tiles,
 * the threat list, the filter options and the component chips.
 *
 * The view model comes from the real adapter, on the demo fixture cut down to its three
 * below-25% threats, all put on one component: that component has 0 visible threats and
 * 3 unverified ones, and one of the three is Critical so the accent test has something to
 * get wrong. ArchitectureGraph is stubbed (React Flow needs layout APIs jsdom lacks) but
 * renders the real NodeContent from the props Dashboard really passes.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { toDashboardViewModel } from "@/client/adapter";
import { validateThreatModel } from "@/shared/schema";
import type { GraphNode } from "@/shared/viewModel";
import demoJson from "../fixtures/demo-analysis.json";

vi.mock("@/components/ArchitectureGraph", async () => {
  const { NodeContent } = await import("@/components/ArchitectureNode");
  return {
    default: ({ nodes, includeUnverified }: { nodes: readonly GraphNode[]; includeUnverified?: boolean }) => (
      <div data-testid="graph">
        {nodes.map((node) => (
          <div key={node.id} data-testid={`graph-node-${node.id}`}>
            <NodeContent data={{ node, on: false, selected: false, dimmed: false, includeUnverified }} />
          </div>
        ))}
      </div>
    ),
  };
});

const { default: Dashboard, SHOW_HIDDEN_STORAGE_KEY } = await import("@/components/Dashboard");
const { threatTotals } = await import("@/components/ArchitectureNode");

const NODE = "admin-panel";
const SWITCH = "Include 3 unverified threats (below 25% confidence)";

/** 0 visible, 3 unverified, all on `admin-panel`, one of them Critical. */
function view() {
  const validated = validateThreatModel(demoJson);
  if (!validated.ok) throw new Error("demo fixture no longer validates");
  const model = structuredClone(validated.data);
  const unverified = model.threats.filter((t) => t.confidence < 0.25);
  model.threats = unverified.map((t, i) => ({
    ...t,
    componentIds: [NODE],
    ...(i === 0 ? { severity: "critical" as const } : {}),
  }));
  model.questions = [];
  return toDashboardViewModel(model);
}

beforeEach(() => window.localStorage.clear());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function renderDashboard() {
  const v = view();
  render(<Dashboard view={v} basisCounts={null} />);
  return v;
}

const nodeText = () => screen.getByTestId(`graph-node-${NODE}`).querySelector('[data-testid="node-threats"]')!.textContent;
const nodeSuffix = () => screen.getByTestId(`graph-node-${NODE}`).querySelector('[data-testid="node-unverified"]');
const accent = () =>
  (screen.getByTestId(`graph-node-${NODE}`).querySelector("span.absolute[aria-hidden='true']") as HTMLElement).style.background;
const flip = () => fireEvent.click(screen.getByRole("checkbox", { name: SWITCH }));

function tiles(): Record<string, number> {
  const region = screen.getByRole("region", { name: "Severity summary" });
  const out: Record<string, number> = {};
  region.querySelectorAll("dl > div").forEach((tile) => {
    out[tile.querySelector("dt")!.textContent!.trim()] = Number(tile.querySelector("dd")!.textContent);
  });
  return out;
}
const tileTotal = () => {
  const t = tiles();
  return t.Critical + t.High + t.Medium + t.Low;
};
const listed = () =>
  within(screen.getByRole("region", { name: "Threats" })).queryAllByRole("article").length;

describe("the view model for this test", () => {
  it("has a node with 0 visible and 3 unverified threats, and no visible severity", () => {
    const node = view().nodes.find((n) => n.id === NODE)!;
    expect(node).toMatchObject({ threatCount: 0, lowConfidenceThreatCount: 3, maxSeverity: null });
  });
});

describe("a node with 0 visible and 3 unverified threats", () => {
  it("reads 0 with the switch off and 3 with +3 unverified on", () => {
    renderDashboard();
    // On by default, as the list's toggle always was.
    expect(nodeText()).toBe("3 threats +3 unverified");
    expect(nodeSuffix()!.textContent).toContain("+3 unverified");
    flip();
    expect(nodeText()).toBe("0 threats");
    expect(nodeSuffix()).toBeNull();
    flip();
    expect(nodeText()).toBe("3 threats +3 unverified");
  });

  it("keeps the diagram's severity accent the same in both states (no severity from an unverified Critical)", () => {
    renderDashboard();
    const on = accent();
    flip();
    const off = accent();
    expect(off).toBe(on);
    expect(screen.getByTestId(`graph-node-${NODE}`).textContent).not.toMatch(/max/);
  });

  it("agrees with the severity tiles and the list in both states", () => {
    renderDashboard();
    // On: node total 3, tiles add the unverified counts, list appends the 3 hidden threats.
    expect(tileTotal()).toBe(3);
    expect(tiles().Critical).toBe(1);
    expect(listed()).toBe(3);
    expect(screen.getByTestId("scored-line").textContent).toContain("3 threats scored, 3 of them below 25% confidence");

    flip();
    // Off: node 0, tiles count visible only, list empty.
    expect(tileTotal()).toBe(0);
    expect(tiles().Critical).toBe(0);
    expect(listed()).toBe(0);
    expect(screen.getByTestId("scored-line").textContent).toContain("0 threats shown; 3 more below 25% confidence are switched off");
    expect(nodeText()).toBe("0 threats");
  });

  it("follows the switch in the component chips", () => {
    renderDashboard();
    const picker = screen.getByLabelText("Components");
    expect(within(picker).getByRole("button", { name: /Admin.*3 threats, 3 unverified/ })).toBeTruthy();
    flip();
    expect(within(picker).getByRole("button", { name: /Admin.*, 0 threats$/ })).toBeTruthy();
  });

  it("offers the unverified threats' filters only when the switch is on", () => {
    const { container } = render(<Dashboard view={view()} basisCounts={null} />);
    expect(container.querySelector("#filter-severity-critical")).not.toBeNull();
    flip();
    expect(container.querySelector("#filter-severity-critical")).toBeNull();
  });
});

describe("the switch's label and its memory", () => {
  it("is labelled with the count and sits beside the diagram views", () => {
    renderDashboard();
    const box = screen.getByRole("checkbox", { name: SWITCH });
    const views = screen.getByRole("radiogroup", { name: "Diagram view" });
    expect(box.closest("div")).toBe(views.parentElement);
  });

  it("is not offered when nothing is unverified", () => {
    const v = { ...view(), hiddenThreats: [] };
    render(<Dashboard view={v} basisCounts={null} />);
    expect(screen.queryByRole("checkbox", { name: /unverified/ })).toBeNull();
  });

  it("saves the choice under attackcanvas:showHidden and restores it on the next visit", () => {
    expect(SHOW_HIDDEN_STORAGE_KEY).toBe("attackcanvas:showHidden");
    renderDashboard();
    flip();
    expect(window.localStorage.getItem("attackcanvas:showHidden")).toBe("0");
    cleanup();

    renderDashboard();
    expect((screen.getByRole("checkbox", { name: SWITCH }) as HTMLInputElement).checked).toBe(false);
    expect(nodeText()).toBe("0 threats");
    flip();
    expect(window.localStorage.getItem("attackcanvas:showHidden")).toBe("1");
  });

  it("ignores a saved value that is not 0 or 1", () => {
    window.localStorage.setItem("attackcanvas:showHidden", "maybe");
    renderDashboard();
    expect((screen.getByRole("checkbox", { name: SWITCH }) as HTMLInputElement).checked).toBe(true);
  });

  it("still works when storage is blocked", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    renderDashboard();
    expect(nodeText()).toBe("3 threats +3 unverified");
    flip();
    expect(nodeText()).toBe("0 threats");
  });
});

describe("threatTotals", () => {
  it("adds the unverified count only when asked, and tolerates a node without one", () => {
    expect(threatTotals({ threatCount: 2, lowConfidenceThreatCount: 3 }, false)).toEqual({ total: 2, unverified: 0 });
    expect(threatTotals({ threatCount: 2, lowConfidenceThreatCount: 3 }, true)).toEqual({ total: 5, unverified: 3 });
    expect(threatTotals({ threatCount: 2 } as GraphNode, true)).toEqual({ total: 2, unverified: 0 });
  });
});
