// @vitest-environment jsdom

/**
 * The custom architecture node's shapes and icons, and the legend under the diagram.
 * NodeContent, NodeShape and TypeIcon need no React Flow context, so they render here.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ComponentTypeSchema } from "@/shared/schema";
import type { GraphNode } from "@/shared/viewModel";
import {
  ICON_SIZE,
  ICON_SLOT,
  NodeContent,
  STUB_HEIGHT,
  STUB_WIDTH,
  StubContent,
  accentFor,
  nodeTypeText,
  shapeOf,
} from "@/components/ArchitectureNode";
import { NODE_HEIGHT } from "@/client/layoutGraph";
import ArchitectureLegend, { legendTypes } from "@/components/ArchitectureLegend";

afterEach(cleanup);

function node(type: string, overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    id: `n-${type}`,
    type: type as GraphNode["type"],
    label: `The ${type}`,
    position: { x: 0, y: 0 },
    threatCount: 2,
    lowConfidenceThreatCount: 0,
    maxSeverity: "high",
    technologies: [],
    assets: [],
    exposure: "internal",
    ...overrides,
  };
}

describe("shapeOf", () => {
  it("gives each named type its own shape and every other type the neutral box", () => {
    expect(shapeOf("actor")).toBe("person");
    expect(shapeOf("frontend")).toBe("browser");
    expect(shapeOf("backend")).toBe("rounded");
    expect(shapeOf("api")).toBe("rounded");
    expect(shapeOf("database")).toBe("cylinder");
    expect(shapeOf("storage")).toBe("bucket");
    expect(shapeOf("external_service")).toBe("cloud");
    expect(shapeOf("auth_provider")).toBe("shield");
    expect(shapeOf("worker")).toBe("neutral");
    expect(shapeOf("queue")).toBe("neutral");
    expect(shapeOf("something_new")).toBe("neutral");
  });

  it("has a shape for every ComponentType value", () => {
    for (const type of ComponentTypeSchema.options) expect(shapeOf(type)).toBeTruthy();
  });
});

describe("NodeContent", () => {
  it("draws the type's outline and icon, and keeps name, type, threats and severity", () => {
    const { container } = render(
      <NodeContent data={{ node: node("database"), on: false, selected: false, dimmed: false }} />,
    );
    expect(container.querySelector('[data-shape="cylinder"]')).not.toBeNull();
    expect(container.querySelector('[data-icon="cylinder"]')).not.toBeNull();
    expect(screen.getByText("The database")).toBeTruthy();
    expect(screen.getByText("Database")).toBeTruthy();
    expect(screen.getByText(/2 threats · High max/)).toBeTruthy();
  });

  it("keeps the severity accent, the highlight outline and the dimming", () => {
    const { container, rerender } = render(
      <NodeContent data={{ node: node("api"), on: true, selected: false, dimmed: false }} />,
    );
    const outline = () => container.querySelector('[data-shape="rounded"] path');
    expect(outline()?.getAttribute("stroke")).toBe("var(--color-mint)");
    const accent = container.querySelector("span[aria-hidden]") as HTMLElement;
    // jsdom normalises the hex accent to rgb(), so compare through a probe element.
    const probe = document.createElement("span");
    probe.style.background = accentFor("high");
    expect(accent.style.background).toBe(probe.style.background);

    rerender(<NodeContent data={{ node: node("api"), on: false, selected: false, dimmed: true }} />);
    expect(outline()?.getAttribute("stroke")).toBe("var(--color-line-strong)");
    expect((container.firstChild as HTMLElement).style.opacity).toBe("0.3");
  });
});

describe("ArchitectureLegend", () => {
  it("lists only the types present, once each, in enum order", () => {
    const nodes = [node("database"), node("actor"), node("database", { id: "db2" })];
    expect(legendTypes(nodes)).toEqual(["actor", "database"]);
    render(<ArchitectureLegend nodes={nodes} />);
    const list = screen.getByRole("list", { name: "Component types" });
    expect(list.textContent).toBe("ActorDatabase");
  });
});

describe("exposure badge", () => {
  it("shows the node's exposure on the node", () => {
    const { container } = render(
      <NodeContent data={{ node: node("external_service", { exposure: "external" }), on: false, selected: false, dimmed: false }} />,
    );
    expect(container.querySelector('[data-exposure="external"]')?.textContent).toBe("External");
  });
});

describe("the icon slot", () => {
  it("is one size for every ComponentType, with the glyph the same size inside it", () => {
    for (const type of ComponentTypeSchema.options) {
      const { container, unmount } = render(
        <NodeContent data={{ node: node(type), on: false, selected: false, dimmed: false }} />,
      );
      const slot = container.querySelector('[data-testid="node-icon-slot"]') as HTMLElement;
      expect(slot.style.width, type).toBe(`${ICON_SLOT}px`);
      expect(slot.style.height, type).toBe(`${ICON_SLOT}px`);
      const glyph = slot.querySelector("svg[data-icon]")!;
      expect(glyph.getAttribute("width"), type).toBe(String(ICON_SIZE));
      expect(glyph.getAttribute("height"), type).toBe(String(ICON_SIZE));
      expect(glyph.getAttribute("viewBox"), type).toBe("0 0 16 16");
      expect(ICON_SIZE, type).toBeLessThan(ICON_SLOT);
      unmount();
    }
  });

  it("puts the icon in its own row, with the name on a line below it", () => {
    render(<NodeContent data={{ node: node("external_service"), on: false, selected: false, dimmed: false }} />);
    const slot = screen.getByTestId("node-icon-slot");
    const name = screen.getByText("The external_service");
    expect(slot.parentElement!.contains(name)).toBe(false);
    expect(slot.parentElement!.nextElementSibling).toBe(name);
  });

  it("draws the cloud for the node's whole height and keeps the other shapes sized to it", () => {
    const { container } = render(
      <NodeContent data={{ node: node("external_service"), on: false, selected: false, dimmed: false }} />,
    );
    const svg = container.querySelector('[data-shape="cloud"]')!;
    expect(svg.getAttribute("height")).toBe(String(NODE_HEIGHT));
    // The cloud's bottom edge is the node's, not a fixed 76.
    expect(svg.querySelector("path")!.getAttribute("d")).toContain(`${NODE_HEIGHT - 1.5}`);
  });

  it("labels an external service just \"Service\" inside a node, and titles the full type", () => {
    expect(nodeTypeText("external_service")).toBe("Service");
    expect(nodeTypeText("database")).toBe("Database");
    const { container } = render(
      <NodeContent data={{ node: node("external_service"), on: false, selected: false, dimmed: false }} />,
    );
    const label = screen.getByText("Service");
    expect(label.getAttribute("title")).toBe("External service");
    expect(container.contains(label)).toBe(true);
  });
});

describe("a stub node", () => {
  const stub = (type = "external_service") => ({
    node: node(type, { label: "Stripe", threatCount: 5, lowConfidenceThreatCount: 2, maxSeverity: "critical" }),
    stub: true,
    on: false,
    selected: false,
    dimmed: false,
  });

  it("is small, dashed, named and labelled as outside the view", () => {
    render(<StubContent data={stub()} />);
    const box = screen.getByTestId("node-stub");
    expect(box.style.width).toBe(`${STUB_WIDTH}px`);
    expect(box.style.height).toBe(`${STUB_HEIGHT}px`);
    expect(STUB_WIDTH).toBeLessThan(220);
    expect(box.className).toContain("border-dashed");
    expect(screen.getByText("Stripe")).toBeTruthy();
    expect(screen.getByText("outside this view")).toBeTruthy();
    expect(box.getAttribute("aria-label")).toBe("Stripe, outside this view");
  });

  it("shows no threat counts and no severity accent, whatever the node carries", () => {
    const { container } = render(<StubContent data={stub()} />);
    expect(screen.queryByText(/threat/)).toBeNull();
    expect(screen.queryByText(/max/)).toBeNull();
    expect(container.querySelector("[data-shape]")).toBeNull();
    expect(container.querySelector("span.absolute")).toBeNull();
  });

  it("is what NodeContent draws when the data says stub", () => {
    render(<NodeContent data={stub()} />);
    expect(screen.getByTestId("node-stub")).toBeTruthy();
    expect(screen.queryByTestId("node-threats")).toBeNull();
  });
});

