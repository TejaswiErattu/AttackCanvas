// @vitest-environment jsdom

/**
 * The custom architecture node's shapes and icons, and the legend under the diagram.
 * NodeContent, NodeShape and TypeIcon need no React Flow context, so they render here.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ComponentTypeSchema } from "@/shared/schema";
import type { GraphNode } from "@/shared/viewModel";
import { NodeContent, accentFor, shapeOf } from "@/components/ArchitectureNode";
import ArchitectureLegend, { legendTypes } from "@/components/ArchitectureLegend";

afterEach(cleanup);

function node(type: string, overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    id: `n-${type}`,
    type: type as GraphNode["type"],
    label: `The ${type}`,
    position: { x: 0, y: 0 },
    threatCount: 2,
    maxSeverity: "high",
    technologies: [],
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
