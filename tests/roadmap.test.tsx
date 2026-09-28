// @vitest-environment jsdom

/**
 * Coming soon (Prompt G): nine items from one source, rendered on the home page and at the
 * end of the dashboard, and copied word for word into README.md.
 */

import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { COMING_SOON } from "@/shared/roadmap";
import { toDashboardViewModel } from "@/client/adapter";
import { validateThreatModel } from "@/shared/schema";
import demoJson from "../fixtures/demo-analysis.json";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock("@/components/ArchitectureGraph", () => ({ default: () => <div data-testid="graph" /> }));

const { default: ComingSoon } = await import("@/components/ComingSoon");
const { default: HomePage } = await import("@/app/page");
const { default: Dashboard } = await import("@/components/Dashboard");

afterEach(cleanup);

function comingSoonSection(): HTMLElement {
  return screen.getByRole("heading", { name: "Coming soon" }).closest("section")!;
}

describe("Coming soon", () => {
  it("has exactly the nine playbook items", () => {
    expect(COMING_SOON).toHaveLength(9);
  });

  it("renders all nine titles and details", () => {
    render(<ComingSoon />);
    const section = within(comingSoonSection());
    for (const item of COMING_SOON) {
      expect(section.getByRole("heading", { name: item.title })).toBeTruthy();
      expect(section.getByText(item.detail)).toBeTruthy();
    }
  });

  it("is the last thing inside <main> on the home page", () => {
    render(<HomePage />);
    const main = screen.getByRole("main");
    expect(main.lastElementChild).toBe(comingSoonSection());
  });

  it("is the last section of the dashboard", () => {
    const validated = validateThreatModel(demoJson);
    if (!validated.ok) throw new Error("demo fixture no longer validates");
    const { container } = render(<Dashboard view={toDashboardViewModel(validated.data)} basisCounts={null} />);
    expect(container.firstElementChild!.lastElementChild).toBe(comingSoonSection());
  });

  it("matches the README Coming soon section word for word", () => {
    const readme = readFileSync("README.md", "utf8");
    const start = readme.indexOf("## Coming soon");
    expect(start).toBeGreaterThan(-1);
    const section = readme.slice(start, readme.indexOf("\n## ", start + 1));
    const bullets = section.split("\n").filter((line) => line.startsWith("- "));
    expect(bullets).toEqual(COMING_SOON.map((item) => `- **${item.title}.** ${item.detail}`));
  });
});
