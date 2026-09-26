// @vitest-environment jsdom

/**
 * Threats across runs, rendered: every scored threat listed (below-25% ones greyed, with a
 * toggle to take them out), severity tiles over every scored threat, an always-present Fix
 * now section, the two-line drift panel, and statuses that follow a threat from run to run. Uses fixtures/demo-analysis.json (6 visible threats and 3
 * below 25%) through the real adapter and Dashboard, with jsdom's localStorage.
 *
 * ArchitectureGraph is stubbed only because React Flow needs layout APIs jsdom lacks.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { toDashboardViewModel } from "@/client/adapter";
import { lastRunKey, threatKey, type DriftResult } from "@/client/drift";
import { statusStorageKey } from "@/client/findingStatus";
import { validateThreatModel } from "@/shared/schema";
import type { DashboardViewModel, ThreatCardData } from "@/shared/viewModel";
import SeveritySummary from "@/components/SeveritySummary";
import SinceLastRun from "@/components/SinceLastRun";
import ThreatList from "@/components/ThreatList";
import { BELOW_CUTOFF_TEXT } from "@/components/ThreatCard";
import demoJson from "../fixtures/demo-analysis.json";

vi.mock("@/components/ArchitectureGraph", () => ({ default: () => <div data-testid="graph" /> }));

const { default: Dashboard } = await import("@/components/Dashboard");

const LAST = lastRunKey("acme", "acme-notes");
const STATUS = statusStorageKey("acme", "acme-notes", "main");

beforeEach(() => window.localStorage.clear());
afterEach(cleanup);

function demoView(): DashboardViewModel {
  const validated = validateThreatModel(demoJson);
  if (!validated.ok) throw new Error("demo fixture no longer validates");
  return toDashboardViewModel(validated.data);
}

function threatsRegion() {
  return screen.getByRole("region", { name: "Threats" });
}

function cardIds(): string[] {
  return within(threatsRegion())
    .getAllByRole("article")
    .map((a) => a.getAttribute("data-testid") ?? "");
}

/** A previous run of the same repository: the demo, plus one threat this run lacks. */
function previousRun(view: DashboardViewModel, extra: ThreatCardData[]) {
  return {
    ...view,
    repo: { ...view.repo, analyzedAt: "2026-09-01T09:00:00Z" },
    threats: [...view.threats, ...extra],
  };
}

function goneThreat(id: string, title: string): ThreatCardData {
  const base = demoView().threats[0];
  return { ...base, id, title, severity: "critical", confidence: 72 };
}

describe("low-confidence threats in the list", () => {
  it("lists every scored threat by default, below-25% ones last, greyed and badged", () => {
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    const toggle = screen.getByRole("checkbox", { name: "Show 3 low-confidence threats" });
    expect((toggle as HTMLInputElement).checked).toBe(true);
    expect(cardIds()).toEqual([
      ...view.threats.map((t) => `threat-card-${t.id}`),
      ...view.hiddenThreats.map((t) => `threat-card-${t.id}`),
    ]);
    const hidden = within(threatsRegion()).getByTestId(`threat-card-${view.hiddenThreats[0].id}`);
    expect(hidden.getAttribute("data-below-cutoff")).toBe("true");
    expect(hidden.className).toContain("opacity-60");
    expect(within(hidden).getByText(BELOW_CUTOFF_TEXT)).toBeTruthy();
    expect(screen.getAllByText(BELOW_CUTOFF_TEXT)).toHaveLength(3);
    expect(
      within(threatsRegion()).getByText("Showing 9 of 9 threats, 3 below 25% confidence"),
    ).toBeTruthy();
  });

  it("takes them out of the list when the toggle is turned off", () => {
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "Show 3 low-confidence threats" }));
    expect(cardIds()).toEqual(view.threats.map((t) => `threat-card-${t.id}`));
    expect(screen.queryByText(BELOW_CUTOFF_TEXT)).toBeNull();
  });

  it("never puts a below-25% threat in Fix now", () => {
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    const fixNow = screen.getByRole("region", { name: "Fix now" });
    view.hiddenThreats.forEach((t) =>
      expect(within(fixNow).queryByTestId(`threat-card-${t.id}`)).toBeNull(),
    );
  });

  it("keeps the Fix now section when nothing meets the bar", () => {
    const view = { ...demoView(), fixNow: [], fixNowTotal: 0 };
    render(<Dashboard view={view} basisCounts={null} />);
    const fixNow = screen.getByRole("region", { name: "Fix now" });
    expect(within(fixNow).getByTestId("fix-now-empty").textContent).toContain(
      "No threat met the Fix now bar in this run",
    );
  });

  it("links the empty-list message to the toggle", () => {
    const onChange = vi.fn();
    render(
      <ThreatList
        threats={[]}
        selectedId={null}
        onSelect={() => {}}
        totalCount={0}
        hiddenSummary={{ scored: 41, hidden: 41, topReason: null, topReasonCount: 0 }}
        hiddenThreats={demoView().hiddenThreats}
        hiddenTotal={41}
        showHidden={false}
        onShowHiddenChange={onChange}
      />,
    );
    expect(screen.getByText(/41 threats were scored; all fell below 25% confidence/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Show 41 low-confidence threats" }));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("shows no toggle when nothing is hidden", () => {
    render(<ThreatList threats={[]} selectedId={null} onSelect={() => {}} totalCount={0} />);
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("button")).toBeNull();
  });
});

describe("severity summary", () => {
  const counts = { critical: 1, high: 3, medium: 1, low: 1 };

  it("counts every scored threat in the tiles and says how many are below 25%", () => {
    render(
      <SeveritySummary
        counts={counts}
        basisCounts={null}
        fixNowCount={2}
        hiddenCounts={{ critical: 0, high: 1, medium: 1, low: 0 }}
      />,
    );
    const tiles = [...document.querySelectorAll("dd")].map((dd) => dd.textContent);
    expect(tiles).toEqual(["1", "4", "2", "1", "2"]);
    expect(screen.getByTestId("scored-line").textContent).toBe(
      "8 threats scored, 2 of them below 25% confidence: unverified, greyed in the list and never in Fix now.",
    );
  });

  it("keeps Fix now to the server's count", () => {
    render(
      <SeveritySummary
        counts={counts}
        basisCounts={null}
        fixNowCount={2}
        hiddenCounts={{ critical: 4, high: 0, medium: 0, low: 0 }}
      />,
    );
    const tiles = [...document.querySelectorAll("dd")].map((dd) => dd.textContent);
    expect(tiles).toEqual(["5", "3", "1", "1", "2"]);
  });

  it("says nothing about 25% when nothing is below it", () => {
    render(
      <SeveritySummary
        counts={counts}
        basisCounts={null}
        fixNowCount={2}
        hiddenCounts={{ critical: 0, high: 0, medium: 0, low: 0 }}
      />,
    );
    expect(screen.getByTestId("scored-line").textContent).toBe("6 threats scored.");
  });
});

describe("drift panel wording", () => {
  const ref = (title: string, confidence: number, belowCutoff = false) => ({
    key: title, title, componentNames: [], owasp: [], severity: "high" as const, confidence, belowCutoff,
  });
  const drift: DriftResult = {
    components: { added: [], removed: [] },
    flows: { added: [], removed: [] },
    threats: {
      new: [],
      persisting: [],
      notFound: [ref("Gone threat", 60), ref("Quiet gone", 10, true)],
      droppedBelowCutoff: [ref("Weak cookie", 12, true)],
    },
  };

  it("shows two short lines and never says resolved or fixed", () => {
    render(<SinceLastRun drift={drift} notClosedCount={1} lastRunDate="2026-09-12" />);
    const panel = screen.getByTestId("since-last-run");
    expect(within(panel).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "0 new threats this run.",
      "2 threats from the last run not found this run, 1 of them not marked Fixed or False positive.",
    ]);
    expect(panel.textContent).toContain("Since last run (2026-09-12)");
    expect(panel.textContent).not.toMatch(/resolved|\bfixed\b/);
  });

  it("keeps the nothing-to-compare message on a first run", () => {
    render(<SinceLastRun drift={null} />);
    expect(screen.getByText(/nothing to compare/)).toBeTruthy();
  });
});

describe("across two runs in the Dashboard", () => {
  it("first run: drift has nothing to compare", async () => {
    render(<Dashboard view={demoView()} basisCounts={null} />);
    expect(await screen.findByText(/nothing to compare/)).toBeTruthy();
  });

  it("counts last-run threats not found and not closed, outside this run's list", async () => {
    const view = demoView();
    const gone = goneThreat("threat-old-1", "Password reset token never expires");
    const closed = goneThreat("threat-old-2", "Debug endpoint left enabled");
    window.localStorage.setItem(LAST, JSON.stringify(previousRun(view, [gone, closed])));
    window.localStorage.setItem(STATUS, JSON.stringify({ [threatKey(closed)]: "fixed" }));
    render(<Dashboard view={view} basisCounts={null} />);

    const panel = await screen.findByTestId("since-last-run");
    expect(await within(panel).findByText(/2 threats from the last run not found this run, 1 of them/)).toBeTruthy();
    expect(panel.textContent).toContain("(2026-09-01)");
    expect(cardIds()).not.toContain("threat-card-threat-old-1");
    expect(panel.textContent).not.toMatch(/resolved/i);
  });

  it("migrates an id-keyed status map once, against the run it was saved on", async () => {
    const view = demoView();
    const first = view.threats[0];
    // The last run numbered this threat differently; its id-keyed map refers to that run.
    const lastRun = { ...view, threats: [{ ...first, id: "threat-9" }, ...view.threats.slice(1)] };
    window.localStorage.setItem(LAST, JSON.stringify(lastRun));
    window.localStorage.setItem(STATUS, JSON.stringify({ "threat-9": "fixed", "threat-404": "fixed" }));
    render(<Dashboard view={view} basisCounts={null} />);

    expect((await within(threatsRegion()).findByTestId(`status-badge-${first.id}`)).textContent).toBe("Fixed");
    const stored = JSON.parse(window.localStorage.getItem(STATUS) ?? "{}");
    expect(stored).toEqual({ [threatKey(first)]: "fixed" });
  });

  it("saves a status by threatKey, so it follows the threat to a run that renumbers it", async () => {
    const view = demoView();
    const target = view.threats[1];
    const { unmount } = render(<Dashboard view={view} basisCounts={null} />);
    const card = within(threatsRegion()).getByTestId(`threat-card-${target.id}`);
    fireEvent.change(within(card).getByRole("combobox"), { target: { value: "fixed" } });
    expect(JSON.parse(window.localStorage.getItem(STATUS) ?? "{}")).toEqual({
      [threatKey(target)]: "fixed",
    });
    unmount();

    const renumbered: DashboardViewModel = {
      ...view,
      repo: { ...view.repo, analyzedAt: "2026-10-01T00:00:00Z" },
      threats: view.threats.map((t, i) => ({ ...t, id: `threat-${i + 100}` })),
      fixNow: [],
    };
    render(<Dashboard view={renumbered} basisCounts={null} />);
    expect((await within(threatsRegion()).findByTestId("status-badge-threat-101")).textContent).toBe("Fixed");
  });
});
