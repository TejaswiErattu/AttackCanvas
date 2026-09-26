// @vitest-environment jsdom

/**
 * Threats across runs, rendered: the low-confidence toggle, the "Including low-confidence"
 * summary line, the drift panel's wording, "Still open from the last run", and statuses that
 * follow a threat from run to run. Uses fixtures/demo-analysis.json (6 visible threats and 3
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

describe("low-confidence toggle", () => {
  it("is off by default and lists only the visible threats", () => {
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    const toggle = screen.getByRole("checkbox", { name: "Show 3 low-confidence threats" });
    expect((toggle as HTMLInputElement).checked).toBe(false);
    expect(cardIds()).toEqual(view.threats.map((t) => `threat-card-${t.id}`));
    expect(screen.queryByText(BELOW_CUTOFF_TEXT)).toBeNull();
  });

  it("lists hidden threats after the visible ones, greyed and badged, when on", () => {
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "Show 3 low-confidence threats" }));
    expect(cardIds()).toEqual([
      ...view.threats.map((t) => `threat-card-${t.id}`),
      ...view.hiddenThreats.map((t) => `threat-card-${t.id}`),
    ]);
    const hidden = within(threatsRegion()).getByTestId(`threat-card-${view.hiddenThreats[0].id}`);
    expect(hidden.getAttribute("data-below-cutoff")).toBe("true");
    expect(hidden.className).toContain("opacity-60");
    expect(within(hidden).getByText(BELOW_CUTOFF_TEXT)).toBeTruthy();
    expect(screen.getAllByText(BELOW_CUTOFF_TEXT)).toHaveLength(3);
    // Still counted as today: the "Showing" line and Fix now ignore hidden threats.
    expect(within(threatsRegion()).getByText(`Showing 6 of 6 threats`)).toBeTruthy();
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

  it("adds the including-low-confidence line under the counts when threats are hidden", () => {
    render(
      <SeveritySummary
        counts={counts}
        basisCounts={null}
        fixNowCount={2}
        hiddenCounts={{ critical: 0, high: 1, medium: 1, low: 0 }}
      />,
    );
    expect(screen.getByTestId("including-low-confidence").textContent).toContain("Including low-confidence: Critical 1, High 4, Medium 2, Low 1");
  });

  it("keeps the visible counts in the tiles", () => {
    render(
      <SeveritySummary
        counts={counts}
        basisCounts={null}
        fixNowCount={2}
        hiddenCounts={{ critical: 4, high: 0, medium: 0, low: 0 }}
      />,
    );
    const tiles = [...document.querySelectorAll("dd")].map((dd) => dd.textContent);
    expect(tiles).toEqual(["1", "3", "1", "1", "2"]);
    expect(screen.getByText(/6 threats shown/)).toBeTruthy();
  });

  it("shows no line when nothing is hidden", () => {
    render(
      <SeveritySummary
        counts={counts}
        basisCounts={null}
        fixNowCount={2}
        hiddenCounts={{ critical: 0, high: 0, medium: 0, low: 0 }}
      />,
    );
    expect(screen.queryByTestId("including-low-confidence")).toBeNull();
    expect(screen.queryByTestId("carried-count")).toBeNull();
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

  it("names the two groups and never says resolved or fixed", () => {
    render(<SinceLastRun drift={drift} />);
    const panel = screen.getByTestId("since-last-run");
    expect(within(panel).getByText("Not found this run (2)")).toBeTruthy();
    expect(within(panel).getByText("Dropped below 25% (1)")).toBeTruthy();
    expect(within(panel).getByText("Quiet gone (was below 25%)")).toBeTruthy();
    expect(within(panel).getByText("Weak cookie (now 12%)")).toBeTruthy();
    expect(panel.textContent).not.toMatch(/resolved|fixed/i);
  });

  it("keeps the nothing-to-compare message on a first run", () => {
    render(<SinceLastRun drift={null} />);
    expect(screen.getByText(/nothing to compare/)).toBeTruthy();
  });
});

describe("across two runs in the Dashboard", () => {
  it("first run: no carried section, drift has nothing to compare, counts as today", async () => {
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    expect(await screen.findByText(/nothing to compare/)).toBeTruthy();
    expect(screen.queryByTestId("carried-forward")).toBeNull();
    expect(screen.queryByTestId("carried-count")).toBeNull();
  });

  it("carries forward an unclosed threat the last run had, outside this run's counts", async () => {
    const view = demoView();
    const gone = goneThreat("threat-old-1", "Password reset token never expires");
    const closed = goneThreat("threat-old-2", "Debug endpoint left enabled");
    window.localStorage.setItem(LAST, JSON.stringify(previousRun(view, [gone, closed])));
    window.localStorage.setItem(STATUS, JSON.stringify({ [threatKey(closed)]: "fixed" }));
    render(<Dashboard view={view} basisCounts={null} />);

    const carried = await screen.findByTestId("carried-forward");
    expect(within(carried).getByText("Still open from the last run (2026-09-01)")).toBeTruthy();
    expect(within(carried).getByText(gone.title)).toBeTruthy();
    expect(within(carried).getByText("72% confidence last run")).toBeTruthy();
    expect(within(carried).getByText("Not re-found this run.")).toBeTruthy();
    expect(within(carried).queryByText(closed.title)).toBeNull();
    expect(screen.getByTestId("carried-count").textContent).toContain("1 from the last run not re-found and not marked fixed.");
    // Not in this run's list or Fix now.
    expect(cardIds()).not.toContain("threat-card-threat-old-1");
    const drift = screen.getByTestId("since-last-run");
    expect(within(drift).getByText("Not found this run (2)")).toBeTruthy();
    expect(drift.textContent).not.toMatch(/resolved/i);
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
