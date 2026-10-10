// @vitest-environment jsdom

/**
 * The History tab of the "Since last run" panel, alone and inside the Dashboard: one row
 * per stored run, a per-threat timeline with a visible gap, status changes on the timeline,
 * and the sentence that Not found never means Fixed.
 *
 * ArchitectureGraph is stubbed only because React Flow needs layout APIs jsdom lacks.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { toDashboardViewModel } from "@/client/adapter";
import { lastRunKey, prevRunKey, threatKey } from "@/client/drift";
import { readRuns, recordRun, runsKey, toRunEntry } from "@/client/runHistory";
import { statusStorageKey } from "@/client/findingStatus";
import { validateThreatModel } from "@/shared/schema";
import type { DashboardViewModel, ThreatCardData } from "@/shared/viewModel";
import SinceLastRun from "@/components/SinceLastRun";
import demoJson from "../fixtures/demo-analysis.json";

vi.mock("@/components/ArchitectureGraph", () => ({ default: () => <div data-testid="graph" /> }));

const { default: Dashboard } = await import("@/components/Dashboard");

beforeEach(() => window.localStorage.clear());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function demoView(): DashboardViewModel {
  const validated = validateThreatModel(demoJson);
  if (!validated.ok) throw new Error("demo fixture no longer validates");
  return toDashboardViewModel(validated.data);
}

function threat(title: string, confidence: number): ThreatCardData {
  return {
    id: `id-${title}`,
    title,
    componentNames: ["API"],
    severity: "high",
    confidence,
    owasp: [{ code: "A01:2025", label: "A01:2025" }],
  } as unknown as ThreatCardData;
}

function entry(n: number, threats: ThreatCardData[]) {
  return toRunEntry({
    nodes: [],
    edges: [],
    threats,
    repo: { ref: "main", analyzedAt: `2026-09-0${n}T10:00:00.000Z` },
    analysisLevel: 2,
  });
}

const SQLI = "SQL injection in login";
const REDIRECT = "Open redirect";
// SQLI in runs 1, 2 and 4; absent from 3.
const RUNS = [
  entry(1, [threat(SQLI, 60)]),
  entry(2, [threat(SQLI, 72), threat(REDIRECT, 50)]),
  entry(3, [threat(REDIRECT, 50)]),
  entry(4, [threat(SQLI, 35)]),
];

function renderPanel(selectedKey: string | null = threatKey(threat(SQLI, 1))) {
  const drift = { threats: { new: [], persisting: [], notFound: [], droppedBelowCutoff: [] } };
  render(<SinceLastRun drift={drift} runs={RUNS} selectedKey={selectedKey} />);
  fireEvent.click(screen.getByRole("tab", { name: "History" }));
}

describe("History tab", () => {
  it("is a second tab only when runs are stored, and opens on Since last run", () => {
    render(<SinceLastRun drift={null} />);
    expect(screen.queryByRole("tab")).toBeNull();
    cleanup();
    render(<SinceLastRun drift={null} runs={RUNS} />);
    expect(screen.getByRole("tab", { name: "Since last run" }).getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tab", { name: "History" }).getAttribute("aria-selected")).toBe("false");
  });

  it("lists one row per stored run, newest first, with counts against the run before it", () => {
    renderPanel();
    const rows = within(screen.getByRole("table")).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(4);
    const text = rows.map((r) => within(r).getAllByRole("cell").map((c) => c.textContent));
    // ref, level, threats, visible, new, not found
    expect(text.map((cells) => cells.slice(2))).toEqual([
      ["1", "1", "1", "1"], // run 4: SQLI is back (new) and REDIRECT is gone
      ["1", "1", "0", "1"], // run 3
      ["2", "2", "1", "0"], // run 2
      ["1", "1", "n/a", "n/a"], // run 1 has nothing before it
    ]);
    expect(within(rows[0]).getByRole("rowheader").textContent).toBe("2026-09-04 10:00 UTC");
  });

  it("shows a gap in the timeline for the run a threat was not found in", () => {
    renderPanel();
    const timeline = within(screen.getByTestId("threat-timeline"));
    const steps = timeline.getAllByRole("listitem");
    expect(steps.map((s) => s.getAttribute("data-found"))).toEqual(["true", "false", "true", "true"]);
    expect(steps.map((s) => s.textContent)).toEqual([
      expect.stringContaining("Found, 35% confidence"),
      expect.stringContaining("Not found in this run"),
      expect.stringContaining("Found, 72% confidence"),
      expect.stringContaining("Found, 60% confidence"),
    ]);
  });

  it("starts the timeline on the selected threat and lets the reader pick another", () => {
    renderPanel(threatKey(threat(REDIRECT, 1)));
    const select = screen.getByRole("combobox") as HTMLSelectElement;
    expect(select.value).toBe(threatKey(threat(REDIRECT, 1)));
    fireEvent.change(select, { target: { value: threatKey(threat(SQLI, 1)) } });
    const steps = within(screen.getByTestId("threat-timeline")).getAllByRole("listitem");
    expect(steps[1].textContent).toContain("Not found in this run");
  });

  it("falls back to the first threat when nothing usable is selected", () => {
    renderPanel(null);
    expect((screen.getByRole("combobox") as HTMLSelectElement).selectedOptions[0].textContent).toBe(SQLI);
  });

  it("never describes a missing threat as fixed or resolved, and says why", () => {
    renderPanel();
    const panel = screen.getByTestId("since-last-run");
    expect(panel.textContent).toContain("not the same as Fixed");
    expect(panel.textContent).not.toMatch(/resolved|\bfixed\b/);
  });

  it("keeps the same reminder on the Since last run tab", () => {
    render(
      <SinceLastRun
        drift={{ threats: { new: [], persisting: [], notFound: [], droppedBelowCutoff: [] } }}
        runs={RUNS}
      />,
    );
    expect(screen.getByTestId("since-last-run").textContent).toContain(
      "Not found is not the same as Fixed: only a status you set closes a threat.",
    );
  });
});

describe("History in the Dashboard", () => {
  it("migrates the old last and prev snapshots into the ring on first load", async () => {
    const view = demoView();
    const old = (at: string) => ({ ...view, repo: { ...view.repo, analyzedAt: at } });
    window.localStorage.setItem(prevRunKey("acme", "acme-notes"), JSON.stringify(old("2026-08-01T09:00:00Z")));
    window.localStorage.setItem(lastRunKey("acme", "acme-notes"), JSON.stringify(old("2026-09-01T09:00:00Z")));
    render(<Dashboard view={view} basisCounts={null} />);

    await screen.findByTestId("since-last-run");
    expect(readRuns(window.localStorage, "acme", "acme-notes")).toHaveLength(3);
    expect(window.localStorage.getItem(lastRunKey("acme", "acme-notes"))).toBeNull();
    expect(window.localStorage.getItem(prevRunKey("acme", "acme-notes"))).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "History" }));
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(4);
  });

  it("logs a status change on the timeline of that threat", async () => {
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    await screen.findByTestId("since-last-run");

    const target = view.threats[1];
    const card = within(screen.getByRole("region", { name: "Threats" })).getByTestId(`threat-card-${target.id}`);
    fireEvent.change(within(card).getByRole("combobox"), { target: { value: "accepted_risk" } });

    const stored = JSON.parse(window.localStorage.getItem(runsKey("acme", "acme-notes")) ?? "[]");
    expect(stored[0].statusChanges).toEqual([
      expect.objectContaining({ key: threatKey(target), status: "accepted_risk" }),
    ]);

    fireEvent.click(screen.getByRole("tab", { name: "History" }));
    const timeline = within(screen.getByTestId("threat-timeline"));
    fireEvent.change(timeline.getByRole("combobox"), { target: { value: threatKey(target) } });
    expect(screen.getByTestId("threat-timeline").textContent).toContain("Status set to Accepted risk on");
  });

  it("keeps five runs when a sixth analysis loads", async () => {
    const view = demoView();
    for (let n = 1; n <= 6; n += 1) {
      const { unmount } = render(
        <Dashboard view={{ ...view, repo: { ...view.repo, analyzedAt: `2026-09-0${n}T10:00:00Z` } }} basisCounts={null} />,
      );
      await screen.findByTestId("since-last-run");
      unmount();
    }
    const stored = readRuns(window.localStorage, "acme", "acme-notes");
    expect(stored.map((r) => r.at.slice(0, 10))).toEqual([
      "2026-09-02", "2026-09-03", "2026-09-04", "2026-09-05", "2026-09-06",
    ]);
  });
});

const REPO = ["acme", "acme-notes"] as const;
const runAt = (n: number) => `2026-09-0${n}T10:00:00.000Z`;

function seedRuns(count: number) {
  const view = demoView();
  for (let n = 1; n <= count; n += 1) {
    recordRun(window.localStorage, ...REPO, { ...view, repo: { ...view.repo, analyzedAt: runAt(n) } });
  }
}

function threatsRegion() {
  return screen.getByRole("region", { name: "Threats" });
}

describe("a replayed result", () => {
  it("is shown with its findings and against the stored runs, and never added to them", async () => {
    seedRuns(5);
    const before = window.localStorage.getItem(runsKey(...REPO));
    const view = { ...demoView(), repo: { ...demoView().repo, analyzedAt: "2026-09-30T10:00:00.000Z" } };

    for (let i = 0; i < 3; i += 1) {
      const { unmount } = render(<Dashboard view={view} basisCounts={null} replayed />);
      const panel = await screen.findByTestId("since-last-run");
      expect(within(threatsRegion()).getAllByRole("article").length).toBeGreaterThan(0);
      expect(screen.getByText("Replayed")).toBeTruthy();
      fireEvent.click(within(panel).getByRole("tab", { name: "History" }));
      expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(6);
      unmount();
    }
    expect(window.localStorage.getItem(runsKey(...REPO))).toBe(before);
  });

  it("writes nothing when there is no history, and shows the first-run message", async () => {
    render(<Dashboard view={demoView()} basisCounts={null} replayed />);
    expect(await screen.findByText(/nothing to compare/)).toBeTruthy();
    expect(window.localStorage.getItem(runsKey(...REPO))).toBeNull();
  });

  it("keeps the ring intact next to a genuine run, which does evict the oldest", async () => {
    seedRuns(5);
    const view = demoView();
    const replay = render(<Dashboard view={view} basisCounts={null} replayed />);
    await screen.findByTestId("since-last-run");
    replay.unmount();
    expect(readRuns(window.localStorage, ...REPO).map((r) => r.at)).toEqual([1, 2, 3, 4, 5].map(runAt));

    render(<Dashboard view={{ ...view, repo: { ...view.repo, analyzedAt: runAt(6) } }} basisCounts={null} />);
    await screen.findByTestId("since-last-run");
    expect(readRuns(window.localStorage, ...REPO).map((r) => r.at)).toEqual([2, 3, 4, 5, 6].map(runAt));
  });

  it("does not log a status change on the history, though the status itself is saved", async () => {
    seedRuns(2);
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} replayed />);
    await screen.findByTestId("since-last-run");
    const card = within(threatsRegion()).getByTestId(`threat-card-${view.threats[1].id}`);
    fireEvent.change(within(card).getByRole("combobox"), { target: { value: "fixed" } });
    expect(readRuns(window.localStorage, ...REPO).every((r) => r.statusChanges === undefined)).toBe(true);
    expect(window.localStorage.getItem(statusStorageKey(...REPO, "main"))).toContain("fixed");
  });
});

describe("statuses through the move from last/prev to the ring", () => {
  const OLD_IDS = ["old-1", "old-2", "old-3"];

  function legacyViews(view: DashboardViewModel) {
    const renamed = view.threats.slice(0, 3).map((t, i) => ({ ...t, id: OLD_IDS[i] }));
    const last = {
      ...view,
      repo: { ...view.repo, analyzedAt: "2026-09-01T09:00:00Z" },
      threats: [...renamed, ...view.threats.slice(3)],
    };
    return { last, prev: { ...last, repo: { ...view.repo, analyzedAt: "2026-08-01T09:00:00Z" } } };
  }

  it("keeps Fixed, Accepted risk and False positive set by threat number, on the same threats", async () => {
    const view = demoView();
    const { last, prev } = legacyViews(view);
    window.localStorage.setItem(`attackcanvas:last:acme/acme-notes`, JSON.stringify(last));
    window.localStorage.setItem(`attackcanvas:prev:acme/acme-notes`, JSON.stringify(prev));
    window.localStorage.setItem(
      statusStorageKey(...REPO, "main"),
      JSON.stringify({ "old-1": "fixed", "old-2": "accepted_risk", "old-3": "false_positive" }),
    );
    render(<Dashboard view={view} basisCounts={null} />);
    await screen.findByTestId("since-last-run");

    const region = within(threatsRegion());
    const label = (i: number) => region.getByTestId(`status-badge-${view.threats[i].id}`).textContent;
    expect([label(0), label(1), label(2)]).toEqual(["Fixed", "Accepted risk", "False positive"]);
    expect(JSON.parse(window.localStorage.getItem(statusStorageKey(...REPO, "main")) ?? "{}")).toEqual({
      [threatKey(view.threats[0])]: "fixed",
      [threatKey(view.threats[1])]: "accepted_risk",
      [threatKey(view.threats[2])]: "false_positive",
    });
    expect(readRuns(window.localStorage, ...REPO)).toHaveLength(3);
    expect(window.localStorage.getItem(`attackcanvas:last:acme/acme-notes`)).toBeNull();
  });

  it("leaves statuses already keyed by threat identity exactly as they are", async () => {
    const view = demoView();
    const { last, prev } = legacyViews(view);
    const saved = JSON.stringify({
      [threatKey(view.threats[0])]: "fixed",
      [threatKey(view.threats[1])]: "accepted_risk",
      [threatKey(view.threats[2])]: "false_positive",
    });
    window.localStorage.setItem(statusStorageKey(...REPO, "main"), saved);
    window.localStorage.setItem(`attackcanvas:last:acme/acme-notes`, JSON.stringify(last));
    window.localStorage.setItem(`attackcanvas:prev:acme/acme-notes`, JSON.stringify(prev));
    render(<Dashboard view={view} basisCounts={null} />);
    await screen.findByTestId("since-last-run");
    expect(window.localStorage.getItem(statusStorageKey(...REPO, "main"))).toBe(saved);
    expect(within(threatsRegion()).getByTestId(`status-badge-${view.threats[2].id}`).textContent).toBe(
      "False positive",
    );
  });
});

describe("status-change timeline", () => {
  it("lists successive changes to one threat in order, none for the others", async () => {
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    await screen.findByTestId("since-last-run");
    const target = view.threats[1];
    const select = () =>
      within(within(threatsRegion()).getByTestId(`threat-card-${target.id}`)).getByRole("combobox");
    fireEvent.change(select(), { target: { value: "accepted_risk" } });
    fireEvent.change(select(), { target: { value: "fixed" } });
    fireEvent.change(select(), { target: { value: "open" } });

    fireEvent.click(screen.getByRole("tab", { name: "History" }));
    const timeline = within(screen.getByTestId("threat-timeline"));
    fireEvent.change(timeline.getByRole("combobox"), { target: { value: threatKey(target) } });
    const text = screen.getByTestId("threat-timeline").textContent ?? "";
    expect([...text.matchAll(/Status set to ([A-Za-z ]+?) on/g)].map((m) => m[1])).toEqual([
      "Accepted risk",
      "Fixed",
      "Open",
    ]);
    fireEvent.change(timeline.getByRole("combobox"), { target: { value: threatKey(view.threats[0]) } });
    expect(screen.getByTestId("threat-timeline").textContent).not.toContain("Status set to");
  });

  it("still shows this run and the change when storage cannot save", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota");
    });
    const view = demoView();
    render(<Dashboard view={view} basisCounts={null} />);
    await screen.findByTestId("since-last-run");
    const target = view.threats[1];
    fireEvent.change(
      within(within(threatsRegion()).getByTestId(`threat-card-${target.id}`)).getByRole("combobox"),
      { target: { value: "fixed" } },
    );
    fireEvent.click(screen.getByRole("tab", { name: "History" }));
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(2);
    fireEvent.change(within(screen.getByTestId("threat-timeline")).getByRole("combobox"), {
      target: { value: threatKey(target) },
    });
    expect(screen.getByTestId("threat-timeline").textContent).toContain("Status set to Fixed on");
  });
});

describe("storage that fails or holds garbage", () => {
  async function renders(view = demoView()) {
    render(<Dashboard view={view} basisCounts={null} />);
    expect(await screen.findByTestId("since-last-run")).toBeTruthy();
    expect(within(threatsRegion()).getAllByRole("article").length).toBeGreaterThan(0);
  }

  it("renders when every read and write throws", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    await renders();
    expect(screen.getByText(/nothing to compare/)).toBeTruthy();
  });

  it("renders when the storage object itself cannot be reached", async () => {
    vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
      throw new Error("SecurityError");
    });
    await renders();
  });

  it.each([
    ["not JSON", "{not json"],
    ["an object", '{"a":1}'],
    ["entries of the wrong shape", '[1,"x",null,{"at":5},{"at":"x","ref":"m","level":null,"threats":[{"key":1}]}]'],
    ["a threat with no title", '[{"at":"2026-09-01T00:00:00Z","ref":"main","level":2,"threats":[{"key":"k"}]}]'],
  ])("renders when the stored runs are %s", async (_name, raw) => {
    window.localStorage.setItem(runsKey(...REPO), raw);
    await renders();
    expect(readRuns(window.localStorage, ...REPO)).toHaveLength(1);
  });

  it("renders when old snapshots are corrupt", async () => {
    window.localStorage.setItem(`attackcanvas:last:acme/acme-notes`, "{not json");
    window.localStorage.setItem(`attackcanvas:prev:acme/acme-notes`, '{"nodes":1}');
    await renders();
  });

  it("stores a run over 200 KB without confidences and still renders and compares it", async () => {
    const view = demoView();
    const fat = (n: number): DashboardViewModel => ({
      ...view,
      repo: { ...view.repo, analyzedAt: runAt(n) },
      threats: view.threats.map((t, i) => ({ ...t, title: `${t.title} ${i} ${"x".repeat(20000)}` })),
    });
    for (const n of [1, 2]) {
      const { unmount } = render(<Dashboard view={fat(n)} basisCounts={null} />);
      await screen.findByTestId("since-last-run");
      unmount();
    }
    const stored = readRuns(window.localStorage, ...REPO);
    expect(stored).toHaveLength(2);
    expect(stored.every((r) => r.threats.every((t) => t.confidence === undefined))).toBe(true);

    render(<Dashboard view={fat(2)} basisCounts={null} />);
    expect(await screen.findByText(/0 new threats this run/)).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: "History" }));
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(3);
  });
});
