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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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

describe("Replayed indicator", () => {
  const counts = { evidence_backed: 7, assumption_dependent: 2 };

  it("shows a Replayed pill only for a replayed result", () => {
    render(<Dashboard view={demoView()} basisCounts={counts} replayed />);
    expect(screen.getByText("Replayed")).toBeTruthy();
  });

  it("shows nothing on a normal result, with or without the prop", () => {
    render(<Dashboard view={demoView()} basisCounts={counts} />);
    expect(screen.queryByText("Replayed")).toBeNull();
    cleanup();
    render(<Dashboard view={demoView()} basisCounts={counts} replayed={false} />);
    expect(screen.queryByText("Replayed")).toBeNull();
  });
});

describe("Dashboard with the demo fixture", () => {
  it("lists every scored threat from the adapter, in its order, below-25% ones last", () => {
    const view = renderDemo();
    expect(listedIds()).toEqual(
      [...view.threats, ...view.hiddenThreats].map((t) => `threat-card-${t.id}`),
    );
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

    expect(listedIds()).toHaveLength(view.threats.length + view.hiddenThreats.length);
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

    fireEvent.click(card.querySelector("button[aria-controls]")!);

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

describe("Limitations fold-out in the Dashboard", () => {
  const SENTENCE = "The diagram shows the Stripe and the build job as external systems.";

  it("selects the node a listed subject names, and shows other subjects as text", () => {
    const view = {
      ...demoView(),
      limitations: [SENTENCE],
      limitationDetails: [
        {
          code: "deployment_modelled_as_external",
          sentence: SENTENCE,
          subjects: ["the Stripe", "the build job"],
        },
      ],
    };
    render(<Dashboard view={view} basisCounts={{ evidence_backed: 7, assumption_dependent: 2 }} />);

    const link = screen.getByRole("button", { name: /^the Stripe/ });
    expect(screen.queryByRole("button", { name: /build job/ })).toBeNull();
    fireEvent.click(link);
    expect(screen.getByTestId("graph").getAttribute("data-selected")).toBe("stripe");
  });
});

/** The demo's ThreatModel, validated and otherwise untouched: what the server sends as rawThreatModel. */
function rawDemoModel() {
  const validated = validateThreatModel(demoJson);
  if (!validated.ok) throw new Error("demo fixture no longer validates");
  return validated.data;
}

describe("Export buttons", () => {
  /** Captures what the page offers as a download, with no network: Blob URLs only. */
  function captureDownloads() {
    const blobs: Blob[] = [];
    const names: string[] = [];
    URL.createObjectURL = vi.fn((blob: Blob) => {
      blobs.push(blob);
      return `blob:test-${blobs.length}`;
    });
    URL.revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      names.push(this.download);
    });
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const read = (blob: Blob) =>
      new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.readAsText(blob);
      });
    const bytes = (blob: Blob) =>
      new Promise<number[]>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve([...new Uint8Array(reader.result as ArrayBuffer)]);
        reader.readAsArrayBuffer(blob);
      });
    return { blobs, names, click, fetchSpy, read, bytes };
  }

  function csvRows(text: string): string[][] {
    return text
      .trim()
      .split("\r\n")
      .map((line) => line.slice(1, -1).split('","'));
  }

  // The unverified switch is remembered in localStorage, which outlives a test.
  beforeEach(() => window.localStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  it("downloads the threats the list is showing, with their status, and sends nothing", async () => {
    const view = renderDemo();
    const d = captureDownloads();
    fireEvent.click(within(screen.getByRole("list", { name: "Components" })).getByRole("button", { name: /Stripe/ }));
    const expected = [...view.threats, ...view.hiddenThreats].filter((t) => t.componentIds.includes("stripe"));
    expect(expected.length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Download CSV" }));
    // A UTF-8 byte order mark first, so a spreadsheet reads non-ASCII text correctly.
    expect((await d.bytes(d.blobs[0])).slice(0, 3)).toEqual([0xef, 0xbb, 0xbf]);
    const rows = csvRows(await d.read(d.blobs[0]));
    expect(rows[0].slice(0, 3)).toEqual(["id", "title", "severity"]);
    expect(rows.slice(1).map((r) => r[0])).toEqual(expected.map((t) => t.id));
    expect(rows[1][10]).toBe("open");
    expect(d.names).toEqual(["acme-acme-notes-threats.csv"]);
    expect(d.fetchSpy).not.toHaveBeenCalled();
  });

  it("includes the unverified threats while their switch is on, and not when it is off", async () => {
    const view = renderDemo();
    const d = captureDownloads();
    fireEvent.click(screen.getByRole("button", { name: "Download CSV" }));
    expect(csvRows(await d.read(d.blobs[0])).length - 1).toBe(view.threats.length + view.hiddenThreats.length);
    fireEvent.click(screen.getByRole("checkbox", { name: /unverified threats/ }));
    fireEvent.click(screen.getByRole("button", { name: "Download CSV" }));
    expect(csvRows(await d.read(d.blobs[1])).length - 1).toBe(view.threats.length);
  });

  it("downloads the ThreatModel as the server sent it, and nothing of the dashboard's own", async () => {
    const view = demoView();
    const raw = rawDemoModel();
    // Local state that must never reach the file: a status, a filter, the unverified switch.
    render(<Dashboard view={view} rawModel={raw} basisCounts={null} />);
    const d = captureDownloads();
    const card = within(screen.getByRole("region", { name: "Threats" })).getByTestId(`threat-card-${view.threats[1].id}`);
    fireEvent.change(within(card).getByRole("combobox"), { target: { value: "fixed" } });
    fireEvent.click(within(screen.getByRole("group", { name: "Severity" })).getByLabelText("High"));
    fireEvent.click(screen.getByRole("checkbox", { name: /unverified threats/ }));

    fireEvent.click(screen.getByRole("button", { name: "Download JSON" }));
    const text = await d.read(d.blobs[0]);
    const parsed = JSON.parse(text);
    expect(parsed).toEqual(JSON.parse(JSON.stringify(raw)));
    expect(Object.keys(parsed)).toEqual(Object.keys(raw));
    expect(validateThreatModel(parsed).ok).toBe(true);
    // The structure is the schema's: no view-model, status or filter fields anywhere.
    for (const uiOnly of ["counts", "fixNow", "fixNowTotal", "hiddenThreats", "filterOptions", "nodes", "edges", "limitationDetails", "analysisLevelLabel"]) {
      expect(parsed).not.toHaveProperty(uiOnly);
    }
    expect(text).not.toMatch(/"status"|"fixed"|accepted_risk|false_positive|"filters"/);
    expect(parsed.threats).toHaveLength(raw.threats.length);
    expect(parsed.components).toHaveLength(raw.components.length);
    expect(d.names).toEqual(["acme-acme-notes-threat-model.json"]);
    expect(d.blobs[0].type).toContain("application/json");
    expect(d.fetchSpy).not.toHaveBeenCalled();
  });

  it("keeps the JSON button off, and saves nothing, when the full model was not sent", () => {
    render(<Dashboard view={demoView()} basisCounts={null} />);
    const d = captureDownloads();
    const button = screen.getByRole("button", { name: "Download JSON" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
    expect(d.blobs).toHaveLength(0);
    expect(screen.getByRole("button", { name: "Download CSV" })).toBeTruthy();
  });

  it("neutralises a hostile title in the downloaded file", async () => {
    const view = demoView();
    const hostile = { ...view, threats: [{ ...view.threats[0], title: '=HYPERLINK("http://x","y")' }, ...view.threats.slice(1)] };
    render(<Dashboard view={hostile} basisCounts={null} />);
    const d = captureDownloads();
    fireEvent.click(screen.getByRole("button", { name: "Download CSV" }));
    const text = await d.read(d.blobs[0]);
    expect(text).toContain(`"'=HYPERLINK(`);
    expect(text).not.toContain(`,"=HYPERLINK`);
  });
});

describe("CSV rows match the list on screen, whatever filters are on", () => {
  beforeEach(() => window.localStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  function setup() {
    const blobs: Blob[] = [];
    URL.createObjectURL = vi.fn((blob: Blob) => {
      blobs.push(blob);
      return `blob:t-${blobs.length}`;
    });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const read = (blob: Blob) =>
      new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.readAsText(blob);
      });
    const region = () => screen.getByRole("region", { name: "Threats" });
    const displayed = () =>
      within(region())
        .queryAllByRole("article")
        .map((a) => (a.getAttribute("data-testid") ?? "").replace("threat-card-", ""));
    /** Downloads the CSV now and returns the ids in its rows. */
    const csvIds = async () => {
      fireEvent.click(screen.getByRole("button", { name: "Download CSV" }));
      const text = await read(blobs[blobs.length - 1]);
      return text
        .trim()
        .split("\r\n")
        .slice(1)
        .map((line) => line.slice(1, line.indexOf('"', 1)));
    };
    const check = async () => {
      const shown = displayed();
      expect(await csvIds()).toEqual(shown);
      return shown;
    };
    return { check, displayed, region };
  }

  const toggle = (group: string, label: string) =>
    fireEvent.click(within(screen.getByRole("group", { name: group })).getByLabelText(label));
  const unverified = () => screen.getByRole("checkbox", { name: /unverified threats/ });
  const setStatus = (id: string, value: string) =>
    fireEvent.change(
      within(within(screen.getByRole("region", { name: "Threats" })).getByTestId(`threat-card-${id}`)).getByRole("combobox"),
      { target: { value } },
    );

  it("matches with no filter, with the unverified switch on and off", async () => {
    const view = demoView();
    render(<Dashboard view={view} rawModel={rawDemoModel()} basisCounts={null} />);
    const { check } = setup();
    expect(await check()).toHaveLength(view.threats.length + view.hiddenThreats.length);
    fireEvent.click(unverified());
    const visibleOnly = await check();
    expect(visibleOnly).toEqual(view.threats.map((t) => t.id));
    for (const hidden of view.hiddenThreats) expect(visibleOnly).not.toContain(hidden.id);
  });

  it("matches under severity, component, search and status filters combined, with the switch both ways", async () => {
    const view = demoView();
    // Two Medium threats on the API Server: one listed, one below 25% confidence. A third
    // (S3, also Medium on the API Server and below 25%) matches the severity and component
    // filters but not the status or search ones.
    const quiet = view.hiddenThreats.find((t) => t.id === "note-search-resource-exhaustion")!;
    const loud = view.threats.find((t) => t.id === "vulnerable-jsonwebtoken-dependency")!;
    expect([quiet.severity, loud.severity]).toEqual(["medium", "medium"]);
    render(<Dashboard view={view} rawModel={rawDemoModel()} basisCounts={null} />);
    const { check } = setup();

    // The reader's own statuses, on one visible and one below-25% threat.
    setStatus(loud!.id, "false_positive");
    setStatus(quiet.id, "false_positive");

    // Severity + component.
    toggle("Severity", SEVERITY_LABEL[quiet.severity]);
    fireEvent.click(
      within(screen.getByRole("list", { name: "Components" })).getByRole("button", {
        name: new RegExp(`^${view.nodes.find((n) => n.id === quiet.componentIds[0])!.label}`),
      }),
    );
    const withHidden = await check();
    expect(withHidden).toContain(quiet.id);
    expect(withHidden).toContain(loud!.id);
    expect(withHidden).toContain("s3-attachments-public-read");
    expect(withHidden.length).toBeLessThan(view.threats.length + view.hiddenThreats.length);

    // + status.
    toggle("Status", "False positive");
    expect((await check()).sort()).toEqual([loud!.id, quiet.id].sort());

    // + search narrowing to the below-25% threat only.
    fireEvent.change(screen.getByLabelText(/Search threats/i), {
      target: { value: quiet.title.slice(0, 18) },
    });
    expect(await check()).toEqual([quiet.id]);

    // Switch off: the below-25% threat leaves the list and so the file; nothing replaces it.
    fireEvent.click(unverified());
    expect(await check()).toEqual([]);

    // Search cleared: only the visible match remains, never the hidden one.
    fireEvent.change(screen.getByLabelText(/Search threats/i), { target: { value: "" } });
    expect(await check()).toEqual([loud!.id]);

    // Back on: both, in list order (visible first, then below-25%).
    fireEvent.click(unverified());
    expect(await check()).toEqual([loud!.id, quiet.id]);
  });

  it("matches an empty list: a header and no rows", async () => {
    render(<Dashboard view={demoView()} rawModel={rawDemoModel()} basisCounts={null} />);
    const { check } = setup();
    fireEvent.change(screen.getByLabelText(/Search threats/i), { target: { value: "zzz-no-such-threat" } });
    expect(await check()).toEqual([]);
  });
});

const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" } as const;
