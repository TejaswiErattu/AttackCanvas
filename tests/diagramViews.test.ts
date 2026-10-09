import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { toDashboardViewModel } from "@/client/adapter";
import {
  DIAGRAM_VIEWS,
  selectDiagramView,
  stubIdsFor,
  viewGraph,
  type DiagramView,
} from "@/client/diagramViews";
import { validateThreatModel } from "@/shared/schema";
import type { DashboardViewModel, GraphEdge, GraphNode, ThreatCardData } from "@/shared/viewModel";

const n = (id: string, type: GraphNode["type"]): GraphNode => ({
  id, type, label: id, position: { x: 0, y: 0 }, threatCount: 0, lowConfidenceThreatCount: 0, maxSeverity: null, technologies: [], assets: [], exposure: "internal",
});
const e = (
  id: string, source: string, target: string,
  dataClassification: GraphEdge["dataClassification"] = "internal", crossesTrustBoundary = false,
): GraphEdge => ({ id, source, target, label: id, dataClassification, crossesTrustBoundary });
const t = (id: string, componentIds: string[], owasp: string[], stride: string[]): ThreatCardData =>
  ({
    id, componentIds, dataFlowIds: [],
    owasp: owasp.map((code) => ({ code, label: code })),
    stride: stride.map((code) => ({ code, label: code })),
  }) as unknown as ThreatCardData;

const VIEW: Pick<DashboardViewModel, "nodes" | "edges" | "threats"> = {
  nodes: [
    n("user", "actor"), n("web", "frontend"), n("api", "api"), n("db", "database"),
    n("idp", "auth_provider"), n("stripe", "external_service"), n("jobs", "worker"),
  ],
  edges: [
    e("user-web", "user", "web", "public", true),
    e("web-api", "web", "api", "credential"),
    e("api-db", "api", "db", "sensitive"),
    e("api-idp", "api", "idp", "internal"),
    e("stripe-api", "stripe", "api", "internal", true),
    e("jobs-db", "jobs", "db", "internal"),
  ],
  threats: [
    t("t-access", ["api"], ["A01:2025"], ["T"]),
    t("t-spoof", ["web"], ["A05:2025"], ["S"]),
    t("t-dos", ["jobs"], ["A06:2025"], ["D"]),
  ],
};

const ids = (view: DiagramView) => selectDiagramView(VIEW, view);

describe("selectDiagramView", () => {
  it("overall shows every node and edge", () => {
    expect(ids("overall")).toEqual({
      nodeIds: VIEW.nodes.map((x) => x.id),
      edgeIds: VIEW.edges.map((x) => x.id),
    });
  });

  it("identity shows auth providers and components with an A01/A07 or S/E threat, and edges among them", () => {
    expect(ids("identity")).toEqual({ nodeIds: ["web", "api", "idp"], edgeIds: ["web-api", "api-idp"] });
  });

  it("identity counts A07 and elevation of privilege too", () => {
    const view = { ...VIEW, threats: [t("a", ["db"], ["A07:2025"], []), t("b", ["jobs"], [], ["E"])] };
    expect(selectDiagramView(view, "identity").nodeIds).toEqual(["db", "idp", "jobs"]);
  });

  it("data flows shows sensitive, credential and boundary-crossing flows and the nodes they touch", () => {
    expect(ids("data_flows")).toEqual({
      nodeIds: ["user", "web", "api", "db", "stripe"],
      edgeIds: ["user-web", "web-api", "api-db", "stripe-api"],
    });
  });

  it("external systems shows external services, auth providers, their neighbours and edges among them", () => {
    expect(ids("external")).toEqual({
      nodeIds: ["api", "idp", "stripe"],
      edgeIds: ["api-idp", "stripe-api"],
    });
  });

  it("returns nothing, not everything, when a view matches nothing", () => {
    const bare = { nodes: [n("web", "frontend")], edges: [], threats: [] };
    expect(selectDiagramView(bare, "external")).toEqual({ nodeIds: [], edgeIds: [] });
    expect(selectDiagramView(bare, "identity")).toEqual({ nodeIds: [], edgeIds: [] });
  });

  it("ignores threat components and flow endpoints that are not nodes", () => {
    const view = { ...VIEW, threats: [t("x", ["ghost"], ["A01:2025"], [])], edges: [e("g", "ghost", "idp", "credential")] };
    expect(selectDiagramView(view, "identity").nodeIds).toEqual(["idp"]);
    expect(selectDiagramView(view, "data_flows")).toEqual({ nodeIds: [], edgeIds: [] });
  });
});

// ---------------------------------------------------------------------------
// Edges never start or end in empty space
// ---------------------------------------------------------------------------

describe("every edge in every view has both endpoints drawn", () => {
  const model = (file: string) => {
    const validated = validateThreatModel(JSON.parse(readFileSync(file, "utf8")));
    if (!validated.ok) throw new Error(`${file} no longer validates`);
    return toDashboardViewModel(validated.data);
  };
  const inputs: [string, Pick<DashboardViewModel, "nodes" | "edges" | "threats">][] = [
    ["the synthetic view", VIEW],
    ["the demo fixture", model("fixtures/demo-analysis.json")],
    ["the saved NodeGoat model", model("fixtures/replay/OWASP__NodeGoat.json")],
  ];

  it.each(inputs)("in %s", (_name, input) => {
    for (const view of DIAGRAM_VIEWS) {
      const graph = viewGraph(input, view);
      const drawn = new Set([...graph.nodes, ...graph.stubs].map((node) => node.id));
      for (const edge of graph.edges) {
        expect(drawn.has(edge.source), `${view}: ${edge.id} source ${edge.source}`).toBe(true);
        expect(drawn.has(edge.target), `${view}: ${edge.id} target ${edge.target}`).toBe(true);
      }
      // The same holds of the plain selection: no view keeps an edge it cannot draw,
      // so today no view needs a stub at all.
      const selection = selectDiagramView(input, view);
      const shown = new Set(selection.nodeIds);
      const byId = new Map((input.edges ?? []).map((edge) => [edge.id, edge]));
      for (const id of selection.edgeIds) {
        expect(shown.has(byId.get(id)!.source), `${view}: ${id}`).toBe(true);
        expect(shown.has(byId.get(id)!.target), `${view}: ${id}`).toBe(true);
      }
      expect(graph.stubs, view).toEqual([]);
      expect(graph.edges.map((edge) => edge.id), view).toEqual(selection.edgeIds);
    }
  });
});

describe("stubs for the far end of a kept flow", () => {
  const input = { nodes: VIEW.nodes, edges: VIEW.edges, threats: [] };

  it("names the endpoint a view keeps an edge to but does not show", () => {
    const selection = { nodeIds: ["web", "api"], edgeIds: ["web-api", "api-db", "user-web"] };
    expect(stubIdsFor(input, selection)).toEqual(["user", "db"]);
  });

  it("gives none when both ends of every kept edge are shown, or no edge is kept", () => {
    expect(stubIdsFor(input, { nodeIds: ["web", "api"], edgeIds: ["web-api"] })).toEqual([]);
    expect(stubIdsFor(input, { nodeIds: ["web"], edgeIds: [] })).toEqual([]);
  });

  it("does not make a stub of a component the view model does not have", () => {
    const ghostly = { ...input, edges: [e("g", "ghost", "api")] };
    expect(stubIdsFor(ghostly, { nodeIds: ["api"], edgeIds: ["g"] })).toEqual([]);
  });

  it("keeps the edge and draws its hidden end as a stub, in the view model's order", () => {
    // A view that, unlike today's four, keeps an edge whose source it drops.
    const keeps = (view: DiagramView) => (view === "overall" ? { nodeIds: ["web", "api"], edgeIds: ["user-web", "web-api"] } : null);
    const selection = keeps("overall")!;
    const stubs = stubIdsFor(input, selection);
    const shown = new Set([...selection.nodeIds, ...stubs]);
    expect(stubs).toEqual(["user"]);
    for (const id of selection.edgeIds) {
      const edge = input.edges.find((x) => x.id === id)!;
      expect(shown.has(edge.source) && shown.has(edge.target)).toBe(true);
    }
  });
});

