import { describe, expect, it } from "vitest";
import { selectDiagramView, type DiagramView } from "@/client/diagramViews";
import type { DashboardViewModel, GraphEdge, GraphNode, ThreatCardData } from "@/shared/viewModel";

const n = (id: string, type: GraphNode["type"]): GraphNode => ({
  id, type, label: id, position: { x: 0, y: 0 }, threatCount: 0, maxSeverity: null, technologies: [], assets: [], exposure: "internal",
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
