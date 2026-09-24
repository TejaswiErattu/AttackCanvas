/**
 * Prompt N2: deterministic architecture merge.
 *
 * Every fixture here is SYNTHETIC. No file, path, name or value comes from a real
 * repository or from a saved live context, and nothing touches the network or the
 * filesystem. The merge is pure, so every test is a plain function call.
 */

import { describe, expect, it } from "vitest";
import {
  GAP_ASSERT_CERTAINTY,
  MAX_UNKNOWNS,
  bindGap,
  isRepoWideFile,
  mergeArchitecture,
  validateMerged,
  type MergedArchitecture,
} from "@/server/analysis/architecture";
import type { RepoFacts } from "@/server/analysis/context";
import type {
  ControlGap,
  Datastore,
  Deployment,
  Route,
} from "@/server/detect/types";
import { ComponentSchema } from "@/shared/schema";
import type {
  ArchitectureDraft,
  Component,
  ComponentType,
  DraftComponent,
  DraftDataFlow,
  Evidence,
  Unknown,
} from "@/shared/schema";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FILE_PATHS = [
  "package.json",
  "Dockerfile",
  "src/api/orders.ts",
  "src/api/users/list.ts",
  "src/db/pool.ts",
  "src/web/app.tsx",
  "src/worker/jobs.ts",
  "README.md",
];

type FactsInput = {
  files?: string[];
  datastores?: Datastore[];
  deployment?: Deployment[];
  gaps?: ControlGap[];
  routes?: Route[];
  evidence?: Evidence[];
  semgrep?: Evidence[];
};

function makeFacts(input: FactsInput = {}): RepoFacts {
  const gaps = input.gaps ?? [];
  const evidence = [...(input.evidence ?? []), ...gaps.map(gapEvidence)];
  return {
    summary: {
      owner: "synthetic",
      name: "repo",
      ref: "main",
      languages: [],
      frameworks: [],
      fileCountAnalyzed: 0,
      analyzedAt: "2026-01-01T00:00:00.000Z",
    },
    detector: {
      frameworks: [],
      routes: input.routes ?? [],
      auth: [],
      datastores: input.datastores ?? [],
      envNames: [],
      tokens: [],
      deployment: input.deployment ?? [],
      gaps,
      evidence,
    },
    controlGaps: gaps,
    semgrep: input.semgrep ?? [],
    osv: [],
    files: (input.files ?? FILE_PATHS).map((path) => ({
      path,
      content: "",
      tier: "high" as const,
      reason: "synthetic",
    })),
  };
}

function ev(
  id: string,
  filePath: string,
  lineStart: number,
  summary: string,
  extra: Partial<Evidence> = {},
): Evidence {
  return {
    id,
    kind: "code",
    source: "detector",
    summary,
    filePath,
    lineStart,
    ...extra,
  };
}

function gap(n: number, over: Partial<ControlGap> = {}): ControlGap {
  return {
    id: `gap-${n}`,
    kind: "input_validation_missing",
    scope: "file",
    control: "input validation",
    expectation: "a handler reads request input",
    file: "src/api/orders.ts",
    line: 10,
    basisFacts: [],
    certainty: 0.5,
    owasp: [],
    stride: [],
    cwe: [],
    ...over,
  };
}

function gapEvidence(g: ControlGap): Evidence {
  return ev(`ev-${g.id}`, g.file, g.line, `${g.control} not found`, {
    ruleId: `gap:${g.kind}`,
  });
}

function comp(
  id: string,
  files: string[],
  type: ComponentType = "backend",
  extra: Partial<DraftComponent> = {},
): DraftComponent {
  return {
    id,
    name: id,
    type,
    description: `${id} component`,
    technologies: [],
    files,
    assets: [],
    evidenceRefs: files.slice(0, 1),
    ...extra,
  };
}

function flow(
  id: string,
  sourceId: string,
  targetId: string,
  extra: Partial<DraftDataFlow> = {},
): DraftDataFlow {
  return {
    id,
    sourceId,
    targetId,
    label: `${id} label`,
    dataClassification: "internal",
    crossesTrustBoundary: false,
    evidenceRefs: ["src/api/orders.ts"],
    ...extra,
  };
}

function draft(over: Partial<ArchitectureDraft> = {}): ArchitectureDraft {
  return {
    components: [],
    dataFlows: [],
    trustBoundaries: [],
    unknowns: [],
    ...over,
  };
}

const pg = (over: Partial<Datastore> = {}): Datastore => ({
  kind: "postgres",
  name: "pg",
  origin: "dependency",
  file: "package.json",
  line: 12,
  ...over,
});

const pgEvidence = (id = "ev-datastore-1", line = 12): Evidence =>
  ev(id, "package.json", line, "Datastore postgres: declared as a dependency", {
    kind: "config",
  });

const docker = (over: Partial<Deployment> = {}): Deployment => ({
  kind: "dockerfile",
  name: "app",
  ports: [3000],
  file: "Dockerfile",
  line: 1,
  ...over,
});

const dockerEvidence = (id = "ev-deploy-1"): Evidence =>
  ev(id, "Dockerfile", 1, "Deployment (dockerfile): app, ports 3000", {
    kind: "config",
  });

const ids = (items: readonly { id: string }[]): string[] =>
  items.map((i) => i.id);

function byIdOf(result: MergedArchitecture, id: string): Component {
  const found = result.components.find((c) => c.id === id);
  if (!found) throw new Error(`no component ${id}`);
  return found;
}

// ---------------------------------------------------------------------------
// Rule 1: drop invented references
// ---------------------------------------------------------------------------

describe("rule 1: invented components are dropped", () => {
  it("drops a component that lists a path outside the loaded file list", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("real-api", ["src/api/orders.ts"]),
          comp("ghost", ["src/api/orders.ts", "src/nowhere/made-up.ts"]),
        ],
      }),
      makeFacts(),
    );
    expect(ids(r.components)).toEqual(["real-api"]);
    expect(r.limitations.join("\n")).toMatch(
      /Dropped component ghost.*made-up\.ts/,
    );
  });

  it("drops a component whose evidenceRefs resolve to nothing, or are empty", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("bad-ref", ["src/api/orders.ts"], "backend", {
            evidenceRefs: ["ev-does-not-exist", "route-99"],
          }),
          comp("no-ref", ["src/api/orders.ts"], "backend", {
            evidenceRefs: [],
          }),
          comp("kept", ["src/api/orders.ts"]),
        ],
      }),
      makeFacts(),
    );
    expect(ids(r.components)).toEqual(["kept"]);
    expect(
      r.limitations.filter((l) => l.startsWith("Dropped component")),
    ).toHaveLength(2);
  });

  it("resolves an evidence id, a route id and a loaded path", () => {
    const route: Route = {
      id: "route-1",
      method: "POST",
      path: "/api/orders",
      normalizedPath: "/api/orders",
      file: "src/api/orders.ts",
      line: 5,
      middleware: [],
      framework: "express",
    };
    const routeEv = ev(
      "ev-route-1",
      "src/api/orders.ts",
      5,
      "POST /api/orders handled here (express)",
    );
    const r = mergeArchitecture(
      draft({
        components: [
          comp("by-evidence", ["src/api/orders.ts"], "api", {
            evidenceRefs: ["ev-route-1"],
          }),
          comp("by-route", ["src/api/users/list.ts"], "api", {
            evidenceRefs: ["route-1"],
          }),
          comp("by-path", ["src/web/app.tsx"], "frontend", {
            evidenceRefs: ["./src/web/app.tsx"],
          }),
        ],
      }),
      makeFacts({ routes: [route], evidence: [routeEv] }),
    );
    expect(ids(r.components)).toEqual(["by-evidence", "by-route", "by-path"]);
    expect(r.componentEvidence.get("by-route")).toEqual(["ev-route-1"]);
    expect(r.componentEvidence.get("by-path")).toEqual([]);
  });

  it("removes flows, boundary members and unknowns that pointed at a drop", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("api", ["src/api/orders.ts"], "api"),
          comp("ghost", ["src/nowhere.ts"]),
        ],
        dataFlows: [
          flow("api-to-ghost", "api", "ghost"),
          flow("ghost-boundary", "api", "api", { boundaryId: "gone" }),
        ],
        trustBoundaries: [
          {
            id: "edge",
            name: "Edge",
            componentIds: ["api", "ghost"],
            description: "d",
          },
          {
            id: "only-ghost",
            name: "Ghost",
            componentIds: ["ghost"],
            description: "d",
          },
        ],
        unknowns: [
          {
            id: "u-ghost",
            description: "about the ghost",
            affectsComponentIds: ["ghost"],
          },
          {
            id: "u-mixed",
            description: "about both",
            affectsComponentIds: ["api", "ghost"],
          },
          {
            id: "u-global",
            description: "about nothing in particular",
            affectsComponentIds: [],
          },
        ],
      }),
      makeFacts(),
    );
    expect(ids(r.dataFlows)).toEqual(["ghost-boundary"]);
    expect(r.dataFlows[0].boundaryId).toBeUndefined();
    expect(r.trustBoundaries).toEqual([
      { id: "edge", name: "Edge", componentIds: ["api"], description: "d" },
    ]);
    expect(ids(r.unknowns).sort()).toEqual(["u-global", "u-mixed"]);
    expect(
      r.unknowns.find((u) => u.id === "u-mixed")?.affectsComponentIds,
    ).toEqual(["api"]);
    expect(r.issues).toEqual([]);
  });

  it("drops a flow whose evidenceRefs resolve to nothing", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("a", ["src/api/orders.ts"]),
          comp("b", ["src/web/app.tsx"]),
        ],
        dataFlows: [flow("a-to-b", "a", "b", { evidenceRefs: ["ev-made-up"] })],
      }),
      makeFacts(),
    );
    expect(r.dataFlows).toEqual([]);
    expect(r.limitations.join("\n")).toMatch(/Dropped data flow a-to-b/);
  });

  it("does not mutate its inputs", () => {
    const d = draft({
      components: [
        comp("a", ["src/api/orders.ts"]),
        comp("ghost", ["nope.ts"]),
      ],
      unknowns: [{ id: "u", description: "x", affectsComponentIds: ["ghost"] }],
    });
    const f = makeFacts({ gaps: [gap(1)] });
    const before = JSON.stringify([d, f]);
    mergeArchitecture(d, f);
    expect(JSON.stringify([d, f])).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// Rule 2: add back certain facts (Item 4: evidence references)
// ---------------------------------------------------------------------------

describe("rule 2: detected datastores and deployments are added back", () => {
  it("adds a detected datastore the draft omitted, citing its real evidence", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("api", ["src/api/orders.ts"], "api")] }),
      makeFacts({ datastores: [pg()], evidence: [pgEvidence()] }),
    );
    const store = r.components.find((c) => c.type === "database");
    expect(store).toBeDefined();
    expect(store?.files).toEqual(["package.json"]);
    expect(r.componentEvidence.get(store!.id)).toEqual(["ev-datastore-1"]);
    expect(r.limitations.join("\n")).toMatch(
      /Added component .* detected datastore postgres/,
    );
  });

  it("adds a detected deployment target as a non-api component", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("api", ["src/api/orders.ts"], "api")] }),
      makeFacts({ deployment: [docker()], evidence: [dockerEvidence()] }),
    );
    const target = r.components.find((c) => c.id.startsWith("deployment-"));
    expect(target?.type).toBe("external_service");
    expect(r.componentEvidence.get(target!.id)).toEqual(["ev-deploy-1"]);
  });

  it("groups several facts of one datastore kind into one component", () => {
    const r = mergeArchitecture(
      draft(),
      makeFacts({
        datastores: [
          pg(),
          pg({
            name: "Pool",
            origin: "usage",
            file: "src/db/pool.ts",
            line: 3,
          }),
        ],
        evidence: [
          pgEvidence("ev-datastore-1", 12),
          ev(
            "ev-datastore-2",
            "src/db/pool.ts",
            3,
            "Datastore postgres: connection opened with Pool",
          ),
        ],
      }),
    );
    const stores = r.components.filter((c) => c.type === "database");
    expect(stores).toHaveLength(1);
    expect(stores[0].files).toEqual(["package.json", "src/db/pool.ts"]);
    expect(r.componentEvidence.get(stores[0].id)).toEqual([
      "ev-datastore-1",
      "ev-datastore-2",
    ]);
  });

  it("does not depend on evidence order: reordering leaves every reference unchanged", () => {
    const evidence = [
      pgEvidence("ev-datastore-1"),
      ev(
        "ev-datastore-2",
        "src/db/pool.ts",
        3,
        "Datastore redis: connection opened with Redis",
      ),
      dockerEvidence("ev-deploy-1"),
    ];
    const input = {
      datastores: [
        pg(),
        {
          kind: "redis",
          name: "Redis",
          origin: "usage",
          file: "src/db/pool.ts",
          line: 3,
        } as Datastore,
      ],
      deployment: [docker()],
    };
    const forward = mergeArchitecture(
      draft(),
      makeFacts({ ...input, evidence }),
    );
    const reversed = mergeArchitecture(
      draft(),
      makeFacts({ ...input, evidence: [...evidence].reverse() }),
    );
    expect([...reversed.componentEvidence.entries()].sort()).toEqual(
      [...forward.componentEvidence.entries()].sort(),
    );
    expect(forward.componentEvidence.size).toBe(3);
  });

  it("uses no ordinal: ids that break the counting pattern are cited exactly as they are", () => {
    // The first datastore fact is given ev-datastore-7, and there is no ev-datastore-1.
    const r = mergeArchitecture(
      draft(),
      makeFacts({
        datastores: [pg()],
        deployment: [docker()],
        evidence: [
          pgEvidence("ev-datastore-7"),
          dockerEvidence("ev-deploy-42"),
        ],
      }),
    );
    const cited = [...r.componentEvidence.values()].flat().sort();
    expect(cited).toEqual(["ev-datastore-7", "ev-deploy-42"]);
  });

  it("does not match evidence at the same place that describes something else", () => {
    const r = mergeArchitecture(
      draft(),
      makeFacts({
        datastores: [pg()],
        evidence: [
          ev("ev-framework-1", "package.json", 12, "Depends on pg (database)"),
          pgEvidence("ev-datastore-3"),
        ],
      }),
    );
    expect([...r.componentEvidence.values()].flat()).toEqual([
      "ev-datastore-3",
    ]);
  });

  it("matches evidence on file and line, not on summary alone", () => {
    // Same summary text as the real evidence, but one is in another file and one is on
    // another line. Neither describes this fact.
    const r = mergeArchitecture(
      draft(),
      makeFacts({
        datastores: [pg()],
        evidence: [
          ev(
            "ev-other-file",
            "src/db/pool.ts",
            12,
            "Datastore postgres: declared as a dependency",
          ),
          ev(
            "ev-other-line",
            "package.json",
            99,
            "Datastore postgres: declared as a dependency",
          ),
          pgEvidence("ev-the-one"),
        ],
      }),
    );
    expect([...r.componentEvidence.values()].flat()).toEqual(["ev-the-one"]);
  });

  it("never attaches a reference that is not in the evidence array", () => {
    // The detector fact exists but no evidence was emitted for it.
    const r = mergeArchitecture(
      draft({
        components: [
          comp("api", ["src/api/orders.ts"], "api", {
            evidenceRefs: ["ev-ghost", "src/api/orders.ts"],
          }),
        ],
      }),
      makeFacts({ datastores: [pg()], deployment: [docker()], evidence: [] }),
    );
    const evidenceIds = new Set(ids(r.evidence));
    for (const refs of r.componentEvidence.values()) {
      for (const id of refs) expect(evidenceIds.has(id)).toBe(true);
    }
    const synthesized = r.components.filter((c) => c.id !== "api");
    expect(synthesized).toHaveLength(2);
    for (const c of synthesized)
      expect(r.componentEvidence.get(c.id)).toEqual([]);
    expect(r.componentEvidence.get("api")).toEqual([]);
    expect(r.issues).toEqual([]);
  });

  it("every synthesized component's references resolve to real evidence", () => {
    const r = mergeArchitecture(
      draft(),
      makeFacts({
        datastores: [pg()],
        deployment: [docker()],
        evidence: [pgEvidence(), dockerEvidence()],
      }),
    );
    const evidenceIds = new Set(ids(r.evidence));
    expect(r.components).toHaveLength(2);
    for (const c of r.components) {
      const refs = r.componentEvidence.get(c.id) ?? [];
      expect(refs.length).toBeGreaterThan(0);
      for (const id of refs) expect(evidenceIds.has(id)).toBe(true);
    }
  });

  it("reserves the id of a dropped component so a boundary cannot latch onto the replacement", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("datastore-postgres", ["src/nowhere.ts"], "database"),
        ],
        trustBoundaries: [
          {
            id: "b",
            name: "B",
            componentIds: ["datastore-postgres"],
            description: "d",
          },
        ],
      }),
      makeFacts({ datastores: [pg()], evidence: [pgEvidence()] }),
    );
    expect(r.trustBoundaries).toEqual([]);
    expect(r.components.map((c) => c.id)).toEqual(["datastore-postgres-2"]);
  });
});

// ---------------------------------------------------------------------------
// Rule 2 / Item 5: is this the same component?
// ---------------------------------------------------------------------------

describe("item 5: matching a draft component to a detected fact", () => {
  const facts = () =>
    makeFacts({ datastores: [pg()], evidence: [pgEvidence()] });

  it("POSITIVE: compatible type plus the same evidence reference matches, adds nothing", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("main-db", ["src/db/pool.ts"], "database", {
            evidenceRefs: ["ev-datastore-1"],
          }),
        ],
      }),
      facts(),
    );
    expect(ids(r.components)).toEqual(["main-db"]);
    expect(r.limitations).toEqual([]);
  });

  it("POSITIVE: compatible type plus the same source file matches", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("main-db", ["package.json"], "storage")] }),
      facts(),
    );
    expect(ids(r.components)).toEqual(["main-db"]);
    expect(r.componentEvidence.get("main-db")).toEqual(["ev-datastore-1"]);
  });

  it("NEGATIVE: a name and technology that say postgres are not an identity", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("postgres-main", ["src/db/pool.ts"], "database", {
            name: "Postgres",
            technologies: ["postgres", "pg"],
          }),
        ],
      }),
      facts(),
    );
    expect(r.components).toHaveLength(2);
    expect(r.components.filter((c) => c.type === "database")).toHaveLength(2);
    expect(r.limitations.join("\n")).toMatch(/Added component/);
  });

  it("NEGATIVE: an anchor on an incompatible type does not match", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("web", ["package.json"], "frontend")] }),
      facts(),
    );
    expect(r.components).toHaveLength(2);
    expect(r.components.map((c) => c.type).sort()).toEqual([
      "database",
      "frontend",
    ]);
  });

  it("AMBIGUOUS: two anchored candidates and no tie-breaker -> synthesize and record it", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("store-a", ["package.json"], "database"),
          comp("store-b", ["package.json"], "storage"),
        ],
      }),
      facts(),
    );
    expect(r.components).toHaveLength(3);
    expect(r.limitations.join("\n")).toMatch(
      /matched store-a, store-b ambiguously; nothing was merged/,
    );
  });

  it("supporting names can break a tie between two anchored candidates", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("pg-store", ["package.json"], "database", {
            technologies: ["pg"],
          }),
          comp("other-store", ["package.json"], "storage"),
        ],
      }),
      facts(),
    );
    expect(ids(r.components)).toEqual(["pg-store", "other-store"]);
  });

  it("AMBIGUOUS: one component anchored to two different datastores merges with neither", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("all-data", ["package.json"], "database")] }),
      makeFacts({
        datastores: [
          pg(),
          { ...pg(), kind: "redis", name: "ioredis", line: 13 },
        ],
        evidence: [
          pgEvidence("ev-datastore-1", 12),
          ev(
            "ev-datastore-2",
            "package.json",
            13,
            "Datastore redis: declared as a dependency",
          ),
        ],
      }),
    );
    expect(r.components).toHaveLength(3);
    expect(r.limitations.filter((l) => l.includes("ambiguously"))).toHaveLength(
      2,
    );
  });

  it("deployment: the same file on a compatible type matches; a frontend does not", () => {
    const facts = makeFacts({
      deployment: [docker()],
      evidence: [dockerEvidence()],
    });
    const matched = mergeArchitecture(
      draft({ components: [comp("runtime", ["Dockerfile"], "backend")] }),
      facts,
    );
    expect(ids(matched.components)).toEqual(["runtime"]);
    const notMatched = mergeArchitecture(
      draft({ components: [comp("ui", ["Dockerfile"], "frontend")] }),
      facts,
    );
    expect(notMatched.components).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// Rule 3 / Item 7: binding
// ---------------------------------------------------------------------------

/** parse() strips the draft-only evidenceRefs key. */
const asComponent = (c: DraftComponent): Component => ComponentSchema.parse(c);

describe("rule 3: gaps bind to components, always", () => {
  it("1. exact ownership through the files list, with no limitation", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("orders", ["src/api/orders.ts"], "api"),
          comp("users", ["src/api/users/list.ts"], "api"),
        ],
      }),
      makeFacts({ gaps: [gap(1)] }),
    );
    expect(r.gapBindings.get("gap-1")).toEqual(["orders"]);
    expect(r.limitations).toEqual([]);
  });

  it("2. longest matching directory prefix wins, and says so", () => {
    const components = [
      asComponent(comp("shallow", ["src/web/app.tsx"], "frontend")),
      asComponent(comp("deep", ["src/api/users/list.ts"], "api")),
      asComponent(comp("mid", ["src/api/other.ts"], "backend")),
    ];
    // Ownership flows downward: a component owns files under the directories its own
    // files live in. Roots here: shallow=src/web, deep=src/api/users, mid=src/api.
    // src/api/users/new.ts is under deep (depth 3) and mid (depth 2): deep wins.
    // src/api/billing.ts is under mid only. src/util.ts is under no root.
    expect(
      bindGap(gap(1, { file: "src/api/users/new.ts" }), components),
    ).toEqual({
      ids: ["deep"],
      via: "directory",
    });
    expect(bindGap(gap(1, { file: "src/api/billing.ts" }), components)).toEqual(
      {
        ids: ["mid"],
        via: "directory",
      },
    );
    expect(bindGap(gap(1, { file: "src/util.ts" }), components)).toEqual({
      ids: ["deep", "mid"],
      via: "api_backend",
    });
  });

  it("2. a directory tie binds every tied component", () => {
    const components = [
      asComponent(comp("a", ["src/api/one.ts"], "api")),
      asComponent(comp("b", ["src/api/two.ts"], "worker")),
    ];
    expect(
      bindGap(gap(1, { file: "src/api/three.ts" }), components).ids,
    ).toEqual(["a", "b"]);
  });

  it("2. records the fallback in limitations, naming the gap and the component", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("users", ["src/api/users/list.ts"], "api"),
          comp("web", ["src/web/app.tsx"], "frontend"),
        ],
      }),
      makeFacts({ gaps: [gap(1, { file: "src/api/users/v2/x.ts" })] }),
    );
    expect(r.gapBindings.get("gap-1")).toEqual(["users"]);
    expect(r.limitations.join("\n")).toMatch(
      /Gap gap-1 .* src\/api\/users\/v2\/x\.ts .*longest prefix.*: users/,
    );
  });

  it("3. no shared directory: falls back to the api/backend component", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("server", ["src/api/orders.ts"], "backend"),
          comp("web", ["src/web/app.tsx"], "frontend"),
        ],
      }),
      makeFacts({ gaps: [gap(1, { file: "README.md" })] }),
    );
    expect(r.gapBindings.get("gap-1")).toEqual(["server"]);
    expect(r.limitations.join("\n")).toMatch(
      /Gap gap-1 .*README\.md .*api\/backend component\(s\): server/,
    );
  });

  it("4. no api or backend at all: binds every component, and says why", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("web", ["src/web/app.tsx"], "frontend"),
          comp("jobs", ["src/worker/jobs.ts"], "worker"),
        ],
      }),
      makeFacts({ gaps: [gap(1, { file: "README.md" })] }),
    );
    expect(r.gapBindings.get("gap-1")).toEqual(["jobs", "web"]);
    expect(r.limitations.join("\n")).toMatch(
      /because none is an api or backend: jobs, web/,
    );
  });

  it("repository scope goes straight to api/backend, else to all", () => {
    const withApi = [
      asComponent(comp("web", ["src/web/app.tsx"], "frontend")),
      asComponent(comp("srv", ["src/api/orders.ts"], "api")),
    ];
    const repoGap = gap(1, { scope: "repository", file: "package.json" });
    expect(bindGap(repoGap, withApi)).toEqual({
      ids: ["srv"],
      via: "api_backend",
    });
    expect(bindGap(repoGap, [withApi[0]])).toEqual({
      ids: ["web"],
      via: "all",
    });
  });

  it("repository scope records no limitation: it has no file owner by definition", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("srv", ["src/api/orders.ts"], "api")] }),
      makeFacts({
        gaps: [gap(1, { scope: "repository", file: "package.json" })],
      }),
    );
    expect(r.gapBindings.get("gap-1")).toEqual(["srv"]);
    expect(r.limitations).toEqual([]);
  });

  it("binds to a synthesized component too, and never leaves a gap unbound", () => {
    const r = mergeArchitecture(
      draft(),
      makeFacts({
        datastores: [pg()],
        evidence: [pgEvidence()],
        gaps: [gap(1, { file: "package.json" }), gap(2, { file: "README.md" })],
      }),
    );
    expect(r.gapBindings.get("gap-1")).toHaveLength(1);
    expect(r.gapBindings.get("gap-2")).toHaveLength(1);
  });

  it("with no components at all the binding is empty and recorded", () => {
    const r = mergeArchitecture(draft(), makeFacts({ gaps: [gap(1)] }));
    expect(r.gapBindings.get("gap-1")).toEqual([]);
    expect(r.limitations.join("\n")).toMatch(/produced no components/);
  });

  it("binding picks the longest matching path prefix (monorepo)", () => {
    const components = [
      asComponent(comp("root-src", ["src/index.ts"], "backend")),
      asComponent(comp("api-src", ["src/api/index.ts"], "api")),
    ];
    expect(
      bindGap(gap(1, { file: "src/api/routes.ts" }), components).ids,
    ).toEqual(["api-src"]);
    expect(bindGap(gap(1, { file: "src/util.ts" }), components).ids).toEqual([
      "root-src",
    ]);
  });
});

// ---------------------------------------------------------------------------
// Rule 4: classify gaps
// ---------------------------------------------------------------------------

describe("rule 4: gaps below the certainty threshold also become unknowns", () => {
  const base = draft({
    components: [comp("orders", ["src/api/orders.ts"], "api")],
  });

  it("a low-certainty gap produces an unknown and keeps its evidence", () => {
    const r = mergeArchitecture(
      base,
      makeFacts({ gaps: [gap(1, { certainty: 0.55 })] }),
    );
    expect(r.unknowns).toHaveLength(1);
    const [u] = r.unknowns;
    expect(u.description).toMatch(
      /^Input validation for src\/api\/orders\.ts on orders could not be confirmed;/,
    );
    expect(u.description).toMatch(/cannot follow/);
    expect(u.affectsComponentIds).toEqual(["orders"]);
    expect(ids(r.evidence)).toContain("ev-gap-1");
    expect(r.evidence.find((e) => e.id === "ev-gap-1")?.ruleId).toBe(
      "gap:input_validation_missing",
    );
  });

  it("names the route when the gap has one", () => {
    const route: Route = {
      id: "route-1",
      method: "POST",
      path: "/api/orders",
      normalizedPath: "/api/orders",
      file: "src/api/orders.ts",
      line: 10,
      middleware: [],
      framework: "express",
    };
    const r = mergeArchitecture(
      base,
      makeFacts({ routes: [route], gaps: [gap(1, { routeId: "route-1" })] }),
    );
    expect(r.unknowns[0].description).toMatch(
      /^Input validation for POST \/api\/orders on orders/,
    );
  });

  it("a high-certainty gap produces no unknown but stays evidence", () => {
    const r = mergeArchitecture(
      base,
      makeFacts({ gaps: [gap(1, { certainty: 0.9 })] }),
    );
    expect(r.unknowns).toEqual([]);
    expect(ids(r.evidence)).toContain("ev-gap-1");
  });

  it("the threshold is inclusive: exactly 0.7 is asserted, not asked about", () => {
    expect(GAP_ASSERT_CERTAINTY).toBe(0.7);
    const r = mergeArchitecture(
      base,
      makeFacts({
        gaps: [gap(1, { certainty: 0.7 }), gap(2, { certainty: 0.69 })],
      }),
    );
    expect(r.unknowns).toHaveLength(1);
    expect(r.unknowns[0].id).toBe("unknown-gap-2");
  });

  it("records a limitation when a gap's evidence is missing", () => {
    const facts = makeFacts({ gaps: [gap(1)] });
    facts.detector.evidence = [];
    const r = mergeArchitecture(base, facts);
    expect(r.limitations.join("\n")).toMatch(/Gap gap-1 has no evidence/);
  });

  describe("dedupe against the model's own unknowns", () => {
    const modelUnknown = (description: string, affects: string[]): Unknown => ({
      id: "model-1",
      description,
      affectsComponentIds: affects,
    });
    const run = (u: Unknown) =>
      mergeArchitecture(
        draft({
          components: [
            comp("orders", ["src/api/orders.ts"], "api"),
            comp("users", ["src/api/users/list.ts"], "api"),
          ],
          unknowns: [u],
        }),
        makeFacts({ gaps: [gap(1)] }),
      );

    it("drops the model unknown when control name AND component both match", () => {
      const r = run(
        modelUnknown("Is Input-Validation applied on orders?", ["orders"]),
      );
      expect(ids(r.unknowns)).toEqual(["unknown-gap-1"]);
    });

    it("keeps it when the control matches but no component overlaps", () => {
      const r = run(
        modelUnknown("Is input validation applied on users?", ["users"]),
      );
      expect(ids(r.unknowns).sort()).toEqual(["model-1", "unknown-gap-1"]);
    });

    it("keeps it when a component overlaps but the control differs", () => {
      const r = run(
        modelUnknown("Is the orders table encrypted at rest?", ["orders"]),
      );
      expect(ids(r.unknowns).sort()).toEqual(["model-1", "unknown-gap-1"]);
    });

    it("does not match a control that is only a substring of another word", () => {
      const r = run(
        modelUnknown("Is preinput validationary logic on orders?", ["orders"]),
      );
      expect(ids(r.unknowns)).toContain("model-1");
    });
  });
});

// ---------------------------------------------------------------------------
// Rule 5: cap
// ---------------------------------------------------------------------------

describe("rule 5: the unknown cap holds", () => {
  const orders = comp("orders", ["src/api/orders.ts"], "api");

  it("keeps at most 12 and records what was dropped", () => {
    const gaps = Array.from({ length: 15 }, (_, i) =>
      gap(i + 1, { certainty: 0.4 }),
    );
    const r = mergeArchitecture(
      draft({ components: [orders] }),
      makeFacts({ gaps }),
    );
    expect(MAX_UNKNOWNS).toBe(12);
    expect(r.unknowns).toHaveLength(12);
    expect(r.limitations.join("\n")).toMatch(
      /3 lower-ranked unknown\(s\) were dropped/,
    );
  });

  it("ranks the lowest certainty first, then the most components affected", () => {
    const gaps = [
      gap(1, { certainty: 0.6, file: "src/api/orders.ts" }),
      gap(2, { certainty: 0.3, file: "src/api/orders.ts" }),
      gap(3, { certainty: 0.6, scope: "repository", file: "package.json" }),
    ];
    const r = mergeArchitecture(
      draft({
        components: [orders, comp("srv", ["src/api/users/list.ts"], "backend")],
      }),
      makeFacts({ gaps }),
    );
    // gap-2 is least certain. gap-3 and gap-1 tie at 0.6; gap-3 affects two components.
    expect(ids(r.unknowns)).toEqual([
      "unknown-gap-2",
      "unknown-gap-3",
      "unknown-gap-1",
    ]);
  });

  it("drops a model unknown before a gap-derived one when the cap bites", () => {
    const gaps = Array.from({ length: 12 }, (_, i) =>
      gap(i + 1, { certainty: 0.6 }),
    );
    const r = mergeArchitecture(
      draft({
        components: [orders],
        unknowns: [
          { id: "model-1", description: "x", affectsComponentIds: ["orders"] },
        ],
      }),
      makeFacts({ gaps }),
    );
    expect(r.unknowns).toHaveLength(12);
    expect(ids(r.unknowns)).not.toContain("model-1");
  });
});

// ---------------------------------------------------------------------------
// Rules 6 and 7
// ---------------------------------------------------------------------------

describe("rule 6: layout", () => {
  it("sets a finite position on every component, left to right along a flow", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("web", ["src/web/app.tsx"], "frontend"),
          comp("api", ["src/api/orders.ts"], "api"),
          comp("jobs", ["src/worker/jobs.ts"], "worker"),
        ],
        dataFlows: [flow("web-api", "web", "api")],
      }),
      makeFacts(),
    );
    for (const c of r.components) {
      expect(Number.isFinite(c.position?.x)).toBe(true);
      expect(Number.isFinite(c.position?.y)).toBe(true);
    }
    expect(byIdOf(r, "web").position!.x).toBeLessThan(
      byIdOf(r, "api").position!.x,
    );
  });

  it("is deterministic", () => {
    const d = draft({
      components: [
        comp("a", ["src/api/orders.ts"], "api"),
        comp("b", ["src/web/app.tsx"], "frontend"),
      ],
      dataFlows: [flow("a-b", "a", "b")],
    });
    expect(mergeArchitecture(d, makeFacts()).components).toEqual(
      mergeArchitecture(d, makeFacts()).components,
    );
  });
});

describe("rule 7: validation returns typed issues", () => {
  it("reports a contract violation instead of throwing", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("Not Kebab", ["src/api/orders.ts"])] }),
      makeFacts(),
    );
    expect(
      r.issues.some(
        (i) => i.code === "schema" && i.path.startsWith("components[0]"),
      ),
    ).toBe(true);
  });

  it("reports a dangling reference and a duplicate id from a hand-built result", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("a", ["src/api/orders.ts"])] }),
      makeFacts(),
    );
    const broken: MergedArchitecture = {
      ...r,
      components: [...r.components, r.components[0]],
      dataFlows: [
        {
          id: "f",
          sourceId: "a",
          targetId: "missing",
          label: "l",
          dataClassification: "internal",
          crossesTrustBoundary: false,
        },
      ],
      componentEvidence: new Map([["a", ["ev-nope"]]]),
    };
    const codes = validateMerged(broken).map((i) => i.code);
    expect(codes).toContain("duplicate_id");
    expect(codes.filter((c) => c === "dangling_reference")).toHaveLength(2);
  });

  it("a clean merge reports no issues", () => {
    const r = mergeArchitecture(
      draft({
        components: [comp("api", ["src/api/orders.ts"], "api")],
      }),
      makeFacts({
        datastores: [pg()],
        deployment: [docker()],
        evidence: [pgEvidence(), dockerEvidence()],
        gaps: [gap(1)],
      }),
    );
    expect(r.issues).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Repository-wide files (manifests, deployment config)
// ---------------------------------------------------------------------------

describe("gaps in repository-wide files bind to api/backend, not to whoever lists the file", () => {
  const supplyChain = (over: Partial<ControlGap> = {}): ControlGap =>
    gap(1, {
      kind: "supply_chain_integrity",
      scope: "file",
      control: "dependency integrity",
      file: "package.json",
      line: 1,
      certainty: 0.9,
      ...over,
    });

  it("REGRESSION: a supply_chain_integrity gap at package.json binds to the api/backend, not only to the datastore synthesized from package.json", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("server", ["src/api/orders.ts"], "backend")] }),
      makeFacts({
        datastores: [pg()],
        evidence: [pgEvidence()],
        gaps: [supplyChain()],
      }),
    );
    const store = r.components.find((c) => c.type === "database");
    expect(store?.files).toEqual(["package.json"]);
    expect(r.gapBindings.get("gap-1")).toEqual(["server"]);
    expect(r.gapBindings.get("gap-1")).not.toContain(store!.id);
    expect(r.limitations.join("\n")).toMatch(
      /Gap gap-1 .* package\.json, a repository-wide file .*repository-wide fallback binding used the api\/backend component\(s\): server/,
    );
  });

  it("with no api or backend it binds to every component, and says so", () => {
    const r = mergeArchitecture(
      draft({ components: [comp("web", ["src/web/app.tsx"], "frontend")] }),
      makeFacts({
        datastores: [pg()],
        evidence: [pgEvidence()],
        gaps: [supplyChain()],
      }),
    );
    const store = r.components.find((c) => c.type === "database")!;
    expect(r.gapBindings.get("gap-1")).toEqual([store.id, "web"].sort());
    expect(r.limitations.join("\n")).toMatch(
      /repository-wide fallback binding used every component, because none is an api or backend/,
    );
  });

  it("holds when a MODEL component also lists the manifest", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("main-db", ["package.json"], "database"),
          comp("server", ["src/api/orders.ts"], "api"),
        ],
      }),
      makeFacts({ gaps: [supplyChain()] }),
    );
    expect(r.gapBindings.get("gap-1")).toEqual(["server"]);
  });

  it("classifies manifests, lockfiles and deployment config, and nothing else", () => {
    for (const path of [
      "package.json",
      "packages/web/package.json",
      "pnpm-lock.yaml",
      "Dockerfile",
      "docker-compose.prod.yml",
      "serverless.yml",
      "infra/main.tf",
      "vercel.json",
      "./package.json",
    ]) {
      expect(isRepoWideFile(path), path).toBe(true);
    }
    for (const path of [
      "src/api/orders.ts",
      "README.md",
      "src/db/pool.ts",
      "src/package-utils.ts",
    ]) {
      expect(isRepoWideFile(path), path).toBe(false);
    }
  });

  it("a gap in an ordinary source file still binds by ownership", () => {
    const r = mergeArchitecture(
      draft({
        components: [
          comp("orders", ["src/api/orders.ts"], "api"),
          comp("users", ["src/api/users/list.ts"], "api"),
        ],
      }),
      makeFacts({ gaps: [gap(1, { file: "src/api/users/list.ts" })] }),
    );
    expect(r.gapBindings.get("gap-1")).toEqual(["users"]);
  });
});

// ---------------------------------------------------------------------------
// Cleanup after a drop: never a silently dangling graph
// ---------------------------------------------------------------------------

/** Every reference in the result points at an object that is in the result. */
function danglingReferences(r: MergedArchitecture): string[] {
  const components = new Set(ids(r.components));
  const boundaries = new Set(ids(r.trustBoundaries));
  const flows = new Set(ids(r.dataFlows));
  const evidence = new Set(ids(r.evidence));
  const bad: string[] = [];
  for (const f of r.dataFlows) {
    if (!components.has(f.sourceId))
      bad.push(`flow ${f.id} source ${f.sourceId}`);
    if (!components.has(f.targetId))
      bad.push(`flow ${f.id} target ${f.targetId}`);
    if (f.boundaryId !== undefined && !boundaries.has(f.boundaryId)) {
      bad.push(`flow ${f.id} boundary ${f.boundaryId}`);
    }
  }
  for (const b of r.trustBoundaries) {
    for (const id of b.componentIds) {
      if (!components.has(id)) bad.push(`boundary ${b.id} component ${id}`);
    }
  }
  for (const u of r.unknowns) {
    for (const id of u.affectsComponentIds) {
      if (!components.has(id)) bad.push(`unknown ${u.id} component ${id}`);
    }
  }
  for (const [gapId, bound] of r.gapBindings) {
    for (const id of bound) {
      if (!components.has(id)) bad.push(`binding ${gapId} component ${id}`);
    }
  }
  for (const [owner, refs] of r.componentEvidence) {
    if (!components.has(owner)) bad.push(`componentEvidence entry ${owner}`);
    for (const id of refs)
      if (!evidence.has(id)) bad.push(`componentEvidence ${owner} -> ${id}`);
  }
  for (const [owner, refs] of r.flowEvidence) {
    if (!flows.has(owner)) bad.push(`flowEvidence entry ${owner}`);
    for (const id of refs)
      if (!evidence.has(id)) bad.push(`flowEvidence ${owner} -> ${id}`);
  }
  return bad;
}

describe("cleanup after dropping an invented component", () => {
  const messy = () =>
    mergeArchitecture(
      draft({
        components: [
          comp("api", ["src/api/orders.ts"], "api"),
          comp("db", ["src/db/pool.ts"], "database"),
          comp(
            "ghost",
            ["src/api/orders.ts", "src/invented/ghost.ts"],
            "worker",
          ),
        ],
        dataFlows: [
          flow("api-to-db", "api", "db"),
          flow("api-to-ghost", "api", "ghost"),
          flow("ghost-to-db", "ghost", "db"),
          flow("api-to-db-unciteable", "api", "db", {
            evidenceRefs: ["ev-made-up"],
          }),
        ],
        trustBoundaries: [
          {
            id: "edge",
            name: "Edge",
            componentIds: ["api", "ghost"],
            description: "d",
          },
          {
            id: "ghost-zone",
            name: "Ghost",
            componentIds: ["ghost"],
            description: "d",
          },
        ],
        unknowns: [
          {
            id: "u-ghost-only",
            description: "about ghost",
            affectsComponentIds: ["ghost"],
          },
          {
            id: "u-both",
            description: "about both",
            affectsComponentIds: ["api", "ghost"],
          },
        ],
      }),
      makeFacts({
        // A gap in the dropped component's only real file still has to bind somewhere.
        gaps: [gap(1, { file: "src/api/orders.ts", certainty: 0.5 })],
      }),
    );

  it("leaves no flow, boundary, unknown, binding or evidence entry that mentions it", () => {
    const r = messy();
    expect(ids(r.components)).toEqual(["api", "db"]);
    expect(ids(r.dataFlows)).toEqual(["api-to-db"]);
    expect(r.trustBoundaries.map((b) => b.id)).toEqual(["edge"]);
    expect(r.trustBoundaries[0].componentIds).toEqual(["api"]);
    expect(ids(r.unknowns).filter((id) => id.startsWith("u-"))).toEqual([
      "u-both",
    ]);
    expect(
      r.unknowns.find((u) => u.id === "u-both")?.affectsComponentIds,
    ).toEqual(["api"]);

    for (const structure of [
      r.dataFlows,
      r.trustBoundaries,
      r.unknowns,
      [...r.gapBindings],
      [...r.componentEvidence],
      [...r.flowEvidence],
    ]) {
      expect(JSON.stringify(structure)).not.toContain("ghost");
    }
  });

  it("keeps componentEvidence and flowEvidence to exactly the surviving objects", () => {
    const r = messy();
    expect([...r.componentEvidence.keys()].sort()).toEqual(["api", "db"]);
    expect([...r.flowEvidence.keys()]).toEqual(["api-to-db"]);
  });

  it("every remaining reference points at an existing object", () => {
    const r = messy();
    expect(danglingReferences(r)).toEqual([]);
    expect(r.issues).toEqual([]);
  });

  it("records each removal as a limitation instead of dropping silently", () => {
    const text = messy().limitations.join("\n");
    expect(text).toMatch(/Dropped component ghost/);
    expect(text).toMatch(/Dropped data flow api-to-ghost/);
    expect(text).toMatch(/Dropped data flow ghost-to-db/);
    expect(text).toMatch(/Dropped data flow api-to-db-unciteable/);
    expect(text).toMatch(/Dropped trust boundary ghost-zone/);
    expect(text).toMatch(/Trust boundary edge lost members/);
    expect(text).toMatch(/Dropped unknown u-ghost-only/);
  });
});

// ---------------------------------------------------------------------------
// Deployment representation
// ---------------------------------------------------------------------------

describe("a deployment target is visibly a schema compromise", () => {
  it("records a limitation whenever one is represented as external_service", () => {
    const r = mergeArchitecture(
      draft(),
      makeFacts({ deployment: [docker()], evidence: [dockerEvidence()] }),
    );
    const target = r.components.find((c) => c.id.startsWith("deployment-"))!;
    expect(target.type).toBe("external_service");
    expect(r.limitations.join("\n")).toMatch(
      new RegExp(
        `Deployment target dockerfile app is represented as component ${target.id} of type external_service: the schema has no deployment component type`,
      ),
    );
  });

  it("records one per synthesized target", () => {
    const r = mergeArchitecture(
      draft(),
      makeFacts({
        deployment: [
          docker(),
          docker({
            kind: "vercel",
            name: "vercel.json",
            file: "package.json",
            line: 1,
            ports: [],
          }),
        ],
        evidence: [
          dockerEvidence(),
          ev(
            "ev-deploy-2",
            "package.json",
            1,
            "Deployment (vercel): vercel.json",
          ),
        ],
      }),
    );
    expect(
      r.limitations.filter((l) => l.includes("is represented as component")),
    ).toHaveLength(2);
  });

  it("records none when the draft's own component is matched, or for a datastore", () => {
    const matched = mergeArchitecture(
      draft({ components: [comp("runtime", ["Dockerfile"], "backend")] }),
      makeFacts({ deployment: [docker()], evidence: [dockerEvidence()] }),
    );
    expect(matched.limitations.join("\n")).not.toMatch(
      /represented as component/,
    );
    const store = mergeArchitecture(
      draft(),
      makeFacts({ datastores: [pg()], evidence: [pgEvidence()] }),
    );
    expect(store.limitations.join("\n")).not.toMatch(
      /represented as component/,
    );
  });
});

// ---------------------------------------------------------------------------
// Validation behaviour on bad model output
// ---------------------------------------------------------------------------

describe("bad model output is reported, never thrown", () => {
  /** Schema-invalid and inconsistent in every way a model reply can be. */
  const badDraft = (): ArchitectureDraft =>
    draft({
      components: [
        comp("Not Kebab", ["src/api/orders.ts"], "api"),
        comp("dup", ["src/api/orders.ts"], "api"),
        comp("dup", ["src/db/pool.ts"], "database"),
        comp("no-name", ["src/web/app.tsx"], "frontend", {
          name: "",
          description: "",
        }),
        comp("__proto__", ["src/worker/jobs.ts"], "worker"),
      ],
      dataFlows: [
        flow("f1", "dup", "missing"),
        flow("f2", "dup", "no-name"),
        flow("f2", "dup", "no-name"),
        flow("f3", "dup", "no-name", { boundaryId: "nowhere" }),
      ],
      trustBoundaries: [
        {
          id: "b",
          name: "B",
          componentIds: ["dup", "missing"],
          description: "d",
        },
      ],
      unknowns: [
        { id: "u", description: "x", affectsComponentIds: ["missing"] },
        { id: "u", description: "", affectsComponentIds: ["dup"] },
      ],
    });

  const facts = () =>
    makeFacts({
      datastores: [pg()],
      deployment: [docker()],
      evidence: [pgEvidence(), dockerEvidence()],
      gaps: [
        gap(1),
        gap(2, {
          file: "package.json",
          kind: "supply_chain_integrity",
          scope: "repository",
        }),
        gap(3, { file: "src/web/app.tsx", certainty: 0.9 }),
        gap(4, { file: "elsewhere/not-loaded.ts", certainty: 0.4 }),
      ],
    });

  it("does not throw", () => {
    expect(() => mergeArchitecture(badDraft(), facts())).not.toThrow();
    expect(() => mergeArchitecture(draft(), makeFacts())).not.toThrow();
  });

  it("returns typed issues for contract violations", () => {
    const r = mergeArchitecture(badDraft(), facts());
    expect(r.issues.length).toBeGreaterThan(0);
    for (const issue of r.issues) {
      expect(["schema", "duplicate_id", "dangling_reference"]).toContain(
        issue.code,
      );
      expect(issue.path).not.toBe("");
      expect(issue.message).not.toBe("");
    }
    expect(
      r.issues.some(
        (i) => i.code === "schema" && i.path.startsWith("components["),
      ),
    ).toBe(true);
  });

  it("gives every final component a finite dagre position", () => {
    const r = mergeArchitecture(badDraft(), facts());
    expect(r.components.length).toBeGreaterThan(0);
    for (const c of r.components) {
      expect(Number.isFinite(c.position?.x), c.id).toBe(true);
      expect(Number.isFinite(c.position?.y), c.id).toBe(true);
    }
  });

  it("every evidence reference in the result resolves to evidence in the result", () => {
    const r = mergeArchitecture(badDraft(), facts());
    const evidence = new Set(ids(r.evidence));
    for (const refs of [
      ...r.componentEvidence.values(),
      ...r.flowEvidence.values(),
    ]) {
      for (const id of refs) expect(evidence.has(id), id).toBe(true);
    }
  });

  it("every control gap has a gapBindings entry, and at least one component when any exists", () => {
    const f = facts();
    const r = mergeArchitecture(badDraft(), f);
    expect(r.components.length).toBeGreaterThan(0);
    for (const g of f.controlGaps) {
      expect(r.gapBindings.has(g.id), g.id).toBe(true);
      expect(r.gapBindings.get(g.id)!.length, g.id).toBeGreaterThanOrEqual(1);
    }
  });

  it("with no components at all every gap still has an entry, empty and recorded", () => {
    const f = makeFacts({ gaps: [gap(1), gap(2, { scope: "repository" })] });
    const r = mergeArchitecture(draft(), f);
    expect([...r.gapBindings]).toEqual([
      ["gap-1", []],
      ["gap-2", []],
    ]);
    expect(r.limitations.join("\n")).toMatch(/produced no components/);
  });
});
