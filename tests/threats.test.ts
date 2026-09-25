import { readFileSync } from "node:fs";
import type Anthropic from "@anthropic-ai/sdk";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AiError, type ClaudeDeps, type MessagesApi } from "@/server/ai/claude";
import { UsageLedger } from "@/server/ai/usage";
import type { MergedArchitecture } from "@/server/analysis/architecture";
import {
  DEDUPE_THRESHOLD,
  THREATS_BATCH_SIZE,
  THREATS_CONCURRENCY,
  assignIds,
  batchElements,
  dedupeThreats,
  generateThreats,
  isPlaceholderAssumption,
  jaccard,
  referenceIssues,
  runPool,
  PoolStoppedError,
  THREATS_THINKING,
  THREATS_TIMEOUT_MS,
  areRelated,
  tokenize,
  type ThreatEngineResult,
} from "@/server/analysis/threats";
import { THREATS_MAX_TOKENS } from "@/server/analysis/threatPrompt";
import type { ControlGap } from "@/server/detect/types";
import type { LoadedFile } from "@/server/ingest/loader";
import { SECURITY_PREAMBLE } from "@/server/security/injection";
import type {
  Component,
  ComponentType,
  DataFlow,
  DraftThreat,
  Evidence,
  Unknown,
} from "@/shared/schema";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function component(id: string, type: ComponentType = "backend"): Component {
  return {
    id,
    name: id,
    type,
    description: `${id} description`,
    technologies: [],
    files: [`src/${id}.ts`],
    assets: [`${id} data`],
  };
}

function flow(id: string, sourceId: string, targetId: string): DataFlow {
  return {
    id,
    sourceId,
    targetId,
    label: `${sourceId} to ${targetId}`,
    dataClassification: "internal",
    crossesTrustBoundary: false,
  };
}

function ev(id: string, over: Partial<Evidence> = {}): Evidence {
  return { id, kind: "code", source: "detector", summary: `${id} summary`, ...over };
}

/**
 * A merged architecture. Every component `c` carries evidence `ev-c`; `gapOn` gets a
 * control gap and its gap evidence `ev-gap-1`; every component is affected by an
 * unknown `unknown-<c>`.
 */
function arch(
  componentIds: readonly string[],
  flows: readonly [string, string, string][] = [],
  gapOn?: string,
): { architecture: MergedArchitecture; gaps: ControlGap[] } {
  const components = componentIds.map((id) => component(id));
  const dataFlows = flows.map(([id, s, t]) => flow(id, s, t));
  const evidence: Evidence[] = [
    ...componentIds.map((id) => ev(`ev-${id}`, { filePath: `src/${id}.ts`, lineStart: 5 })),
    ...flows.map(([id]) => ev(`ev-${id}`)),
  ];
  const gaps: ControlGap[] = [];
  const gapBindings = new Map<string, string[]>();
  if (gapOn !== undefined) {
    gaps.push({
      id: "gap-1",
      kind: "authz_missing",
      scope: "route",
      control: "ownership check",
      expectation: "route returns a record by id",
      file: `src/${gapOn}.ts`,
      line: 7,
      basisFacts: [],
      certainty: 0.8,
      owasp: ["A01:2025"],
      stride: ["E"],
      cwe: ["CWE-639"],
    });
    evidence.push(
      ev("ev-gap-1", {
        kind: "assumption",
        ruleId: "gap:authz_missing",
        filePath: `src/${gapOn}.ts`,
        lineStart: 7,
      }),
    );
    gapBindings.set("gap-1", [gapOn]);
  }
  const unknowns: Unknown[] = componentIds.map((id) => ({
    id: `unknown-${id}`,
    description: `Is ${id} safe?`,
    affectsComponentIds: [id],
  }));
  return {
    architecture: {
      components,
      dataFlows,
      trustBoundaries: [],
      unknowns,
      evidence,
      limitations: [],
      gapBindings,
      componentEvidence: new Map(componentIds.map((id) => [id, [`ev-${id}`]])),
      flowEvidence: new Map(flows.map(([id]) => [id, [`ev-${id}`]])),
      issues: [],
    },
    gaps,
  };
}

/** The merged shape of the saved bezkoder architecture: 5 components, 9 flows. */
function bezkoderShape() {
  const flows: [string, string, string][] = [
    "df-root",
    "df-signin",
    "df-signout",
    "df-signup",
    "df-test-admin",
    "df-test-all",
    "df-test-mod",
    "df-test-user",
  ].map((id) => [id, "client", "express-api"]);
  flows.push(["df-api-db", "express-api", "mysql-db"]);
  return arch(
    ["client", "datastore-mysql", "datastore-sequelize", "express-api", "mysql-db"],
    flows,
  ).architecture;
}

function files(ids: readonly string[]): LoadedFile[] {
  return ids.map((id) => ({
    path: `src/${id}.ts`,
    content: Array.from({ length: 20 }, (_, i) => `// ${id} line ${i + 1}`).join("\n"),
    tier: "high",
    reason: "source",
  }));
}

function threat(over: Partial<DraftThreat> = {}): DraftThreat {
  return {
    title: "SQL injection through the status filter",
    stride: ["T"],
    owasp: ["A05:2025"],
    cwe: ["CWE-89"],
    componentIds: ["orders-api"],
    dataFlowIds: [],
    asset: "the orders table",
    attackScenario: "attacker sends a crafted status parameter and reads the users table",
    evidenceIds: ["ev-orders-api"],
    assumptions: [],
    dependsOnUnknownIds: [],
    impact: 3,
    likelihood: 3,
    impactReason: "reads the schema",
    likelihoodReason: "reachable without login",
    mitigation: {
      summary: "Parameterise the query.",
      steps: ["Use placeholders."],
      codeLocation: "src/orders-api.ts",
    },
    ...over,
  };
}

/** Shuffles deterministically, so a failing case reproduces. */
function shuffled<T>(items: readonly T[], seed: number): T[] {
  const out = [...items];
  let state = seed;
  for (let i = out.length - 1; i > 0; i--) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    const j = state % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Model double. No network: the client is injected and fetch is watched.
// ---------------------------------------------------------------------------

type Reply = { threats: DraftThreat[] } | string | Error;

type Harness = {
  deps: Partial<ClaudeDeps>;
  calls: { body: Anthropic.MessageCreateParamsNonStreaming; elementIds: string[] }[];
  ledger: UsageLedger;
  inflight: () => number;
  maxInflight: () => number;
};

function message(text: string): Anthropic.Message {
  return {
    id: "msg_test",
    type: "message",
    role: "assistant",
    model: "claude-sonnet-5",
    content: [{ type: "text", text, citations: null }],
    stop_reason: "end_turn",
    stop_sequence: null,
    stop_details: null,
    usage: {
      input_tokens: 100,
      output_tokens: 50,
      cache_read_input_tokens: 0,
      cache_creation_input_tokens: 0,
    },
  } as Anthropic.Message;
}

function elementsIn(body: Anthropic.MessageCreateParamsNonStreaming): string[] {
  const user = body.messages[0].content;
  const text = typeof user === "string" ? user : "";
  return [...text.matchAll(/^### ELEMENT (\S+)/gm)].map((m) => m[1]);
}

/**
 * `respond` chooses the reply from the elements a call was about, so a test does not
 * depend on which call number a batch happened to get. `gate` lets a test hold a call
 * open, to observe concurrency and to finish calls out of order.
 */
function harness(
  respond: (elementIds: string[], callNo: number) => Reply,
  gate?: (elementIds: string[], callNo: number) => Promise<void>,
): Harness {
  const calls: Harness["calls"] = [];
  const ledger = new UsageLedger();
  let inflight = 0;
  let max = 0;

  const client: MessagesApi = {
    async create(body) {
      const elementIds = elementsIn(body);
      const callNo = calls.length + 1;
      calls.push({ body, elementIds });
      inflight++;
      max = Math.max(max, inflight);
      try {
        if (gate) await gate(elementIds, callNo);
        const reply = respond(elementIds, callNo);
        if (reply instanceof Error) throw reply;
        return message(typeof reply === "string" ? reply : JSON.stringify(reply));
      } finally {
        inflight--;
      }
    },
  };

  return {
    calls,
    ledger,
    inflight: () => inflight,
    maxInflight: () => max,
    deps: {
      client,
      ledger,
      sleep: async () => {},
      schedule: () => () => {},
      isDevelopment: false,
      writeDebug: () => {},
    },
  };
}

function run(
  h: Harness,
  a: { architecture: MergedArchitecture; gaps: ControlGap[] },
  extra: { concurrency?: number; shouldContinue?: () => boolean } = {},
): Promise<ThreatEngineResult> {
  return generateThreats({
    architecture: a.architecture,
    gaps: a.gaps,
    files: files(a.architecture.components.map((c) => c.id)),
    analysisId: "test-analysis",
    deps: h.deps,
    ...extra,
  });
}

/** An event-loop turn, so already-resolved promises and started calls settle. */
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 5));

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

afterEach(() => vi.restoreAllMocks());

// ---------------------------------------------------------------------------
// 1. Batching
// ---------------------------------------------------------------------------

describe("batchElements", () => {
  const ids = (n: number) =>
    Array.from({ length: n }, (_, i) => `svc-${String(i + 1).padStart(2, "0")}`);

  it("uses the documented limits", () => {
    expect(THREATS_BATCH_SIZE).toBe(2);
    expect(THREATS_MAX_TOKENS).toBe(12_000);
    expect(THREATS_CONCURRENCY).toBe(3);
    expect(THREATS_TIMEOUT_MS).toBe(300_000);
    expect(DEDUPE_THRESHOLD).toBe(0.6);
  });

  it("never puts more than two elements in a batch", () => {
    const a = arch(ids(11), [
      ["flow-1", "svc-01", "svc-02"],
      ["flow-2", "svc-03", "svc-04"],
      ["flow-3", "svc-05", "svc-06"],
    ]).architecture;
    const batches = batchElements(a);
    expect(Math.max(...batches.map((b) => b.length))).toBeLessThanOrEqual(2);
    expect(batches.length).toBeGreaterThanOrEqual(Math.ceil(14 / 2));
  });

  it("stays within the specification's limit of four whatever the default", () => {
    expect(THREATS_BATCH_SIZE).toBeLessThanOrEqual(4);
  });

  it("puts every element in exactly one batch", () => {
    const a = arch(ids(9), [
      ["flow-1", "svc-01", "svc-02"],
      ["flow-2", "svc-01", "svc-03"],
      ["flow-3", "svc-09", "svc-01"],
    ]).architecture;
    const all = batchElements(a).flat();
    const expected = [...a.components.map((c) => c.id), ...a.dataFlows.map((f) => f.id)];
    expect(all.slice().sort()).toEqual(expected.slice().sort());
    expect(new Set(all).size).toBe(all.length);
  });

  it("keeps a flow in the batch of its source component when they fit together", () => {
    const a = arch(ids(6), [
      ["flow-1", "svc-01", "svc-02"],
      ["flow-2", "svc-03", "svc-04"],
      ["flow-3", "svc-05", "svc-06"],
    ]).architecture;
    const batches = batchElements(a);
    const batchOf = (id: string) => batches.findIndex((b) => b.includes(id));
    expect(batchOf("flow-1")).toBe(batchOf("svc-01"));
    expect(batchOf("flow-2")).toBe(batchOf("svc-03"));
    expect(batchOf("flow-3")).toBe(batchOf("svc-05"));
  });

  it("lays out components and their flows in a fixed order, topping up short batches", () => {
    const a = arch(ids(4), [
      ["flow-1", "svc-01", "svc-02"],
      ["flow-2", "svc-03", "svc-04"],
    ]).architecture;
    expect(batchElements(a)).toEqual([
      ["svc-01", "flow-1"],
      ["svc-02", "svc-04"],
      ["svc-03", "flow-2"],
    ]);
  });

  it("places a unit in the first batch with room, not only the last", () => {
    const a = arch(["svc-01", "svc-02", "svc-03"], [["flow-1", "svc-02", "svc-01"]]).architecture;
    // svc-01 waits alone, svc-02 and its flow need two places, so svc-03 fills the gap.
    expect(batchElements(a)).toEqual([["svc-01", "svc-03"], ["svc-02", "flow-1"]]);
  });

  it("makes the saved bezkoder shape (5 components, 9 flows) exactly 7 batches", () => {
    expect(batchElements(bezkoderShape())).toHaveLength(7);
  });

  it("keeps every element of the saved shape once, at most two per batch, flows beside their source where they fit", () => {
    const a = bezkoderShape();
    const batches = batchElements(a);
    const all = batches.flat();
    expect(all).toHaveLength(14);
    expect(new Set(all).size).toBe(14);
    expect(Math.max(...batches.map((b) => b.length))).toBe(2);
    // express-api and its only flow fit together, so they share a batch.
    const batchOf = (id: string) => batches.findIndex((b) => b.includes(id));
    expect(batchOf("df-api-db")).toBe(batchOf("express-api"));
    // client has eight flows, more than a batch: its first batch starts with it.
    expect(batches[0][0]).toBe("client");
  });

  it("starts a new batch rather than split a unit that would fit", () => {
    // svc-01 alone, then svc-02 with its flow: together they would make three.
    const a = arch(["svc-01", "svc-02"], [["flow-1", "svc-02", "svc-01"]]).architecture;
    expect(batchElements(a)).toEqual([["svc-01"], ["svc-02", "flow-1"]]);
  });

  it("splits a unit larger than a batch, component first", () => {
    const a = arch(
      ["svc-01", "svc-02"],
      [
        ["flow-1", "svc-01", "svc-02"],
        ["flow-2", "svc-01", "svc-02"],
        ["flow-3", "svc-01", "svc-02"],
      ],
    ).architecture;
    expect(batchElements(a)).toEqual([
      ["svc-01", "flow-1"],
      ["flow-2", "flow-3"],
      ["svc-02"],
    ]);
  });

  it("lets a short trailing chunk share a batch with the next unit", () => {
    const a = arch(
      ["svc-01", "svc-02"],
      [
        ["flow-1", "svc-01", "svc-02"],
        ["flow-2", "svc-01", "svc-02"],
      ],
    ).architecture;
    expect(batchElements(a)).toEqual([["svc-01", "flow-1"], ["flow-2", "svc-02"]]);
  });

  it("never puts a chunk of an oversize unit beside a smaller unit that would overflow it", () => {
    const a = arch(
      ["svc-00", "svc-01"],
      [
        ["flow-1", "svc-01", "svc-00"],
        ["flow-2", "svc-01", "svc-00"],
        ["flow-3", "svc-01", "svc-00"],
      ],
    ).architecture;
    expect(batchElements(a)).toEqual([
      ["svc-00"],
      ["svc-01", "flow-1"],
      ["flow-2", "flow-3"],
    ]);
  });

  it("keeps a flow whose source is not a component instead of dropping it", () => {
    const a = arch(["svc-01"], [["flow-1", "ghost", "svc-01"]]).architecture;
    expect(batchElements(a).flat().sort()).toEqual(["flow-1", "svc-01"]);
  });

  it("keeps its order stable: the same batches, in the same sequence, on every call", () => {
    const a = arch(ids(10), [
      ["flow-1", "svc-02", "svc-03"],
      ["flow-2", "svc-02", "svc-04"],
      ["flow-3", "svc-07", "svc-01"],
      ["flow-4", "svc-10", "svc-01"],
    ]).architecture;
    const first = batchElements(a);
    expect(batchElements(a)).toEqual(first);
    expect(batchElements(a)).toEqual(first);
    // Batches are opened in unit order, so the components that open a batch are in id order.
    const openers = first.map((b) => b[0]).filter((id) => id.startsWith("svc-"));
    expect(openers).toEqual([...openers].sort());
  });

  it("is deterministic whatever order the input arrives in", () => {
    const a = arch(ids(10), [
      ["flow-1", "svc-02", "svc-03"],
      ["flow-2", "svc-02", "svc-04"],
      ["flow-3", "svc-07", "svc-01"],
      ["flow-4", "svc-10", "svc-01"],
    ]).architecture;
    const expected = batchElements(a);
    for (const seed of [1, 2, 3, 4, 5]) {
      expect(
        batchElements({
          components: shuffled(a.components, seed),
          dataFlows: shuffled(a.dataFlows, seed + 10),
        }),
      ).toEqual(expected);
    }
  });

  it("honours a size argument and rejects a bad one", () => {
    const a = arch(ids(9)).architecture;
    expect(batchElements(a, 4).map((b) => b.length)).toEqual([4, 4, 1]);
    expect(batchElements(a, 1).every((b) => b.length === 1)).toBe(true);
    expect(() => batchElements(a, 0)).toThrow(/positive integer/);
    expect(() => batchElements(a, 1.5)).toThrow(/positive integer/);
  });

  it("returns no batches for an empty architecture", () => {
    expect(batchElements({ components: [], dataFlows: [] })).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 2. Concurrency
// ---------------------------------------------------------------------------

describe("runPool", () => {
  it("returns results in item order however the tasks finish", async () => {
    const gates = [deferred(), deferred(), deferred()];
    const promise = runPool([0, 1, 2], 3, async (i) => {
      await gates[i].promise;
      return `r${i}`;
    });
    gates[2].resolve();
    await tick();
    gates[0].resolve();
    await tick();
    gates[1].resolve();
    expect(await promise).toEqual(["r0", "r1", "r2"]);
  });

  it("rethrows the lowest-index failure and starts nothing after it", async () => {
    const started: number[] = [];
    await expect(
      runPool([0, 1, 2, 3, 4], 1, async (i) => {
        started.push(i);
        if (i === 1) throw new Error("boom-1");
        return i;
      }),
    ).rejects.toThrow("boom-1");
    expect(started).toEqual([0, 1]);
  });

  it("rethrows the lowest-index failure even when a later task fails first", async () => {
    const late = deferred();
    const promise = runPool([0, 1], 2, async (i) => {
      if (i === 0) {
        await late.promise;
        throw new Error("boom-0");
      }
      throw new Error("boom-1");
    });
    const outcome = promise.catch((e: Error) => e.message);
    await tick();
    late.resolve();
    expect(await outcome).toBe("boom-0");
  });

  it("rejects a limit that is not a positive integer", async () => {
    await expect(runPool([1], 0, async (x) => x)).rejects.toThrow(/positive integer/);
  });
});

describe("generateThreats concurrency", () => {
  const sixteen = Array.from({ length: 16 }, (_, i) => `svc-${String(i + 1).padStart(2, "0")}`);

  it("runs at most three model calls at once, and does use all three", async () => {
    const gate = deferred();
    const h = harness(() => ({ threats: [] }), () => gate.promise);
    const done = run(h, arch(sixteen));

    await tick();
    expect(h.calls).toHaveLength(3);
    expect(h.inflight()).toBe(3);

    gate.resolve();
    await done;
    expect(h.calls).toHaveLength(8);
    expect(h.maxInflight()).toBe(3);
  });

  it("honours a lower concurrency", async () => {
    const gate = deferred();
    const h = harness(() => ({ threats: [] }), () => gate.promise);
    const done = run(h, arch(sixteen), { concurrency: 1 });
    await tick();
    expect(h.calls).toHaveLength(1);
    gate.resolve();
    await done;
    expect(h.maxInflight()).toBe(1);
  });

  it("gives the same result when calls finish out of order", async () => {
    const a = arch(sixteen.slice(0, 12));
    const reply = (elementIds: string[]): Reply => ({
      threats: elementIds.map((id) =>
        threat({
          componentIds: [id],
          evidenceIds: [`ev-${id}`],
          title: `Distinct finding for ${id}`,
          attackScenario: `scenario unique to ${id}`,
        }),
      ),
    });

    const inOrder = await run(harness(reply), a);

    // Held so the LAST batch answers first and the FIRST answers last.
    const gates = new Map<string, ReturnType<typeof deferred>>();
    const h = harness(reply, (elementIds) => {
      const g = deferred();
      gates.set(elementIds[0], g);
      return g.promise;
    });
    const pending = run(h, a);
    await tick();
    // Three calls are in flight: release them newest-first.
    for (const key of [...gates.keys()].reverse()) gates.get(key)!.resolve();
    await tick();
    for (const key of [...gates.keys()]) gates.get(key)!.resolve();
    const outOfOrder = await pending;

    expect(outOfOrder.threats).toEqual(inOrder.threats);
    expect(outOfOrder.batches.map((b) => b.index)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(outOfOrder.limitations).toEqual(inOrder.limitations);
  });
});

// ---------------------------------------------------------------------------
// The schema sent to the API
// ---------------------------------------------------------------------------

describe("schema and deadline sent by the engine", () => {
  it("sends an API-compatible schema and still rejects an out-of-range impact", async () => {
    const h = harness(() => ({
      threats: [{ ...threat({ componentIds: ["svc-01"], evidenceIds: ["ev-svc-01"] }), impact: 9 }],
    }));
    const error = await run(h, arch(["svc-01"])).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AiError);
    const sent = JSON.stringify(h.calls[0].body.output_config);
    for (const keyword of ["minimum", "maximum"]) expect(sent).not.toContain(`"${keyword}"`);
    expect(sent).toContain('"integer"');
  });

  it("disables extended thinking on every threat call, and changes nothing else about the request", async () => {
    const h = harness(() => ({ threats: [] }));
    await run(h, arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"]));
    expect(THREATS_THINKING).toEqual({ type: "disabled" });
    expect(h.calls).toHaveLength(3);
    for (const call of h.calls) {
      expect(call.body.thinking).toEqual({ type: "disabled" });
      expect(call.body.max_tokens).toBe(12_000);
      expect(call.body.model).toBe("claude-sonnet-5");
    }
  });

  it("keeps the prompt unchanged when thinking is disabled", async () => {
    const h = harness(() => ({ threats: [] }));
    await run(h, arch(["svc-01"]));
    const system = h.calls[0].body.system as { text: string }[];
    const file = readFileSync("prompts/threats.v2.md", "utf8");
    expect(system[0].text).toBe(`${SECURITY_PREAMBLE}${file}`);
  });

  it("keeps the concurrency limit, batch size and 300 second deadline with thinking disabled", async () => {
    expect(THREATS_BATCH_SIZE).toBe(2);
    expect(THREATS_CONCURRENCY).toBe(3);
    expect(THREATS_TIMEOUT_MS).toBe(300_000);
    const gate = deferred();
    const h = harness(() => ({ threats: [] }), () => gate.promise);
    const done = run(h, arch(Array.from({ length: 16 }, (_, i) => `svc-${String(i + 1).padStart(2, "0")}`)));
    await tick();
    expect(h.calls).toHaveLength(3);
    gate.resolve();
    await done;
    expect(h.maxInflight()).toBe(3);
  });

  it("still validates every threat reply with thinking disabled", async () => {
    const h = harness(() => ({ threats: [{ ...threat({ componentIds: ["svc-01"], evidenceIds: ["ev-svc-01"] }), likelihood: 0 }] }));
    const error = await run(h, arch(["svc-01"])).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AiError);
    expect(h.calls.every((c) => c.body.thinking?.type === "disabled")).toBe(true);
  });

  it("gives every threat call a 300 second deadline", async () => {
    const asked: number[] = [];
    const h = harness(() => ({ threats: [] }));
    h.deps.schedule = (ms) => {
      asked.push(ms);
      return () => {};
    };
    await run(h, arch(Array.from({ length: 9 }, (_, i) => `svc-${i + 1}`)));
    expect(THREATS_TIMEOUT_MS).toBe(300_000);
    expect(asked.length).toBeGreaterThan(1);
    expect(asked.every((ms) => ms === 300_000)).toBe(true);
  });

  it("aborts the whole run with a typed TIMEOUT when one batch times out, returning nothing partial", async () => {
    const pending: (() => void)[] = [];
    const h = harness((ids) => ({
      threats: [threat({ title: `ok ${ids[0]}`, attackScenario: `s ${ids[0]}`, componentIds: [ids[0]], evidenceIds: [`ev-${ids[0]}`] })],
    }));
    const inner = h.deps.client!;
    h.deps.schedule = (_ms, fn) => {
      pending.push(fn);
      return () => {};
    };
    h.deps.client = {
      async create(body, options) {
        // The batch holding svc-05 never answers on its own: only the deadline ends it.
        if (elementsIn(body).includes("svc-05")) {
          await new Promise<never>((_, reject) => {
            options?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
            pending.forEach((fire) => fire());
          });
        }
        return inner.create(body, options);
      },
    };
    const outcome = await run(h, arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"])).then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    expect("value" in outcome).toBe(false);
    const error = (outcome as { error: AiError }).error;
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("TIMEOUT");
    expect(error.message).toContain("300000ms");
  });
});

// ---------------------------------------------------------------------------
// Payload isolation
// ---------------------------------------------------------------------------

describe("what each call is shown", () => {
  it("sends the P1 prompt, the P1 payload and an object-rooted schema", async () => {
    const h = harness(() => ({ threats: [] }));
    await run(h, arch(["orders-api", "web-ui"], [], "orders-api"));
    const body = h.calls[0].body;
    const system = body.system as { text: string }[];
    expect(system[0].text).toContain("STRIDE-per-element");
    expect(system[0].text).toContain("`threats`");
    expect(body.model).toBe("claude-sonnet-5");
    const format = body.output_config?.format as unknown as {
      schema: { properties: object };
    };
    expect(Object.keys(format.schema.properties)).toEqual(["threats"]);
  });

  it("shows a batch only its own elements' evidence, gaps and unknowns", async () => {
    const a = arch(
      ["svc-01", "svc-02", "svc-03", "svc-04", "orders-api"],
      [],
      "orders-api",
    );
    const h = harness(() => ({ threats: [] }));
    await run(h, a);

    expect(h.calls.map((c) => c.elementIds)).toEqual([
      ["orders-api", "svc-01"],
      ["svc-02", "svc-03"],
      ["svc-04"],
    ]);
    const [first, second, third] = h.calls.map((c) => c.body.messages[0].content as string);
    expect(first).toContain("ev-gap-1");
    expect(first).toContain("ev-svc-01");
    expect(first).not.toContain("ev-svc-02");
    expect(first).not.toContain("unknown-svc-04");
    // Other batches see neither the gap nor the first batch's evidence.
    for (const other of [second, third]) {
      expect(other).not.toContain("ev-gap-1");
      expect(other).not.toContain("ev-svc-01");
      expect(other).not.toContain("ev-orders-api");
    }
    expect(second).toContain("ev-svc-02");
    expect(second).not.toContain("ev-svc-04");
    expect(third).toContain("ev-svc-04");
    expect(third).not.toContain("ev-svc-03");
  });

  it("sends the 12,000-token limit and the 300 second deadline on every call", async () => {
    const asked: number[] = [];
    const h = harness(() => ({ threats: [] }));
    h.deps.schedule = (ms) => {
      asked.push(ms);
      return () => {};
    };
    await run(h, arch(["svc-01", "svc-02", "svc-03"]));
    expect(h.calls).toHaveLength(2);
    expect(h.calls.every((c) => c.body.max_tokens === 12_000)).toBe(true);
    expect(asked).toEqual([300_000, 300_000]);
  });

  it("uses the gaps the N2 binding map assigned", async () => {
    const a = arch(["orders-api", "web-ui"], [], "web-ui");
    const h = harness(() => ({ threats: [] }));
    await run(h, a);
    const text = h.calls[0].body.messages[0].content as string;
    const web = text.split("### ELEMENT ").find((b) => b.startsWith("web-ui "))!;
    const orders = text.split("### ELEMENT ").find((b) => b.startsWith("orders-api "))!;
    expect(web).toContain("[gap-1]");
    expect(orders).not.toContain("[gap-1]");
  });
});

// ---------------------------------------------------------------------------
// 3. Reference validation
// ---------------------------------------------------------------------------

describe("reference validation", () => {
  const a = () => arch(["orders-api", "web-ui"], [["flow-1", "web-ui", "orders-api"]], "orders-api");

  async function generate(bad: DraftThreat[]) {
    const good = threat({ title: "Kept threat about orders", attackScenario: "kept scenario words" });
    // orders-api is in the first batch; the flow's batch has nothing to say.
    const h = harness((ids) => ({ threats: ids.includes("orders-api") ? [good, ...bad] : [] }));
    return { result: await run(h, a()), good };
  }

  const CASES: [string, Partial<DraftThreat>, string][] = [
    ["componentIds", { componentIds: ["ghost-service"] }, "componentIds not found: ghost-service"],
    ["dataFlowIds", { dataFlowIds: ["flow-99"] }, "dataFlowIds not found: flow-99"],
    ["evidenceIds", { evidenceIds: ["ev-invented"] }, "evidenceIds not found: ev-invented"],
    [
      "dependsOnUnknownIds",
      { dependsOnUnknownIds: ["unknown-invented"] },
      "dependsOnUnknownIds not found: unknown-invented",
    ],
  ];

  it.each(CASES)("drops a threat with unresolved %s and says so", async (_name, over, message) => {
    const { result, good } = await generate([
      threat({ title: "Bad reference threat", attackScenario: "bad scenario", ...over }),
    ]);
    expect(result.threats).toHaveLength(1);
    expect(result.threats[0].title).toBe(good.title);
    expect(result.limitations).toHaveLength(1);
    expect(result.limitations[0]).toContain('Dropped threat "Bad reference threat"');
    expect(result.limitations[0]).toContain("batch 1");
    expect(result.limitations[0]).toContain(message);
  });

  it("does not repair an unresolved id: the threat is dropped whole", async () => {
    const { result } = await generate([
      threat({ title: "Typo threat", componentIds: ["orders-apii"], attackScenario: "typo" }),
    ]);
    expect(JSON.stringify(result.threats)).not.toContain("orders-apii");
    expect(result.threats.map((t) => t.title)).not.toContain("Typo threat");
  });

  it("reports every problem a dropped threat has in one limitation", async () => {
    const { result } = await generate([
      threat({
        title: "Many problems",
        attackScenario: "many",
        componentIds: ["ghost"],
        evidenceIds: ["ev-invented"],
      }),
    ]);
    expect(result.limitations).toHaveLength(1);
    expect(result.limitations[0]).toContain("componentIds not found: ghost");
    expect(result.limitations[0]).toContain("evidenceIds not found: ev-invented");
  });

  it("drops a threat citing evidence its batch was never shown, even though it exists", async () => {
    const big = arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"]);
    const h = harness((ids) =>
      ids.includes("svc-05")
        ? { threats: [] }
        : {
            threats: [
              threat({
                title: "Borrowed evidence",
                componentIds: ["svc-01"],
                evidenceIds: ["ev-svc-05"],
                attackScenario: "borrowed",
              }),
            ],
          },
    );
    const result = await run(h, big);
    expect(result.threats).toEqual([]);
    expect(result.limitations[0]).toContain("evidenceIds not found: ev-svc-05");
  });

  it("drops a threat that names no element, or only elements outside its batch", async () => {
    const big = arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"]);
    const h = harness((ids) =>
      ids.includes("svc-05")
        ? { threats: [] }
        : {
            threats: [
              threat({ title: "No element", componentIds: [], evidenceIds: [], assumptions: ["a"], attackScenario: "none" }),
              threat({
                title: "Foreign element",
                componentIds: ["svc-05"],
                evidenceIds: ["ev-svc-01"],
                attackScenario: "foreign",
              }),
            ],
          },
    );
    const result = await run(h, big);
    expect(result.threats).toEqual([]);
    expect(result.limitations.join("\n")).toContain("names no component or data flow");
    expect(result.limitations.join("\n")).toContain("names no element from its batch");
  });

  it("keeps a threat that names an element outside its batch as well as one inside", async () => {
    const big = arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"]);
    const h = harness((ids) =>
      !ids.includes("svc-01")
        ? { threats: [] }
        : {
            threats: [
              threat({
                title: "Spans two batches",
                componentIds: ["svc-01", "svc-05"],
                evidenceIds: ["ev-svc-01"],
                attackScenario: "spans",
              }),
            ],
          },
    );
    const result = await run(h, big);
    expect(result.threats).toHaveLength(1);
    expect(result.limitations).toEqual([]);
  });

  it("drops a threat that cites nothing and assumes nothing", async () => {
    const { result } = await generate([
      threat({ title: "Unsupported", evidenceIds: [], assumptions: [], attackScenario: "unsupported" }),
    ]);
    expect(result.limitations[0]).toContain("cites no evidence and states no assumption");
  });

  it("drops a placeholder: no evidence and only placeholder assumptions", async () => {
    const { result } = await generate([
      threat({
        title: "Placeholder",
        evidenceIds: [],
        assumptions: ["duplicate placeholder, removed"],
        attackScenario: "placeholder",
      }),
    ]);
    expect(result.threats.map((t) => t.title)).not.toContain("Placeholder");
    expect(result.limitations.join("\n")).toContain(
      'Dropped threat "Placeholder" from batch 1: is a placeholder',
    );
  });

  it("keeps a placeholder-assumption threat that cites evidence, or has one real assumption", async () => {
    const { result } = await generate([
      threat({ title: "Backed", assumptions: ["N/A"], attackScenario: "backed by default evidence" }),
      threat({
        title: "One real premise",
        evidenceIds: [],
        assumptions: ["TBD", "the Worker is deployed with ALLOWED_ORIGINS unset"],
        attackScenario: "premise",
      }),
    ]);
    expect(result.limitations).toEqual([]);
    expect(result.threats.map((t) => t.title).sort()).toEqual([
      "Backed",
      "Kept threat about orders",
      "One real premise",
    ]);
  });

  it("accepts an assumption-only threat", async () => {
    const { result } = await generate([
      threat({
        title: "Assumed only",
        evidenceIds: [],
        assumptions: ["the upload directory is world-readable"],
        attackScenario: "assumed scenario",
      }),
    ]);
    expect(result.threats.map((t) => t.title)).toContain("Assumed only");
  });

  it("returns only the evidence the surviving threats cite", async () => {
    const { result } = await generate([]);
    expect(result.evidence.map((e) => e.id)).toEqual(["ev-orders-api"]);
  });

  it("referenceIssues is empty for a sound threat", () => {
    const { architecture } = a();
    expect(
      referenceIssues(threat(), architecture, {
        evidence: new Map([["orders-api", new Set(["ev-orders-api"])]]),
        unknowns: new Map([["orders-api", new Set<string>()]]),
      }),
    ).toEqual([]);
  });

  it("referenceIssues rejects evidence and unknowns offered only to another element of the batch", () => {
    const { architecture } = arch(["alpha", "beta"]);
    const offered = {
      evidence: new Map([
        ["alpha", new Set(["ev-alpha"])],
        ["beta", new Set(["ev-beta"])],
      ]),
      unknowns: new Map([
        ["alpha", new Set(["unknown-alpha"])],
        ["beta", new Set(["unknown-beta"])],
      ]),
    };
    const borrowing = threat({
      componentIds: ["beta"],
      evidenceIds: ["ev-alpha", "ev-beta"],
      dependsOnUnknownIds: ["unknown-alpha"],
    });
    expect(referenceIssues(borrowing, architecture, offered)).toEqual([
      "evidenceIds offered only to another element of the batch: ev-alpha",
      "dependsOnUnknownIds offered only to another element of the batch: unknown-alpha",
    ]);
    // Naming both elements makes both elements' blocks its own.
    expect(
      referenceIssues({ ...borrowing, componentIds: ["alpha", "beta"] }, architecture, offered),
    ).toEqual([]);
  });

  describe("route-scoped gap citations", () => {
    const withLearnGap = () => {
      const a = arch(["alpha"], [], "alpha");
      a.gaps[0] = { ...a.gaps[0], kind: "input_validation_missing", routePath: "/learn", summary: "GET /learn reads request input" };
      return a;
    };
    const runWith = (h: Harness, a: ReturnType<typeof withLearnGap>) =>
      generateThreats({
        architecture: a.architecture,
        gaps: a.gaps,
        routePaths: ["/learn", "/research"],
        files: files(["alpha"]),
        analysisId: "test-analysis",
        deps: h.deps,
      });
    const base = { componentIds: ["alpha"], assumptions: [], impact: 4, likelihood: 3 };

    it("keeps a same-route citation", async () => {
      const h = harness(() => ({
        threats: [threat({ ...base, title: "Open redirect on GET /learn", attackScenario: "url", evidenceIds: ["ev-alpha", "ev-gap-1"] })],
      }));
      const result = await runWith(h, withLearnGap());
      expect(result.threats[0].evidenceIds).toEqual(["ev-alpha", "ev-gap-1"]);
      expect(result.limitations).toEqual([]);
    });

    it("removes a cross-route citation, records why, and keeps the threat on its other evidence", async () => {
      const h = harness(() => ({
        threats: [threat({ ...base, title: "SSRF on GET /research", attackScenario: "fetch", evidenceIds: ["ev-alpha", "ev-gap-1"] })],
      }));
      const result = await runWith(h, withLearnGap());
      expect(result.threats[0].evidenceIds).toEqual(["ev-alpha"]);
      expect(result.evidence.map((e) => e.id)).toEqual(["ev-alpha"]);
      expect(result.limitations).toEqual([
        'Removed citation ev-gap-1 from threat "SSRF on GET /research" in batch 1: the gap is about /learn, the threat names /research.',
      ]);
    });

    it("drops the threat under the existing rule when the wrong citation was its only support", async () => {
      const h = harness(() => ({
        threats: [threat({ ...base, title: "SSRF on GET /research", attackScenario: "fetch", evidenceIds: ["ev-gap-1"] })],
      }));
      const result = await runWith(h, withLearnGap());
      expect(result.threats).toEqual([]);
      expect(result.limitations).toEqual([
        'Dropped threat "SSRF on GET /research" from batch 1: cites no evidence and states no assumption.',
        'Removed citation ev-gap-1 from threat "SSRF on GET /research" in batch 1: the gap is about /learn, the threat names /research.',
      ]);
    });

    it("keeps the citation when the threat names no route", async () => {
      const h = harness(() => ({
        threats: [threat({ ...base, title: "Unvalidated input", attackScenario: "no validation", evidenceIds: ["ev-gap-1"] })],
      }));
      const result = await runWith(h, withLearnGap());
      expect(result.threats[0].evidenceIds).toEqual(["ev-gap-1"]);
    });
  });

  it("drops a threat that borrows a co-batched element's evidence, so it cannot read as evidence-backed", async () => {
    // alpha and beta have no flows, so first-fit packs them into ONE batch. The model is
    // shown ev-alpha only under alpha, then cites it for a threat about beta alone.
    const pair = arch(["alpha", "beta"]);
    expect(batchElements(pair.architecture)).toEqual([["alpha", "beta"]]);
    const h = harness(() => ({
      threats: [
        threat({
          title: "SQL injection in beta",
          componentIds: ["beta"],
          evidenceIds: ["ev-alpha"],
          assumptions: [],
          attackScenario: "borrowed from alpha",
          impact: 5,
          likelihood: 4,
        }),
      ],
    }));
    const result = await run(h, pair);

    expect(h.calls).toHaveLength(1);
    const user = String(h.calls[0].body.messages[0].content);
    expect(user.split("### ELEMENT beta")[1]).not.toContain("[ev-alpha]");
    expect(result.threats).toEqual([]);
    expect(result.evidence).toEqual([]);
    expect(result.limitations).toEqual([
      'Dropped threat "SQL injection in beta" from batch 1: evidenceIds offered only to another element of the batch: ev-alpha.',
    ]);
  });

  it("keeps a flow threat citing a gap its endpoint passed down to the flow's block", async () => {
    // gap-1 is bound to alpha; the flow's block lists it (via alpha), so it is the flow's own.
    const withFlow = arch(["alpha", "beta"], [["df-alpha-beta", "alpha", "beta"]], "alpha");
    const h = harness((ids) => ({
      threats: ids.includes("df-alpha-beta")
        ? [
            threat({
              title: "Flow inherits the ownership gap",
              componentIds: [],
              dataFlowIds: ["df-alpha-beta"],
              evidenceIds: ["ev-gap-1"],
              attackScenario: "inherited gap",
            }),
          ]
        : [],
    }));
    const result = await run(h, withFlow);
    expect(result.limitations).toEqual([]);
    expect(result.threats.map((t) => t.evidenceIds)).toEqual([["ev-gap-1"]]);
  });

  it("orders limitations within a batch regardless of the order the model returned", async () => {
    const bad = (name: string) =>
      threat({ title: name, attackScenario: name, evidenceIds: ["ev-invented"] });
    const only = (threats: DraftThreat[]) => (ids: string[]) => ({
      threats: ids.includes("orders-api") ? threats : [],
    });
    const forward = await run(harness(only([bad("Aaa"), bad("Zzz")])), a());
    const backward = await run(harness(only([bad("Zzz"), bad("Aaa")])), a());
    expect(forward.limitations).toHaveLength(2);
    expect(backward.limitations).toEqual(forward.limitations);
  });

  it("orders limitations deterministically across batches", async () => {
    const big = arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"]);
    const h = harness((ids) => ({
      threats: [
        threat({
          title: `Bad ${ids[0]}`,
          componentIds: [ids[0]],
          evidenceIds: ["ev-invented"],
          attackScenario: `s ${ids[0]}`,
        }),
      ],
    }));
    const { limitations } = await run(h, big);
    expect(limitations).toHaveLength(3);
    expect(limitations[0]).toContain("batch 1");
    expect(limitations[1]).toContain("batch 2");
    expect(limitations[2]).toContain("batch 3");
  });
});

// ---------------------------------------------------------------------------
// 4. Deduplication
// ---------------------------------------------------------------------------

describe("dedupe", () => {
  const EV = [
    ev("ev-code"),
    ev("ev-gap-1", { kind: "assumption", ruleId: "gap:authz_missing" }),
    ev("ev-gap-2", { kind: "assumption", ruleId: "gap:input_validation_missing" }),
  ];

  /** Two threats whose token sets are exactly the given words. Title holds the first. */
  function pair(a: string[], b: string[], overA: Partial<DraftThreat> = {}, overB: Partial<DraftThreat> = {}) {
    const make = (words: string[], over: Partial<DraftThreat>) =>
      threat({ title: words[0], attackScenario: words.slice(1).join(" "), ...over });
    return [make(a, overA), make(b, overB)];
  }
  const w = (...n: number[]) => n.map((i) => `zq${i}`);

  it("tokenises to lowercase words without stopwords", () => {
    expect([...tokenize("The Attacker CAN send a token, to the API!")].sort()).toEqual([
      "api",
      "attacker",
      "send",
      "token",
    ]);
  });

  it("computes Jaccard as shared over union", () => {
    expect(jaccard(new Set(["a", "b", "c"]), new Set(["b", "c", "d"]))).toBe(0.5);
    expect(jaccard(new Set(), new Set())).toBe(0);
    expect(jaccard(new Set(["a"]), new Set(["a"]))).toBe(1);
  });

  it("merges at exactly 0.60 (3 shared of 5)", () => {
    const [x, y] = pair(w(1, 2, 3, 4), w(1, 2, 3, 5));
    expect(jaccard(tokenize(`${x.title} ${x.attackScenario}`), tokenize(`${y.title} ${y.attackScenario}`))).toBe(0.6);
    expect(dedupeThreats([x, y], EV)).toHaveLength(1);
  });

  it("does not merge just below 0.60 (4 shared of 7 = 0.571)", () => {
    const [x, y] = pair(w(1, 2, 3, 4, 5), w(1, 2, 3, 4, 6, 7));
    expect(dedupeThreats([x, y], EV)).toHaveLength(2);
  });

  it("does not merge well below 0.60 (2 shared of 4 = 0.50)", () => {
    const [x, y] = pair(w(1, 2, 3), w(1, 2, 4));
    expect(dedupeThreats([x, y], EV)).toHaveLength(2);
  });

  it("merges above 0.60 (4 shared of 5 = 0.80)", () => {
    const [x, y] = pair(w(1, 2, 3, 4), w(1, 2, 3, 4, 5));
    expect(dedupeThreats([x, y], EV)).toHaveLength(1);
  });

  it("does not merge identical wording about two different elements", () => {
    const [x, y] = pair(w(1, 2, 3, 4), w(1, 2, 3, 4), { componentIds: ["orders-api"] }, { componentIds: ["web-ui"] });
    expect(dedupeThreats([x, y], EV)).toHaveLength(2);
  });

  describe("relationship between candidates", () => {
    const FLOWS = [
      { id: "flow-1", sourceId: "web-ui", targetId: "orders-api" },
      { id: "flow-2", sourceId: "queue-1", targetId: "cache-1" },
    ];
    const same = w(1, 2, 3, 4, 5);
    const on = (over: Partial<DraftThreat>) =>
      threat({ title: same[0], attackScenario: same.slice(1).join(" "), ...over });

    it("merges similar threats for the same component", () => {
      const merged = dedupeThreats(
        [on({ componentIds: ["orders-api"], stride: ["T"] }), on({ componentIds: ["orders-api"], stride: ["I"] })],
        EV,
        FLOWS,
      );
      expect(merged).toHaveLength(1);
    });

    it("merges similar threats for the same data flow", () => {
      const merged = dedupeThreats(
        [
          on({ componentIds: [], dataFlowIds: ["flow-1"] }),
          on({ componentIds: [], dataFlowIds: ["flow-1"], stride: ["D"] }),
        ],
        EV,
        FLOWS,
      );
      expect(merged).toHaveLength(1);
    });

    it("merges a component threat with a flow threat whose target is that component", () => {
      const component = on({ componentIds: ["orders-api"] });
      const flowThreat = on({ componentIds: [], dataFlowIds: ["flow-1"], stride: ["I"] });
      const [merged, ...rest] = dedupeThreats([component, flowThreat], EV, FLOWS);
      expect(rest).toEqual([]);
      expect(merged.componentIds).toEqual(["orders-api"]);
      expect(merged.dataFlowIds).toEqual(["flow-1"]);
    });

    it("merges a component threat with a flow threat whose source is that component", () => {
      const merged = dedupeThreats(
        [on({ componentIds: ["web-ui"] }), on({ componentIds: [], dataFlowIds: ["flow-1"], stride: ["I"] })],
        EV,
        FLOWS,
      );
      expect(merged).toHaveLength(1);
    });

    it("does not merge similar threats from unrelated components", () => {
      const merged = dedupeThreats(
        [on({ componentIds: ["orders-api"] }), on({ componentIds: ["cache-1"] })],
        EV,
        FLOWS,
      );
      expect(merged).toHaveLength(2);
    });

    it("does not merge similar threats from unrelated flows, or a flow and an unconnected component", () => {
      expect(
        dedupeThreats(
          [on({ componentIds: [], dataFlowIds: ["flow-1"] }), on({ componentIds: [], dataFlowIds: ["flow-2"] })],
          EV,
          FLOWS,
        ),
      ).toHaveLength(2);
      expect(
        dedupeThreats(
          [on({ componentIds: ["cache-1"] }), on({ componentIds: [], dataFlowIds: ["flow-1"] })],
          EV,
          FLOWS,
        ),
      ).toHaveLength(2);
    });

    it("needs the flow to be known: an unlisted flow relates nothing", () => {
      const merged = dedupeThreats(
        [on({ componentIds: ["orders-api"] }), on({ componentIds: [], dataFlowIds: ["flow-1"] })],
        EV,
        [],
      );
      expect(merged).toHaveLength(2);
    });

    it("does not merge related threats whose wording is below the threshold", () => {
      const merged = dedupeThreats(
        [
          on({ componentIds: ["orders-api"] }),
          threat({ title: "unrelated words entirely", attackScenario: "nothing shared here", componentIds: ["orders-api"] }),
        ],
        EV,
        FLOWS,
      );
      expect(merged).toHaveLength(2);
    });

    it("is symmetric", () => {
      const a = on({ componentIds: ["orders-api"] });
      const b = on({ componentIds: [], dataFlowIds: ["flow-1"] });
      const c = on({ componentIds: ["cache-1"] });
      const map = new Map(FLOWS.map((f) => [f.id, f]));
      expect(areRelated(a, b, map)).toBe(true);
      expect(areRelated(b, a, map)).toBe(true);
      expect(areRelated(a, c, map)).toBe(false);
      expect(areRelated(c, a, map)).toBe(false);
      expect(areRelated(b, c, map)).toBe(false);
      expect(areRelated(c, b, map)).toBe(false);
    });

    it("gives the same groups whatever order threats or flows arrive in", () => {
      const set = [
        on({ componentIds: ["orders-api"], evidenceIds: ["ev-gap-1"] }),
        on({ componentIds: [], dataFlowIds: ["flow-1"], stride: ["I"], evidenceIds: ["ev-code"] }),
        on({ componentIds: ["web-ui"], stride: ["S"], evidenceIds: ["ev-gap-2"] }),
        on({ componentIds: ["cache-1"], stride: ["D"] }),
        threat({ title: "unrelated thing", attackScenario: "elsewhere", componentIds: ["queue-1"] }),
      ];
      const expected = dedupeThreats(set, EV, FLOWS);
      // orders-api, flow-1 and web-ui chain into one group; cache-1 and queue-1 stand alone.
      expect(expected).toHaveLength(3);
      for (const seed of [1, 2, 3, 4, 5, 6]) {
        expect(dedupeThreats(shuffled(set, seed), EV, shuffled(FLOWS, seed))).toEqual(expected);
      }
    });

    it("keeps the evidence-backed preference across a component-to-flow merge", () => {
      const gapOnly = on({ title: `Aaa ${same[0]}`, componentIds: ["orders-api"], evidenceIds: ["ev-gap-1"] });
      const backed = on({ title: `Zzz ${same[0]}`, componentIds: [], dataFlowIds: ["flow-1"], evidenceIds: ["ev-code"] });
      for (const input of [[gapOnly, backed], [backed, gapOnly]]) {
        const [merged] = dedupeThreats(input, EV, FLOWS);
        expect(merged.title).toBe(`Zzz ${same[0]}`);
        expect(merged.evidenceIds).toEqual(["ev-code", "ev-gap-1"]);
      }
    });

    it("is used by the engine: a component threat and its flow's threat from different batches merge", async () => {
      // orders-api and flow-1 (sourced at web-ui) land in different batches.
      const a = arch(["web-ui", "orders-api", "svc-3", "svc-4", "svc-5"], [["flow-1", "web-ui", "orders-api"]]);
      const words = { title: "zq1", attackScenario: "zq2 zq3 zq4 zq5" };
      const h = harness((ids) => ({
        threats: ids.includes("orders-api")
          ? [threat({ ...words, componentIds: ["orders-api"], evidenceIds: ["ev-orders-api"] })]
          : ids.includes("flow-1")
            ? [threat({ ...words, componentIds: [], dataFlowIds: ["flow-1"], evidenceIds: ["ev-flow-1"], stride: ["I"] })]
            : [],
      }));
      const result = await run(h, a);
      expect(h.calls.length).toBeGreaterThan(1);
      expect(result.threats).toHaveLength(1);
      expect(result.threats[0].componentIds).toEqual(["orders-api"]);
      expect(result.threats[0].dataFlowIds).toEqual(["flow-1"]);
    });
  });

  it("does not merge threats that only share common security words", () => {
    const x = threat({
      title: "Session fixation on login",
      attackScenario:
        "the attacker sends an authenticated request with a forged token to the login route and the server accepts the injection",
    });
    const y = threat({
      title: "Path traversal in file download",
      attackScenario:
        "the attacker sends an authenticated request with a forged token to the download route and the server accepts the injection",
      stride: ["I"],
    });
    const similarity = jaccard(
      tokenize(`${x.title} ${x.attackScenario}`),
      tokenize(`${y.title} ${y.attackScenario}`),
    );
    expect(similarity).toBeLessThan(DEDUPE_THRESHOLD);
    expect(dedupeThreats([x, y], EV)).toHaveLength(2);
  });

  it("prefers the evidence-backed threat over a gap-only duplicate", () => {
    const gapOnly = threat({
      title: "Aaa driven wording zq1 zq2 zq3 zq4",
      attackScenario: "zq5",
      evidenceIds: ["ev-gap-1"],
      mitigation: { summary: "Gap fix", steps: ["gap step"] },
    });
    const backed = threat({
      title: "Zzz driven wording zq1 zq2 zq3 zq4",
      attackScenario: "zq5",
      evidenceIds: ["ev-code"],
      mitigation: { summary: "Evidence fix", steps: ["evidence step"] },
    });
    for (const input of [[gapOnly, backed], [backed, gapOnly]]) {
      const [merged, ...rest] = dedupeThreats(input, EV);
      expect(rest).toEqual([]);
      expect(merged.title).toContain("Zzz driven");
      expect(merged.mitigation.summary).toBe("Evidence fix");
    }
  });

  it("does not treat an inference as evidence when picking the winner (same rule as scoring's basis)", () => {
    const withInference = [...EV, ev("ev-inf", { kind: "inference" })];
    const inferred = threat({
      title: "Aaa driven wording zq1 zq2 zq3 zq4",
      attackScenario: "zq5",
      evidenceIds: ["ev-inf"],
      mitigation: { summary: "Inferred fix", steps: ["inferred step"] },
    });
    const backed = threat({
      title: "Zzz driven wording zq1 zq2 zq3 zq4",
      attackScenario: "zq5",
      evidenceIds: ["ev-code"],
      mitigation: { summary: "Evidence fix", steps: ["evidence step"] },
    });
    // "Aaa" sorts first, so before the fix the inference-only threat won the tie.
    for (const input of [[inferred, backed], [backed, inferred]]) {
      const [merged, ...rest] = dedupeThreats(input, withInference);
      expect(rest).toEqual([]);
      expect(merged.mitigation.summary).toBe("Evidence fix");
    }
  });

  it("prefers the evidence-backed threat even when its impact is lower", () => {
    const gapOnly = threat({ title: "zq1 zq2 zq3 zq4 zq5", attackScenario: "gapword", evidenceIds: ["ev-gap-1"], impact: 5 });
    const backed = threat({ title: "zq1 zq2 zq3 zq4 zq5", attackScenario: "backword", evidenceIds: ["ev-code"], impact: 2 });
    const [merged] = dedupeThreats([gapOnly, backed], EV);
    expect(merged.attackScenario).toBe("backword");
    expect(merged.impact).toBe(5);
  });

  it("counts evidence that cannot be found as no support", () => {
    const unknown = threat({ title: "zq1 zq2 zq3 zq4 zq5", attackScenario: "unk", evidenceIds: ["ev-missing"] });
    const backed = threat({ title: "zq1 zq2 zq3 zq4 zq5", attackScenario: "bck", evidenceIds: ["ev-code"] });
    expect(dedupeThreats([unknown, backed], EV)[0].attackScenario).toBe("bck");
  });

  it("unions evidence, assumptions and unknown ids without duplicates", () => {
    const [x, y] = pair(
      w(1, 2, 3, 4, 5),
      w(1, 2, 3, 4, 5),
      { evidenceIds: ["ev-code", "ev-gap-1"], assumptions: ["a1", "shared"], dependsOnUnknownIds: ["unknown-a", "unknown-shared"] },
      { evidenceIds: ["ev-gap-1", "ev-gap-2"], assumptions: ["shared", "a2"], dependsOnUnknownIds: ["unknown-shared", "unknown-b"] },
    );
    const [merged] = dedupeThreats([x, y], EV);
    expect(merged.evidenceIds).toEqual(["ev-code", "ev-gap-1", "ev-gap-2"]);
    expect(merged.assumptions).toEqual(["a1", "a2", "shared"]);
    expect(merged.dependsOnUnknownIds).toEqual(["unknown-a", "unknown-b", "unknown-shared"]);
  });

  it("unions elements, categories and mappings, in canonical order", () => {
    // The first threat wins (lowest element id, then category); the second holds the extras.
    const [x, y] = pair(
      w(1, 2, 3, 4, 5),
      w(1, 2, 3, 4, 5),
      { componentIds: ["orders-api"], dataFlowIds: ["flow-1"], stride: ["S"], owasp: ["A05:2025"], cwe: ["CWE-89"] },
      { componentIds: ["orders-api", "web-ui"], dataFlowIds: ["flow-2"], stride: ["I", "T"], owasp: ["A01:2025"], cwe: ["CWE-200"] },
    );
    const [merged] = dedupeThreats([y, x], EV);
    expect(merged.componentIds).toEqual(["orders-api", "web-ui"]);
    expect(merged.dataFlowIds).toEqual(["flow-1", "flow-2"]);
    expect(merged.stride).toEqual(["S", "T", "I"]);
    expect(merged.owasp).toEqual(["A01:2025", "A05:2025"]);
    expect(merged.cwe).toEqual(["CWE-200", "CWE-89"]);
  });

  it("takes each reason from the threat that owns the maximum, not from the winner", () => {
    const base = { title: "zq1", attackScenario: "zq2 zq3 zq4 zq5" };
    const winner = threat({ ...base, evidenceIds: ["ev-code"], impact: 3, likelihood: 3, impactReason: "winner impact", likelihoodReason: "winner likelihood" });
    const maxImpact = threat({ ...base, evidenceIds: ["ev-gap-1"], impact: 5, likelihood: 1, impactReason: "max impact", likelihoodReason: "low likelihood" });
    const maxLikelihood = threat({ ...base, evidenceIds: ["ev-gap-2"], impact: 1, likelihood: 5, impactReason: "low impact", likelihoodReason: "max likelihood" });
    const [merged] = dedupeThreats([maxImpact, maxLikelihood, winner], EV);
    expect(merged.evidenceIds).toContain("ev-code");
    expect([merged.impact, merged.impactReason]).toEqual([5, "max impact"]);
    expect([merged.likelihood, merged.likelihoodReason]).toEqual([5, "max likelihood"]);
  });

  it("de-duplicates the arrays of a threat that merges with nothing", () => {
    const [only] = dedupeThreats(
      [threat({ evidenceIds: ["ev-code", "ev-code"], assumptions: ["x", "x"], dependsOnUnknownIds: ["u", "u"] })],
      EV,
    );
    expect(only.evidenceIds).toEqual(["ev-code"]);
    expect(only.assumptions).toEqual(["x"]);
    expect(only.dependsOnUnknownIds).toEqual(["u"]);
  });

  it("keeps the higher impact and the higher likelihood, each with its own reason", () => {
    const [x, y] = pair(
      w(1, 2, 3, 4, 5),
      w(1, 2, 3, 4, 5),
      { impact: 5, likelihood: 1, impactReason: "high impact reason", likelihoodReason: "low likelihood reason" },
      { impact: 2, likelihood: 4, impactReason: "low impact reason", likelihoodReason: "high likelihood reason" },
    );
    const [merged] = dedupeThreats([x, y], EV);
    expect(merged.impact).toBe(5);
    expect(merged.likelihood).toBe(4);
    expect(merged.impactReason).toBe("high impact reason");
    expect(merged.likelihoodReason).toBe("high likelihood reason");
  });

  it("gives the same result whatever order the threats arrive in", () => {
    const base = [
      threat({ title: "zq1 zq2 zq3 zq4 zq5", attackScenario: "one", evidenceIds: ["ev-gap-1"], impact: 4 }),
      threat({ title: "zq1 zq2 zq3 zq4 zq5", attackScenario: "two", evidenceIds: ["ev-code"], impact: 2 }),
      threat({ title: "zq1 zq2 zq3 zq4 zq5", attackScenario: "three", evidenceIds: ["ev-gap-2"], impact: 3 }),
      threat({ title: "unrelated finding", attackScenario: "elsewhere", componentIds: ["web-ui"], stride: ["S"] }),
    ];
    const expected = dedupeThreats(base, EV);
    for (const seed of [1, 2, 3, 4, 5, 6]) {
      expect(dedupeThreats(shuffled(base, seed), EV)).toEqual(expected);
    }
    expect(expected).toHaveLength(2);
  });

  it("does not mutate its input", () => {
    const x = threat({ evidenceIds: ["ev-code", "ev-code"] });
    const before = JSON.stringify(x);
    dedupeThreats([x], EV);
    expect(JSON.stringify(x)).toBe(before);
  });
});

// ---------------------------------------------------------------------------
// 5. Stable ids
// ---------------------------------------------------------------------------

describe("stable ids", () => {
  const set = [
    threat({ title: "web threat", attackScenario: "w", componentIds: ["web-ui"], stride: ["I"] }),
    threat({ title: "orders elevation", attackScenario: "oe", stride: ["E"] }),
    threat({ title: "orders tampering", attackScenario: "ot", stride: ["T"] }),
    threat({ title: "orders spoofing", attackScenario: "os", stride: ["S"] }),
    threat({ title: "flow threat", attackScenario: "f", componentIds: [], dataFlowIds: ["flow-1"], stride: ["D"] }),
  ];

  it("numbers threats threat-1, threat-2, ... ordered by element then category", () => {
    const ids = assignIds(set);
    expect(ids.map((t) => t.id)).toEqual(["threat-1", "threat-2", "threat-3", "threat-4", "threat-5"]);
    expect(ids.map((t) => t.title)).toEqual([
      "flow threat", // flow-1 sorts before orders-api and web-ui
      "orders spoofing", // S
      "orders tampering", // T
      "orders elevation", // E
      "web threat",
    ]);
  });

  it("breaks a tie on element and category deterministically", () => {
    const a = threat({ title: "aaa first", attackScenario: "x" });
    const b = threat({ title: "bbb second", attackScenario: "y" });
    expect(assignIds([b, a]).map((t) => t.title)).toEqual(assignIds([a, b]).map((t) => t.title));
  });

  it("gives the same ids for repeated and reordered inputs", () => {
    const first = assignIds(set);
    for (const seed of [1, 2, 3, 4]) {
      expect(assignIds(shuffled(set, seed))).toEqual(first);
    }
  });

  it("assigns ids after dedupe, with no gaps in the numbering", async () => {
    const a = arch(["orders-api", "web-ui"], [], "orders-api");
    const dup = threat({ title: "zq1 zq2 zq3 zq4 zq5", attackScenario: "dup one" });
    const h = harness(() => ({
      threats: [dup, { ...dup, attackScenario: "dup two" }, threat({ title: "other", attackScenario: "o", componentIds: ["web-ui"], evidenceIds: ["ev-web-ui"] })],
    }));
    const { threats } = await run(h, a);
    expect(threats.map((t) => t.id)).toEqual(["threat-1", "threat-2"]);
  });

  it("gives identical ids and order across runs, and when the model reorders its reply", async () => {
    const a = arch(["orders-api", "web-ui", "queue-1"], [["flow-1", "web-ui", "orders-api"]], "orders-api");
    const replies = [
      threat({ title: "one orders", attackScenario: "a", stride: ["T"] }),
      threat({ title: "two orders", attackScenario: "b", stride: ["E"], evidenceIds: ["ev-gap-1"] }),
      threat({ title: "web one", attackScenario: "c", componentIds: ["web-ui"], evidenceIds: ["ev-web-ui"], stride: ["I"] }),
      threat({ title: "flow one", attackScenario: "d", componentIds: [], dataFlowIds: ["flow-1"], evidenceIds: ["ev-flow-1"], stride: ["T"] }),
    ];
    const results = await Promise.all(
      [0, 1, 2].map((seed) => run(harness(() => ({ threats: shuffled(replies, seed) })), a)),
    );
    expect(results[1].threats).toEqual(results[0].threats);
    expect(results[2].threats).toEqual(results[0].threats);
    expect(results[0].threats.map((t) => t.id)).toEqual(["threat-1", "threat-2", "threat-3", "threat-4"]);
  });

  it("gives the same result when the architecture's arrays are reordered", async () => {
    const a = arch(["orders-api", "web-ui", "queue-1", "cache-1", "db-1"], [["flow-1", "web-ui", "orders-api"]], "orders-api");
    const reply = (ids: string[]): Reply => ({
      threats: ids
        .filter((id) => !id.startsWith("flow"))
        .map((id) => threat({ title: `finding ${id}`, attackScenario: `s ${id}`, componentIds: [id], evidenceIds: [`ev-${id}`] })),
    });
    const base = await run(harness(reply), a);
    const reordered = {
      architecture: {
        ...a.architecture,
        components: shuffled(a.architecture.components, 7),
        dataFlows: shuffled(a.architecture.dataFlows, 3),
      },
      gaps: a.gaps,
    };
    const again = await run(harness(reply), reordered);
    expect(again.threats).toEqual(base.threats);
    expect(again.batches.map((b) => b.elementIds)).toEqual(base.batches.map((b) => b.elementIds));
  });
});

// ---------------------------------------------------------------------------
// 6. Model failures and the network
// ---------------------------------------------------------------------------

describe("model failures", () => {
  const five = arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"]);
  const good = (ids: string[]): Reply => ({
    threats: [threat({ title: `ok ${ids[0]}`, attackScenario: `s ${ids[0]}`, componentIds: [ids[0]], evidenceIds: [`ev-${ids[0]}`] })],
  });

  it("retries once with the validation error, then accepts a corrected reply", async () => {
    let n = 0;
    const h = harness((ids) => (n++ === 0 ? "not json" : good(ids)));
    const result = await run(h, arch(["svc-01"]));
    expect(h.calls).toHaveLength(2);
    expect(result.threats).toHaveLength(1);
    expect(result.limitations).toEqual([]);
  });

  it("fails the whole run when one batch fails validation twice, returning nothing partial", async () => {
    const h = harness((ids) => (ids.includes("svc-05") ? "still not json" : good(ids)));
    const outcome = await run(h, five).then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    expect("value" in outcome).toBe(false);
    const error = (outcome as { error: AiError }).error;
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("MODEL_OUTPUT_INVALID");
    expect(error.issues.length).toBeGreaterThan(0);
  });

  it("treats a reply that breaks the schema as a failure of the run", async () => {
    const h = harness((ids) =>
      ids.includes("svc-05") ? { threats: [{ ...threat(), impact: 9 }] } : good(ids),
    );
    const error = await run(h, five).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AiError);
    expect((error as AiError).code).toBe("MODEL_OUTPUT_INVALID");
  });

  it("starts no further batch after a failure, and calls the model twice for the failing one", async () => {
    const h = harness((ids) => (ids.includes("svc-01") ? "not json" : good(ids)));
    const error = await run(h, arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05", "svc-06"]), {
      concurrency: 1,
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AiError);
    // The first batch, and its one validation retry. Batches 2 and 3 were never started.
    expect(h.calls).toHaveLength(2);
    expect(h.calls.every((c) => c.elementIds.includes("svc-01"))).toBe(true);
  });

  it("does not let a model supply a severity, confidence or priority", async () => {
    const smuggled = {
      ...threat({ componentIds: ["svc-01"], evidenceIds: ["ev-svc-01"] }),
      severity: "critical",
      confidence: 1,
      confidenceLabel: "high",
      priority: "fix_now",
      basis: "evidence_backed",
    };
    const h = harness(() => JSON.stringify({ threats: [smuggled] }));
    const { threats } = await run(h, arch(["svc-01"]));
    for (const key of ["severity", "confidence", "confidenceLabel", "basis", "priority"]) {
      expect(threats[0]).not.toHaveProperty(key);
    }
  });

  it("throws the typed error when every batch fails validation", async () => {
    const h = harness(() => "nope");
    const error = await run(h, five).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AiError);
    expect((error as AiError).code).toBe("MODEL_OUTPUT_INVALID");
    expect((error as AiError).issues.length).toBeGreaterThan(0);
  });

  it("stops the run on a systemic failure instead of degrading", async () => {
    const rate = Object.assign(new Error("HTTP 429"), { status: 429 });
    const h = harness(() => rate);
    const error = await run(h, arch(Array.from({ length: 12 }, (_, i) => `svc-${i + 1}`)), {
      concurrency: 1,
    }).catch((e: unknown) => e);
    expect((error as AiError).code).toBe("UPSTREAM_RATE_LIMITED");
    // Three transport attempts for the first batch, and no second batch was started.
    expect(new Set(h.calls.map((c) => c.elementIds.join())).size).toBe(1);
  });

  it("does not absorb an AI_FAILURE that is not a validation failure", async () => {
    const bad = Object.assign(new Error("HTTP 400"), { status: 400 });
    const h = harness((ids) => (ids.includes("svc-05") ? bad : good(ids)));
    const error = await run(h, five).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AiError);
    expect((error as AiError).code).toBe("AI_FAILURE");
    expect((error as AiError).issues).toEqual([]);
  });

  it("fails the run when a batch is cut off twice: one retry with a larger budget, no partial threats, usage kept", async () => {
    const h = harness((ids) => good(ids));
    const inner = h.deps.client!;
    h.deps.client = {
      async create(body, options) {
        const response = await inner.create(body, options);
        return elementsIn(body).includes("svc-01")
          ? { ...response, stop_reason: "max_tokens", usage: { ...response.usage, output_tokens: body.max_tokens } }
          : response;
      },
    };
    const outcome = await run(h, arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05", "svc-06"]), {
      concurrency: 1,
    }).then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    expect("value" in outcome).toBe(false);
    const error = (outcome as { error: AiError }).error;
    expect(error).toBeInstanceOf(AiError);
    expect(error.code).toBe("MODEL_OUTPUT_INVALID");
    expect(error.message).toBe(
      "stride: structured output was truncated at the configured token limit (21333 tokens)",
    );
    // Two model calls, both for the cut-off batch: the original and its one retry with
    // the larger budget. No later batch was started.
    expect(h.calls).toHaveLength(2);
    expect(h.calls.map((c) => c.body.max_tokens)).toEqual([12_000, 21_333]);
    expect(h.calls.every((c) => c.elementIds.includes("svc-01"))).toBe(true);
    const entries = h.ledger.forAnalysis("test-analysis").calls;
    expect(entries).toHaveLength(2);
    expect(entries.map((e) => e.outputTokens)).toEqual([12_000, 21_333]);
    expect(entries.every((e) => e.stopReason === "max_tokens")).toBe(true);
  });

  it("keeps a batch whose reply was cut off once, when the larger retry completes it", async () => {
    const h = harness((ids) => good(ids));
    const inner = h.deps.client!;
    let cut = false;
    h.deps.client = {
      async create(body, options) {
        const response = await inner.create(body, options);
        if (!cut && elementsIn(body).includes("svc-01")) {
          cut = true;
          return { ...response, stop_reason: "max_tokens" };
        }
        return response;
      },
    };
    const result = await run(h, arch(["svc-01", "svc-02"]), { concurrency: 1 });
    expect(result.threats.length).toBeGreaterThan(0);
    const svc01Calls = h.calls.filter((c) => c.elementIds.includes("svc-01"));
    expect(svc01Calls.map((c) => c.body.max_tokens)).toEqual([12_000, 21_333]);
  });

  it("runs exactly the batches it is given, for a one-call smoke test", async () => {
    const h = harness((ids) => good(ids));
    const result = await generateThreats({
      architecture: five.architecture,
      gaps: five.gaps,
      files: files(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"]),
      analysisId: "smoke",
      deps: h.deps,
      batches: [["svc-02", "svc-04"]],
    });
    expect(h.calls).toHaveLength(1);
    expect(h.calls[0].elementIds).toEqual(["svc-02", "svc-04"]);
    expect(result.batches).toEqual([{ index: 0, elementIds: ["svc-02", "svc-04"], returned: 1 }]);
  });

  it("returns an empty result without calling the model for an empty architecture", async () => {
    const h = harness(() => ({ threats: [] }));
    const result = await run(h, arch([]));
    expect(h.calls).toHaveLength(0);
    expect(result.threats).toEqual([]);
    expect(result.batches).toEqual([]);
  });

  it("returns usage per successful call and the prompt id", async () => {
    const h = harness(() => ({ threats: [] }));
    const result = await run(h, five);
    expect(result.usage).toHaveLength(3);
    expect(result.usage.every((u) => u.stage === "stride")).toBe(true);
    expect(result.promptId).toBe("threats.v2");
  });
});

describe("no live network", () => {
  it("never calls fetch, and every model call goes through the injected client", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network is off"));
    const h = harness(() => ({ threats: [] }));
    await run(h, arch(Array.from({ length: 9 }, (_, i) => `svc-${i + 1}`)));
    expect(h.calls.length).toBeGreaterThan(0);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("sends no credential to the model: sentinels in architecture and evidence text are redacted first", async () => {
    const SHORT = "Zq7Kp1";
    const LONG = "sentinel-signing-key-0042";
    const a = arch(["svc-01"], [], "svc-01");
    a.architecture.components[0].description = `db config PASSWORD: "${SHORT}"`;
    a.architecture.components[0].assets = [`jwt secret: "${LONG}"`];
    a.architecture.evidence[0].summary = `apiKey=\`${LONG}\` in source`;
    a.gaps[0].control = `token = "${SHORT}"`;
    const h = harness(() => ({ threats: [] }));
    await run(h, a);

    expect(h.calls).toHaveLength(1);
    const request = JSON.stringify(h.calls[0].body);
    expect(request).not.toContain(SHORT);
    expect(request).not.toContain(LONG);
    expect(h.calls[0].body.messages[0].content as string).toContain("[REDACTED:generic_secret]");
    // The trusted system prompt is exactly the prompt file, untouched.
    const system = h.calls[0].body.system as { text: string }[];
    const file = readFileSync("prompts/threats.v2.md", "utf8");
    expect(system[0].text).toBe(`${SECURITY_PREAMBLE}${file}`);
  });

  it("fails closed on a credential-shaped path: no request is made and the error names no value", async () => {
    const a = arch(["svc-01", "svc-02"]);
    a.architecture.components[0].files = ["src/AKIAZZTHREATZZ000001.ts"];
    const h = harness(() => ({ threats: [] }));
    const error = (await run(h, a).catch((e: unknown) => e)) as Error;
    expect(error.name).toBe("SecretLeakError");
    expect(error.message).not.toContain("AKIAZZ");
    expect(h.calls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// shouldContinue: no new provider request once the pipeline says stop
// ---------------------------------------------------------------------------

describe("runPool, shouldStart", () => {
  it("starts no task once shouldStart returns false, lets running ones finish, then throws PoolStoppedError", async () => {
    const gates = [deferred(), deferred(), deferred(), deferred(), deferred()];
    const started: number[] = [];
    let go = true;
    const promise = runPool(
      [0, 1, 2, 3, 4],
      2,
      async (i) => {
        started.push(i);
        await gates[i].promise;
        return i;
      },
      () => go,
    );
    await tick();
    expect(started).toEqual([0, 1]);

    go = false;
    gates[0].resolve();
    gates[1].resolve();
    const error = await promise.catch((e: unknown) => e);

    expect(started).toEqual([0, 1]); // both running tasks finished; no replacement began
    expect(error).toBeInstanceOf(PoolStoppedError);
    expect((error as PoolStoppedError).started).toBe(2);
    expect((error as PoolStoppedError).total).toBe(5);
  });

  it("defaults to always continuing", async () => {
    expect(await runPool([0, 1, 2], 2, async (i) => i)).toEqual([0, 1, 2]);
  });
});

describe("generateThreats, shouldContinue", () => {
  const FIVE_BATCHES = ["svc-01", "svc-02", "svc-03", "svc-04", "svc-05", "svc-06", "svc-07", "svc-08", "svc-09", "svc-10"];

  it("makes no provider request at all when shouldContinue is already false (cancelled job)", async () => {
    const h = harness(() => ({ threats: [] }));

    const error = await run(h, arch(FIVE_BATCHES), { shouldContinue: () => false }).catch(
      (e: unknown) => e,
    );

    expect(h.calls).toHaveLength(0);
    expect(error).toBeInstanceOf(AiError);
    expect((error as AiError).code).toBe("TIMEOUT");
  });

  it("when it turns false mid-pool: every not-yet-started batch is skipped, running ones finish, no replacement starts", async () => {
    const release = deferred();
    const h = harness(
      () => ({ threats: [] }),
      () => release.promise,
    );
    let go = true;

    const promise = run(h, arch(FIVE_BATCHES), { concurrency: 3, shouldContinue: () => go });
    await vi.waitFor(() => expect(h.calls).toHaveLength(3)); // round 1 in flight
    go = false; // the deadline fires
    release.resolve();
    const error = await promise.catch((e: unknown) => e);

    expect(h.calls).toHaveLength(3); // batches 4 and 5 never reached the client
    expect(h.maxInflight()).toBe(3);
    expect(error).toBeInstanceOf(AiError);
    expect((error as AiError).code).toBe("TIMEOUT");
    expect((error as AiError).message).toContain("stopped before all batches started");
  });

  it("returns no partial threat list when stopped, even though finished batches returned threats", async () => {
    const h = harness((elementIds) => ({
      threats: [threat({ componentIds: [elementIds[0]], evidenceIds: [`ev-${elementIds[0]}`] })],
    }));
    let started = 0;

    const outcome = await run(h, arch(FIVE_BATCHES), {
      concurrency: 1,
      shouldContinue: () => started++ < 2,
    }).then(
      (result) => ({ result }),
      (error: unknown) => ({ error }),
    );

    expect(h.calls).toHaveLength(2);
    expect(outcome).not.toHaveProperty("result");
    expect((outcome as { error: AiError }).error.code).toBe("TIMEOUT");
  });

  it("is checked before every batch and changes nothing when it stays true", async () => {
    const h = harness(() => ({ threats: [] }));
    let checks = 0;

    await run(h, arch(FIVE_BATCHES), {
      concurrency: 3,
      shouldContinue: () => {
        checks++;
        return true;
      },
    });

    expect(h.calls).toHaveLength(5);
    expect(checks).toBeGreaterThanOrEqual(5);
  });
});

describe("generateThreats, per-batch dump names", () => {
  it("gives each batch its own development dump, so none overwrites another", async () => {
    const files: string[] = [];
    const h = harness(() => ({ threats: [] }));
    const deps = { ...h.deps, isDevelopment: true, writeDebug: (_id: string, file: string) => files.push(file) };

    await generateThreats({
      architecture: arch(["svc-01", "svc-02", "svc-03", "svc-04", "svc-05"]).architecture,
      gaps: [],
      files: [],
      analysisId: "test-analysis",
      deps,
    });

    expect([...files].sort()).toEqual([
      "stride.b00.attempt-1.txt",
      "stride.b01.attempt-1.txt",
      "stride.b02.attempt-1.txt",
    ]);
  });
});

describe("isPlaceholderAssumption", () => {
  it.each(["N/A", "n/a.", "none", "TBD", "see above", "---", "...", "duplicate placeholder, removed", "placeholder", "", "  "])(
    "treats %j as a placeholder",
    (text) => expect(isPlaceholderAssumption(text)).toBe(true),
  );

  it.each([
    "the Worker is deployed with ALLOWED_ORIGINS unset",
    "The Firebase config in firebase-config.js is assumed to hold a placeholder API key, not the production one",
    "unknown callers can reach /api/chat",
    "no rate limiting is applied in front of the Worker",
  ])("keeps %j", (text) => expect(isPlaceholderAssumption(text)).toBe(false));
});
