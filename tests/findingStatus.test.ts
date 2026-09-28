/**
 * findingStatus: pure, storage-injected triage statuses. Plain Node, no DOM.
 */

import { describe, expect, it } from "vitest";
import {
  isThreatKeyEntry,
  loadStatuses,
  migrateStatuses,
  orderByStatus,
  setStatus,
  splitFullName,
  statusesById,
  statusStorageKey,
  summarise,
  type StatusStorage,
} from "@/client/findingStatus";
import { threatKey } from "@/client/drift";
import { EMPTY_FILTERS, filterThreats, hasActiveFilters } from "@/client/filterThreats";
import type { Priority } from "@/shared/schema";
import type { ThreatCardData } from "@/shared/viewModel";

function memoryStorage(initial: Record<string, string> = {}): StatusStorage & {
  data: Record<string, string>;
} {
  const data = { ...initial };
  return {
    data,
    getItem: (key) => (key in data ? data[key] : null),
    setItem: (key, value) => {
      data[key] = value;
    },
  };
}

const throwing: StatusStorage = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => {
    throw new Error("quota");
  },
};

const KEY = statusStorageKey("acme", "shop", "main");

function t(id: string, priority: Priority): ThreatCardData {
  return { id, priority } as ThreatCardData;
}

describe("statusStorageKey", () => {
  it("uses the documented format", () => {
    expect(KEY).toBe("attackcanvas:status:acme/shop@main");
  });
  it("splits a full name", () => {
    expect(splitFullName("acme/shop")).toEqual({ owner: "acme", repo: "shop" });
    expect(splitFullName("nonsense")).toBeNull();
  });
});

describe("loadStatuses / setStatus", () => {
  it("defaults to empty (everything open)", () => {
    expect(loadStatuses(memoryStorage(), KEY)).toEqual({});
  });

  it("round-trips a status", () => {
    const storage = memoryStorage();
    const next = setStatus(storage, KEY, {}, "t1", "fixed");
    expect(next).toEqual({ t1: "fixed" });
    expect(loadStatuses(storage, KEY)).toEqual({ t1: "fixed" });
    expect(JSON.parse(storage.data[KEY])).toEqual({ t1: "fixed" });
  });

  it("does not store open; setting open removes the entry", () => {
    const storage = memoryStorage();
    const fixed = setStatus(storage, KEY, {}, "t1", "fixed");
    const reopened = setStatus(storage, KEY, fixed, "t1", "open");
    expect(reopened).toEqual({});
    expect(loadStatuses(storage, KEY)).toEqual({});
  });

  it("does not mutate the map it is given", () => {
    const current = Object.freeze({ t1: "fixed" as const });
    expect(() => setStatus(memoryStorage(), KEY, current, "t2", "accepted_risk")).not.toThrow();
  });

  it("ignores malformed or unknown saved data", () => {
    expect(loadStatuses(memoryStorage({ [KEY]: "not json" }), KEY)).toEqual({});
    expect(loadStatuses(memoryStorage({ [KEY]: "[1,2]" }), KEY)).toEqual({});
    expect(
      loadStatuses(memoryStorage({ [KEY]: '{"a":"fixed","b":"nope","c":"open"}' }), KEY),
    ).toEqual({ a: "fixed" });
  });

  it("survives storage that throws, keeping the in-memory choice", () => {
    expect(loadStatuses(throwing, KEY)).toEqual({});
    expect(setStatus(throwing, KEY, {}, "t1", "false_positive")).toEqual({ t1: "false_positive" });
    expect(loadStatuses(null, KEY)).toEqual({});
    expect(setStatus(null, KEY, {}, "t1", "fixed")).toEqual({ t1: "fixed" });
  });
});

describe("summarise", () => {
  it("counts by status, treating missing ids as open", () => {
    const counts = summarise(["a", "b", "c", "d"], { a: "fixed", b: "fixed", c: "accepted_risk" });
    expect(counts).toEqual({ open: 1, fixed: 2, accepted_risk: 1, false_positive: 0 });
  });
  it("ignores saved statuses for threats no longer listed", () => {
    expect(summarise(["a"], { gone: "fixed" })).toEqual({
      open: 1,
      fixed: 0,
      accepted_risk: 0,
      false_positive: 0,
    });
  });
});

describe("orderByStatus", () => {
  const threats = [
    t("a", "fix_now"),
    t("b", "fix_now"),
    t("c", "fix_now"),
    t("d", "fix_soon"),
    t("e", "fix_soon"),
    t("f", "monitor"),
  ];

  it("returns the server order when nothing is handled", () => {
    expect(orderByStatus(threats, {}).map((x) => x.id)).toEqual(["a", "b", "c", "d", "e", "f"]);
  });

  it("moves handled threats after open ones inside their own band only", () => {
    const statuses = { a: "fixed", d: "false_positive", e: "accepted_risk" } as const;
    expect(orderByStatus(threats, statuses).map((x) => x.id)).toEqual([
      "b",
      "c",
      "a",
      "d",
      "e",
      "f",
    ]);
  });

  it("keeps server order within each group and does not mutate", () => {
    const frozen = Object.freeze([...threats]);
    const out = orderByStatus(frozen, { b: "fixed", a: "fixed" });
    expect(out.map((x) => x.id).slice(0, 3)).toEqual(["c", "a", "b"]);
  });
});

describe("status facet in filterThreats", () => {
  const list = [t("a", "fix_now"), t("b", "fix_now")].map(
    (x) => ({ ...x, severity: "high", stride: [], owasp: [], componentIds: [] }) as unknown as ThreatCardData,
  );

  it("treats an empty selection as no constraint", () => {
    expect(filterThreats(list, EMPTY_FILTERS, { a: "fixed" })).toHaveLength(2);
  });

  it("filters by status, with open covering threats that have no saved status", () => {
    const statuses = { a: "fixed" } as const;
    expect(filterThreats(list, { ...EMPTY_FILTERS, statuses: ["fixed"] }, statuses).map((x) => x.id)).toEqual(["a"]);
    expect(filterThreats(list, { ...EMPTY_FILTERS, statuses: ["open"] }, statuses).map((x) => x.id)).toEqual(["b"]);
  });

  it("counts the status facet as an active filter", () => {
    expect(hasActiveFilters({ ...EMPTY_FILTERS, statuses: ["fixed"] })).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Keyed by threatKey across runs
// ---------------------------------------------------------------------------

function card(id: string, title: string, components: string[], owasp: string[]): ThreatCardData {
  return {
    id,
    title,
    componentNames: components,
    owasp: owasp.map((code) => ({ code, label: code })),
  } as unknown as ThreatCardData;
}

describe("threatKey stability", () => {
  it("is the same for the same threat under a new id, title case and component order", () => {
    const a = card("threat-1", "SQL injection in login", ["API", "DB"], ["A05:2025"]);
    const b = card("threat-7", "  sql Injection in login!", ["DB", "API"], ["A05:2025"]);
    expect(threatKey(a)).toBe(threatKey(b));
  });

  it("differs when the components or OWASP codes differ", () => {
    const a = card("threat-1", "Same", ["API"], ["A05:2025"]);
    expect(threatKey(card("x", "Same", ["Worker"], ["A05:2025"]))).not.toBe(threatKey(a));
    expect(threatKey(card("x", "Same", ["API"], ["A01:2025"]))).not.toBe(threatKey(a));
  });

  it("marks key entries apart from legacy id entries", () => {
    expect(isThreatKeyEntry(threatKey(card("t", "X", [], [])))).toBe(true);
    expect(isThreatKeyEntry("threat-3")).toBe(false);
    expect(isThreatKeyEntry("[not json")).toBe(false);
  });
});

describe("statusesById", () => {
  it("lets a Fixed status follow the same threat to the next run under a new id", () => {
    const run1 = card("threat-1", "Weak cookie", ["API"], ["A07:2025"]);
    const storage = memoryStorage();
    const saved = setStatus(storage, KEY, {}, threatKey(run1), "fixed");
    const run2 = [
      card("threat-1", "Open redirect", ["API"], ["A01:2025"]),
      card("threat-2", "Weak cookie", ["API"], ["A07:2025"]),
    ];
    const reloaded = loadStatuses(storage, KEY);
    expect(reloaded).toEqual(saved);
    expect(statusesById(run2, reloaded)).toEqual({ "threat-2": "fixed" });
  });
});

describe("migrateStatuses", () => {
  const savedOn = {
    threats: [card("threat-1", "Weak cookie", ["API"], ["A07:2025"])],
    hiddenThreats: [card("threat-2", "Quiet one", ["API"], ["A01:2025"])],
  };

  it("rewrites id entries to threatKey entries using the run they were saved on", () => {
    const { statuses, changed } = migrateStatuses(
      { "threat-1": "fixed", "threat-2": "false_positive" },
      savedOn,
    );
    expect(changed).toBe(true);
    expect(statuses).toEqual({
      [threatKey(savedOn.threats[0])]: "fixed",
      [threatKey(savedOn.hiddenThreats[0])]: "false_positive",
    });
  });

  it("drops id entries the saved run does not have, and keeps existing key entries", () => {
    const existing = threatKey(card("x", "Other", ["API"], []));
    const { statuses } = migrateStatuses(
      { "threat-9": "fixed", [existing]: "accepted_risk" },
      savedOn,
    );
    expect(statuses).toEqual({ [existing]: "accepted_risk" });
  });

  it("lets an existing key entry win over a migrated one", () => {
    const key = threatKey(savedOn.threats[0]);
    const { statuses } = migrateStatuses({ "threat-1": "fixed", [key]: "accepted_risk" }, savedOn);
    expect(statuses).toEqual({ [key]: "accepted_risk" });
  });

  it("runs once: a migrated map has nothing left to migrate", () => {
    const first = migrateStatuses({ "threat-1": "fixed" }, savedOn);
    const second = migrateStatuses(first.statuses, null);
    expect(second.changed).toBe(false);
    expect(second.statuses).toBe(first.statuses);
  });

  it("drops every id entry when there is no saved run to read them against", () => {
    expect(migrateStatuses({ "threat-1": "fixed" }, null)).toEqual({ statuses: {}, changed: true });
  });
});
