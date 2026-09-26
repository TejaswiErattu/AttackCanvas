/**
 * findingStatus: pure, storage-injected triage statuses. Plain Node, no DOM.
 */

import { describe, expect, it } from "vitest";
import {
  loadStatuses,
  orderByStatus,
  setStatus,
  splitFullName,
  statusStorageKey,
  summarise,
  type StatusStorage,
} from "@/client/findingStatus";
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
