/**
 * runHistory: the ring of the last runs of a repository, the one-time migration from the
 * old last/prev snapshots, the size cap, and what the History tab reads. Plain Node.
 */

import { describe, expect, it } from "vitest";
import { lastRunKey, prevRunKey, threatKey, type DriftModel } from "@/client/drift";
import {
  MAX_ENTRY_BYTES,
  MAX_RUNS,
  capEntry,
  formatRunTime,
  historyRows,
  levelLabel,
  migrateLegacyRuns,
  readHistory,
  readRuns,
  recordRun,
  recordStatusChange,
  runsKey,
  threatTimeline,
  threatsAcrossRuns,
  toRunEntry,
  type RunStorage,
} from "@/client/runHistory";
import type { ThreatCardData } from "@/shared/viewModel";

type Store = RunStorage & { data: Record<string, string>; removed: string[] };

function memoryStorage(withRemove = true): Store {
  const data: Record<string, string> = {};
  const removed: string[] = [];
  return {
    data,
    removed,
    getItem: (k) => (k in data ? data[k] : null),
    setItem: (k, v) => {
      data[k] = v;
    },
    ...(withRemove
      ? {
          removeItem: (k: string) => {
            removed.push(k);
            delete data[k];
          },
        }
      : {}),
  };
}

function threat(title: string, confidence = 60, components = ["API"]): ThreatCardData {
  return {
    id: `id-${title}`,
    title,
    componentNames: components,
    severity: "high",
    confidence,
    owasp: [{ code: "A01:2025", label: "A01:2025" }],
  } as unknown as ThreatCardData;
}

/** A run of the dashboard: `visible` threats at their confidence, `hidden` ones below 25%. */
function run(
  n: number,
  visible: ThreatCardData[],
  hidden: ThreatCardData[] = [],
  ref = "main",
): DriftModel & { analysisLevel: number } {
  return {
    nodes: [],
    edges: [],
    threats: visible,
    hiddenThreats: hidden,
    repo: { ref, analyzedAt: `2026-09-0${n}T10:00:00.000Z` },
    analysisLevel: 2,
  };
}

const SQLI = threat("SQL injection in login");
const COOKIE = threat("Weak session cookie");
const REDIRECT = threat("Open redirect");

describe("recordRun", () => {
  it("has no previous run the first time, and stores one entry", () => {
    const storage = memoryStorage();
    const { runs, previous } = recordRun(storage, "acme", "shop", run(1, [SQLI, COOKIE]));
    expect(previous).toBeNull();
    expect(runs).toHaveLength(1);
    const stored = JSON.parse(storage.data[runsKey("acme", "shop")]);
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ at: "2026-09-01T10:00:00.000Z", ref: "main", level: 2 });
    expect(stored[0].threats.map((t: { key: string }) => t.key)).toEqual([
      threatKey(SQLI),
      threatKey(COOKIE),
    ]);
  });

  it("keeps each threat's identity and confidence, and marks the ones below 25%", () => {
    const quiet = threat("Quiet", 10);
    const { runs } = recordRun(memoryStorage(), "acme", "shop", run(1, [SQLI], [quiet]));
    expect(runs[0].threats).toEqual([
      expect.objectContaining({ key: threatKey(SQLI), confidence: 60, hidden: false }),
      expect.objectContaining({ key: threatKey(quiet), confidence: 10, hidden: true }),
    ]);
  });

  it("returns the run before as `previous` and keeps oldest first", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", run(1, [SQLI]));
    const { runs, previous } = recordRun(storage, "acme", "shop", run(2, [SQLI, COOKIE]));
    expect(previous?.at).toBe("2026-09-01T10:00:00.000Z");
    expect(runs.map((r) => r.at)).toEqual(["2026-09-01T10:00:00.000Z", "2026-09-02T10:00:00.000Z"]);
  });

  it("evicts the oldest run when a sixth is recorded", () => {
    const storage = memoryStorage();
    for (let n = 1; n <= 6; n += 1) recordRun(storage, "acme", "shop", run(n, [SQLI]));
    const stored = readRuns(storage, "acme", "shop");
    expect(MAX_RUNS).toBe(5);
    expect(stored).toHaveLength(5);
    expect(stored.map((r) => r.at.slice(0, 10))).toEqual([
      "2026-09-02",
      "2026-09-03",
      "2026-09-04",
      "2026-09-05",
      "2026-09-06",
    ]);
  });

  it("does not add the same run again on a reload", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", run(1, [SQLI]));
    recordRun(storage, "acme", "shop", run(2, [SQLI]));
    const again = recordRun(storage, "acme", "shop", run(2, [SQLI]));
    expect(again.runs).toHaveLength(2);
    expect(again.previous?.at).toBe("2026-09-01T10:00:00.000Z");
    expect(readRuns(storage, "acme", "shop")).toHaveLength(2);
  });

  it("keeps repositories apart", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", run(1, [SQLI]));
    expect(recordRun(storage, "acme", "other", run(2, [SQLI])).previous).toBeNull();
  });

  it("still returns the right runs when storage throws, is missing or holds junk", () => {
    const throwing: RunStorage = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("quota");
      },
    };
    expect(recordRun(throwing, "acme", "shop", run(1, [SQLI])).runs).toHaveLength(1);
    expect(recordRun(null, "acme", "shop", run(1, [SQLI])).previous).toBeNull();
    const junk = memoryStorage();
    junk.data[runsKey("acme", "shop")] = "{not json";
    const result = recordRun(junk, "acme", "shop", run(1, [SQLI]));
    expect(result.runs).toHaveLength(1);
    expect(readRuns(junk, "acme", "shop")).toHaveLength(1);
  });

  it("drops stored entries that are malformed and keeps the good ones", () => {
    const storage = memoryStorage();
    const good = toRunEntry(run(1, [SQLI]));
    storage.data[runsKey("acme", "shop")] = JSON.stringify([{ at: 5 }, good, "x", null]);
    expect(readRuns(storage, "acme", "shop")).toEqual([good]);
  });
});

describe("migrateLegacyRuns", () => {
  function legacyStore(withRemove = true): Store {
    const storage = memoryStorage(withRemove);
    storage.data[prevRunKey("acme", "shop")] = JSON.stringify(run(1, [SQLI, COOKIE]));
    storage.data[lastRunKey("acme", "shop")] = JSON.stringify(run(2, [SQLI]));
    return storage;
  }

  it("turns prev and last into entries, oldest first, and removes the old keys", () => {
    const storage = legacyStore();
    const migrated = migrateLegacyRuns(storage, "acme", "shop");
    expect(migrated?.map((r) => r.at.slice(0, 10))).toEqual(["2026-09-01", "2026-09-02"]);
    expect(readRuns(storage, "acme", "shop")).toHaveLength(2);
    expect(storage.data[prevRunKey("acme", "shop")]).toBeUndefined();
    expect(storage.data[lastRunKey("acme", "shop")]).toBeUndefined();
  });

  it("runs once: a second call changes nothing, even when the old keys are back", () => {
    const storage = legacyStore();
    migrateLegacyRuns(storage, "acme", "shop");
    const after = storage.data[runsKey("acme", "shop")];
    storage.data[lastRunKey("acme", "shop")] = JSON.stringify(run(5, [REDIRECT]));
    expect(migrateLegacyRuns(storage, "acme", "shop")).toBeNull();
    expect(storage.data[runsKey("acme", "shop")]).toBe(after);
  });

  it("runs once even when the storage cannot remove keys", () => {
    const storage = legacyStore(false);
    expect(migrateLegacyRuns(storage, "acme", "shop")).toHaveLength(2);
    expect(storage.data[lastRunKey("acme", "shop")]).toBeDefined();
    expect(migrateLegacyRuns(storage, "acme", "shop")).toBeNull();
    expect(readRuns(storage, "acme", "shop")).toHaveLength(2);
  });

  it("is done by recordRun, which then compares with the migrated last run", () => {
    const storage = legacyStore();
    const { runs, previous } = recordRun(storage, "acme", "shop", run(3, [SQLI, REDIRECT]));
    expect(previous?.at).toBe("2026-09-02T10:00:00.000Z");
    expect(runs).toHaveLength(3);
    expect(readRuns(storage, "acme", "shop")).toHaveLength(3);
  });

  it("does nothing when there is nothing to migrate, and ignores junk snapshots", () => {
    const storage = memoryStorage();
    expect(migrateLegacyRuns(storage, "acme", "shop")).toBeNull();
    storage.data[lastRunKey("acme", "shop")] = "{not json";
    expect(migrateLegacyRuns(storage, "acme", "shop")).toBeNull();
    expect(storage.data[runsKey("acme", "shop")]).toBeUndefined();
  });

  it("records a migrated run's missing level as unknown", () => {
    const storage = memoryStorage();
    const noLevel: Partial<ReturnType<typeof run>> = run(1, [SQLI]);
    delete noLevel.analysisLevel;
    storage.data[lastRunKey("acme", "shop")] = JSON.stringify(noLevel);
    expect(migrateLegacyRuns(storage, "acme", "shop")?.[0].level).toBeNull();
  });
});

describe("the 200 KB cap", () => {
  const big = (n: number) =>
    run(1, Array.from({ length: n }, (_, i) => threat(`Threat ${i} ${"x".repeat(900)}`, 40 + (i % 50))));

  it("stores an entry over the cap without its per-threat confidences", () => {
    const entry = toRunEntry(big(400));
    expect(JSON.stringify(entry).length).toBeGreaterThan(MAX_ENTRY_BYTES);
    const capped = capEntry(entry);
    expect(capped.threats).toHaveLength(400);
    expect(capped.threats.every((t) => !("confidence" in t))).toBe(true);
    expect(capped.threats[0]).toMatchObject({ key: entry.threats[0].key, title: entry.threats[0].title });
  });

  it("leaves an entry under the cap whole", () => {
    const entry = toRunEntry(run(1, [SQLI, COOKIE]));
    expect(capEntry(entry)).toBe(entry);
  });

  it("applies when recording, and the capped run still compares and reads back", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", big(400));
    const stored = readRuns(storage, "acme", "shop");
    expect(stored[0].threats.every((t) => t.confidence === undefined)).toBe(true);
    const { previous } = recordRun(storage, "acme", "shop", {
      ...big(400),
      repo: { ref: "main", analyzedAt: "2026-09-02T10:00:00.000Z" },
    });
    expect(previous?.threats).toHaveLength(400);
  });

  it("shows no confidence for a capped run in the timeline", () => {
    const runs = [capEntry(toRunEntry(big(400)))];
    const key = runs[0].threats[0].key;
    expect(threatTimeline(runs, key)[0]).toMatchObject({ found: true, confidence: null });
  });
});

describe("historyRows", () => {
  const runs = [
    toRunEntry(run(1, [SQLI, COOKIE], [threat("Quiet", 10)])),
    toRunEntry(run(2, [SQLI, REDIRECT])),
    toRunEntry(run(3, [SQLI, REDIRECT, COOKIE])),
  ];

  it("lists one row per run, newest first, with counts against the run before", () => {
    const rows = historyRows(runs);
    expect(rows.map((r) => r.run.at.slice(0, 10))).toEqual(["2026-09-03", "2026-09-02", "2026-09-01"]);
    expect(rows.map((r) => [r.threats, r.visible, r.newCount, r.notFoundCount])).toEqual([
      [3, 3, 1, 0],
      [2, 2, 1, 2],
      [3, 2, null, null],
    ]);
  });

  it("counts a threat as new again after it was not found, and as not found when it was only below 25%", () => {
    // COOKIE was absent in run 2 and is back in run 3 (new); Quiet vanished after run 1.
    const rows = historyRows(runs);
    expect(rows[0].newCount).toBe(1);
    expect(rows[1].notFoundCount).toBe(2);
  });
});

describe("threatTimeline", () => {
  const runs = [
    toRunEntry(run(1, [SQLI, COOKIE])),
    toRunEntry(run(2, [threat("SQL injection in login", 72), REDIRECT])),
    toRunEntry(run(3, [REDIRECT])),
    toRunEntry(run(4, [threat("SQL injection in login", 35)])),
  ];

  it("shows a threat present in runs 1, 2 and 4 with a gap at 3", () => {
    const steps = threatTimeline(runs, threatKey(SQLI));
    expect(steps.map((s) => s.found)).toEqual([true, true, false, true]);
    expect(steps.map((s) => s.confidence)).toEqual([60, 72, null, 35]);
    expect(steps[2].run.at).toBe("2026-09-03T10:00:00.000Z");
  });

  it("marks a run where the threat was below 25% as hidden, not as a gap", () => {
    const withHidden = [toRunEntry(run(1, [], [threat("Quiet", 12)]))];
    expect(threatTimeline(withHidden, threatKey(threat("Quiet")))[0]).toMatchObject({
      found: true,
      hidden: true,
      confidence: 12,
    });
  });

  it("lists every threat seen in any run, newest run's first", () => {
    expect(threatsAcrossRuns(runs).map((t) => t.title)).toEqual([
      "SQL injection in login",
      "Open redirect",
      "Weak session cookie",
    ]);
  });
});

describe("recordStatusChange", () => {
  it("logs the change on the run on screen, and the timeline shows it for that threat only", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", run(1, [SQLI, COOKIE]));
    const { runs } = recordRun(storage, "acme", "shop", run(2, [SQLI, COOKIE]));
    const at = runs[1].at;
    const after = recordStatusChange(storage, "acme", "shop", runs, at, {
      key: threatKey(SQLI),
      status: "fixed",
      at: "2026-09-10T08:00:00.000Z",
    });
    expect(after[0].statusChanges).toBeUndefined();
    expect(threatTimeline(after, threatKey(SQLI))[1].statusChanges).toEqual([
      { key: threatKey(SQLI), status: "fixed", at: "2026-09-10T08:00:00.000Z" },
    ]);
    expect(threatTimeline(after, threatKey(COOKIE))[1].statusChanges).toEqual([]);
    expect(readRuns(storage, "acme", "shop")[1].statusChanges).toHaveLength(1);
  });

  it("ignores a run that is in neither the store nor the caller's ring, and survives broken storage", () => {
    const storage = memoryStorage();
    const { runs } = recordRun(storage, "acme", "shop", run(1, [SQLI]));
    const change = { key: "k", status: "fixed" as const, at: "2026-09-10T08:00:00.000Z" };
    const same = recordStatusChange(storage, "acme", "shop", runs, "nope", change);
    expect(same).toEqual(runs);
    expect(same[0].statusChanges).toBeUndefined();
    expect(recordStatusChange(null, "acme", "shop", [], "x", change)).toEqual([]);
  });

  it("keeps the run on screen and logs the change when an earlier save failed", () => {
    // The ring never reached storage (quota), so the caller's copy is the only one with run 2.
    const failing: RunStorage = { getItem: () => null, setItem: () => { throw new Error("quota"); } };
    const { runs } = recordRun(failing, "acme", "shop", run(2, [SQLI]));
    const after = recordStatusChange(failing, "acme", "shop", runs, runs[0].at, {
      key: threatKey(SQLI),
      status: "accepted_risk",
      at: "2026-09-10T08:00:00.000Z",
    });
    expect(after).toHaveLength(1);
    expect(after[0].at).toBe(runs[0].at);
    expect(after[0].statusChanges).toHaveLength(1);
  });

  it("does not replace the caller's ring with a stale stored one", () => {
    const storage = memoryStorage();
    recordRun(storage, "acme", "shop", run(1, [SQLI]));
    const inMemory = [...readRuns(storage, "acme", "shop"), toRunEntry(run(2, [SQLI]))];
    const after = recordStatusChange(storage, "acme", "shop", inMemory, inMemory[1].at, {
      key: threatKey(SQLI),
      status: "fixed",
      at: "2026-09-10T08:00:00.000Z",
    });
    expect(after.map((r) => r.at.slice(0, 10))).toEqual(["2026-09-01", "2026-09-02"]);
    expect(after[1].statusChanges).toHaveLength(1);
  });
});

describe("readHistory (what a replayed result is shown against)", () => {
  function seeded(): Store {
    const storage = memoryStorage();
    for (let n = 1; n <= 5; n += 1) recordRun(storage, "acme", "shop", run(n, [SQLI]));
    return storage;
  }

  it("never adds a run, however many times it is called, and never evicts one", () => {
    const storage = seeded();
    const before = storage.data[runsKey("acme", "shop")];
    for (let i = 0; i < 4; i += 1) readHistory(storage, "acme", "shop", run(6, [SQLI, COOKIE]));
    expect(storage.data[runsKey("acme", "shop")]).toBe(before);
    expect(readRuns(storage, "acme", "shop")).toHaveLength(5);
  });

  it("compares the replay with the latest stored run", () => {
    const { runs, previous } = readHistory(seeded(), "acme", "shop", run(6, [SQLI]));
    expect(runs).toHaveLength(5);
    expect(previous?.at).toBe("2026-09-05T10:00:00.000Z");
  });

  it("skips the stored copy of the replayed run itself when choosing `previous`", () => {
    const { previous } = readHistory(seeded(), "acme", "shop", run(5, [SQLI]));
    expect(previous?.at).toBe("2026-09-04T10:00:00.000Z");
  });

  it("has no previous run and writes nothing when there is no history", () => {
    const storage = memoryStorage();
    expect(readHistory(storage, "acme", "shop", run(1, [SQLI]))).toEqual({ runs: [], previous: null });
    expect(storage.data[runsKey("acme", "shop")]).toBeUndefined();
  });

  it("still migrates the old snapshots, which are existing history, and survives broken storage", () => {
    const storage = memoryStorage();
    storage.data[lastRunKey("acme", "shop")] = JSON.stringify(run(2, [SQLI]));
    expect(readHistory(storage, "acme", "shop", run(9, [SQLI])).runs).toHaveLength(1);
    const throwing: RunStorage = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("quota");
      },
    };
    expect(readHistory(throwing, "acme", "shop", run(1, [SQLI]))).toEqual({ runs: [], previous: null });
    expect(readHistory(null, "acme", "shop", run(1, [SQLI]))).toEqual({ runs: [], previous: null });
  });
});

describe("formatting", () => {
  it("formats a run time without a locale, and passes through what is not a time", () => {
    expect(formatRunTime("2026-09-12T14:03:55.000Z")).toBe("2026-09-12 14:03 UTC");
    expect(formatRunTime("")).toBe("unknown time");
    expect(formatRunTime("yesterday")).toBe("yesterday");
  });

  it("names a level, and says unknown for a migrated run", () => {
    expect(levelLabel(2)).not.toBe("Unknown");
    expect(levelLabel(null)).toBe("Unknown");
  });
});
