/**
 * The last few analyses of a repository, kept in this browser: what the "Since last run"
 * panel compares against and what its History tab lists.
 *
 * A ring of at most MAX_RUNS entries lives under attackcanvas:runs:<owner>/<repo>, oldest
 * first. An entry holds the run's time, ref and level and, for every scored threat, its
 * identity (threatKey, src/client/drift.ts) and the confidence it was given. It does not
 * hold the diagram: only threats are compared across runs. An entry over MAX_ENTRY_BYTES is
 * stored without the per-threat confidences, which are the part that grows with the run.
 *
 * Before this the browser kept two full snapshots under attackcanvas:last:<owner>/<repo>
 * and attackcanvas:prev:<owner>/<repo>. migrateLegacyRuns() turns them into entries once:
 * the runs key existing at all means it has happened, so it never runs again, and the old
 * keys are removed when the storage can remove them.
 *
 * A status the reader sets is not a property of a run, but the History timeline shows when
 * it changed, so each change is logged on the entry for the run being viewed
 * (recordStatusChange). The statuses themselves stay in src/client/findingStatus.ts.
 *
 * Pure and DOM-free. Storage is injected and every access is wrapped: a blocked, full or
 * corrupt store never breaks the dashboard, it only means less history. Nothing is sent to
 * a server.
 */

import { ANALYSIS_LEVEL_LABELS, type Severity } from "@/shared/schema";
import {
  allThreatRefs,
  diffThreatRefs,
  lastRunKey,
  prevRunKey,
  type DriftModel,
  type DriftResult,
  type ThreatRef,
} from "@/client/drift";
import type { FindingStatus, StatusStorage } from "@/client/findingStatus";
import { isFindingStatus } from "@/client/findingStatus";

export const MAX_RUNS = 5;
/** An entry larger than this is stored without its per-threat confidences. */
export const MAX_ENTRY_BYTES = 200 * 1024;
/** A run's status log stops growing here, oldest changes dropped first. */
const MAX_STATUS_CHANGES = 200;

/** Storage that may also be able to remove a key (all real Web Storage can). */
export type RunStorage = StatusStorage & Partial<Pick<Storage, "removeItem">>;

export type RunThreat = {
  /** threatKey: the threat's identity across runs. */
  key: string;
  title: string;
  componentNames: string[];
  owasp: string[];
  severity: Severity;
  /** True when the threat was below 25% confidence in this run. */
  hidden: boolean;
  /** 0-100. Absent when the entry was over MAX_ENTRY_BYTES. */
  confidence?: number;
};

export type StatusChange = { key: string; status: FindingStatus; at: string };

export type RunEntry = {
  /** repo.analyzedAt, an ISO time ("" when the run did not carry one). */
  at: string;
  ref: string;
  /** An AnalysisLevel, or null for a run migrated from a snapshot that did not record it. */
  level: number | null;
  threats: RunThreat[];
  statusChanges?: StatusChange[];
};

export function runsKey(owner: string, repo: string): string {
  return `attackcanvas:runs:${owner}/${repo}`;
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

type EntrySource = DriftModel & { analysisLevel?: number };

/** The entry for a run, from the dashboard view model (or a legacy snapshot of one). */
export function toRunEntry(model: EntrySource): RunEntry {
  return {
    at: model.repo?.analyzedAt ?? "",
    ref: model.repo?.ref ?? "",
    level: typeof model.analysisLevel === "number" ? model.analysisLevel : null,
    threats: allThreatRefs(model).map(
      (ref): RunThreat => ({
        key: ref.key,
        title: ref.title,
        componentNames: ref.componentNames,
        owasp: ref.owasp,
        severity: ref.severity,
        hidden: ref.belowCutoff,
        confidence: ref.confidence,
      }),
    ),
  };
}

/** An entry's threats as the refs drift.ts compares; a stripped confidence reads as 0. */
export function refsOf(entry: RunEntry): ThreatRef[] {
  return entry.threats.map((t) => ({
    key: t.key,
    title: t.title,
    componentNames: t.componentNames,
    owasp: t.owasp,
    severity: t.severity,
    confidence: t.confidence ?? 0,
    belowCutoff: t.hidden,
  }));
}

/** The threat changes from `before` to `after`: the same rules as the panel's two counts. */
export function diffEntries(before: RunEntry, after: RunEntry): DriftResult["threats"] {
  return diffThreatRefs(refsOf(before), refsOf(after));
}

const byteLength = (text: string): number => new TextEncoder().encode(text).length;

/** The entry as it will be stored: without per-threat confidences when it is too large. */
export function capEntry(entry: RunEntry): RunEntry {
  if (byteLength(JSON.stringify(entry)) <= MAX_ENTRY_BYTES) return entry;
  return {
    ...entry,
    threats: entry.threats.map((t) => {
      const withoutConfidence = { ...t };
      delete withoutConfidence.confidence;
      return withoutConfidence;
    }),
  };
}

// ---------------------------------------------------------------------------
// Reading and validating
// ---------------------------------------------------------------------------

const isString = (v: unknown): v is string => typeof v === "string";
const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every(isString);

function asThreat(value: unknown): RunThreat | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (!isString(v.key) || !isString(v.title) || !isString(v.severity)) return null;
  if (!isStringArray(v.componentNames) || !isStringArray(v.owasp)) return null;
  if (typeof v.hidden !== "boolean") return null;
  if (v.confidence !== undefined && typeof v.confidence !== "number") return null;
  return {
    key: v.key,
    title: v.title,
    componentNames: v.componentNames,
    owasp: v.owasp,
    severity: v.severity as Severity,
    hidden: v.hidden,
    ...(v.confidence === undefined ? {} : { confidence: v.confidence as number }),
  };
}

function asChange(value: unknown): StatusChange | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  return isString(v.key) && isFindingStatus(v.status) && isString(v.at)
    ? { key: v.key, status: v.status, at: v.at }
    : null;
}

function asEntry(value: unknown): RunEntry | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (!isString(v.at) || !isString(v.ref) || !Array.isArray(v.threats)) return null;
  if (v.level !== null && typeof v.level !== "number") return null;
  const threats = v.threats.map(asThreat);
  if (threats.some((t) => t === null)) return null;
  const changes = Array.isArray(v.statusChanges)
    ? v.statusChanges.map(asChange).filter((c): c is StatusChange => c !== null)
    : [];
  return {
    at: v.at,
    ref: v.ref,
    level: v.level,
    threats: threats as RunThreat[],
    ...(changes.length ? { statusChanges: changes } : {}),
  };
}

/** The stored ring, oldest first, keeping at most MAX_RUNS valid entries; [] when unreadable. */
export function readRuns(
  storage: StatusStorage | null | undefined,
  owner: string,
  repo: string,
): RunEntry[] {
  try {
    const raw = storage?.getItem(runsKey(owner, repo));
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map(asEntry)
      .filter((e): e is RunEntry => e !== null)
      .slice(-MAX_RUNS);
  } catch {
    return [];
  }
}

function writeRuns(
  storage: StatusStorage | null | undefined,
  owner: string,
  repo: string,
  runs: readonly RunEntry[],
): boolean {
  try {
    storage?.setItem(runsKey(owner, repo), JSON.stringify(runs));
    return storage != null;
  } catch {
    // Storage unavailable or full: the comparison for this visit still works.
    return false;
  }
}

// ---------------------------------------------------------------------------
// Migration from attackcanvas:last / attackcanvas:prev
// ---------------------------------------------------------------------------

function isLegacyModel(value: unknown): value is EntrySource {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    Array.isArray(v.nodes) &&
    Array.isArray(v.edges) &&
    Array.isArray(v.threats) &&
    (v.hiddenThreats === undefined || Array.isArray(v.hiddenThreats))
  );
}

function readLegacy(
  storage: StatusStorage | null | undefined,
  key: string,
): EntrySource | null {
  try {
    const raw = storage?.getItem(key);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    return isLegacyModel(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The single full snapshot the browser kept before the ring: the run the reader was
 * looking at when they last set a status. The caller migrates an id-keyed status map
 * against it (migrateStatuses), so read it before recordRun() moves it into the ring.
 */
export function readLegacyLastRun(
  storage: StatusStorage | null | undefined,
  owner: string,
  repo: string,
): DriftModel | null {
  return readLegacy(storage, lastRunKey(owner, repo));
}

/**
 * Turns the old prev and last snapshots into ring entries (prev first), once. Done when
 * the runs key is absent and at least one snapshot is readable; the key's existence then
 * marks it finished, so a second call changes nothing. The old keys are removed afterwards
 * where the storage allows. Returns the entries written, or null when nothing migrated.
 */
export function migrateLegacyRuns(
  storage: RunStorage | null | undefined,
  owner: string,
  repo: string,
): RunEntry[] | null {
  try {
    if (!storage || storage.getItem(runsKey(owner, repo)) != null) return null;
  } catch {
    return null;
  }
  const snapshots = [prevRunKey(owner, repo), lastRunKey(owner, repo)]
    .map((key) => readLegacy(storage, key))
    .filter((model): model is EntrySource => model !== null);
  if (snapshots.length === 0) return null;
  const entries = snapshots.map((model) => capEntry(toRunEntry(model)));
  if (!writeRuns(storage, owner, repo, entries)) return null;
  for (const key of [prevRunKey(owner, repo), lastRunKey(owner, repo)]) {
    try {
      storage.removeItem?.(key);
    } catch {
      // Left behind: harmless, the runs key now decides.
    }
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

export type RecordedRun = {
  /** Every stored run including this one, oldest first. */
  runs: RunEntry[];
  /** The run before this one, or null for the first. */
  previous: RunEntry | null;
};

/**
 * Records a finished run and returns the ring with the run before it.
 *
 * Migrates the old two-snapshot keys first, if that has not happened. The oldest entry is
 * evicted once there are MAX_RUNS. A run already stored last (same `at`, e.g. the page was
 * reloaded) is not added again, so a reload cannot push a real run out or compare a run
 * with a copy of itself. The result is right even when the save fails.
 */
export function recordRun(
  storage: RunStorage | null | undefined,
  owner: string,
  repo: string,
  model: EntrySource,
): RecordedRun {
  migrateLegacyRuns(storage, owner, repo);
  const stored = readRuns(storage, owner, repo);
  const entry = capEntry(toRunEntry(model));
  const last = stored[stored.length - 1];
  if (last && entry.at !== "" && last.at === entry.at) {
    return { runs: stored, previous: stored[stored.length - 2] ?? null };
  }
  const runs = [...stored, entry].slice(-MAX_RUNS);
  writeRuns(storage, owner, repo, runs);
  return { runs, previous: last ?? null };
}

/**
 * Reads the stored runs without adding one: what a replayed result is shown against. A
 * replay is a saved copy of an analysis, not a new analysis, so it must neither push a run
 * into the ring nor evict a real one. Migrates the old two-snapshot keys first, since that
 * is existing history. `previous` is the latest stored run that is not this run itself.
 */
export function readHistory(
  storage: RunStorage | null | undefined,
  owner: string,
  repo: string,
  model: EntrySource,
): RecordedRun {
  migrateLegacyRuns(storage, owner, repo);
  const runs = readRuns(storage, owner, repo);
  const at = model.repo?.analyzedAt ?? "";
  const earlier = at === "" ? runs : runs.filter((r) => r.at !== at);
  return { runs, previous: earlier[earlier.length - 1] ?? null };
}

/**
 * Logs a status change on the entry for the run `runAt` (the run on screen) and returns the
 * ring. `current` is the caller's own copy of the ring, used when the store no longer has
 * that run (a save that failed earlier), so the change is still shown and the ring is not
 * replaced by a stale one. Returns `current` unchanged when the run is in neither.
 */
export function recordStatusChange(
  storage: StatusStorage | null | undefined,
  owner: string,
  repo: string,
  current: readonly RunEntry[],
  runAt: string,
  change: StatusChange,
): RunEntry[] {
  const stored = readRuns(storage, owner, repo);
  const runs = stored.some((r) => r.at === runAt) ? stored : [...current];
  const index = runs.findIndex((r) => r.at === runAt);
  if (index === -1) return [...current];
  const target = runs[index];
  const statusChanges = [...(target.statusChanges ?? []), change].slice(-MAX_STATUS_CHANGES);
  const next = runs.map((r, i) => (i === index ? capEntry({ ...target, statusChanges }) : r));
  writeRuns(storage, owner, repo, next);
  return next;
}

// ---------------------------------------------------------------------------
// What the History tab shows
// ---------------------------------------------------------------------------

export type HistoryRow = {
  run: RunEntry;
  /** Every scored threat in the run. */
  threats: number;
  /** Threats at 25% confidence or above. */
  visible: number;
  /** Against the run before it; null for the oldest stored run. */
  newCount: number | null;
  notFoundCount: number | null;
};

/** One row per stored run, newest first. */
export function historyRows(runs: readonly RunEntry[]): HistoryRow[] {
  return runs
    .map((run, index): HistoryRow => {
      const before = index > 0 ? runs[index - 1] : null;
      const diff = before ? diffEntries(before, run) : null;
      return {
        run,
        threats: run.threats.length,
        visible: run.threats.filter((t) => !t.hidden).length,
        newCount: diff ? diff.new.length : null,
        notFoundCount: diff ? diff.notFound.length : null,
      };
    })
    .reverse();
}

export type TimelineStep = {
  run: RunEntry;
  /** False when the threat was not reported in this run: a gap, never "fixed". */
  found: boolean;
  /** 0-100; null when not found, or when the entry was stored without confidences. */
  confidence: number | null;
  hidden: boolean;
  /** Status changes for this threat logged while this run was on screen. */
  statusChanges: StatusChange[];
};

/** One step per stored run, oldest first, for the threat with this key. */
export function threatTimeline(runs: readonly RunEntry[], key: string): TimelineStep[] {
  return runs.map((run) => {
    const threat = run.threats.find((t) => t.key === key);
    return {
      run,
      found: threat !== undefined,
      confidence: threat?.confidence ?? null,
      hidden: threat?.hidden ?? false,
      statusChanges: (run.statusChanges ?? []).filter((c) => c.key === key),
    };
  });
}

/** Every threat seen in any stored run, newest run's first, for choosing a timeline. */
export function threatsAcrossRuns(runs: readonly RunEntry[]): { key: string; title: string }[] {
  const seen = new Map<string, string>();
  for (const run of [...runs].reverse()) {
    for (const t of run.threats) if (!seen.has(t.key)) seen.set(t.key, t.title);
  }
  return [...seen].map(([key, title]) => ({ key, title }));
}

/** "2026-09-12 14:03 UTC" for an ISO time, the text itself when it is not one. Never locale-dependent. */
export function formatRunTime(value: string): string {
  const parsed = new Date(value);
  if (value === "" || Number.isNaN(parsed.getTime())) return value || "unknown time";
  return `${parsed.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** The level's plain name, or "Unknown" for a migrated run that did not record one. */
export function levelLabel(level: number | null): string {
  const labels = ANALYSIS_LEVEL_LABELS as Record<number, string>;
  return level !== null && labels[level] ? labels[level] : "Unknown";
}
