"use client";

/**
 * The completed threat model.
 *
 * Everything rendered here is read from the DashboardViewModel the server returned:
 * counts, fixNow, fixNowTotal, nodes, edges, threats, assumptions, limitations and
 * filterOptions. The only client-side computation is presentation — which threats are
 * currently filtered in (src/client/filterThreats.ts) and where graph nodes are drawn
 * (src/client/layoutGraph.ts). No severity, confidence, priority or basis is recalculated,
 * and the server's threat ordering is preserved (CLAUDE.md rule 2).
 *
 * Selection is shared between the two panes: picking a threat highlights the components
 * and flows it touches, and picking a node (in the map, or with the keyboard-reachable
 * component buttons under it) filters the list down to that component. Both
 * are view state and neither changes the underlying result. A selected node only stays
 * selected while the component filter still includes it, so clearing that filter also
 * clears the node's highlight.
 */

import ComingSoon from "@/components/ComingSoon";
import { useEffect, useMemo, useState } from "react";
import type { DashboardViewModel } from "@/shared/viewModel";
import { assignBoundaries } from "@/client/layoutGraph";
import {
  DIAGRAM_VIEWS,
  DIAGRAM_VIEW_LABELS,
  selectDiagramView,
  type DiagramView,
} from "@/client/diagramViews";
import {
  EMPTY_FILTERS,
  filterThreats,
  type ThreatFilters,
} from "@/client/filterThreats";
import {
  loadStatuses,
  orderByStatus,
  setStatus,
  splitFullName,
  statusStorageKey,
  summarise,
  type FindingStatus,
  type StatusMap,
} from "@/client/findingStatus";
import {
  diffThreatModels,
  newThreatKeys,
  recordRun,
  threatKey,
  type DriftModel,
} from "@/client/drift";
import type { BasisCounts, HiddenSummary } from "@/client/useAnalysis";
import ArchitectureGraph from "@/components/ArchitectureGraph";
import ArchitectureLegend from "@/components/ArchitectureLegend";
import { ExposureBadge, typeText } from "@/components/ArchitectureNode";
import type { Exposure } from "@/shared/viewModel";

/** What each exposure means, for the node detail panel. */
const EXPOSURE_DESCRIPTIONS: Record<Exposure, string> = {
  external: "External: a service someone else runs.",
  edge: "Edge: takes input from outside (an actor, a frontend, or a direct target of an actor).",
  internal: "Internal: reachable only through other components.",
};
import SectionLabel from "@/components/SectionLabel";
import FilterBar from "@/components/FilterBar";
import SeveritySummary from "@/components/SeveritySummary";
import SinceLastRun from "@/components/SinceLastRun";
import ThreatCard from "@/components/ThreatCard";
import ThreatList from "@/components/ThreatList";

type DashboardProps = {
  view: DashboardViewModel;
  basisCounts: BasisCounts | null;
  hiddenSummary?: HiddenSummary | null;
};

/** Reading window.localStorage itself can throw when storage is blocked. */
function safeLocalStorage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

/** Date only, and never locale-dependent, so the markup is stable between renders. */
function formatAnalyzedAt(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString().slice(0, 10);
}

export default function Dashboard({ view, basisCounts, hiddenSummary = null }: DashboardProps) {
  const [filters, setFilters] = useState<ThreatFilters>({ ...EMPTY_FILTERS });
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  // Which sub-view of the diagram is shown. Presentation only: the threat list ignores it.
  const [diagramView, setDiagramView] = useState<DiagramView>("overall");

  const threats = useMemo(() => view.threats ?? [], [view.threats]);

  // Triage statuses live in this browser only. Read after mount so the first render
  // matches the server's, and re-read if the repo or ref changes.
  const statusKey = useMemo(() => {
    const name = splitFullName(view.repo?.fullName ?? "");
    return name && view.repo?.ref ? statusStorageKey(name.owner, name.repo, view.repo.ref) : null;
  }, [view.repo?.fullName, view.repo?.ref]);
  const [statuses, setStatuses] = useState<StatusMap>({});
  useEffect(() => {
    setStatuses(statusKey ? loadStatuses(safeLocalStorage(), statusKey) : {});
  }, [statusKey]);
  const handleStatusChange = (id: string, status: FindingStatus) => {
    if (!statusKey) return;
    setStatuses((current) => setStatus(safeLocalStorage(), statusKey, current, id, status));
  };
  const statusCounts = useMemo(
    () => summarise(threats.map((t) => t.id), statuses),
    [threats, statuses],
  );

  // The run before this one, read once this run is recorded. undefined until then, so the
  // first render (which must match the server's) shows nothing; null means no earlier run.
  const [prevRun, setPrevRun] = useState<DriftModel | null | undefined>(undefined);
  useEffect(() => {
    const name = splitFullName(view.repo?.fullName ?? "");
    setPrevRun(name ? recordRun(safeLocalStorage(), name.owner, name.repo, view) : null);
  }, [view]);
  const drift = useMemo(() => (prevRun ? diffThreatModels(prevRun, view) : null), [prevRun, view]);
  const newKeys = useMemo(
    () => (prevRun ? newThreatKeys(prevRun, view) : new Set<string>()),
    [prevRun, view],
  );

  const issueRepo = view.repo?.fullName && view.repo.ref
    ? { fullName: view.repo.fullName, ref: view.repo.ref }
    : undefined;

  const visible = useMemo(
    () => orderByStatus(filterThreats(threats, filters, statuses), statuses),
    [threats, filters, statuses],
  );

  const selectedThreat = useMemo(
    () => threats.find((threat) => threat.id === selectedThreatId) ?? null,
    [threats, selectedThreatId],
  );

  // A selected threat wins over a selected node: the user asked about that threat. Its
  // component ids light up nodes and its data-flow ids light up edges, never crosswise.
  const highlight = useMemo(() => {
    if (selectedThreat) {
      return {
        nodeIds: selectedThreat.componentIds ?? [],
        edgeIds: selectedThreat.dataFlowIds ?? [],
      };
    }
    return { nodeIds: selectedNodeId ? [selectedNodeId] : [], edgeIds: [] };
  }, [selectedThreat, selectedNodeId]);

  const handleSelectThreat = (id: string) => {
    setSelectedThreatId((current) => (current === id ? null : id));
    setSelectedNodeId(null);
  };

  const handleSelectNode = (id: string | null) => {
    setSelectedNodeId(id);
    setSelectedThreatId(null);
    // Clicking a node narrows the list to that component; clicking the canvas clears it.
    setFilters((current) => ({ ...current, componentIds: id ? [id] : [] }));
  };

  // Filter bar changes ("Clear all", unchecking a component) can drop the selected node
  // from the component filter; the node's highlight must not outlive that.
  const handleFiltersChange = (next: ThreatFilters) => {
    setFilters(next);
    if (selectedNodeId !== null && !(next.componentIds ?? []).includes(selectedNodeId)) {
      setSelectedNodeId(null);
    }
  };

  const repo = view.repo;
  // Falls back to the list length only for a partial response that lacks the total.
  const fixNowTotal = view.fixNowTotal ?? view.fixNow?.length ?? 0;
  const nodes = useMemo(() => view.nodes ?? [], [view.nodes]);
  const boundaries = useMemo(() => view.boundaries ?? [], [view.boundaries]);
  // The sub-view's nodes and edges. Hidden items are removed, not dimmed, so the diagram
  // lays itself out again for what is left.
  const shown = useMemo(() => {
    const selection = selectDiagramView(
      { nodes, edges: view.edges ?? [], threats },
      diagramView,
    );
    const nodeIds = new Set(selection.nodeIds);
    const edgeIds = new Set(selection.edgeIds);
    return {
      nodes: nodes.filter((node) => nodeIds.has(node.id)),
      edges: (view.edges ?? []).filter((edge) => edgeIds.has(edge.id)),
    };
  }, [nodes, view.edges, threats, diagramView]);
  const layoutNotes = useMemo(
    () => assignBoundaries(boundaries, shown.nodes).notes,
    [boundaries, shown.nodes],
  );
  const selectedNode = nodes.find((node) => node.id === selectedNodeId) ?? null;
  const assumptions = view.assumptions ?? [];
  const limitations = view.limitations ?? [];

  return (
    <div className="space-y-8">
      <header>
        <SectionLabel>Threat model</SectionLabel>
        <h1 className="mt-4 break-words font-display text-3xl font-semibold tracking-tight text-fg sm:text-4xl">
          {repo?.fullName ?? "Threat model"}
        </h1>
        <p className="mt-2 flex flex-wrap gap-x-2 text-sm text-muted">
          <span className="font-mono">{repo?.ref}</span>
          <span aria-hidden="true">&middot;</span>
          <span>{view.analysisLevelLabel} analysis</span>
          <span aria-hidden="true">&middot;</span>
          <span>{repo?.fileCount ?? 0} files analyzed</span>
          {repo?.analyzedAt ? (
            <>
              <span aria-hidden="true">&middot;</span>
              <span>{formatAnalyzedAt(repo.analyzedAt)}</span>
            </>
          ) : null}
        </p>
        {repo?.frameworks?.length ? (
          <p className="mt-1 text-sm text-subtle">Frameworks: {repo.frameworks.join(", ")}</p>
        ) : null}
      </header>

      {/* The diagram reads left to right in five type columns, so it takes the full row. */}
      <div className="space-y-6">
        <section aria-labelledby="architecture-heading" className="min-w-0">
          <h2 id="architecture-heading" className="font-display text-xl font-semibold text-fg">
            Architecture
          </h2>
          <p className="mt-1 text-sm text-muted">
            Select a component to see the threats that involve it, or select a threat to
            highlight what it touches.
          </p>
          <div
            role="radiogroup"
            aria-label="Diagram view"
            className="mt-3 inline-flex flex-wrap gap-1 rounded-full border border-line bg-surface-2 p-1"
          >
            {DIAGRAM_VIEWS.map((name) => {
              const active = diagramView === name;
              return (
                <button
                  key={name}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  onClick={() => setDiagramView(name)}
                  className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                    active ? "bg-mint text-white shadow-sm" : "text-muted hover:text-fg"
                  }`}
                >
                  {DIAGRAM_VIEW_LABELS[name]}
                </button>
              );
            })}
          </div>
          <div className="mt-3">
            <ArchitectureGraph
              nodes={shown.nodes}
              edges={shown.edges}
              emptyMessage={
                diagramView === "overall"
                  ? undefined
                  : `Nothing in this analysis belongs in the "${DIAGRAM_VIEW_LABELS[diagramView]}" view.`
              }
              boundaries={boundaries}
              highlightNodeIds={highlight.nodeIds}
              highlightEdgeIds={highlight.edgeIds}
              selectedNodeId={selectedNodeId}
              onSelectNode={handleSelectNode}
            />
            <ArchitectureLegend nodes={shown.nodes} notes={layoutNotes} />
          </div>

          {nodes.length > 0 ? (
            <div className="mt-3">
              <p id="component-picker-label" className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted">
                Components
              </p>
              <ul aria-labelledby="component-picker-label" className="mt-2 flex flex-wrap gap-1.5">
                {nodes.map((node) => {
                  const pressed = selectedNodeId === node.id;
                  return (
                    <li key={node.id}>
                      <button
                        type="button"
                        aria-pressed={pressed}
                        onClick={() => handleSelectNode(pressed ? null : node.id)}
                        className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                          pressed
                            ? "border-mint bg-mint-deep text-fg"
                            : "border-line bg-ink-2/70 text-muted hover:border-line-strong"
                        }`}
                      >
                        {node.label}
                        <span aria-hidden="true" className="ml-1.5 font-mono text-muted">
                          {node.threatCount}
                        </span>
                        <span className="sr-only">
                          , {node.threatCount} threat{node.threatCount === 1 ? "" : "s"}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ) : null}

          {selectedNode ? (
            <section
              aria-label={`${selectedNode.label} details`}
              className="mt-3 rounded-xl border border-mint/40 bg-mint-deep/50 px-4 py-3 text-sm text-fg"
            >
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-display text-base font-semibold">{selectedNode.label}</h3>
                <span className="text-xs uppercase tracking-wider text-subtle">
                  {typeText(selectedNode.type)}
                </span>
                {selectedNode.exposure ? <ExposureBadge exposure={selectedNode.exposure} /> : null}
              </div>
              <dl className="mt-2 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
                <dt className="text-muted">Exposure</dt>
                <dd>{EXPOSURE_DESCRIPTIONS[selectedNode.exposure ?? "internal"]}</dd>
                <dt className="text-muted">Assets</dt>
                <dd>{selectedNode.assets?.length ? selectedNode.assets.join(", ") : "None recorded"}</dd>
                <dt className="text-muted">Technologies</dt>
                <dd>
                  {selectedNode.technologies?.length
                    ? selectedNode.technologies.join(", ")
                    : "None recorded"}
                </dd>
              </dl>
              <p role="status" className="mt-2">
                The threat list below is narrowed to threats that involve{" "}
                <strong className="font-semibold">{selectedNode.label}</strong>.{" "}
                <a href="#threats-heading" className="text-mint underline underline-offset-2">
                  Go to the list
                </a>
              </p>
            </section>
          ) : null}
        </section>

        <div className="grid min-w-0 gap-6 lg:grid-cols-2 lg:items-start">
          <SeveritySummary
            counts={view.counts}
            basisCounts={basisCounts}
            // The server's total, not the length of the (capped) list below.
            fixNowCount={fixNowTotal}
            statusCounts={statusCounts}
          />

          <section
            aria-labelledby="caveats-heading"
            className="rounded-2xl border border-sev-medium/30 bg-surface/70 p-5"
          >
            <h2 id="caveats-heading" className="font-display text-base font-semibold text-fg">
              Read this with care
            </h2>
            <p className="mt-1 text-sm text-muted">
              What this analysis assumed, and what it could not see.
            </p>
            {hiddenSummary && hiddenSummary.hidden > 0 ? (
              <p className="mt-3 text-sm text-muted">
                {hiddenSummary.hidden} of {hiddenSummary.scored} scored threat
                {hiddenSummary.scored === 1 ? "" : "s"} fell below 25% confidence and are
                not listed.
              </p>
            ) : null}
            {assumptions.length ? (
              <div className="mt-4">
                <h3 className="text-[11px] font-medium uppercase tracking-[0.14em] text-sev-medium">
                  Assumptions
                </h3>
                <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
                  {assumptions.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {limitations.length ? (
              <div className="mt-4">
                <h3 className="text-[11px] font-medium uppercase tracking-[0.14em] text-sev-medium">
                  Limitations
                </h3>
                <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
                  {limitations.map((item, index) => (
                    <li key={index}>{item}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {!assumptions.length && !limitations.length ? (
              <p className="mt-3 text-sm text-muted">
                The analysis recorded no assumptions or limitations. Findings still come
                from reading code, not running it.
              </p>
            ) : null}
          </section>
        </div>
      </div>

      {prevRun !== undefined ? <SinceLastRun drift={drift} /> : null}

      {view.fixNow?.length ? (
        <section aria-labelledby="fix-now-heading">
          <h2 id="fix-now-heading" className="font-display text-xl font-semibold text-fg">
            Fix now
          </h2>
          <p className="mt-1 text-sm text-muted">
            Critical threats, and high-severity threats the analysis is at least 50%
            confident in.
            {fixNowTotal > view.fixNow.length
              ? ` Showing the top ${view.fixNow.length} of ${fixNowTotal}; the full list is below.`
              : ""}
          </p>
          <ul className="mt-4 grid gap-3 xl:grid-cols-2">
            {view.fixNow.map((threat) => (
              <li key={`fix-now-${threat.id}`} className="min-w-0">
                <ThreatCard
                  threat={threat}
                  selected={selectedThreatId === threat.id}
                  onSelect={handleSelectThreat}
                  status={statuses[threat.id] ?? "open"}
                  onStatusChange={statusKey ? handleStatusChange : undefined}
                  repo={issueRepo}
                  isNew={newKeys.has(threatKey(threat))}
                />
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section aria-labelledby="threats-heading" className="scroll-mt-24">
        <h2 id="threats-heading" className="font-display text-xl font-semibold text-fg">
          Threats
        </h2>
        <div className="mt-4 grid gap-6 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
          <div className="min-w-0 lg:sticky lg:top-24 lg:self-start">
            <FilterBar
              options={view.filterOptions}
              filters={filters}
              onChange={handleFiltersChange}
            />
          </div>
          <div className="min-w-0">
            <ThreatList
              threats={visible}
              selectedId={selectedThreatId}
              onSelect={handleSelectThreat}
              totalCount={threats.length}
              hiddenSummary={hiddenSummary}
              statuses={statuses}
              onStatusChange={statusKey ? handleStatusChange : undefined}
              repo={issueRepo}
              newKeys={newKeys}
            />
          </div>
        </div>
      </section>

      <ComingSoon />
    </div>
  );
}
