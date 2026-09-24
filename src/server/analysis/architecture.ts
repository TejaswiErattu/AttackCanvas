/**
 * Architecture inference (Prompt N1). The first step that asks a model to reason.
 *
 * Everything before this point is deterministic: files were loaded, detectors ran, gaps
 * were proved, scanners reported. buildContext turned all of it into text. This module
 * sends that text to a model and gets back an ArchitectureDraft -- components, data
 * flows, trust boundaries and unknowns.
 *
 * The interesting half is the unknowns. The prompt asks the model to enumerate the
 * controls a component of each type normally has, and then to split them: a control the
 * gap detector already proved absent stays evidence and produces no unknown; a control
 * the evidence settles produces no unknown; a control the context cannot settle either
 * way becomes an Unknown, which lowers confidence downstream and becomes a candidate
 * developer question. That is how the pipeline records uncertainty instead of guessing.
 *
 * inferArchitecture infers and nothing else. It drops no invented reference, adds back
 * no detected fact, binds no gap and computes no layout -- all of that is
 * mergeArchitecture (Prompt N2, further down), which is where hallucination control
 * lives. The model proposes in the first half of this file; code disposes in the second.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { callStructured, type ClaudeDeps } from "@/server/ai/claude";
import { loadPrompt } from "@/server/ai/prompts";
import type { CallUsage } from "@/server/ai/usage";
import dagre from "dagre";
import type { z } from "zod";
import {
  debugDirName,
  gapEvidenceId,
  oneLine,
  type BuiltContext,
  type RepoFacts,
} from "@/server/analysis/context";
import {
  isCompose,
  isDockerfile,
  isServerless,
  isTerraform,
  isVercel,
} from "@/server/detect/deployment";
import { isManifest } from "@/server/detect/frameworks";
import type { ControlGap, Route } from "@/server/detect/types";
import {
  ArchitectureDraftSchema,
  architectureDraftJsonSchema,
  ComponentSchema,
  DataFlowSchema,
  TrustBoundarySchema,
  UnknownSchema,
  type ArchitectureDraft,
  type Component,
  type ComponentType,
  type DataFlow,
  type Evidence,
  type TrustBoundary,
  type Unknown,
} from "@/shared/schema";

// ---------------------------------------------------------------------------
// Knobs
// ---------------------------------------------------------------------------

export const ARCHITECTURE_PROMPT_NAME = "architecture";
export const ARCHITECTURE_PROMPT_VERSION = 1;

/**
 * Output budget. Above the client's 8000 default because a draft carrying a dozen
 * components, their flows and up to 12 unknowns runs long, and a reply cut off at
 * max_tokens spends the single retry CLAUDE.md rule 5 allows on length rather than on
 * a schema error. That retry gets a larger budget (truncationRetryTokens: 21,333 from
 * here) and the time to use it, but it is still a paid second call, so this stays sized
 * to fit the first time.
 */
export const ARCHITECTURE_MAX_TOKENS = 12_000;

/**
 * Extended thinking is disabled for architecture calls, as for threat calls
 * (THREATS_THINKING): reasoning tokens count against ARCHITECTURE_MAX_TOKENS, and on a
 * larger repository they consumed all 12,000 and returned an empty, truncated draft.
 */
export const ARCHITECTURE_THINKING = { type: "disabled" } as const;

/**
 * Input budget handed to buildContext. At the context builder's conservative 3.5
 * chars/token this is roughly 210k characters, which leaves room for the whole facts
 * prefix plus a useful spread of file excerpts while staying well inside the input
 * window of every model in the profile table.
 */
export const ARCHITECTURE_CONTEXT_TOKENS = 60_000;

/** Written next to context.txt, under the same gitignored directory. */
export const DRAFT_FILENAME = "architecture.draft.json";

// ---------------------------------------------------------------------------
// Public shape
// ---------------------------------------------------------------------------

export type InferArchitectureOptions = {
  repo: { owner: string; name: string };
  /** The context built by Prompt L. Already redacted, escaped and secret-checked. */
  context: BuiltContext;
  analysisId: string;
  maxTokens?: number;
  /** Passed straight to callStructured. The test seam; nothing production sets it. */
  deps?: Partial<ClaudeDeps>;
  /** Where to read the prompt from. Defaults to the prompts directory. */
  promptDir?: string;
  /** Root for the debug dump. Defaults to .debug under the working directory. */
  rootDir?: string;
  /** Overrides NODE_ENV for the dump decision. */
  nodeEnv?: string;
};

export type InferArchitectureResult = {
  draft: ArchitectureDraft;
  usage: CallUsage;
  /** 1 when the first reply validated, 2 when the retry saved it. */
  attempts: number;
  /** "architecture.v1". Recorded alongside whatever the draft becomes. */
  promptId: string;
  /** Where the raw draft was dumped, when it was. Development only. */
  draftPath?: string;
};

// ---------------------------------------------------------------------------
// inferArchitecture
// ---------------------------------------------------------------------------

export async function inferArchitecture(
  options: InferArchitectureOptions,
): Promise<InferArchitectureResult> {
  const prompt = loadPrompt(
    ARCHITECTURE_PROMPT_NAME,
    ARCHITECTURE_PROMPT_VERSION,
    options.promptDir,
  );

  // The context text goes on the wire verbatim. It already carries the <repo_file>
  // wrappers, the escaping and the redaction buildContext applied, and it has been
  // through guardText; wrapping it again here would only break the model's ability to
  // cite the paths it contains. callStructured re-runs assertNoSecrets regardless.
  const { value, usage, attempts } = await callStructured({
    stage: "architecture",
    system: prompt.text,
    user: options.context.text,
    schema: ArchitectureDraftSchema,
    jsonSchema: architectureDraftJsonSchema as Record<string, unknown>,
    maxTokens: options.maxTokens ?? ARCHITECTURE_MAX_TOKENS,
    thinking: ARCHITECTURE_THINKING,
    analysisId: options.analysisId,
    deps: options.deps,
  });

  const draftPath = await writeArchitectureDraft(options.repo, value, {
    rootDir: options.rootDir,
    nodeEnv: options.nodeEnv,
  });

  return { draft: value, usage, attempts, promptId: prompt.id, draftPath };
}

// ---------------------------------------------------------------------------
// Debug output
// ---------------------------------------------------------------------------

/**
 * Writes .debug/<repo>/architecture.draft.json so a draft can be read by hand next to
 * the context that produced it. Writes only when NODE_ENV is exactly "development"
 * (CLAUDE.md rule 8), exactly as writeDebugContext does, and reuses debugDirName so an
 * owner or repository name can never escape the directory.
 *
 * Best effort: a filesystem failure here returns undefined rather than throwing. The
 * draft is the result of a paid model call, and losing it to an unwritable .debug
 * directory would be a poor trade.
 */
export async function writeArchitectureDraft(
  repo: { owner: string; name: string },
  draft: ArchitectureDraft,
  options: { rootDir?: string; nodeEnv?: string } = {},
): Promise<string | undefined> {
  const env = options.nodeEnv ?? process.env.NODE_ENV;
  if (env !== "development") return undefined;

  // turbopackIgnore: the path is development-only and runtime-computed. Without it the
  // bundler's file tracer cannot scope it and copies the whole project (.debug dumps and
  // .env.local included) into the server output of every route that imports this file.
  const dir = join(
    /*turbopackIgnore: true*/ options.rootDir ?? join(process.cwd(), ".debug"),
    debugDirName(repo.owner, repo.name),
  );
  const path = join(dir, DRAFT_FILENAME);
  try {
    await mkdir(dir, { recursive: true });
    await writeFile(path, `${JSON.stringify(draft, null, 2)}\n`, "utf8");
    return path;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Merge (Prompt N2)
// ---------------------------------------------------------------------------

/**
 * The line between "we will say this" and "we will ask about this". A gap whose
 * certainty is at or above it is treated as verifiably absent: it stays evidence and a
 * threat may cite it. Below it the gap is still evidence, but it also becomes an Unknown,
 * because a detector that is 55% sure input validation is missing may simply not have
 * followed the middleware that supplies it. That lowers confidence downstream and gives
 * the question engine something to ask. A policy, not a fact; tune it here.
 */
export const GAP_ASSERT_CERTAINTY = 0.7;

/** Unknowns feed the question engine; an unbounded list is an unbounded ranking problem. */
export const MAX_UNKNOWNS = 12;

/**
 * Rank certainty for a model unknown, which has no gap behind it. Set to the assert
 * threshold so every gap-derived unknown (all below it) outranks a model one: the
 * gap-derived wording is specific and its certainty is measured, the model's is neither.
 */
const MODEL_UNKNOWN_RANK_CERTAINTY = GAP_ASSERT_CERTAINTY;

const NODE_WIDTH = 220;
const NODE_HEIGHT = 80;

/**
 * The schema has no deployment or infrastructure type, and it may not change. A
 * deployment target is where the application runs, so it is modelled as an
 * external_service: that keeps it out of the api/backend set that repository-scope gaps
 * bind to, which a "backend" deployment component would otherwise pollute.
 */
const DEPLOYMENT_SYNTH_TYPE: ComponentType = "external_service";
const DATASTORE_TYPES: readonly ComponentType[] = ["database", "storage"];
/** Types a model might reasonably give a deployment target. Still needs an anchor. */
const DEPLOYMENT_TYPES: readonly ComponentType[] = [
  "external_service",
  "backend",
  "worker",
];
const API_TYPES: readonly ComponentType[] = ["api", "backend"];

export type MergeIssue = {
  code: "schema" | "duplicate_id" | "dangling_reference";
  path: string;
  message: string;
};

export type MergedArchitecture = {
  components: Component[];
  dataFlows: DataFlow[];
  trustBoundaries: TrustBoundary[];
  unknowns: Unknown[];
  /** Detector, Semgrep and OSV evidence, de-duplicated by id. Everything a threat may cite. */
  evidence: Evidence[];
  limitations: string[];
  /** gap id -> component ids. Consumed by Prompt P. */
  gapBindings: Map<string, string[]>;
  /**
   * component id -> evidence ids. The contract's Component has no evidenceRefs field, so
   * the citations that survived the merge are returned beside it. Every id listed exists
   * in `evidence`.
   */
  componentEvidence: Map<string, string[]>;
  flowEvidence: Map<string, string[]>;
  /** Contract violations found by the final check. Empty when the result is sound. */
  issues: MergeIssue[];
};

type Kept = { component: Component; evidenceIds: string[] };
type KeptFlow = { flow: DataFlow; evidenceIds: string[] };
/** `control` is set only on gap-derived unknowns; it drives the dedupe. */
type RankedUnknown = { unknown: Unknown; certainty: number; control?: string };

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

export function normalizePath(path: string): string {
  return path
    .trim()
    .replace(/\\/g, "/")
    .replace(/^(\.\/)+/, "")
    .replace(/^\/+/, "")
    .replace(/\/{2,}/g, "/");
}

const byId = (a: string, b: string): number =>
  a.localeCompare(b, "en", { numeric: true });

const sortIds = (ids: Iterable<string>): string[] =>
  [...new Set(ids)].sort(byId);

function slug(text: string): string {
  const s = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return s === "" ? "x" : s;
}

function uniqueId(base: string, taken: Set<string>): string {
  let id = base;
  for (let n = 2; taken.has(id); n += 1) id = `${base}-${n}`;
  taken.add(id);
  return id;
}

function normalizedText(text: string): string {
  return ` ${text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()} `;
}

// ---------------------------------------------------------------------------
// Evidence and reference resolution
// ---------------------------------------------------------------------------

function mergeEvidence(facts: RepoFacts): Evidence[] {
  const seen = new Set<string>();
  const out: Evidence[] = [];
  for (const item of [
    ...facts.detector.evidence,
    ...facts.semgrep,
    ...facts.osv,
  ]) {
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    out.push(item);
  }
  return out;
}

/**
 * Evidence ids for a detector fact, found by what the evidence says (file, line and the
 * summary the detector wrote for that kind of fact) and never by where it sits in the
 * array or by counting. Reordering the evidence cannot change the answer.
 */
function evidenceFor(
  evidence: readonly Evidence[],
  file: string,
  line: number,
  summaryPrefix: string,
): string[] {
  const at = Math.max(1, Math.floor(line));
  return sortIds(
    evidence
      .filter(
        (e) =>
          e.filePath === file &&
          e.lineStart === at &&
          e.summary.startsWith(summaryPrefix),
      )
      .map((e) => e.id),
  );
}

function routeEvidenceIds(
  route: Route,
  evidence: readonly Evidence[],
): string[] {
  return evidenceFor(
    evidence,
    route.file,
    route.line,
    `${route.method} ${route.normalizedPath} handled here`,
  );
}

type RefIndex = {
  evidenceIds: ReadonlySet<string>;
  routes: ReadonlyMap<string, string[]>;
  paths: ReadonlySet<string>;
};

function buildRefIndex(
  facts: RepoFacts,
  evidence: readonly Evidence[],
): RefIndex {
  return {
    evidenceIds: new Set(evidence.map((e) => e.id)),
    routes: new Map(
      facts.detector.routes.map((r) => [r.id, routeEvidenceIds(r, evidence)]),
    ),
    paths: new Set(facts.files.map((f) => normalizePath(f.path))),
  };
}

/**
 * A ref resolves when it is an evidence id in the array, a route id, or a loaded file
 * path (the three things the N1 prompt allows). Only evidence ids are returned for
 * attachment: a route id maps to the evidence written for that route, a bare path maps
 * to nothing, and an id that is not in the array is never passed on.
 */
function resolveRefs(
  refs: readonly string[],
  idx: RefIndex,
): { resolved: boolean; evidenceIds: string[] } {
  const ids = new Set<string>();
  let resolved = false;
  for (const raw of refs) {
    const ref = raw.trim();
    if (idx.evidenceIds.has(ref)) {
      resolved = true;
      ids.add(ref);
    } else if (idx.routes.has(ref)) {
      resolved = true;
      for (const id of idx.routes.get(ref) ?? []) ids.add(id);
    } else if (idx.paths.has(normalizePath(ref))) {
      resolved = true;
    }
  }
  return { resolved, evidenceIds: sortIds(ids) };
}

// ---------------------------------------------------------------------------
// Rule 1: drop invented references
// ---------------------------------------------------------------------------

function dropComponents(
  draft: ArchitectureDraft,
  idx: RefIndex,
  limitations: string[],
): Kept[] {
  const kept: Kept[] = [];
  const seen = new Set<string>();
  for (const { evidenceRefs, ...component } of draft.components) {
    const label = oneLine(component.id);
    const unknownFile = component.files.find(
      (f) => !idx.paths.has(normalizePath(f)),
    );
    const refs = resolveRefs(evidenceRefs, idx);
    if (unknownFile !== undefined) {
      limitations.push(
        `Dropped component ${label}: it lists ${oneLine(unknownFile)}, which is not in the loaded file list.`,
      );
    } else if (!refs.resolved) {
      limitations.push(
        `Dropped component ${label}: none of its evidenceRefs resolves to evidence, a route or a loaded file.`,
      );
    } else if (seen.has(component.id)) {
      limitations.push(`Dropped a second component with the id ${label}.`);
    } else {
      seen.add(component.id);
      kept.push({
        component: { ...component, files: component.files.map(normalizePath) },
        evidenceIds: refs.evidenceIds,
      });
    }
  }
  return kept;
}

function dropFlows(
  draft: ArchitectureDraft,
  componentIds: ReadonlySet<string>,
  idx: RefIndex,
  limitations: string[],
): KeptFlow[] {
  const kept: KeptFlow[] = [];
  const seen = new Set<string>();
  for (const { evidenceRefs, ...flow } of draft.dataFlows) {
    const label = oneLine(flow.id);
    const refs = resolveRefs(evidenceRefs, idx);
    if (!componentIds.has(flow.sourceId) || !componentIds.has(flow.targetId)) {
      limitations.push(
        `Dropped data flow ${label}: an endpoint is not a component that survived the merge.`,
      );
    } else if (!refs.resolved) {
      limitations.push(
        `Dropped data flow ${label}: none of its evidenceRefs resolves to evidence, a route or a loaded file.`,
      );
    } else if (seen.has(flow.id)) {
      limitations.push(`Dropped a second data flow with the id ${label}.`);
    } else {
      seen.add(flow.id);
      kept.push({ flow, evidenceIds: refs.evidenceIds });
    }
  }
  return kept;
}

function pruneBoundaries(
  boundaries: readonly TrustBoundary[],
  componentIds: ReadonlySet<string>,
  limitations: string[],
): TrustBoundary[] {
  const out: TrustBoundary[] = [];
  for (const boundary of boundaries) {
    const members = boundary.componentIds.filter((id) => componentIds.has(id));
    if (members.length === boundary.componentIds.length) {
      out.push(boundary);
    } else if (members.length === 0) {
      limitations.push(
        `Dropped trust boundary ${oneLine(boundary.id)}: none of its components survived the merge.`,
      );
    } else {
      limitations.push(
        `Trust boundary ${oneLine(boundary.id)} lost members that did not survive the merge.`,
      );
      out.push({ ...boundary, componentIds: members });
    }
  }
  return out;
}

function pruneUnknowns(
  unknowns: readonly Unknown[],
  componentIds: ReadonlySet<string>,
  limitations: string[],
): Unknown[] {
  const out: Unknown[] = [];
  for (const unknown of unknowns) {
    const affects = unknown.affectsComponentIds.filter((id) =>
      componentIds.has(id),
    );
    if (affects.length === 0 && unknown.affectsComponentIds.length > 0) {
      limitations.push(
        `Dropped unknown ${oneLine(unknown.id)}: every component it affects was dropped.`,
      );
    } else {
      out.push({ ...unknown, affectsComponentIds: affects });
    }
  }
  return out;
}

/** A flow may only name a boundary that survived. */
function fixBoundaryRefs(
  flows: KeptFlow[],
  boundaries: readonly TrustBoundary[],
  limitations: string[],
): KeptFlow[] {
  const ids = new Set(boundaries.map((b) => b.id));
  return flows.map(({ flow, evidenceIds }) => {
    if (flow.boundaryId === undefined || ids.has(flow.boundaryId)) {
      return { flow, evidenceIds };
    }
    limitations.push(
      `Data flow ${oneLine(flow.id)} named a trust boundary that does not exist; the reference was removed.`,
    );
    const cleaned = { ...flow };
    delete cleaned.boundaryId;
    return { flow: cleaned, evidenceIds };
  });
}

// ---------------------------------------------------------------------------
// Rule 2: add back certain facts
// ---------------------------------------------------------------------------

type FactGroup = {
  kind: "datastore" | "deployment";
  key: string;
  label: string;
  files: string[];
  evidenceIds: string[];
  /** Words that may SUPPORT a match. They never establish one. */
  terms: string[];
  names: string[];
  detail: string;
};

function groupFacts(
  facts: RepoFacts,
  evidence: readonly Evidence[],
): FactGroup[] {
  const groups = new Map<string, FactGroup>();
  const touch = (
    init: FactGroup,
    file: string,
    ids: string[],
    name: string,
  ): void => {
    const group = groups.get(init.key) ?? init;
    groups.set(init.key, group);
    group.files = sortIds([...group.files, normalizePath(file)]);
    group.evidenceIds = sortIds([...group.evidenceIds, ...ids]);
    group.names = sortIds([...group.names, name]);
  };

  for (const d of facts.detector.datastores) {
    const key =
      d.kind === "unknown"
        ? `datastore:unknown:${d.name}`
        : `datastore:${d.kind}`;
    touch(
      {
        kind: "datastore",
        key,
        label: d.kind === "unknown" ? d.name : d.kind,
        files: [],
        evidenceIds: [],
        terms: [d.kind, d.name].map((t) => t.toLowerCase()),
        names: [],
        detail: "",
      },
      d.file,
      evidenceFor(evidence, d.file, d.line, `Datastore ${d.kind}:`),
      d.name,
    );
  }
  for (const d of facts.detector.deployment) {
    touch(
      {
        kind: "deployment",
        key: `deployment:${d.kind}:${d.name}`,
        label: d.kind,
        files: [],
        evidenceIds: [],
        terms: [d.kind, d.name].map((t) => t.toLowerCase()),
        names: [],
        detail: d.ports.length > 0 ? `, ports ${d.ports.join(", ")}` : "",
      },
      d.file,
      evidenceFor(
        evidence,
        d.file,
        d.line,
        `Deployment (${d.kind}): ${d.name}`,
      ),
      d.name,
    );
  }
  return [...groups.values()].sort((a, b) => byId(a.key, b.key));
}

/**
 * Identity needs a compatible type AND a strong anchor: the component cites the same
 * detector evidence, or lists the same source file. A shared name or technology never
 * anchors on its own.
 */
function anchored(kept: Kept, group: FactGroup): boolean {
  return (
    kept.evidenceIds.some((id) => group.evidenceIds.includes(id)) ||
    kept.component.files.some((f) => group.files.includes(f))
  );
}

function supports(kept: Kept, group: FactGroup): boolean {
  const c = kept.component;
  const haystack =
    `${c.id} ${c.name} ${c.technologies.join(" ")}`.toLowerCase();
  return group.terms.some((t) => t.length >= 2 && haystack.includes(t));
}

/** Anchored candidates; name and technology support only narrows a tie. */
function candidatesFor(
  group: FactGroup,
  kept: readonly Kept[],
  types: readonly ComponentType[],
): Kept[] {
  const found = kept.filter(
    (k) => types.includes(k.component.type) && anchored(k, group),
  );
  if (found.length <= 1) return found;
  const supported = found.filter((k) => supports(k, group));
  return supported.length === 1 ? supported : found;
}

function synthesize(group: FactGroup, taken: Set<string>): Kept {
  const isStore = group.kind === "datastore";
  const name = oneLine(group.names.join(", "), 80);
  const files = group.files;
  return {
    component: {
      id: uniqueId(
        isStore
          ? `datastore-${slug(group.label)}`
          : `deployment-${slug(group.label)}-${slug(group.names[0] ?? "")}`,
        taken,
      ),
      name: isStore
        ? `${oneLine(group.label, 40)} datastore`
        : `${name} (${group.label})`,
      type: isStore ? "database" : DEPLOYMENT_SYNTH_TYPE,
      description: isStore
        ? `Datastore detected from ${name} in ${files.join(", ")}.`
        : `Deployment target (${group.label}) ${name} defined in ${files.join(", ")}${group.detail}.`,
      technologies: isStore
        ? group.names.map((n) => oneLine(n, 80))
        : [group.label],
      files,
      assets: [],
    },
    evidenceIds: group.evidenceIds,
  };
}

/**
 * Every detected datastore (grouped by kind) and deployment target must be a component.
 * A draft component counts as the same thing only on type plus an anchor; when more
 * than one draft component qualifies, or one component would stand for two facts, the
 * match is ambiguous and the deterministic component is added beside them instead of
 * silently merging two things that may differ.
 */
function addBackFacts(
  kept: Kept[],
  groups: readonly FactGroup[],
  taken: Set<string>,
  limitations: string[],
): Kept[] {
  const picks = new Map(
    groups.map((g) => [
      g.key,
      candidatesFor(
        g,
        kept,
        g.kind === "datastore" ? DATASTORE_TYPES : DEPLOYMENT_TYPES,
      ),
    ]),
  );
  const claims = new Map<string, number>();
  for (const found of picks.values()) {
    if (found.length === 1) {
      const id = found[0].component.id;
      claims.set(id, (claims.get(id) ?? 0) + 1);
    }
  }

  const added: Kept[] = [];
  for (const group of groups) {
    const found = picks.get(group.key) ?? [];
    const label = `${group.kind} ${oneLine(group.label)}`;
    if (found.length === 1 && claims.get(found[0].component.id) === 1) {
      found[0].evidenceIds = sortIds([
        ...found[0].evidenceIds,
        ...group.evidenceIds,
      ]);
      continue;
    }
    const ambiguous = found.map((k) => k.component.id);
    const synthesized = synthesize(group, taken);
    added.push(synthesized);
    if (group.kind === "deployment") {
      limitations.push(
        `Deployment target ${oneLine(group.label)} ${oneLine(group.names.join(", "))} is represented as component ${synthesized.component.id} of type ${DEPLOYMENT_SYNTH_TYPE}: the schema has no deployment component type, so this is the closest valid type, not a claim that it is a third-party service.`,
      );
    }
    limitations.push(
      ambiguous.length > 0
        ? `Detected ${label} matched ${ambiguous.map((id) => oneLine(id)).join(", ")} ambiguously; nothing was merged and component ${synthesized.component.id} was added from the detector fact.`
        : `Added component ${synthesized.component.id} for the detected ${label}; the draft did not include it.`,
    );
  }
  return [...kept, ...added];
}

// ---------------------------------------------------------------------------
// Rule 3: bind gaps to components
// ---------------------------------------------------------------------------

type BindVia = "exact" | "directory" | "api_backend" | "all" | "none";
type Binding = { ids: string[]; via: BindVia; repoWide?: true };

const LOCKFILE =
  /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/i;

/**
 * Files that describe the whole repository or the whole deployment rather than one
 * component: dependency manifests, lockfiles and deployment configuration. A gap in one
 * of them is repository-wide however the detector scoped it. Without this, a manifest
 * that a synthesized datastore also lists (package.json is where its dependency was
 * found) would "own" the gap exactly, and the gap would bind to the datastore alone.
 * Uses the detectors' own file classifiers so the two cannot disagree about what a
 * manifest is.
 */
export function isRepoWideFile(path: string): boolean {
  const file = normalizePath(path);
  return (
    isManifest(file) ||
    LOCKFILE.test(file) ||
    isDockerfile(file) ||
    isCompose(file) ||
    isServerless(file) ||
    isTerraform(file) ||
    isVercel(file)
  );
}

function dirSegments(path: string): string[] {
  return path.split("/").slice(0, -1);
}

/**
 * How deep a directory root of `owner` reaches into `file`: the segment count of the
 * owner's directory when that directory is a prefix of the file's, else 0. Ownership
 * flows downward only, so a component rooted at src/api/ does not own a file in src/.
 * A file at the repository root has no directory root and owns nothing.
 */
function rootDepth(owner: string, file: string): number {
  const root = dirSegments(owner);
  const dir = dirSegments(file);
  return root.length <= dir.length && root.every((seg, i) => seg === dir[i])
    ? root.length
    : 0;
}

function fallbackBinding(components: readonly Component[]): Binding {
  const api = components.filter((c) => API_TYPES.includes(c.type));
  if (api.length > 0)
    return { ids: sortIds(api.map((c) => c.id)), via: "api_backend" };
  return components.length > 0
    ? { ids: sortIds(components.map((c) => c.id)), via: "all" }
    : { ids: [], via: "none" };
}

/**
 * Deterministic order: (1) components listing the file, (2) the components whose files
 * have a directory root that is the longest prefix of its directory, (3) api/backend components,
 * (4) every component. Repository-scope gaps, and gaps in a repository-wide file (a
 * manifest or deployment config), have no single owner and go straight to (3)/(4).
 */
export function bindGap(
  gap: ControlGap,
  components: readonly Component[],
): Binding {
  if (gap.scope === "repository") return fallbackBinding(components);
  if (isRepoWideFile(gap.file)) {
    return { ...fallbackBinding(components), repoWide: true };
  }

  const file = normalizePath(gap.file);
  const exact = components.filter((c) =>
    c.files.some((f) => normalizePath(f) === file),
  );
  if (exact.length > 0)
    return { ids: sortIds(exact.map((c) => c.id)), via: "exact" };

  const depth = new Map(
    components.map((c) => [
      c.id,
      Math.max(0, ...c.files.map((f) => rootDepth(normalizePath(f), file))),
    ]),
  );
  const best = Math.max(0, ...depth.values());
  if (best > 0) {
    const ids = components
      .filter((c) => depth.get(c.id) === best)
      .map((c) => c.id);
    return { ids: sortIds(ids), via: "directory" };
  }
  return fallbackBinding(components);
}

const VIA_TEXT: Record<BindVia, string> = {
  exact: "",
  directory: "the components whose directory root is the longest prefix",
  api_backend: "the api/backend component(s)",
  all: "every component, because none is an api or backend",
  none: "nothing, because the merge produced no components",
};

function bindAll(
  gaps: readonly ControlGap[],
  components: readonly Component[],
  limitations: string[],
): Map<string, string[]> {
  const bindings = new Map<string, string[]>();
  for (const gap of gaps) {
    const { ids, via, repoWide } = bindGap(gap, components);
    bindings.set(gap.id, ids);
    const bound = ids.length > 0 ? ids.join(", ") : "none";
    if (repoWide) {
      limitations.push(
        `Gap ${oneLine(gap.id)} (${oneLine(gap.control)}) is in ${oneLine(gap.file)}, a repository-wide file (dependency manifest or deployment config); repository-wide fallback binding used ${VIA_TEXT[via]}: ${bound}.`,
      );
    } else if (gap.scope !== "repository" && via !== "exact") {
      limitations.push(
        `Gap ${oneLine(gap.id)} (${oneLine(gap.control)}) in ${oneLine(gap.file)} has no component listing that file; fallback binding used ${VIA_TEXT[via]}: ${bound}.`,
      );
    }
  }
  return bindings;
}

// ---------------------------------------------------------------------------
// Rule 4: classify gaps
// ---------------------------------------------------------------------------

/** The evidence id detectGaps gave this gap, confirmed by rule id and not by position. */
function gapEvidenceIds(
  gap: ControlGap,
  evidence: readonly Evidence[],
): string[] {
  const rule = `gap:${gap.kind}`;
  const direct = evidence.find(
    (e) => e.id === gapEvidenceId(gap) && e.ruleId === rule,
  );
  if (direct) return [direct.id];
  return sortIds(
    evidence
      .filter(
        (e) =>
          e.ruleId === rule &&
          e.filePath === gap.file &&
          e.lineStart === Math.max(1, Math.floor(gap.line)),
      )
      .map((e) => e.id),
  );
}

function describeGap(
  gap: ControlGap,
  names: readonly string[],
  routes: readonly Route[],
): string {
  const route = gap.routeId
    ? routes.find((r) => r.id === gap.routeId)
    : undefined;
  const control = oneLine(gap.control);
  const subject = route
    ? `${route.method} ${oneLine(route.normalizedPath)}`
    : oneLine(gap.file);
  const where =
    names.length > 0
      ? ` on ${names.map((n) => oneLine(n, 60)).join(", ")}`
      : "";
  return `${control.charAt(0).toUpperCase()}${control.slice(1)} for ${subject}${where} could not be confirmed; it may be supplied by middleware, configuration or infrastructure this analysis cannot follow (detector certainty ${gap.certainty.toFixed(2)}).`;
}

function gapUnknowns(
  gaps: readonly ControlGap[],
  bindings: ReadonlyMap<string, string[]>,
  components: readonly Component[],
  routes: readonly Route[],
  evidence: readonly Evidence[],
  takenIds: Set<string>,
  limitations: string[],
): RankedUnknown[] {
  const nameOf = new Map(components.map((c) => [c.id, c.name]));
  const out: RankedUnknown[] = [];
  for (const gap of gaps) {
    if (gapEvidenceIds(gap, evidence).length === 0) {
      limitations.push(
        `Gap ${oneLine(gap.id)} has no evidence in the evidence array; a threat cannot cite it.`,
      );
    }
    if (gap.certainty >= GAP_ASSERT_CERTAINTY) continue;
    const ids = bindings.get(gap.id) ?? [];
    out.push({
      certainty: gap.certainty,
      control: gap.control,
      unknown: {
        id: uniqueId(`unknown-${gap.id}`, takenIds),
        description: describeGap(
          gap,
          ids.map((id) => nameOf.get(id) ?? id),
          routes,
        ),
        affectsComponentIds: ids,
      },
    });
  }
  return out;
}

/**
 * A model unknown is a duplicate of a gap-derived one only when BOTH hold: it names the
 * gap's control (compared on normalized words) and it affects at least one of the same
 * components. The gap-derived wording is kept.
 */
function dedupeModelUnknowns(
  modelUnknowns: readonly Unknown[],
  gapDerived: readonly RankedUnknown[],
): Unknown[] {
  return modelUnknowns.filter((m) => {
    const text = normalizedText(m.description);
    return !gapDerived.some(({ unknown, control }) => {
      const name = normalizedText(control ?? "");
      return (
        name.trim() !== "" &&
        text.includes(name) &&
        unknown.affectsComponentIds.some((id) =>
          m.affectsComponentIds.includes(id),
        )
      );
    });
  });
}

// ---------------------------------------------------------------------------
// Rule 5: cap
// ---------------------------------------------------------------------------

function capUnknowns(
  ranked: readonly RankedUnknown[],
  limitations: string[],
): Unknown[] {
  const sorted = [...ranked].sort(
    (a, b) =>
      a.certainty - b.certainty ||
      b.unknown.affectsComponentIds.length -
        a.unknown.affectsComponentIds.length ||
      byId(a.unknown.id, b.unknown.id),
  );
  if (sorted.length > MAX_UNKNOWNS) {
    limitations.push(
      `${sorted.length - MAX_UNKNOWNS} lower-ranked unknown(s) were dropped to keep the cap of ${MAX_UNKNOWNS}.`,
    );
  }
  return sorted.slice(0, MAX_UNKNOWNS).map((r) => r.unknown);
}

// ---------------------------------------------------------------------------
// Rule 6: layout
// ---------------------------------------------------------------------------

/** dagre, left to right. dagre returns node centres; React Flow wants top-left corners. */
export function layoutComponents(
  components: readonly Component[],
  flows: readonly DataFlow[],
): Component[] {
  // dagre keeps nodes in plain objects, so a model-supplied id such as "__proto__" would
  // silently lose its node. Nodes are keyed by position in the array instead.
  const index = new Map(components.map((c, i) => [c.id, `n${i}`]));
  const graph = new dagre.graphlib.Graph();
  graph.setGraph({ rankdir: "LR", nodesep: 40, ranksep: 90 });
  graph.setDefaultEdgeLabel(() => ({}));
  for (const key of index.values())
    graph.setNode(key, { width: NODE_WIDTH, height: NODE_HEIGHT });
  for (const f of flows) {
    const from = index.get(f.sourceId);
    const to = index.get(f.targetId);
    if (from !== undefined && to !== undefined) graph.setEdge(from, to);
  }
  dagre.layout(graph);
  return components.map((c, i) => {
    const node = graph.node(`n${i}`);
    return {
      ...c,
      position: {
        x: Math.round(node.x - NODE_WIDTH / 2),
        y: Math.round(node.y - NODE_HEIGHT / 2),
      },
    };
  });
}

// ---------------------------------------------------------------------------
// Rule 7: validate
// ---------------------------------------------------------------------------

function schemaIssues(
  name: string,
  items: readonly { id: string }[],
  schema: z.ZodType,
): MergeIssue[] {
  const issues: MergeIssue[] = [];
  const seen = new Set<string>();
  items.forEach((item, i) => {
    const parsed = schema.safeParse(item);
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        issues.push({
          code: "schema",
          path: `${name}[${i}].${issue.path.join(".")}`,
          message: issue.message,
        });
      }
    }
    if (seen.has(item.id)) {
      issues.push({
        code: "duplicate_id",
        path: `${name}[${i}].id`,
        message: `duplicate id ${item.id}`,
      });
    }
    seen.add(item.id);
  });
  return issues;
}

function danglingIssues(r: MergedArchitecture): MergeIssue[] {
  const components = new Set(r.components.map((c) => c.id));
  const boundaries = new Set(r.trustBoundaries.map((b) => b.id));
  const evidence = new Set(r.evidence.map((e) => e.id));
  const out: MergeIssue[] = [];
  const check = (ok: boolean, path: string, message: string): void => {
    if (!ok) out.push({ code: "dangling_reference", path, message });
  };
  r.dataFlows.forEach((f, i) => {
    check(
      components.has(f.sourceId),
      `dataFlows[${i}].sourceId`,
      `unknown component ${f.sourceId}`,
    );
    check(
      components.has(f.targetId),
      `dataFlows[${i}].targetId`,
      `unknown component ${f.targetId}`,
    );
    check(
      f.boundaryId === undefined || boundaries.has(f.boundaryId),
      `dataFlows[${i}].boundaryId`,
      `unknown trust boundary ${f.boundaryId}`,
    );
  });
  r.trustBoundaries.forEach((b, i) => {
    for (const id of b.componentIds) {
      check(
        components.has(id),
        `trustBoundaries[${i}].componentIds`,
        `unknown component ${id}`,
      );
    }
  });
  r.unknowns.forEach((u, i) => {
    for (const id of u.affectsComponentIds) {
      check(
        components.has(id),
        `unknowns[${i}].affectsComponentIds`,
        `unknown component ${id}`,
      );
    }
  });
  for (const [kind, refs] of [
    ["componentEvidence", r.componentEvidence],
    ["flowEvidence", r.flowEvidence],
  ] as const) {
    for (const [owner, ids] of refs) {
      for (const id of ids) {
        check(
          evidence.has(id),
          `${kind}.${owner}`,
          `evidence ${id} is not in the evidence array`,
        );
      }
    }
  }
  return out;
}

export function validateMerged(r: MergedArchitecture): MergeIssue[] {
  return [
    ...schemaIssues("components", r.components, ComponentSchema),
    ...schemaIssues("dataFlows", r.dataFlows, DataFlowSchema),
    ...schemaIssues("trustBoundaries", r.trustBoundaries, TrustBoundarySchema),
    ...schemaIssues("unknowns", r.unknowns, UnknownSchema),
    ...danglingIssues(r),
  ];
}

// ---------------------------------------------------------------------------
// mergeArchitecture
// ---------------------------------------------------------------------------

/**
 * The model proposes; this disposes. Pure: no I/O, and the same inputs give the same
 * output regardless of the order the evidence arrives in.
 */
export function mergeArchitecture(
  draft: ArchitectureDraft,
  facts: RepoFacts,
): MergedArchitecture {
  const limitations: string[] = [];
  const evidence = mergeEvidence(facts);
  const idx = buildRefIndex(facts, evidence);

  // 1. Drop invented references, and whatever pointed at what was dropped.
  const survivors = dropComponents(draft, idx, limitations);
  const survivorIds = new Set(survivors.map((k) => k.component.id));
  const trustBoundaries = pruneBoundaries(
    draft.trustBoundaries,
    survivorIds,
    limitations,
  );
  const flows = fixBoundaryRefs(
    dropFlows(draft, survivorIds, idx, limitations),
    trustBoundaries,
    limitations,
  );
  const modelUnknowns = pruneUnknowns(draft.unknowns, survivorIds, limitations);

  // 2. Add back certain facts. Ids of dropped draft components stay reserved so a
  //    synthesized component can never inherit their boundary or unknown references.
  const taken = new Set(draft.components.map((c) => c.id));
  const kept = addBackFacts(
    survivors,
    groupFacts(facts, evidence),
    taken,
    limitations,
  );
  const components = kept.map((k) => k.component);

  // 3. Bind gaps.
  const gaps = facts.controlGaps;
  const gapBindings = bindAll(gaps, components, limitations);

  // 4. Classify gaps; keep the evidence either way.
  const gapDerived = gapUnknowns(
    gaps,
    gapBindings,
    components,
    facts.detector.routes,
    evidence,
    new Set(draft.unknowns.map((u) => u.id)),
    limitations,
  );
  const remaining = dedupeModelUnknowns(modelUnknowns, gapDerived);

  // 5. Cap.
  const unknowns = capUnknowns(
    [
      ...gapDerived,
      ...remaining.map((unknown) => ({
        unknown,
        certainty: MODEL_UNKNOWN_RANK_CERTAINTY,
      })),
    ],
    limitations,
  );

  // 6. Layout.
  const dataFlows = flows.map((f) => f.flow);
  const laidOut = layoutComponents(components, dataFlows);

  const result: MergedArchitecture = {
    components: laidOut,
    dataFlows,
    trustBoundaries,
    unknowns,
    evidence,
    limitations,
    gapBindings,
    componentEvidence: new Map(
      kept.map((k) => [k.component.id, k.evidenceIds]),
    ),
    flowEvidence: new Map(flows.map((f) => [f.flow.id, f.evidenceIds])),
    issues: [],
  };

  // 7. Validate. Issues are returned; nothing throws.
  result.issues = validateMerged(result);
  return result;
}
