import type { Evidence } from "@/shared/schema";
import {
  rank,
  severityOf,
  type Severity,
  type SeverityLabel,
} from "@/server/scanners/cvss";
import {
  compareVersions,
  isFullVersion,
  isRegistryRange,
  minVersion,
} from "@/server/scanners/versions";

/**
 * Known vulnerabilities in direct npm dependencies, from OSV (https://osv.dev).
 *
 * What leaves the machine: package names and version strings, nothing else. No file
 * content, no paths, no repository name. Names are validated against the npm naming
 * rules before they are sent, so a hostile package.json cannot put arbitrary text on
 * the wire. What comes back is untrusted too, and is sanitised before it reaches a
 * summary (CLAUDE.md rule 3).
 *
 * If OSV is unreachable this returns no evidence and a limitation message instead of
 * failing the analysis: a missing vulnerability check is a caveat, not an error.
 *
 * Shapes here were captured from the live API, not assumed. Three things that real
 * data taught and the code depends on:
 *   - one record lists many affected packages (lodash, lodash-es, lodash.pick and a
 *     RubyGems gem), each with its own fix, so the entry must be matched by name AND
 *     ecosystem or the wrong package's fix gets reported;
 *   - one record can have several ranges (minimist has a 0.x fix and a 1.x fix), so the
 *     fix reported is the first APPLICABLE fixed version: the first fix of the range that
 *     contains the installed version, not the first fix listed in the record (0.2.1 for
 *     minimist@1.2.0 is below what is installed and would be wrong advice);
 *   - two advisories can describe the same issue and list each other as aliases, and
 *     querybatch returns both.
 */

export const OSV_API = "https://api.osv.dev";
export const OSV_TIMEOUT_MS = 10_000;
export const BATCH_SIZE = 500;
export const DETAIL_CONCURRENCY = 5;
export const MAX_EVIDENCE = 40;

/** Refuse a response bigger than this rather than parse it. OSV records are a few KB. */
const MAX_RESPONSE_CHARS = 2_000_000;

const SUMMARY_MAX_CHARS = 100;

/** What the scanner reads: only package.json and package-lock.json ever matter. */
export type ScanFile = { path: string; content: string };

export type DependencyRef = {
  name: string;
  /** The version sent to OSV. Exact from a lockfile, else the range's minimum. */
  version: string;
  versionExact: boolean;
  dev: boolean;
  /** The declared range, e.g. "^4.17.15". */
  range: string;
  file: string;
  line: number;
};

export type OsvEvidenceMetadata = {
  package: string;
  version: string;
  versionExact: boolean;
  dev: boolean;
  vulnId: string;
  cve: string[];
  aliases: string[];
  severityScore?: number;
  severityLabel?: SeverityLabel;
  fixedVersion?: string;
};

/**
 * Evidence plus this scanner's metadata. `package`, `version`, `versionExact`, `cve` and
 * `fixedVersion` are fields of EvidenceMetadataSchema and survive EvidenceSchema.parse().
 * `dev`, `vulnId`, `aliases`, `severityScore` and `severityLabel` are emitted for callers
 * but are not in the closed schema, so parse() strips them.
 */
export type OsvEvidence = Evidence & { metadata: OsvEvidenceMetadata };

export type OsvResult = {
  evidence: OsvEvidence[];
  /** Plain-language caveats to show alongside the results. Empty when all went well. */
  limitations: string[];
};

/** A parsed OSV vulnerability record, holding only what we use. */
export type OsvVuln = {
  id: string;
  summary: string;
  aliases: string[];
  withdrawn: boolean;
  severity: Severity;
  affected: {
    name: string;
    ecosystem: string;
    ranges: { type: string; events: Record<string, string>[] }[];
  }[];
};

export type OsvDeps = {
  fetch?: typeof fetch;
  /** Advisory records by id. Shared across scans in production; injected in tests. */
  cache?: Map<string, OsvVuln>;
  timeoutMs?: number;
};

// ---------------------------------------------------------------------------
// Dependencies from package.json and package-lock.json
// ---------------------------------------------------------------------------

/** Official npm name rules: lowercase, optional @scope/, URL-safe, at most 214 chars. */
const NPM_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

export function isValidPackageName(name: string): boolean {
  return name.length <= 214 && NPM_NAME.test(name);
}

function basename(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] ?? "";
}

function dirname(path: string): string {
  const parts = path.replace(/\\/g, "/").replace(/^\.\//, "").split("/");
  return parts.slice(0, -1).join("/");
}

function lineAtOffset(content: string, offset: number): number {
  if (offset === -1) return 1;
  let line = 1;
  for (let index = 0; index < offset; index++)
    if (content[index] === "\n") line += 1;
  return line;
}

/**
 * The line of a dependency's key inside its own section. The same name can be a
 * top-level config key first (`"prisma": { "seed": … }`), so the search starts at the
 * section's key; the first occurrence anywhere is the fallback, and line 1 after that.
 */
function dependencyLine(
  content: string,
  section: string,
  name: string,
): number {
  const key = `"${name}"`;
  const start = content.indexOf(`"${section}"`);
  const inSection = start === -1 ? -1 : content.indexOf(key, start);
  return lineAtOffset(
    content,
    inSection === -1 ? content.indexOf(key) : inSection,
  );
}

function parseJson(content: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(content);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function stringMap(value: unknown): Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};

  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string") out[key] = entry;
  }
  return out;
}

type Lockfile = {
  dir: string;
  packages: Record<string, { version?: string; link?: boolean }>;
};

/** Lockfiles by directory. Only lockfileVersion 2 and 3 carry a "packages" map. */
function readLockfiles(files: readonly ScanFile[]): Lockfile[] {
  const lockfiles: Lockfile[] = [];

  for (const file of files) {
    if (basename(file.path) !== "package-lock.json") continue;

    const parsed = parseJson(file.content);
    const packages = parsed?.packages;
    if (!packages || typeof packages !== "object" || Array.isArray(packages))
      continue;

    lockfiles.push({
      dir: dirname(file.path),
      packages: packages as Lockfile["packages"],
    });
  }
  return lockfiles;
}

/** The manifest's directory relative to the lockfile's: "" when they are the same. */
function relativeDir(lockfile: Lockfile, manifestDir: string): string {
  return manifestDir.slice(lockfile.dir.length).replace(/^\//, "");
}

/**
 * Whether a lockfile resolved this manifest's dependencies: the one in its own
 * directory always did; one in a directory above only when it lists the manifest as a
 * workspace member (npm records each member under its path, e.g. "packages/api"). A
 * standalone example or a subproject whose own lockfile was not loaded is not in it, and
 * the parent's versions for the same names would be reported as exact and be wrong.
 */
function resolvesManifest(lockfile: Lockfile, manifestDir: string): boolean {
  if (manifestDir === lockfile.dir) return true;
  const inside =
    lockfile.dir === "" || manifestDir.startsWith(`${lockfile.dir}/`);
  return (
    inside &&
    Object.prototype.hasOwnProperty.call(
      lockfile.packages,
      relativeDir(lockfile, manifestDir),
    )
  );
}

/** The lockfile in the manifest's directory, else the nearest workspace root above it. */
function lockfileFor(
  manifestDir: string,
  lockfiles: readonly Lockfile[],
): Lockfile | undefined {
  let best: Lockfile | undefined;
  for (const lockfile of lockfiles) {
    if (!resolvesManifest(lockfile, manifestDir)) continue;
    if (!best || lockfile.dir.length > best.dir.length) best = lockfile;
  }
  return best;
}

/**
 * The version a lockfile resolved for a direct dependency. In a workspace the lockfile
 * sits at the root and a package's own copy lives under its directory, so that path is
 * tried before the hoisted node_modules/<name>.
 */
function lockedVersion(
  name: string,
  manifestDir: string,
  lockfile: Lockfile,
): string | undefined {
  const relative = relativeDir(lockfile, manifestDir);
  const keys = [
    ...(relative ? [`${relative}/node_modules/${name}`] : []),
    `node_modules/${name}`,
  ];

  for (const key of keys) {
    const entry = lockfile.packages[key];
    if (
      entry &&
      !entry.link &&
      typeof entry.version === "string" &&
      isFullVersion(entry.version)
    ) {
      return entry.version;
    }
  }
  return undefined;
}

export type Collected = {
  dependencies: DependencyRef[];
  limitations: string[];
};

/**
 * Direct dependencies with the version to query. Pure: no network.
 *
 * Exact when a lockfile resolves it, otherwise the minimum of the declared range with
 * versionExact=false. A minimum is a floor, not what is installed, which is why it is
 * marked: OSV may report a flaw that a newer resolved version already fixed.
 */
export function collectDependencies(files: readonly ScanFile[]): Collected {
  const lockfiles = readLockfiles(files);
  const dependencies: DependencyRef[] = [];
  let skipped = 0;

  const manifests = files
    .filter((file) => basename(file.path) === "package.json")
    .sort((a, b) => a.path.localeCompare(b.path));

  for (const manifest of manifests) {
    const parsed = parseJson(manifest.content);
    if (!parsed) continue;

    const dir = dirname(manifest.path);
    const lockfile = lockfileFor(dir, lockfiles);

    const sections: [string, boolean][] = [
      ["dependencies", false],
      ["optionalDependencies", false],
      ["devDependencies", true],
    ];

    const seen = new Set<string>();
    for (const [section, dev] of sections) {
      for (const [name, range] of Object.entries(stringMap(parsed[section]))) {
        if (seen.has(name) || !isValidPackageName(name)) continue;
        seen.add(name);

        // An alias, git, file or link specifier installs something other than the
        // registry package of this name, so neither the lockfile nor the range says
        // what to ask OSV about: the lockfile's version belongs to another package.
        const locked =
          lockfile && isRegistryRange(range)
            ? lockedVersion(name, dir, lockfile)
            : undefined;
        const inferred = locked ? undefined : minVersion(range);
        const version = locked ?? inferred;

        if (!version || !isFullVersion(version)) {
          skipped += 1;
          continue;
        }

        dependencies.push({
          name,
          version,
          versionExact: locked !== undefined,
          dev,
          range,
          file: manifest.path,
          line: dependencyLine(manifest.content, section, name),
        });
      }
    }
  }

  const limitations: string[] = [];

  if (skipped > 0) {
    limitations.push(
      `${skipped} ${skipped === 1 ? "dependency was" : "dependencies were"} not checked against OSV ` +
        "because no version could be determined (a workspace, git or file specifier, " +
        "or a range with no lower bound).",
    );
  }

  // Said whatever the cause: there is no lockfile, it is over the 1 MiB the loader can
  // fetch, it is an unsupported version, or it does not list the package. The effect is
  // the same and is what the reader needs to know: OSV was asked about the lowest
  // version the range allows, which can report a flaw the installed version already
  // fixed.
  const inferred = dependencies.filter(
    (dependency) => !dependency.versionExact,
  ).length;
  if (inferred > 0) {
    limitations.push(
      `${inferred} ${inferred === 1 ? "dependency was" : "dependencies were"} checked at the lowest ` +
        `version of ${inferred === 1 ? "its" : "their"} declared range (versionExact is false) because no ` +
        "exact version was available from a package-lock.json. The lockfile may be missing, " +
        "larger than the 1 MiB that can be fetched, or not list " +
        `${inferred === 1 ? "it" : "them"}.`,
    );
  }

  return { dependencies, limitations };
}

// ---------------------------------------------------------------------------
// OSV requests
// ---------------------------------------------------------------------------

class OsvError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OsvError";
  }
}

/** One request, one timeout. The reason is short and never includes a response body. */
async function requestJson(
  doFetch: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<unknown> {
  let response: Response;
  try {
    response = await doFetch(url, {
      ...init,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (cause) {
    const name = cause instanceof Error ? cause.name : "";
    throw new OsvError(
      name === "TimeoutError" || name === "AbortError"
        ? `timed out after ${timeoutMs >= 1000 ? `${Math.round(timeoutMs / 1000)}s` : `${timeoutMs}ms`}`
        : "network error",
    );
  }

  if (!response.ok) throw new OsvError(`HTTP ${response.status}`);

  const text = await response.text();
  if (text.length > MAX_RESPONSE_CHARS)
    throw new OsvError("response too large");

  try {
    return JSON.parse(text);
  } catch {
    throw new OsvError("invalid JSON");
  }
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
}

/** Vulnerability ids for each query, by index. A package with none has no "vulns" key. */
export function parseBatchResponse(
  body: unknown,
  expected: number,
): string[][] {
  const results = (body as { results?: unknown } | null)?.results;
  if (!Array.isArray(results) || results.length !== expected) {
    throw new OsvError("unexpected querybatch shape");
  }

  return results.map((result) => {
    const vulns = (result as { vulns?: unknown } | null)?.vulns;
    if (!Array.isArray(vulns)) return [];

    return vulns
      .map((vuln) => (vuln as { id?: unknown } | null)?.id)
      .filter((id): id is string => typeof id === "string" && isSafeId(id));
  });
}

/** Ids go into a URL path, so only accept what OSV ids actually look like. */
export function isSafeId(id: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/.test(id);
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

/** Reads an OSV record defensively: it is external data and its shape is not promised. */
export function parseVuln(body: unknown): OsvVuln | undefined {
  if (!body || typeof body !== "object") return undefined;
  const record = body as Record<string, unknown>;
  if (typeof record.id !== "string" || !isSafeId(record.id)) return undefined;

  const severityEntries = Array.isArray(record.severity)
    ? (record.severity as { type?: unknown; score?: unknown }[]).filter(
        (entry) => entry && typeof entry === "object",
      )
    : [];
  const database = record.database_specific as
    { severity?: unknown } | null | undefined;

  const affected = Array.isArray(record.affected)
    ? (record.affected as Record<string, unknown>[])
        .filter((entry) => entry && typeof entry === "object")
        .map((entry) => {
          const pkg = (entry.package ?? {}) as {
            name?: unknown;
            ecosystem?: unknown;
          };
          const ranges = Array.isArray(entry.ranges)
            ? (entry.ranges as Record<string, unknown>[])
                .filter((range) => range && typeof range === "object")
                .map((range) => ({
                  type: typeof range.type === "string" ? range.type : "",
                  events: Array.isArray(range.events)
                    ? (range.events as Record<string, unknown>[])
                        .filter((event) => event && typeof event === "object")
                        .map((event) => {
                          const flat: Record<string, string> = {};
                          for (const [key, value] of Object.entries(event)) {
                            if (typeof value === "string") flat[key] = value;
                          }
                          return flat;
                        })
                    : [],
                }))
            : [];

          return {
            name: typeof pkg.name === "string" ? pkg.name : "",
            ecosystem: typeof pkg.ecosystem === "string" ? pkg.ecosystem : "",
            ranges,
          };
        })
    : [];

  return {
    id: record.id,
    summary: typeof record.summary === "string" ? record.summary : "",
    aliases: stringArray(record.aliases),
    withdrawn: typeof record.withdrawn === "string" && record.withdrawn !== "",
    severity: severityOf(severityEntries, database?.severity),
    affected,
  };
}

/** Runs `fn` over `items` with at most `limit` in flight, keeping input order. */
async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;

  async function worker(): Promise<void> {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, worker),
  );
  return results;
}

/** Process-wide, so a vulnerability fetched for one analysis is free for the next. */
const SHARED_CACHE = new Map<string, OsvVuln>();
const CACHE_LIMIT = 5000;

function remember(cache: Map<string, OsvVuln>, vuln: OsvVuln): void {
  if (cache.size >= CACHE_LIMIT) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(vuln.id, vuln);
}

// ---------------------------------------------------------------------------
// Reading a record
// ---------------------------------------------------------------------------

/**
 * The first applicable fixed version: the version that fixes this vulnerability *for the
 * installed version*.
 *
 * Walks the record's ranges for this package only and finds the introduced..fixed
 * interval that contains the installed version. Falls back to the lowest fix above the
 * installed version when no interval contains it (a version inferred from a range can
 * sit outside them), and to undefined when the interval containing it has no fix: it
 * ends in last_affected, or it is open-ended (an introduced with no closing event).
 */
export function fixedVersionFor(
  vuln: OsvVuln,
  name: string,
  version: string,
): string | undefined {
  const containing: string[] = [];
  const above: string[] = [];
  let unfixed = false;

  for (const entry of vuln.affected) {
    if (entry.name !== name || entry.ecosystem !== "npm") continue;

    for (const range of entry.ranges) {
      let introduced: string | undefined;

      for (const event of range.events) {
        if (event.introduced !== undefined) {
          introduced = event.introduced;
        } else if (event.fixed !== undefined) {
          const start = introduced ?? "0";
          if (compareVersions(event.fixed, version) > 0)
            above.push(event.fixed);
          if (
            compareVersions(version, start) >= 0 &&
            compareVersions(version, event.fixed) < 0
          ) {
            containing.push(event.fixed);
          }
          introduced = undefined;
        } else if (event.last_affected !== undefined) {
          const start = introduced ?? "0";
          if (
            compareVersions(version, start) >= 0 &&
            compareVersions(version, event.last_affected) <= 0
          ) {
            unfixed = true;
          }
          introduced = undefined;
        }
      }

      // An introduced left open affects every later version, and nothing fixes it.
      if (introduced !== undefined && compareVersions(version, introduced) >= 0)
        unfixed = true;
    }
  }

  const lowest = (versions: string[]): string | undefined =>
    versions.length === 0
      ? undefined
      : versions.reduce((low, next) =>
          compareVersions(next, low) < 0 ? next : low,
        );

  if (containing.length > 0) return lowest(containing);
  if (unfixed) return undefined;
  return lowest(above);
}

function sanitise(text: string): string {
  // Control characters and newlines have no place in a one-line summary, and OSV text
  // is external, so it is treated as data and never as an instruction. Filtered by code
  // point rather than by a regex class, so no control character has to appear in this
  // source file (they are easily mangled by tooling, and git treats NUL as binary).
  let printable = "";
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    printable += code < 32 || code === 127 ? " " : character;
  }

  const cleaned = printable.replace(/\s+/g, " ").trim();
  return cleaned.length <= SUMMARY_MAX_CHARS
    ? cleaned
    : `${cleaned.slice(0, SUMMARY_MAX_CHARS - 1).trimEnd()}…`;
}

/** "Prototype Pollution in lodash" -> "Prototype Pollution". */
function shortTitle(vuln: OsvVuln, packageName: string): string {
  const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const stripped = vuln.summary.replace(
    new RegExp(`\\s+in\\s+\`?${escaped}\`?\\s*$`, "i"),
    "",
  );
  return sanitise(stripped);
}

function summaryFor(
  ref: DependencyRef,
  vuln: OsvVuln,
  fixed: string | undefined,
): string {
  const cve = vuln.aliases.find((alias) => /^CVE-\d{4}-\d+$/.test(alias));
  const title = shortTitle(vuln, ref.name);
  const version = `${ref.name}@${ref.version}${ref.versionExact ? "" : " (inferred from range)"}`;
  const fix = fixed ? `, fixed in ${fixed}` : ", no fixed version listed";

  return `${version} affected by ${cve ?? vuln.id}${title ? ` (${title})` : ""}${fix}`;
}

// ---------------------------------------------------------------------------
// De-duplication
// ---------------------------------------------------------------------------

export type AliasGroup = {
  /** The highest-severity record in the group, which stands for it. */
  vuln: OsvVuln;
  /** Every record in the group, the representative included. */
  members: OsvVuln[];
};

/**
 * Groups advisories that are the same issue. OSV lists GHSA-a and GHSA-b as aliases of
 * one another, and querybatch returns both, so without this one flaw would take two of
 * the 40 slots. Connected components over id + aliases; the highest-severity record of
 * each group represents it, and the members are kept so the fix can cover all of them.
 */
export function collapseAliases(vulns: readonly OsvVuln[]): AliasGroup[] {
  const parent = new Map<string, string>();
  const find = (key: string): string => {
    let root = parent.get(key) ?? key;
    while ((parent.get(root) ?? root) !== root) root = parent.get(root) ?? root;
    parent.set(key, root);
    return root;
  };
  const union = (a: string, b: string): void => {
    parent.set(find(a), find(b));
  };

  for (const vuln of vulns) {
    for (const alias of vuln.aliases) union(vuln.id, alias);
  }

  const groups = new Map<string, AliasGroup>();
  for (const vuln of vulns) {
    const root = find(vuln.id);
    const group = groups.get(root);
    if (!group) {
      groups.set(root, { vuln, members: [vuln] });
      continue;
    }

    group.members.push(vuln);
    const better =
      rank(vuln.severity) > rank(group.vuln.severity) ||
      (rank(vuln.severity) === rank(group.vuln.severity) &&
        vuln.id < group.vuln.id);
    if (better) group.vuln = vuln;
  }
  return [...groups.values()];
}

/**
 * The version that fixes every advisory in a group: the highest fix any member needs.
 * Upgrading only to the representative's fix could leave a sibling advisory unresolved
 * (GHSA-35jh is fixed in 4.17.21 but its alias GHSA-r5fr in 4.18.0). Undefined when no
 * member lists a fix.
 */
export function fixedVersionForGroup(
  group: AliasGroup,
  name: string,
  version: string,
): string | undefined {
  let highest: string | undefined;
  for (const member of group.members) {
    const fixed = fixedVersionFor(member, name, version);
    if (
      fixed !== undefined &&
      (highest === undefined || compareVersions(fixed, highest) > 0)
    ) {
      highest = fixed;
    }
  }
  return highest;
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

type Finding = { ref: DependencyRef; vuln: OsvVuln; fixed: string | undefined };

function osvUrl(id: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

function unreachable(reason: string): OsvResult {
  return {
    evidence: [],
    limitations: [
      `OSV (api.osv.dev) could not be reached (${reason}), so dependencies were not checked ` +
        "for known vulnerabilities.",
    ],
  };
}

/**
 * Looks up every direct dependency and returns dependency evidence, at most 40 items,
 * highest severity first.
 */
export async function scanDependencies(
  files: readonly ScanFile[],
  deps: OsvDeps = {},
): Promise<OsvResult> {
  const doFetch = deps.fetch ?? fetch;
  const cache = deps.cache ?? SHARED_CACHE;
  const timeoutMs = deps.timeoutMs ?? OSV_TIMEOUT_MS;

  const { dependencies, limitations } = collectDependencies(files);
  if (dependencies.length === 0) return { evidence: [], limitations };

  // One query per distinct name@version, however many manifests declare it.
  const queries = [
    ...new Map(
      dependencies.map((ref) => [`${ref.name}@${ref.version}`, ref]),
    ).values(),
  ];

  const idsByQuery = new Map<string, string[]>();
  let unchecked = 0;
  let firstFailure: string | undefined;

  for (const group of chunk(queries, BATCH_SIZE)) {
    try {
      const body = await requestJson(
        doFetch,
        `${OSV_API}/v1/querybatch`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            queries: group.map((ref) => ({
              package: { name: ref.name, ecosystem: "npm" },
              version: ref.version,
            })),
          }),
        },
        timeoutMs,
      );

      const ids = parseBatchResponse(body, group.length);
      group.forEach((ref, index) =>
        idsByQuery.set(`${ref.name}@${ref.version}`, ids[index]),
      );
    } catch (cause) {
      unchecked += group.length;
      firstFailure ??= cause instanceof Error ? cause.message : "unknown error";
    }
  }

  if (idsByQuery.size === 0)
    return unreachable(firstFailure ?? "unknown error");

  const partial =
    unchecked > 0
      ? [
          `OSV could not be reached for ${unchecked} of ${queries.length} dependencies ` +
            `(${firstFailure}), so those were not checked.`,
        ]
      : [];

  // Fetch each distinct advisory once.
  const wanted = [...new Set([...idsByQuery.values()].flat())].filter(
    (id) => !cache.has(id),
  );
  let unavailable = 0;

  await mapWithConcurrency(wanted, DETAIL_CONCURRENCY, async (id) => {
    try {
      const body = await requestJson(
        doFetch,
        `${OSV_API}/v1/vulns/${encodeURIComponent(id)}`,
        { method: "GET" },
        timeoutMs,
      );
      const vuln = parseVuln(body);
      if (vuln) remember(cache, vuln);
      else unavailable += 1;
    } catch {
      unavailable += 1;
    }
  });

  const detailNote =
    unavailable > 0
      ? [
          `${unavailable} ${unavailable === 1 ? "advisory" : "advisories"} could not be ` +
            "retrieved from OSV and " +
            `${unavailable === 1 ? "is" : "are"} missing from the results.`,
        ]
      : [];

  // Findings per distinct dependency, with same-issue advisories collapsed.
  const findingsByQuery = new Map<
    string,
    { vuln: OsvVuln; fixed: string | undefined }[]
  >();
  for (const ref of queries) {
    const key = `${ref.name}@${ref.version}`;
    const records = (idsByQuery.get(key) ?? [])
      .map((id) => cache.get(id))
      .filter((vuln): vuln is OsvVuln => vuln !== undefined && !vuln.withdrawn);

    findingsByQuery.set(
      key,
      collapseAliases(records).map((group) => ({
        vuln: group.vuln,
        fixed: fixedVersionForGroup(group, ref.name, ref.version),
      })),
    );
  }

  const findings: Finding[] = [];
  for (const ref of dependencies) {
    for (const found of findingsByQuery.get(`${ref.name}@${ref.version}`) ??
      []) {
      findings.push({ ref, ...found });
    }
  }

  // Highest severity first; then runtime before dev, since a flaw that ships matters
  // more than one in a build tool; then name and id, so the order is total and stable.
  findings.sort(
    (a, b) =>
      rank(b.vuln.severity) - rank(a.vuln.severity) ||
      Number(a.ref.dev) - Number(b.ref.dev) ||
      a.ref.name.localeCompare(b.ref.name) ||
      a.vuln.id.localeCompare(b.vuln.id) ||
      a.ref.file.localeCompare(b.ref.file),
  );

  const capNote =
    findings.length > MAX_EVIDENCE
      ? [
          `${findings.length - MAX_EVIDENCE} lower-severity dependency findings were omitted ` +
            `(the report keeps the ${MAX_EVIDENCE} most severe).`,
        ]
      : [];

  const evidence: OsvEvidence[] = findings
    .slice(0, MAX_EVIDENCE)
    .map(({ ref, vuln, fixed }, index) => ({
      id: `ev-osv-${index + 1}`,
      kind: "dependency",
      source: "osv",
      summary: summaryFor(ref, vuln, fixed),
      filePath: ref.file,
      lineStart: ref.line,
      ruleId: vuln.id,
      url: osvUrl(vuln.id),
      metadata: {
        package: ref.name,
        version: ref.version,
        versionExact: ref.versionExact,
        dev: ref.dev,
        vulnId: vuln.id,
        cve: vuln.aliases.filter((alias) => /^CVE-\d{4}-\d+$/.test(alias)),
        aliases: [...vuln.aliases],
        ...(vuln.severity.score !== undefined
          ? { severityScore: vuln.severity.score }
          : {}),
        ...(vuln.severity.label ? { severityLabel: vuln.severity.label } : {}),
        ...(fixed ? { fixedVersion: fixed } : {}),
      },
    }));

  return {
    evidence,
    limitations: [...limitations, ...partial, ...detailNote, ...capNote],
  };
}
