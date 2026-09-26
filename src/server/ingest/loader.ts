import type { ErrorCode, RepoSummary } from "@/shared/schema";
import {
  GitHubMcpError,
  getFileContent,
  getRepoMetadata,
  listTree,
  type RepoMetadata,
  type TreeResult,
} from "@/server/mcp/githubClient";
import {
  LOCKFILE_REASON,
  maxBytesFor,
  classifyPath,
  isSourceFile,
  type Tier,
} from "@/server/ingest/classifier";

export const MAX_TREE_ENTRIES = 20_000;
export const MAX_FILES = 300;
export const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
export const FETCH_CONCURRENCY = 5;
export const MIN_SOURCE_FILES = 3;

/**
 * How much the tree may CLAIM before selection stops fetching: twice the byte budget.
 * Tree sizes can be missing or wrong, so the real budget (applySizePolicy) is still
 * enforced on downloaded bytes; this only stops a 300-file selection from downloading
 * many times the budget to fill it. A missing size counts as 0, so an entry with no size
 * is never held back by it.
 */
export const MAX_CLAIMED_BYTES = 2 * MAX_TOTAL_BYTES;

export type LoadedTier = Exclude<Tier, "ignore">;

export type LoadedFile = {
  path: string;
  content: string;
  tier: LoadedTier;
  reason: string;
};

export type LoadedRepo = {
  summary: RepoSummary;
  files: LoadedFile[];
  skipped: { ignored: number; overLimit: number };
  /** True when the repo had more worth loading than the limits allowed. */
  truncated: boolean;
};

/** A repository we cannot usefully analyse, carrying the ErrorCode to show the user. */
export class IngestError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "IngestError";
  }
}

/** The slice of githubClient the loader needs, so tests can supply a fake. */
export type LoaderDeps = {
  getRepoMetadata(owner: string, repo: string): Promise<RepoMetadata>;
  listTree(owner: string, repo: string, ref: string): Promise<TreeResult>;
  getFileContent(
    owner: string,
    repo: string,
    ref: string,
    path: string,
  ): Promise<string>;
  now?: () => Date;
};

const TIER_RANK: Record<LoadedTier, number> = { high: 0, medium: 1, low: 2 };

export type Candidate = { path: string; tier: LoadedTier; reason: string };

/** Runs `fn` over `items` with at most `limit` in flight, keeping input order. */
export async function mapWithConcurrency<T, R>(
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

/**
 * Classifies a tree and picks what to fetch: high before medium before low, path order
 * within a tier, at most MAX_FILES of them, and no further once the sizes the tree
 * claims add up to MAX_CLAIMED_BYTES. Everything past that is `overLimit`.
 *
 * Tree sizes are not trusted for the budget itself: GitHub may omit them or get them
 * wrong, so the byte budget is enforced later, on what was actually downloaded. They
 * are trusted only as a ceiling on how much to download in the first place.
 */
export function selectCandidates(entries: TreeResult["entries"]): {
  candidates: Candidate[];
  ignored: number;
  overLimit: number;
} {
  const all: (Candidate & { size: number })[] = [];
  let ignored = 0;

  for (const entry of entries) {
    if (entry.type !== "file") continue;
    const { tier, reason } = classifyPath(entry.path, entry.size);
    if (tier === "ignore") {
      ignored += 1;
    } else {
      all.push({ path: entry.path, tier, reason, size: entry.size ?? 0 });
    }
  }

  all.sort(
    (a, b) =>
      TIER_RANK[a.tier] - TIER_RANK[b.tier] || a.path.localeCompare(b.path),
  );

  const candidates: Candidate[] = [];
  let claimed = 0;
  for (const { path, tier, reason, size } of all) {
    if (candidates.length >= MAX_FILES) break;
    if (claimed + size > MAX_CLAIMED_BYTES) continue; // a smaller or unsized entry may still fit
    claimed += size;
    candidates.push({ path, tier, reason });
  }

  return {
    candidates,
    ignored,
    overLimit: all.length - candidates.length,
  };
}

/** Files that may be sent to a model. Lockfiles are for OSV only and never are. */
export function modelBoundFiles(files: readonly LoadedFile[]): LoadedFile[] {
  return files.filter((file) => file.reason !== LOCKFILE_REASON);
}

/** An already-classified file plus its real, measured byte length. */
export type SizedCandidate = { file: LoadedFile; bytes: number };

export type SizePolicyResult = {
  files: LoadedFile[];
  /** Over its own per-file cap (maxBytesFor) -- too big to load at all. */
  ignored: number;
  /** Would fit alone, but the shared byte budget was already spent by an earlier file. */
  overLimit: number;
};

/**
 * The per-file and total-byte-budget policy every loader applies once it has real file
 * content in hand, factored out so the GitHub loader (loadRepositoryWith, below) and the
 * local fixture loader (src/server/ingest/fixtureLoader.ts) enforce the exact same rule
 * from the exact same code, not two copies of the same constants.
 *
 * Candidates are consumed in the order given: caller commits in priority order (tier,
 * then path -- selectCandidates already sorts that way) against the real byte length, so
 * the running total can never exceed `totalBudget` regardless of what a tree listing
 * claimed, and a file that no longer fits is skipped so a later, smaller one still can.
 */
export function applySizePolicy(
  candidates: readonly SizedCandidate[],
  totalBudget: number = MAX_TOTAL_BYTES,
): SizePolicyResult {
  const files: LoadedFile[] = [];
  let remaining = totalBudget;
  let ignored = 0;
  let overLimit = 0;

  for (const { file, bytes } of candidates) {
    if (bytes > maxBytesFor(file.path)) {
      ignored += 1; // too big for this file's own cap (the tree size may be missing or wrong)
    } else if (bytes > remaining) {
      overLimit += 1;
    } else {
      remaining -= bytes;
      files.push(file);
    }
  }

  return { files, ignored, overLimit };
}

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ts: "TypeScript",
  tsx: "TypeScript",
  js: "JavaScript",
  jsx: "JavaScript",
  mjs: "JavaScript",
  cjs: "JavaScript",
  py: "Python",
  rb: "Ruby",
  go: "Go",
  java: "Java",
  kt: "Kotlin",
  kts: "Kotlin",
  php: "PHP",
  rs: "Rust",
  cs: "C#",
  swift: "Swift",
  scala: "Scala",
  vue: "Vue",
  svelte: "Svelte",
  sql: "SQL",
};

/** Languages by file count, most common first. Used when GitHub does not report any. */
export function detectLanguages(paths: readonly string[]): string[] {
  const counts = new Map<string, number>();
  for (const path of paths) {
    const language =
      LANGUAGE_BY_EXTENSION[
        path.slice(path.lastIndexOf(".") + 1).toLowerCase()
      ];
    if (language) counts.set(language, (counts.get(language) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([language]) => language);
}

/**
 * The exact messages githubClient.ts raises when a file's content is not text: binary
 * bytes (decodeText), a directory, a submodule or symlink, or an encoding it cannot
 * read (parseContentsResponse, parseFileContent). Each is `${path}${suffix}` for the
 * path that was asked for, or a fixed string. tests/loader.test.ts produces them with
 * githubClient's own functions, so a change of wording there fails a test here.
 */
const NOT_TEXT_SUFFIXES = [
  " looks binary, not text",
  " is a directory, not a file",
  " is not a regular file",
  " came back in an unsupported encoding",
] as const;
const NOT_TEXT_MESSAGES: ReadonlySet<string> = new Set([
  "expected a file but received a directory",
]);

/**
 * A fetch failure that means "this is not text", not "GitHub is unwell".
 *
 * Not every GITHUB_UNAVAILABLE: that code also covers a 5xx from the REST API
 * (restErrorFor) and a network failure ("fetch failed"), and treating those as "not text"
 * silently dropped whatever file they hit -- src/middleware/auth.ts included -- counted it
 * as ignored, and left `truncated` false. Those now propagate, like the TIMEOUT and
 * UPSTREAM_RATE_LIMITED failures already do: a load that could not read a file it
 * selected fails, retryably, instead of analysing a repository with a hole in it.
 */
function isNotText(cause: unknown, path: string): boolean {
  if (!(cause instanceof GitHubMcpError) || cause.code !== "GITHUB_UNAVAILABLE") return false;
  return (
    NOT_TEXT_MESSAGES.has(cause.message) ||
    NOT_TEXT_SUFFIXES.some((suffix) => cause.message === `${path}${suffix}`)
  );
}

/**
 * A file the client refused as too large (over its 1 MiB response cap). The classifier
 * keeps such a file out of the fetch when the tree reports its size, but the tree size
 * can be missing or wrong. The per-file cap is a policy about that one file, exactly as
 * it is when the size is known, so the file is skipped and counted as ignored instead of
 * failing the whole load. A lockfile is the same case with the same answer: the
 * dependency scan falls back to version ranges without it.
 */
function isTooLarge(cause: unknown): boolean {
  return cause instanceof GitHubMcpError && cause.code === "REPO_TOO_LARGE";
}

export async function loadRepositoryWith(
  deps: LoaderDeps,
  owner: string,
  repo: string,
  ref?: string,
): Promise<LoadedRepo> {
  const metadata = await deps.getRepoMetadata(owner, repo);
  const resolvedRef = ref ?? metadata.defaultBranch;
  const tree = await deps.listTree(owner, repo, resolvedRef);

  if (tree.entries.length > MAX_TREE_ENTRIES) {
    throw new IngestError(
      "REPO_TOO_LARGE",
      `the tree has ${tree.entries.length} entries; the limit is ${MAX_TREE_ENTRIES}`,
    );
  }

  const selection = selectCandidates(tree.entries);
  let { ignored, overLimit } = selection;

  const fetched = await mapWithConcurrency(
    selection.candidates,
    FETCH_CONCURRENCY,
    async (file) => {
      try {
        const content = await deps.getFileContent(
          owner,
          repo,
          resolvedRef,
          file.path,
        );
        return { file, content };
      } catch (cause) {
        if (isNotText(cause, file.path) || isTooLarge(cause)) {
          return { file, content: undefined };
        }
        throw cause;
      }
    },
  );

  // Real UTF-8 byte length against the shared per-file/total-budget policy (see
  // applySizePolicy). "not text" and "too large to fetch" are fetch-layer outcomes the
  // shared policy doesn't know about, so they are filtered out here first.
  const sized: SizedCandidate[] = [];
  for (const { file, content } of fetched) {
    if (content === undefined) {
      ignored += 1; // not text, or over the client's response cap
      continue;
    }
    sized.push({
      file: { path: file.path, content, tier: file.tier, reason: file.reason },
      bytes: Buffer.byteLength(content, "utf8"),
    });
  }
  const sizePolicy = applySizePolicy(sized, MAX_TOTAL_BYTES);
  const files = sizePolicy.files;
  ignored += sizePolicy.ignored;
  overLimit += sizePolicy.overLimit;

  const sourceCount = files.filter((file) => isSourceFile(file.path)).length;
  if (sourceCount < MIN_SOURCE_FILES) {
    throw new IngestError(
      "INSUFFICIENT_CODE",
      `found ${sourceCount} source files; at least ${MIN_SOURCE_FILES} are needed`,
    );
  }

  const paths = files.map((file) => file.path);
  const languages = metadata.languages?.length
    ? metadata.languages
    : detectLanguages(paths);

  return {
    summary: {
      owner,
      name: repo,
      ref: resolvedRef,
      languages,
      frameworks: [], // detectors fill this in a later stage
      fileCountAnalyzed: files.length,
      analyzedAt: (deps.now?.() ?? new Date()).toISOString(),
    },
    files,
    skipped: { ignored, overLimit },
    truncated: overLimit > 0 || tree.truncated,
  };
}

/** loadRepositoryWith() against the real GitHub client. */
export function loadRepository(
  owner: string,
  repo: string,
  ref?: string,
): Promise<LoadedRepo> {
  return loadRepositoryWith(
    { getRepoMetadata, listTree, getFileContent },
    owner,
    repo,
    ref,
  );
}
