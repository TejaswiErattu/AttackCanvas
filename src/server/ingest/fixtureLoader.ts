/**
 * A local fixture-repo loader path (Prompt U, Parts 1-2).
 *
 * The canary repo at tests/fixtures/canary-repo/ was only reachable from a test-only
 * helper (tests/canaryRepo.ts), so nothing could drive the real pipeline against it: the
 * live canary test hand-calls each stage instead of `runAnalysis`. This module is the
 * loader path that closes that gap -- a `fixture:<name>` "repo URL" resolves to a
 * directory under tests/fixtures/ and is read through the same classification,
 * file-count and size policy the real GitHub loader uses (selectCandidates and
 * applySizePolicy, both from src/server/ingest/loader.ts -- reused, not reimplemented),
 * so `createAnalysis("fixture:canary-repo")` exercises the genuine end-to-end pipeline:
 * detectors, Semgrep, OSV, architecture, STRIDE, scoring, and the post-output checks in
 * src/server/security/injection.ts.
 *
 * Dev and test only, by construction, not by convention: fixturesEnabled() is checked
 * inside loadFixtureRepo (not only at the URL-parsing dispatch point one layer up), so a
 * fixture URL cannot be routed around the check. It is a fail-closed ALLOWLIST of
 * exactly {"development", "test"}, not a `!== "production"` denylist, so an unset
 * NODE_ENV or an unexpected value (a typo, a future environment name) is refused, not
 * silently accepted -- a deployed instance rejects it as an ordinary invalid repo before
 * touching the filesystem. The public route (src/app/api/analyze/route.ts) is a second,
 * independent wall: it validates repoUrl with the plain, fixture-unaware parseGitHubUrl,
 * never this module's dispatch, so a fixture: URL 400s there in every environment, not
 * only production -- see tests/analyzeRoute.test.ts.
 *
 * Deliberately NOT the same guarantee tests/canaryRepo.ts has ("nothing in src/ imports
 * it"): production code needs a loader path that exists, which is exactly the gap this
 * closes. The environment check plus the route's independent validation are the
 * substitute guarantees.
 *
 * Path safety: a fixture name is restricted to lowercase letters, digits and hyphens
 * (NAME_PATTERN) before it ever touches the filesystem, which already rules out "..",
 * "/", "\", a leading "/", NUL bytes and any encoded form of them (none of those
 * characters are in the allowed set, and no decoding is ever applied to the raw input).
 * On top of that, every accepted file is required to be a genuine regular file whose
 * REALPATH resolves inside the fixture root (isPlainFileWithinRoot). This is NOT mere
 * defense in depth: measured directly (see "does not descend into a symlinked
 * DIRECTORY" in tests/fixtureLoader.test.ts), Node's recursive readdirSync DOES follow
 * a symlinked directory and lists files through it, even though it correctly reports
 * the symlink itself as `isSymbolicLink()` / not `isFile()`. Without the realpath
 * check, a symlinked directory placed inside tests/fixtures/<repo>/ pointing outside
 * the repo would leak that outside content into the loaded repo under a path like
 * "escape/secret.js". A plain symlinked FILE (not a directory) IS excluded by
 * readdirSync's own isFile() filter before isPlainFileWithinRoot ever sees it -- that
 * narrower case is defense in depth; the directory case is load-bearing.
 */

import { lstatSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";
import type { RepoSummary } from "@/shared/schema";
import {
  IngestError,
  applySizePolicy,
  detectLanguages,
  selectCandidates,
  type LoadedRepo,
  type SizedCandidate,
} from "@/server/ingest/loader";
import type { parseGitHubUrl } from "@/server/ingest/urlParser";

/** The shape parseGitHubUrl returns; there is no exported name for it to reuse. */
type UrlParseResult = ReturnType<typeof parseGitHubUrl>;

/** The scheme a fixture "repo URL" uses in place of a github.com URL. */
export const FIXTURE_PREFIX = "fixture:";

/** The reserved owner every fixture repo is reported under. Never a real GitHub owner. */
export const FIXTURE_OWNER = "attackcanvas-fixtures";

/** Where fixture repos live, relative to the process cwd (the project root). */
export const FIXTURE_ROOT = join("tests", "fixtures");

/**
 * A fixture name: lowercase letters, digits and hyphens, no leading/trailing/doubled
 * hyphen, at least one character -- the same shape loadPrompt requires of a prompt name
 * (src/server/ai/prompts.ts). Anchored on both ends, so "canary-repo/../../etc" or
 * "canary-repo\x00" is rejected by the pattern itself, not by a later filesystem check.
 */
const NAME_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** The only two NODE_ENV values that ever enable fixture repos. */
const FIXTURE_ENABLED_ENVS = new Set(["development", "test"]);

/**
 * Fixture repos are refused outside development and test, so a deployed instance never
 * exposes tests/fixtures/ through the analyze API. Checked as a function, not a
 * module-level constant, so a test can flip process.env.NODE_ENV and see the effect
 * without reimporting the module.
 *
 * Fail-closed allowlist, not a denylist: enabled ONLY when NODE_ENV is exactly
 * "development" or "test". `!== "production"` was rejected on purpose -- it would
 * enable fixtures for an unset NODE_ENV, a typo'd value, or any future environment name
 * (staging, preview, ...) nobody has thought to deny yet. An allowlist fails safe by
 * construction: a new or missing value is refused, not silently accepted.
 */
export function fixturesEnabled(): boolean {
  return FIXTURE_ENABLED_ENVS.has(process.env.NODE_ENV ?? "");
}

/**
 * True when `input` names a fixture repo rather than a github.com URL. Exact-prefix
 * match, no trimming: " fixture:x" (leading whitespace) or "Fixture:x" (wrong case) is
 * not a fixture URL at all and falls through to parseGitHubUrl in the pipeline's
 * dispatch, which will reject it as an ordinary invalid URL. isFixtureUrl and
 * parseFixtureUrl agree on this by construction -- both test the raw string against the
 * same FIXTURE_PREFIX with no normalisation in between, so there is no input for which
 * one says "this is a fixture" and the other disagrees.
 */
export function isFixtureUrl(input: string): boolean {
  return typeof input === "string" && input.startsWith(FIXTURE_PREFIX);
}

/**
 * Parses a `fixture:<name>` URL into the same shape parseGitHubUrl returns, so the
 * pipeline's dispatch can treat the two uniformly. `<name>` becomes the "repo"; the
 * "owner" is always FIXTURE_OWNER, a value parseGitHubUrl can never produce.
 *
 * Exact syntax only: no trimming, so "fixture:canary-repo " (trailing space) or
 * " fixture:canary-repo" (leading space) fails NAME_PATTERN or the prefix check rather
 * than silently having whitespace stripped into something that happens to validate.
 *
 * Disabled outside development/test, so a `fixture:` URL submitted to a deployed
 * instance is an ordinary INVALID_URL rejection, not a 500 or a filesystem read. (In
 * practice the public route never reaches this function at all -- see the module
 * header -- but the check stays here too, since this function is also the pipeline's
 * DEFAULT_DEPS dispatch target and must not depend on its caller for safety.)
 */
export function parseFixtureUrl(input: string): UrlParseResult {
  if (!fixturesEnabled()) {
    return { ok: false, code: "INVALID_URL", message: "Fixture repos are not available" };
  }
  if (typeof input !== "string" || !input.startsWith(FIXTURE_PREFIX)) {
    return { ok: false, code: "INVALID_URL", message: "Not a fixture: URL" };
  }
  const name = input.slice(FIXTURE_PREFIX.length);
  if (!NAME_PATTERN.test(name)) {
    return {
      ok: false,
      code: "INVALID_URL",
      message: "Fixture name must be lowercase letters, digits and hyphens",
    };
  }
  return { ok: true, owner: FIXTURE_OWNER, repo: name };
}

/**
 * True when `absPath` is a genuine regular file (not a symlink, directory, device, etc.)
 * whose fully-resolved real path is inside `root`'s real path.
 *
 * Load-bearing, not just defense in depth: see the module header for the measured
 * finding that Node's recursive readdirSync DOES follow a symlinked directory, so this
 * realpath check is what actually stops a symlinked directory from leaking content from
 * outside the fixture root. It doubles as the (narrower, already-redundant-in-practice)
 * guard against a directly symlinked FILE, and against `root` itself being a symlink.
 * lstat, not stat, so a symlink is identified as a symlink rather than resolved through
 * before the type check runs.
 */
export function isPlainFileWithinRoot(root: string, absPath: string): boolean {
  let lst: ReturnType<typeof lstatSync>;
  try {
    lst = lstatSync(absPath);
  } catch {
    return false; // gone between listing and checking -- treat as unreadable
  }
  if (!lst.isFile()) return false; // excludes symlinks, directories, devices, FIFOs, ...

  let real: string;
  let realRoot: string;
  try {
    real = realpathSync(absPath);
    realRoot = realpathSync(root);
  } catch {
    return false;
  }
  const rel = relative(realRoot, real);
  return rel !== "" && rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

/** Every plain file under `dir`, as repository-relative POSIX paths, sorted for determinism. */
function listFixtureFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile()) // Dirent.isFile() is false for a symlink (lstat-based)
    .map((entry) => join(entry.parentPath, entry.name).slice(dir.length + 1))
    .map((path) => path.split(sep).join("/"))
    .sort();
}

/**
 * Reads a fixture repo from tests/fixtures/<repo>/ as a LoadedRepo, as if the real
 * GitHub loader had fetched it.
 *
 * Classification, the ignored-path rule and the MAX_FILES cap all come from
 * selectCandidates; the per-file and total-byte-budget cap come from applySizePolicy --
 * both imported from src/server/ingest/loader.ts, the same functions loadRepositoryWith
 * itself calls, so a fixture repo is filtered by identical rules to a real one.
 *
 * Deliberately does NOT enforce loadRepository's MIN_SOURCE_FILES: the canary repo
 * exists to prove an injection defense, not to look like a real codebase, and has only
 * two source files.
 */
export async function loadFixtureRepo(
  owner: string,
  repo: string,
  ref?: string,
): Promise<LoadedRepo> {
  if (!fixturesEnabled()) {
    throw new IngestError("REPO_NOT_FOUND", "fixture repos are not available");
  }
  if (owner !== FIXTURE_OWNER) {
    throw new IngestError("REPO_NOT_FOUND", `unknown fixture owner "${owner}"`);
  }
  if (!NAME_PATTERN.test(repo)) {
    throw new IngestError("REPO_NOT_FOUND", `invalid fixture name "${repo}"`);
  }

  const dir = join(FIXTURE_ROOT, repo);
  let isDirectory: boolean;
  try {
    // Real stat (follows symlinks): a symlinked fixture directory that ultimately
    // resolves outside tests/fixtures/ is caught below by the realpath containment
    // check, not here -- this only confirms something exists to list.
    isDirectory = statSync(dir).isDirectory();
  } catch {
    isDirectory = false;
  }
  if (!isDirectory) {
    throw new IngestError("REPO_NOT_FOUND", `no fixture repo named "${repo}"`);
  }

  // The whole fixture directory must itself resolve inside FIXTURE_ROOT -- guards
  // against tests/fixtures/<repo> being a symlink to somewhere else entirely.
  const realRoot = realpathSync(FIXTURE_ROOT);
  const realDir = realpathSync(dir);
  const dirRel = relative(realRoot, realDir);
  if (dirRel === ".." || dirRel.startsWith(`..${sep}`) || isAbsolute(dirRel)) {
    throw new IngestError("REPO_NOT_FOUND", `fixture "${repo}" escapes the fixture root`);
  }

  const allPaths = listFixtureFiles(dir);
  const safePaths = allPaths.filter((path) => isPlainFileWithinRoot(dir, join(dir, path)));
  const unsafeCount = allPaths.length - safePaths.length;

  // Classification, the ignored-path rule and MAX_FILES: identical to the real loader.
  // `size` is the on-disk byte length, used the same way a GitHub tree entry's `size`
  // is used -- as a hint; the real cap is enforced on content below, by applySizePolicy.
  const entries = safePaths.map((path) => ({
    path,
    type: "file" as const,
    size: statSync(join(dir, path)).size,
  }));
  const selection = selectCandidates(entries);

  let unreadableCount = 0;
  const sized: SizedCandidate[] = [];
  for (const { path, tier, reason } of selection.candidates) {
    let content: string;
    try {
      content = readFileSync(join(dir, path), "utf8");
    } catch {
      // Permission denied, or removed between listing and reading: skip it rather than
      // fail the whole fixture load (CLAUDE.md rule 5's "never throws" spirit, applied
      // to a loader instead of a model call).
      unreadableCount += 1;
      continue;
    }
    sized.push({
      file: { path, content, tier, reason },
      bytes: Buffer.byteLength(content, "utf8"),
    });
  }

  // Per-file and total-byte-budget policy: identical to the real loader.
  const sizePolicy = applySizePolicy(sized);

  const summary: RepoSummary = {
    owner,
    name: repo,
    ref: ref ?? "fixture",
    languages: detectLanguages(sizePolicy.files.map((f) => f.path)),
    frameworks: [],
    fileCountAnalyzed: sizePolicy.files.length,
    analyzedAt: new Date().toISOString(),
  };

  return {
    summary,
    files: sizePolicy.files,
    skipped: {
      ignored: selection.ignored + sizePolicy.ignored + unsafeCount + unreadableCount,
      overLimit: selection.overLimit + sizePolicy.overLimit,
    },
    truncated: selection.overLimit + sizePolicy.overLimit > 0,
  };
}
