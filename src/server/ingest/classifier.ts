/**
 * Decides, from a path and a size alone, whether a repository file is worth fetching
 * and how much it matters. Pure: no I/O, no content. That is what lets the loader
 * refuse to fetch a file (CLAUDE.md rule 3: never fetch .env) instead of fetching and
 * then discarding it.
 */

export type Tier = "high" | "medium" | "low" | "ignore";

export type Classification = { tier: Tier; reason: string };

/** Files larger than this are ignored (200 KB). */
export const MAX_FILE_BYTES = 200 * 1024;

/**
 * The one lockfile the dependency scanner reads, and so the one exempt from
 * MAX_FILE_BYTES. It is routinely larger than 200 KB, and without it every dependency
 * is scanned at the lowest version its range allows instead of the version installed.
 *
 * The exemption is bounded, not open: 1 MiB is the GitHub client's own response cap
 * (MAX_RESPONSE_BYTES in githubClient.ts, on both the MCP and REST paths; the Contents
 * API returns no inline content above 1 MB either), so a bigger file cannot be
 * retrieved at all. A test pins the two numbers together.
 *
 * It is safe to relax for this file because a lockfile is never sent to a model
 * (modelBoundFiles drops it) and is parsed as JSON, not read as prose. Every other file,
 * including the other lockfiles, keeps the 200 KB limit, and the 2 MiB total budget in
 * the loader is unchanged.
 */
export const MAX_LOCKFILE_BYTES = 1024 * 1024;

/** Files exempt from MAX_FILE_BYTES, up to MAX_LOCKFILE_BYTES. */
const SCANNED_LOCKFILES = new Set(["package-lock.json"]);

/** Reason attached to lockfiles. They are used for OSV only, never sent to a model. */
export const LOCKFILE_REASON = "dependencies";

const IGNORED_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  ".next",
  "out",
  "coverage",
  "vendor",
  ".git",
  "__pycache__",
  ".venv",
  "public",
  "assets",
]);

const BINARY_EXTENSIONS = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "svg",
  "ico",
  "webp",
  "bmp",
  "avif",
  "pdf",
  "zip",
  "gz",
  "tgz",
  "tar",
  "7z",
  "rar",
  "mp4",
  "mov",
  "webm",
  "mp3",
  "wav",
  "woff",
  "woff2",
  "ttf",
  "otf",
  "eot",
  "exe",
  "dll",
  "so",
  "dylib",
  "class",
  "jar",
  "bin",
  "wasm",
  "lockb",
]);

const LOCKFILES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "poetry.lock",
  "uv.lock",
  "pipfile.lock",
  "gemfile.lock",
  "composer.lock",
  "cargo.lock",
  "go.sum",
]);

const SOURCE_EXTENSIONS = new Set([
  "js",
  "jsx",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "vue",
  "svelte",
  "py",
  "rb",
  "go",
  "java",
  "kt",
  "kts",
  "scala",
  "php",
  "rs",
  "cs",
  "swift",
  "c",
  "cc",
  "cpp",
  "h",
  "hpp",
  "dart",
  "ex",
  "exs",
  "lua",
  "pl",
  "sql",
  "sh",
  "bash",
]);

const LOW_DIRS = new Set([
  "test",
  "tests",
  "__tests__",
  "__mocks__",
  "e2e",
  "docs",
  "doc",
  "examples",
  "example",
  "scripts",
]);

const HIGH_DIRS = new Set([
  "routes",
  "controllers",
  "middleware",
  "models",
  "prisma",
]);
const MEDIUM_DIRS = new Set(["src", "lib", "server", "api", "config"]);

type Parts = { lower: string; dirs: string[]; base: string; ext: string };

/** The largest size a file may have and still be loaded. */
export function maxBytesFor(path: string): number {
  const base = path.replace(/\\/g, "/").split("/").pop()?.toLowerCase() ?? "";
  return SCANNED_LOCKFILES.has(base) ? MAX_LOCKFILE_BYTES : MAX_FILE_BYTES;
}

function split(path: string): Parts {
  const lower = path
    .replace(/\\/g, "/")
    .replace(/^\.?\//, "")
    .toLowerCase();
  const segments = lower.split("/");
  const base = segments[segments.length - 1] ?? "";
  const dot = base.lastIndexOf(".");
  return {
    lower,
    dirs: segments.slice(0, -1),
    base,
    ext: dot > 0 ? base.slice(dot + 1) : "",
  };
}

function inDirs(parts: Parts, names: ReadonlySet<string>): string | undefined {
  return parts.dirs.find((dir) => names.has(dir));
}

/** True for a file worth counting as source code (used for the "enough code" check). */
export function isSourceFile(path: string): boolean {
  const parts = split(path);
  return SOURCE_EXTENSIONS.has(parts.ext) && !LOCKFILES.has(parts.base);
}

function isLockfile(parts: Parts): boolean {
  return LOCKFILES.has(parts.base);
}

/** .env, .env.<x>, .env-<x>, .env_<x>, .envrc, and <name>.env. */
function isEnvironmentFile(base: string, ext: string): boolean {
  return /^\.env(?:rc|[._-].*)?$/.test(base) || ext === "env";
}

/** Never-fetch rules. Checked before everything else, including size. */
function ignoreReason(parts: Parts, size?: number): string | undefined {
  const { base, ext } = parts;

  // .env holds real secrets; .env.example is the documented, safe exception (the
  // envNames detector reads its keys, and redact() blanks its values). The same goes for
  // every other spelling of an environment file: .env-prod, .env_test, direnv's .envrc
  // (`export API_TOKEN=...`) and compose-style env_file names such as web.env.
  if (isEnvironmentFile(base, ext) && base !== ".env.example") {
    return "environment file (never fetched)";
  }

  const dir = inDirs(parts, IGNORED_DIRS);
  if (dir) return `${dir}/ is not first-party source`;

  if (BINARY_EXTENSIONS.has(ext)) return `binary or media (.${ext})`;
  if (/\.min\.(js|mjs|css)$/.test(base)) return "minified file";
  if (size !== undefined) {
    if (SCANNED_LOCKFILES.has(base)) {
      if (size > MAX_LOCKFILE_BYTES)
        return "lockfile over 1 MiB (too large to fetch)";
    } else if (size > MAX_FILE_BYTES) {
      return "over 200 KB";
    }
  }

  return undefined;
}

function lowReason(parts: Parts): string | undefined {
  const { base, ext } = parts;

  const dir = inDirs(parts, LOW_DIRS);
  if (dir) return `${dir}/`;
  if (/\.(test|spec)\.[a-z]+$/.test(base) || /_test\.(go|py|rb)$/.test(base))
    return "test";
  if (/^test_.+\.py$/.test(base)) return "test";
  if (ext === "md" || ext === "mdx" || ext === "rst") return "documentation";

  return undefined;
}

function highReason(parts: Parts): string | undefined {
  const { lower, base } = parts;

  if (base === "package.json") return "package manifest";

  const dir = inDirs(parts, HIGH_DIRS);
  if (dir) return `${dir}/`;

  // *auth*, *session*, *login*, *admin* against the whole normalized path, so
  // src/admin/panel.ts and src/auth/helpers.ts count, not just admin.ts.
  if (/auth|session|login|admin/.test(lower))
    return "authentication or administration";

  if (base === "schema.prisma") return "data schema";
  if (/(^|\/)app\/(.+\/)?route\.(ts|js)$/.test(lower))
    return "app router route handler";
  if (/(^|\/)pages\/api\//.test(lower)) return "pages API route";
  if (/^(server|app)\.(ts|js)$/.test(base)) return "application entry point";
  if (/^(src\/)?index\.(ts|js)$/.test(lower)) return "application entry point";

  if (base === "dockerfile" || base.startsWith("dockerfile."))
    return "container build";
  if (/^docker-compose.*\.ya?ml$/.test(base)) return "container orchestration";
  if (base.endsWith(".tf")) return "infrastructure as code";
  if (base === "serverless.yml" || base === "vercel.json")
    return "deployment config";
  if (base.startsWith("next.config.")) return "framework config";
  if (
    base === "firebase.json" ||
    base === "firestore.rules" ||
    base === "storage.rules"
  ) {
    return "Firebase config and rules";
  }
  if (base === ".env.example") return "documents required environment";
  if (base.endsWith(".graphql")) return "GraphQL schema";

  return undefined;
}

function mediumReason(parts: Parts): string | undefined {
  if (parts.dirs.includes("config")) return "config/";
  const dir = inDirs(parts, MEDIUM_DIRS);
  if (dir && SOURCE_EXTENSIONS.has(parts.ext)) return `source in ${dir}/`;
  return undefined;
}

/**
 * Tiers a path. `size` is in bytes and optional, since some tree responses omit it; an
 * unknown size is never a reason to ignore a file.
 *
 * Precedence, first match wins:
 *   1. ignore: environment files (.env, .env.*, .env-*, .env_*, .envrc, *.env; not
 *      .env.example), ignored directories (node_modules, dist, build, .next, out,
 *      coverage, vendor, .git, __pycache__, .venv, public, assets), binaries and media,
 *      minified files, anything over 200 KiB (lockfiles included);
 *   2. lockfiles: medium, reason "dependencies" (OSV only, never model-bound). Above
 *      low and high so a lockfile under src/auth/ is not promoted by its path;
 *   3. low: tests, docs, examples, scripts, so `auth.test.ts` and `docs/admin.md` are
 *      not promoted by their names;
 *   4. high: sensitive application paths;
 *   5. medium: other source files in src, lib, server, api, and config/**;
 *   6. anything else is low ("other"): first-party, just unremarkable.
 */
export function classifyPath(path: string, size?: number): Classification {
  const parts = split(path);

  const ignored = ignoreReason(parts, size);
  if (ignored) return { tier: "ignore", reason: ignored };

  if (isLockfile(parts)) return { tier: "medium", reason: LOCKFILE_REASON };

  const low = lowReason(parts);
  if (low) return { tier: "low", reason: low };

  const high = highReason(parts);
  if (high) return { tier: "high", reason: high };

  const medium = mediumReason(parts);
  if (medium) return { tier: "medium", reason: medium };

  return { tier: "low", reason: "other" };
}
