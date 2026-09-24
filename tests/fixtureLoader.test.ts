/**
 * Prompt U, Parts 1-2: src/server/ingest/fixtureLoader.ts.
 *
 * Fully offline: reads only tests/fixtures/ from disk. No network, no MCP client.
 * NODE_ENV is saved and restored around every test that touches it.
 *
 * The "security" describe blocks below create and tear down small, uniquely-named
 * scratch directories directly under tests/fixtures/ (never touching canary-repo/ or
 * root-level fixtures/, which tests/fixtures.test.ts owns) to exercise symlink and
 * traversal handling against the real filesystem, which is the only way to prove
 * realpath containment and Dirent symlink semantics actually hold on this platform
 * rather than asserting what the Node docs say they should do.
 */

import { mkdirSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_FILE_BYTES } from "@/server/ingest/classifier";
import {
  FIXTURE_OWNER,
  FIXTURE_ROOT,
  fixturesEnabled,
  isFixtureUrl,
  isPlainFileWithinRoot,
  loadFixtureRepo,
  parseFixtureUrl,
} from "@/server/ingest/fixtureLoader";
import { IngestError } from "@/server/ingest/loader";
import { loadCanaryRepo } from "./canaryRepo";

beforeEach(() => {
  vi.stubEnv("NODE_ENV", "test");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// isFixtureUrl / parseFixtureUrl
// ---------------------------------------------------------------------------

describe("isFixtureUrl", () => {
  it("recognises the exact fixture: prefix", () => {
    expect(isFixtureUrl("fixture:canary-repo")).toBe(true);
  });

  it("rejects leading whitespace or wrong case -- exact syntax only, no trimming", () => {
    expect(isFixtureUrl("  fixture:canary-repo")).toBe(false);
    expect(isFixtureUrl("Fixture:canary-repo")).toBe(false);
    expect(isFixtureUrl("FIXTURE:canary-repo")).toBe(false);
  });

  it("rejects a plain github URL or shorthand", () => {
    expect(isFixtureUrl("https://github.com/acme/widgets")).toBe(false);
    expect(isFixtureUrl("acme/widgets")).toBe(false);
    expect(isFixtureUrl("")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// fixturesEnabled -- a fail-closed ALLOWLIST, not a `!== "production"` denylist
// ---------------------------------------------------------------------------

describe("fixturesEnabled", () => {
  // The module-level beforeEach/afterEach (top of file) stub "test" and unstub-all
  // around every test in this file, so each `it` below overrides that stub for its own
  // duration and the outer afterEach cleans it up -- no local hook needed here.

  it("is enabled for NODE_ENV=development", () => {
    vi.stubEnv("NODE_ENV", "development");
    expect(fixturesEnabled()).toBe(true);
  });

  it("is enabled for NODE_ENV=test", () => {
    vi.stubEnv("NODE_ENV", "test");
    expect(fixturesEnabled()).toBe(true);
  });

  it("is disabled for NODE_ENV=production", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(fixturesEnabled()).toBe(false);
  });

  it("is disabled when NODE_ENV is unset", () => {
    vi.stubEnv("NODE_ENV", undefined);
    expect(fixturesEnabled()).toBe(false);
  });

  it.each(["staging", "preview", "Production", "Test", "development ", "dev", ""])(
    "is disabled for every unexpected NODE_ENV value: %s",
    (value) => {
      vi.stubEnv("NODE_ENV", value);
      expect(fixturesEnabled()).toBe(false);
    },
  );
});

describe("parseFixtureUrl", () => {
  it("parses a valid fixture name to the reserved owner", () => {
    const result = parseFixtureUrl("fixture:canary-repo");
    expect(result).toEqual({ ok: true, owner: FIXTURE_OWNER, repo: "canary-repo" });
  });

  it.each([
    "fixture:../secrets",
    "fixture:a/b",
    "fixture:/etc/passwd",
    "fixture:UPPER",
    "fixture:has_underscore",
    "fixture:",
  ])("rejects a malformed fixture name: %s", (input) => {
    const result = parseFixtureUrl(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("INVALID_URL");
  });

  it("rejects any fixture URL when NODE_ENV is production", () => {
    vi.stubEnv("NODE_ENV", "production");
    const result = parseFixtureUrl("fixture:canary-repo");
    expect(result).toEqual({
      ok: false,
      code: "INVALID_URL",
      message: "Fixture repos are not available",
    });
  });
});

// ---------------------------------------------------------------------------
// loadFixtureRepo
// ---------------------------------------------------------------------------

describe("loadFixtureRepo", () => {
  it("loads the canary repo with the same paths and tiers loadCanaryRepo() reports", async () => {
    const loaded = await loadFixtureRepo(FIXTURE_OWNER, "canary-repo");
    const expected = loadCanaryRepo();

    expect(loaded.files.map((f) => f.path).sort()).toEqual(
      expected.map((f) => f.path).sort(),
    );
    const byPath = new Map(loaded.files.map((f) => [f.path, f]));
    for (const file of expected) {
      expect(byPath.get(file.path)?.tier).toBe(file.tier);
      expect(byPath.get(file.path)?.content).toBe(file.content);
    }
  });

  it("reports a RepoSummary naming the fixture and no truncation", async () => {
    const loaded = await loadFixtureRepo(FIXTURE_OWNER, "canary-repo");
    expect(loaded.summary.owner).toBe(FIXTURE_OWNER);
    expect(loaded.summary.name).toBe("canary-repo");
    expect(loaded.summary.ref).toBe("fixture");
    expect(loaded.summary.frameworks).toEqual([]);
    expect(loaded.summary.fileCountAnalyzed).toBe(loaded.files.length);
    expect(loaded.truncated).toBe(false);
    expect(loaded.skipped).toEqual({ ignored: 0, overLimit: 0 });
  });

  it("honours an explicit ref instead of the fixture default", async () => {
    const loaded = await loadFixtureRepo(FIXTURE_OWNER, "canary-repo", "my-ref");
    expect(loaded.summary.ref).toBe("my-ref");
  });

  it("rejects an unknown fixture owner", async () => {
    await expect(loadFixtureRepo("someone-else", "canary-repo")).rejects.toThrow(IngestError);
  });

  it("rejects an unknown fixture name", async () => {
    await expect(loadFixtureRepo(FIXTURE_OWNER, "does-not-exist")).rejects.toThrow(IngestError);
  });

  it.each([
    "../secrets",
    "a/b",
    "..",
    "UPPER",
    "has_underscore",
    "",
    "..%2fsecrets",
    "%2e%2e%2fsecrets",
    "a\\b",
    "a:b",
    "a\0b",
    "/etc/passwd",
    "-leading-hyphen",
    "trailing-hyphen-",
    "a--b", // doubled hyphen
  ])("rejects a traversal or malformed fixture name without reading the filesystem: %s", async (repo) => {
    await expect(loadFixtureRepo(FIXTURE_OWNER, repo)).rejects.toThrow(IngestError);
  });

  it("refuses to load when NODE_ENV is production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    await expect(loadFixtureRepo(FIXTURE_OWNER, "canary-repo")).rejects.toThrow(IngestError);
  });

  it("never exposes the absolute local filesystem path in a thrown error's message", async () => {
    try {
      await loadFixtureRepo(FIXTURE_OWNER, "does-not-exist");
      expect.unreachable("expected loadFixtureRepo to throw");
    } catch (cause) {
      expect(cause).toBeInstanceOf(IngestError);
      const message = (cause as IngestError).message;
      expect(message).not.toContain(process.cwd());
      expect(message).not.toMatch(/^\//); // no leading absolute-path segment
    }
  });
});

// ---------------------------------------------------------------------------
// Exact fixture: syntax and the name allowlist (Prompt U, Part 2 audit)
// ---------------------------------------------------------------------------

describe("isFixtureUrl / parseFixtureUrl -- exact syntax", () => {
  it.each([
    "fixture::canary-repo", // extra colon
    "fixture:canary:repo", // colon inside the name
    "fixturex:canary-repo", // not the exact prefix
    "xfixture:canary-repo",
    "fixture", // prefix with no colon at all
  ])("does not accept %s as a fixture name resolving successfully", (input) => {
    // isFixtureUrl only gates the dispatch; the real guarantee is that a string with
    // the prefix but a bad tail is still rejected by parseFixtureUrl's NAME_PATTERN.
    if (isFixtureUrl(input)) {
      const result = parseFixtureUrl(input);
      expect(result.ok, input).toBe(false);
    }
  });

  it.each([
    "fixture:a\\b", // backslash
    "fixture:a\0b", // NUL byte
    "fixture:..%2f..%2fsecrets", // encoded traversal
    "fixture:%2e%2e", // encoded ".."
    "fixture: canary-repo", // space after colon is part of the name and must fail
    "fixture:canary-repo ", // trailing space
  ])("rejects a fixture: URL with disallowed characters: %s", (input) => {
    const result = parseFixtureUrl(input);
    expect(result.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Canonical-path containment and symlink escape (Prompt U, Part 2 audit)
// ---------------------------------------------------------------------------

describe("loadFixtureRepo -- filesystem security", () => {
  const scratchDirs: string[] = [];
  let outsideSecret: string | undefined;

  function makeScratchDir(name: string): string {
    const dir = join(FIXTURE_ROOT, name);
    mkdirSync(dir, { recursive: true });
    scratchDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    for (const dir of scratchDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
    if (outsideSecret !== undefined) {
      rmSync(outsideSecret, { force: true });
      outsideSecret = undefined;
    }
  });

  it("proves the platform-level invariant: a symlink Dirent never reports isFile() true", () => {
    // The premise the loader depends on ("readdirSync already excludes symlinks via
    // entry.isFile()") is a platform behavior, not something this codebase controls --
    // verified directly here so a future Node/OS change that breaks it fails loudly.
    const dir = makeScratchDir("zz-symlink-invariant");
    writeFileSync(join(dir, "normal.js"), "const safe = true;\n");
    const target = join(tmpdir(), `attackcanvas-invariant-target-${process.pid}.js`);
    writeFileSync(target, "const outside = true;\n");
    symlinkSync(target, join(dir, "link.js"));

    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      const link = entries.find((e) => e.name === "link.js");
      expect(link?.isSymbolicLink()).toBe(true);
      expect(link?.isFile()).toBe(false);
    } finally {
      rmSync(target, { force: true });
    }
  });

  it("excludes a symlinked FILE that points outside the fixture root", async () => {
    outsideSecret = join(tmpdir(), `attackcanvas-fixture-secret-${process.pid}.txt`);
    writeFileSync(outsideSecret, "OUTSIDE SECRET, must never be loaded");

    const dir = makeScratchDir("zz-symlink-file");
    writeFileSync(join(dir, "normal.js"), "const safe = true;\n");
    symlinkSync(outsideSecret, join(dir, "evil.js"));

    const loaded = await loadFixtureRepo(FIXTURE_OWNER, "zz-symlink-file");

    // The symlink is invisible to Node's own recursive readdir (Dirent.isFile() is
    // false for it, verified separately below), so it is simply never listed -- there
    // is no "ignored" count to bump for something that was never a candidate. What
    // matters, and what every assertion here proves, is that its target's content
    // never reaches the loaded repo.
    expect(loaded.files.map((f) => f.path)).toEqual(["normal.js"]);
    expect(loaded.files.some((f) => f.content.includes("OUTSIDE SECRET"))).toBe(false);
  });

  it("does not descend into a symlinked DIRECTORY that points outside the fixture root", async () => {
    const outsideDir = join(tmpdir(), `attackcanvas-fixture-outside-dir-${process.pid}`);
    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(outsideDir, "secret.js"), "const leaked = true;\n");

    const dir = makeScratchDir("zz-symlink-dir");
    writeFileSync(join(dir, "normal.js"), "const safe = true;\n");
    symlinkSync(outsideDir, join(dir, "escape"));

    try {
      const loaded = await loadFixtureRepo(FIXTURE_OWNER, "zz-symlink-dir");
      expect(loaded.files.map((f) => f.path)).toEqual(["normal.js"]);
      expect(loaded.files.some((f) => f.content.includes("leaked"))).toBe(false);
    } finally {
      rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  it("rejects the whole fixture when the fixture directory itself is a symlink escaping the root", async () => {
    const outsideDir = join(tmpdir(), `attackcanvas-fixture-outside-root-${process.pid}`);
    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(outsideDir, "secret.js"), "const leaked = true;\n");

    const linkPath = join(FIXTURE_ROOT, "zz-symlink-root-escape");
    symlinkSync(outsideDir, linkPath);
    scratchDirs.push(linkPath);

    try {
      await expect(loadFixtureRepo(FIXTURE_OWNER, "zz-symlink-root-escape")).rejects.toThrow(
        IngestError,
      );
    } finally {
      rmSync(outsideDir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Reuse of the normal loader's classification / ignored-path / size policy
// ---------------------------------------------------------------------------

describe("loadFixtureRepo -- shares the real loader's classification and size policy", () => {
  const scratchDirs: string[] = [];

  function makeScratchDir(name: string): string {
    const dir = join(FIXTURE_ROOT, name);
    mkdirSync(dir, { recursive: true });
    scratchDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    for (const dir of scratchDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("excludes a binary-extension file the classifier ignores", async () => {
    const dir = makeScratchDir("zz-binary-file");
    writeFileSync(join(dir, "keep.js"), "const kept = true;\n");
    writeFileSync(join(dir, "logo.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47]));

    const loaded = await loadFixtureRepo(FIXTURE_OWNER, "zz-binary-file");

    expect(loaded.files.map((f) => f.path)).toEqual(["keep.js"]);
  });

  it("excludes an ignored directory (node_modules) entirely", async () => {
    const dir = makeScratchDir("zz-ignored-dir");
    writeFileSync(join(dir, "keep.js"), "const kept = true;\n");
    mkdirSync(join(dir, "node_modules", "some-pkg"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "some-pkg", "index.js"), "module.exports = {};\n");

    const loaded = await loadFixtureRepo(FIXTURE_OWNER, "zz-ignored-dir");

    expect(loaded.files.map((f) => f.path)).toEqual(["keep.js"]);
  });

  it("excludes a file over the per-file byte cap via the shared applySizePolicy", async () => {
    const dir = makeScratchDir("zz-oversized-file");
    writeFileSync(join(dir, "keep.js"), "const kept = true;\n");
    writeFileSync(join(dir, "huge.js"), "x".repeat(MAX_FILE_BYTES + 1));

    const loaded = await loadFixtureRepo(FIXTURE_OWNER, "zz-oversized-file");

    expect(loaded.files.map((f) => f.path)).toEqual(["keep.js"]);
    expect(loaded.skipped.ignored).toBeGreaterThanOrEqual(1);
    // The total-byte-budget branch of the very same applySizePolicy function is already
    // covered against a real MAX_TOTAL_BYTES-sized workload in tests/loader.test.ts
    // ("limits" describe block) -- reproducing a multi-megabyte fixture on disk here
    // would only re-test the same shared function a second, more expensive way.
  });
});

// ---------------------------------------------------------------------------
// isPlainFileWithinRoot -- direct unit tests, independent of readdir's own symlink
// filtering, so the containment/symlink check is killable on its own even though the
// integration-level symlink tests above cannot reach it (Node's recursive readdir
// already excludes a symlink Dirent before this function is ever called on one).
// ---------------------------------------------------------------------------

describe("isPlainFileWithinRoot", () => {
  const scratchDirs: string[] = [];
  let outsideFile: string | undefined;

  afterEach(() => {
    for (const dir of scratchDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
    if (outsideFile !== undefined) {
      rmSync(outsideFile, { force: true });
      outsideFile = undefined;
    }
  });

  it("accepts a genuine regular file inside the root", () => {
    const dir = join(FIXTURE_ROOT, "zz-plain-file-unit");
    mkdirSync(dir, { recursive: true });
    scratchDirs.push(dir);
    const file = join(dir, "normal.js");
    writeFileSync(file, "const safe = true;\n");

    expect(isPlainFileWithinRoot(dir, file)).toBe(true);
  });

  it("rejects a symlink, even one pointing back inside the root", () => {
    const dir = join(FIXTURE_ROOT, "zz-plain-file-unit-symlink");
    mkdirSync(dir, { recursive: true });
    scratchDirs.push(dir);
    // The symlink target MUST be absolute here: a relative target is resolved relative
    // to the symlink's OWN directory when dereferenced, so passing the cwd-relative
    // `join(dir, "real.js")` would silently create a dangling symlink (wrong target
    // path) and make this test pass for the wrong reason -- via isPlainFileWithinRoot's
    // realpathSync-throws-on-a-broken-link branch, not via the isFile()/isSymbolicLink()
    // type check this test exists to cover. Caught by a mutation that widened the type
    // check to also accept isSymbolicLink(): with a relative (and therefore dangling)
    // target the mutant still returned false, masking the mutation.
    const real = resolve(dir, "real.js");
    writeFileSync(real, "const safe = true;\n");
    const link = join(dir, "link.js");
    symlinkSync(real, link);

    expect(isPlainFileWithinRoot(dir, link)).toBe(false);
  });

  it("rejects a symlink whose target resolves outside the root", () => {
    outsideFile = join(tmpdir(), `attackcanvas-unit-outside-${process.pid}.js`);
    writeFileSync(outsideFile, "const outside = true;\n");
    const dir = join(FIXTURE_ROOT, "zz-plain-file-unit-escape");
    mkdirSync(dir, { recursive: true });
    scratchDirs.push(dir);
    const link = join(dir, "escape.js");
    symlinkSync(outsideFile, link);

    expect(isPlainFileWithinRoot(dir, link)).toBe(false);
  });

  it("rejects a path that does not exist", () => {
    expect(isPlainFileWithinRoot(FIXTURE_ROOT, join(FIXTURE_ROOT, "does-not-exist.js"))).toBe(
      false,
    );
  });

  it("rejects a directory passed where a file is expected", () => {
    expect(isPlainFileWithinRoot(FIXTURE_ROOT, join(FIXTURE_ROOT, "canary-repo"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

describe("loadFixtureRepo -- deterministic ordering", () => {
  it("returns files in the same tier-then-path order on repeated loads", async () => {
    const first = await loadFixtureRepo(FIXTURE_OWNER, "canary-repo");
    const second = await loadFixtureRepo(FIXTURE_OWNER, "canary-repo");

    expect(second.files.map((f) => f.path)).toEqual(first.files.map((f) => f.path));
    expect(second.files.map((f) => f.tier)).toEqual(first.files.map((f) => f.tier));

    // Within a tier, alphabetical by path; across tiers, high before medium before low --
    // the same order selectCandidates produces for the real loader.
    const rank: Record<string, number> = { high: 0, medium: 1, low: 2 };
    for (let i = 1; i < first.files.length; i++) {
      const prev = first.files[i - 1];
      const curr = first.files[i];
      const prevRank = rank[prev.tier];
      const currRank = rank[curr.tier];
      expect(prevRank <= currRank).toBe(true);
      if (prevRank === currRank) {
        expect(prev.path.localeCompare(curr.path)).toBeLessThan(0);
      }
    }
  });
});
