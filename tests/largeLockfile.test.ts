import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  MAX_FILE_BYTES,
  MAX_LOCKFILE_BYTES,
  classifyPath,
} from "@/server/ingest/classifier";
import {
  MAX_TOTAL_BYTES,
  loadRepositoryWith,
  modelBoundFiles,
  type LoaderDeps,
} from "@/server/ingest/loader";
import {
  GitHubMcpError,
  MAX_RESPONSE_BYTES,
  type TreeEntry,
} from "@/server/mcp/githubClient";
import { collectDependencies, scanDependencies } from "@/server/scanners/osv";
import { EvidenceSchema } from "@/shared/schema";
import { BATCH_RESPONSE, VULNS } from "./osvResponses";

/**
 * A package-lock.json larger than 200 KB, taken through the real loader and the real
 * dependency scanner. Nothing here reaches the network: OSV is answered from the saved
 * responses, and the global fetch is a guard that fails the test if anything uses it.
 */

const NO_NETWORK = vi.fn(() => {
  throw new Error("a test tried to use the real network");
}) as unknown as typeof fetch;

beforeAll(() => {
  vi.stubGlobal("fetch", NO_NETWORK);
});
afterAll(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// The fixture: generated, deterministic, and deliberately like a real lockfile
// ---------------------------------------------------------------------------

const pad = (n: number) => String(n).padStart(5, "0");

/** A 86-character stand-in for a sha512 integrity string. Not a real hash. */
const integrity = (n: number) =>
  `sha512-${`${pad(n)}AbCdEf0123456789`.repeat(6).slice(0, 86)}==`;

type LockEntry = Record<string, unknown>;

function entry(
  name: string,
  version: string,
  n: number,
  extra: LockEntry = {},
): LockEntry {
  return {
    version,
    resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    integrity: integrity(n),
    license: "MIT",
    engines: { node: ">=10" },
    ...extra,
  };
}

/**
 * A lockfileVersion 3 lockfile with two DIRECT dependencies (lodash, left-pad) and
 * `transitive` others. Among the transitive ones are traps for a scanner that confuses
 * transitive with direct: a top-level minimist@1.2.0 (vulnerable, not in package.json)
 * and a nested lodash@3.0.0 under another package.
 */
function buildLockfile(transitive: number): string {
  const packages: Record<string, LockEntry> = {
    "": {
      name: "app",
      version: "1.0.0",
      dependencies: { lodash: "^4.0.0", "left-pad": "1.3.0" },
    },
    "node_modules/lodash": entry("lodash", "4.17.15", 1),
    "node_modules/left-pad": entry("left-pad", "1.3.0", 2),
    "node_modules/minimist": entry("minimist", "1.2.0", 3), // transitive, vulnerable
    "node_modules/transitive-00000/node_modules/lodash": entry(
      "lodash",
      "3.0.0",
      4,
    ), // nested
  };

  for (let i = 0; i < transitive; i++) {
    const name = `transitive-${pad(i)}`;
    const version = `${1 + (i % 9)}.${i % 20}.${i % 7}`;
    packages[`node_modules/${name}`] = entry(name, version, i + 10, {
      dependencies: {
        [`transitive-${pad(i + 1)}`]: "^1.0.0",
        minimist: "^1.2.0",
      },
    });
  }

  return JSON.stringify(
    { name: "app", lockfileVersion: 3, requires: true, packages },
    null,
    2,
  );
}

const BIG_LOCK = buildLockfile(1400);
const bytes = (text: string) => Buffer.byteLength(text, "utf8");

const PACKAGE_JSON = JSON.stringify(
  { name: "app", dependencies: { lodash: "^4.0.0", "left-pad": "1.3.0" } },
  null,
  2,
);

// ---------------------------------------------------------------------------
// Harness: a fake GitHub and a fake OSV
// ---------------------------------------------------------------------------

const file = (path: string, size?: number): TreeEntry => ({
  path,
  type: "file",
  ...(size !== undefined ? { size } : {}),
});

function githubDeps(
  entries: TreeEntry[],
  contents: Record<string, string>,
  failOn: (path: string) => unknown = () => undefined,
): LoaderDeps & { fetched: string[] } {
  const fetched: string[] = [];
  return {
    fetched,
    async getRepoMetadata() {
      return { defaultBranch: "main", source: "rest" };
    },
    async listTree() {
      return { entries, source: "mcp", truncated: false };
    },
    async getFileContent(_o, _r, _ref, path) {
      fetched.push(path);
      const failure = failOn(path);
      if (failure) throw failure;
      return contents[path] ?? `// ${path}`;
    },
  };
}

/** Answers OSV from the saved real responses: lodash and left-pad as captured; nothing else is vulnerable. */
function savedOsv() {
  const queries: { name: string; version: string }[] = [];
  const results = (BATCH_RESPONSE as { results: unknown[] }).results;

  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const body = JSON.parse(String(init?.body)) as {
        queries: { package: { name: string }; version: string }[];
      };
      for (const q of body.queries)
        queries.push({ name: q.package.name, version: q.version });

      return new Response(
        JSON.stringify({
          results: body.queries.map((q) =>
            q.package.name === "lodash" && q.version === "4.17.15"
              ? results[0]
              : q.package.name === "left-pad" && q.version === "1.3.0"
                ? results[1]
                : {},
          ),
        }),
      );
    }
    const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
    return new Response(JSON.stringify(VULNS[id] ?? {}), {
      status: VULNS[id] ? 200 : 404,
    });
  }) as unknown as typeof fetch;

  return { fetch: fetchFn, queries };
}

const sources = {
  "src/a.ts": "export const a = 1;",
  "src/b.ts": "export const b = 2;",
  "src/c.ts": "export const c = 3;",
};
const SOURCE_ENTRIES = Object.keys(sources).map((p) => file(p));

async function loadWithLockfile(
  lockSize: number | undefined,
  lockContent = BIG_LOCK,
) {
  const entries = [
    file("package.json"),
    file("package-lock.json", lockSize),
    ...SOURCE_ENTRIES,
  ];
  const deps = githubDeps(entries, {
    "package.json": PACKAGE_JSON,
    "package-lock.json": lockContent,
    ...sources,
  });
  return { deps, loaded: await loadRepositoryWith(deps, "o", "r") };
}

// ---------------------------------------------------------------------------

describe("the fixture is a realistic lockfile larger than 200 KB", () => {
  it("is over the general 200 KB file limit and under the lockfile cap", () => {
    expect(bytes(BIG_LOCK)).toBeGreaterThan(MAX_FILE_BYTES * 2); // comfortably over, not borderline
    expect(bytes(BIG_LOCK)).toBeLessThan(MAX_LOCKFILE_BYTES);
  });

  it("has two direct dependencies and well over a thousand transitive ones", () => {
    const lock = JSON.parse(BIG_LOCK) as { packages: Record<string, unknown> };
    const names = Object.keys(lock.packages);

    expect(names.length).toBeGreaterThan(1400);
    expect(names).toContain("node_modules/minimist"); // transitive
    expect(names).toContain(
      "node_modules/transitive-00000/node_modules/lodash",
    ); // nested
  });

  it("would previously have been ignored as over 200 KB, so this is the case being fixed", () => {
    // The classifier's answer for any other file of this size.
    expect(classifyPath("pnpm-lock.yaml", bytes(BIG_LOCK)).tier).toBe("ignore");
    expect(classifyPath("src/generated.ts", bytes(BIG_LOCK)).tier).toBe(
      "ignore",
    );
  });
});

describe("a package-lock.json over 200 KB is loaded", () => {
  it("is classified medium, for dependencies, at its real size", () => {
    expect(classifyPath("package-lock.json", bytes(BIG_LOCK))).toEqual({
      tier: "medium",
      reason: "dependencies",
    });
  });

  it("is fetched and returned in full by the loader", async () => {
    const { deps, loaded } = await loadWithLockfile(bytes(BIG_LOCK));
    const lock = loaded.files.find((f) => f.path === "package-lock.json");

    expect(deps.fetched).toContain("package-lock.json");
    expect(lock).toBeDefined();
    expect(lock?.content).toBe(BIG_LOCK);
    expect(bytes(lock?.content ?? "")).toBeGreaterThan(MAX_FILE_BYTES);
    expect(lock).toMatchObject({ tier: "medium", reason: "dependencies" });
  });

  it("is still never model-bound, and does not count as source code", async () => {
    const { loaded } = await loadWithLockfile(bytes(BIG_LOCK));

    expect(modelBoundFiles(loaded.files).map((f) => f.path)).not.toContain(
      "package-lock.json",
    );
    expect(loaded.files.map((f) => f.path)).toContain("package-lock.json");
  });

  it("keeps the whole load inside the 2 MiB budget", async () => {
    const { loaded } = await loadWithLockfile(bytes(BIG_LOCK));
    const total = loaded.files.reduce((sum, f) => sum + bytes(f.content), 0);

    expect(total).toBeLessThanOrEqual(MAX_TOTAL_BYTES);
  });

  it("does not need the tree to report a size", async () => {
    const { loaded } = await loadWithLockfile(undefined);
    expect(loaded.files.map((f) => f.path)).toContain("package-lock.json");
  });
});

describe("the large lockfile is actually parsed, and exact direct versions are used", () => {
  it("resolves exactly the two direct dependencies to their locked versions", async () => {
    const { loaded } = await loadWithLockfile(bytes(BIG_LOCK));
    const { dependencies, limitations } = collectDependencies(loaded.files);

    expect(
      dependencies.map((d) => [d.name, d.version, d.versionExact]),
    ).toEqual([
      ["lodash", "4.17.15", true],
      ["left-pad", "1.3.0", true],
    ]);
    expect(limitations).toEqual([]);
  });

  it("takes the locked 4.17.15, not the 4.0.0 that the range ^4.0.0 would give", async () => {
    // If the lockfile had been skipped, the scanner would fall back to the range's
    // minimum. Getting 4.17.15 can only come from reading the lockfile.
    const { loaded } = await loadWithLockfile(bytes(BIG_LOCK));
    const lodash = collectDependencies(loaded.files).dependencies.find(
      (d) => d.name === "lodash",
    );

    expect(lodash?.version).toBe("4.17.15");
    expect(lodash?.range).toBe("^4.0.0");
  });

  it("does not treat any of the 1,400 transitive packages as direct", async () => {
    const { loaded } = await loadWithLockfile(bytes(BIG_LOCK));
    const names = collectDependencies(loaded.files).dependencies.map(
      (d) => d.name,
    );

    expect(names).toEqual(["lodash", "left-pad"]);
    expect(names).not.toContain("minimist");
    expect(names.some((n) => n.startsWith("transitive-"))).toBe(false);
  });

  it("does not let the nested lodash 3.0.0 override the direct lodash", async () => {
    const { loaded } = await loadWithLockfile(bytes(BIG_LOCK));
    const lodash = collectDependencies(loaded.files).dependencies.find(
      (d) => d.name === "lodash",
    );
    expect(lodash?.version).not.toBe("3.0.0");
  });
});

describe("the whole path, loader to OSV evidence, with saved responses", () => {
  async function run() {
    const { loaded } = await loadWithLockfile(bytes(BIG_LOCK));
    const osv = savedOsv();
    const result = await scanDependencies(loaded.files, {
      fetch: osv.fetch,
      cache: new Map(),
    });
    return { loaded, osv, result };
  }

  it("asks OSV about the two direct dependencies at their exact versions, and nothing else", async () => {
    const { osv } = await run();

    expect(osv.queries).toEqual([
      { name: "lodash", version: "4.17.15" },
      { name: "left-pad", version: "1.3.0" },
    ]);
  });

  it("never asks about the vulnerable transitive minimist, which is in the lockfile", async () => {
    const { osv, result } = await run();

    expect(osv.queries.map((q) => q.name)).not.toContain("minimist");
    expect(
      result.evidence.some((e) => e.metadata?.package === "minimist"),
    ).toBe(false);
  });

  it("produces the four lodash findings with versionExact true and no limitation", async () => {
    const { result } = await run();

    expect(result.evidence).toHaveLength(4);
    for (const item of result.evidence) {
      expect(item.metadata).toMatchObject({
        package: "lodash",
        version: "4.17.15",
        versionExact: true,
      });
      expect(item.summary).not.toContain("inferred from range");
    }
    expect(result.limitations).toEqual([]);
  });

  it("carries versionExact: true through EvidenceSchema.parse()", async () => {
    const { result } = await run();

    for (const item of result.evidence) {
      expect(EvidenceSchema.parse(item).metadata?.versionExact).toBe(true);
    }
  });

  it("differs from the same repository with no lockfile, which is why the lockfile matters", async () => {
    const osv = savedOsv();
    const noLock = await scanDependencies(
      [{ path: "package.json", content: PACKAGE_JSON }],
      {
        fetch: osv.fetch,
        cache: new Map(),
      },
    );

    expect(osv.queries.find((q) => q.name === "lodash")?.version).toBe("4.0.0"); // the range's minimum
    expect(
      noLock.limitations.some((m) => m.includes("package-lock.json")),
    ).toBe(true);
    for (const item of noLock.evidence)
      expect(item.metadata?.versionExact).toBe(false);
  });

  it("uses no live network at any point", async () => {
    await run();
    expect(NO_NETWORK).not.toHaveBeenCalled();
  });
});

describe("the 1 MiB hard limit: graceful, and stated", () => {
  const NOTE = "package-lock.json";

  it("pins the lockfile cap to the GitHub client's own response cap", () => {
    // Above this the client cannot retrieve the file at all (MCP and REST both refuse), so
    // a higher exemption would only move the failure. If the client's cap changes, this
    // fails and the lockfile cap should be revisited with it.
    expect(MAX_LOCKFILE_BYTES).toBe(MAX_RESPONSE_BYTES);
  });

  it("does not fetch a lockfile whose tree size is over 1 MiB, and does not fail the load", async () => {
    const { deps, loaded } = await loadWithLockfile(MAX_LOCKFILE_BYTES + 1);

    expect(deps.fetched).not.toContain("package-lock.json");
    expect(loaded.files.map((f) => f.path)).not.toContain("package-lock.json");
    expect(loaded.skipped.ignored).toBe(1);
    expect(loaded.files.map((f) => f.path)).toContain("package.json"); // the rest is intact
  });

  it("skips a lockfile the client refuses as too large, instead of failing the whole analysis", async () => {
    const entries = [
      file("package.json"),
      file("package-lock.json"),
      ...SOURCE_ENTRIES,
    ]; // no size claimed
    const deps = githubDeps(
      entries,
      { "package.json": PACKAGE_JSON, ...sources },
      (path) =>
        path === "package-lock.json"
          ? new GitHubMcpError(
              "REPO_TOO_LARGE",
              "package-lock.json exceeds 1048576 bytes",
            )
          : undefined,
    );
    const loaded = await loadRepositoryWith(deps, "o", "r");

    expect(loaded.files.map((f) => f.path)).not.toContain("package-lock.json");
    expect(loaded.files.map((f) => f.path)).toEqual(
      expect.arrayContaining(["package.json", "src/a.ts"]),
    );
    expect(loaded.skipped.ignored).toBe(1);
  });

  it("re-checks the downloaded size, so a lockfile the tree under-reported is still refused", async () => {
    const huge = "x".repeat(MAX_LOCKFILE_BYTES + 1);
    const { loaded } = await loadWithLockfile(1000, huge);

    expect(loaded.files.map((f) => f.path)).not.toContain("package-lock.json");
    expect(loaded.skipped.ignored).toBe(1);
  });

  it("accepts a lockfile of exactly 1 MiB", async () => {
    const exact = "x".repeat(MAX_LOCKFILE_BYTES);
    const { loaded } = await loadWithLockfile(MAX_LOCKFILE_BYTES, exact);

    expect(loaded.files.map((f) => f.path)).toContain("package-lock.json");
  });

  it("falls back to ranges, marked inexact, and says why, when the lockfile could not be read", async () => {
    const { loaded } = await loadWithLockfile(MAX_LOCKFILE_BYTES + 1);
    const osv = savedOsv();
    const result = await scanDependencies(loaded.files, {
      fetch: osv.fetch,
      cache: new Map(),
    });

    expect(osv.queries.find((q) => q.name === "lodash")?.version).toBe("4.0.0");
    for (const item of result.evidence)
      expect(item.metadata?.versionExact).toBe(false);

    const note = result.limitations.find((m) => m.includes(NOTE));
    expect(note).toContain(
      "2 dependencies were checked at the lowest version of their declared range",
    );
    expect(note).toContain("versionExact is false");
    expect(note).toContain("larger than the 1 MiB that can be fetched");
  });

  it("does not swallow other failures: a too-large source file still fails the load", async () => {
    const entries = [file("package.json"), ...SOURCE_ENTRIES];
    const deps = githubDeps(
      entries,
      { "package.json": PACKAGE_JSON },
      (path) =>
        path === "src/a.ts"
          ? new GitHubMcpError("REPO_TOO_LARGE", "too big")
          : undefined,
    );

    await expect(loadRepositoryWith(deps, "o", "r")).rejects.toMatchObject({
      code: "REPO_TOO_LARGE",
    });
  });

  it("does not swallow a rate limit on the lockfile either", async () => {
    const entries = [
      file("package.json"),
      file("package-lock.json"),
      ...SOURCE_ENTRIES,
    ];
    const deps = githubDeps(
      entries,
      { "package.json": PACKAGE_JSON, ...sources },
      (path) =>
        path === "package-lock.json"
          ? new GitHubMcpError("UPSTREAM_RATE_LIMITED", "slow down")
          : undefined,
    );

    await expect(loadRepositoryWith(deps, "o", "r")).rejects.toMatchObject({
      code: "UPSTREAM_RATE_LIMITED",
    });
  });
});

describe("the 2 MiB total budget is not weakened", () => {
  it("drops a large lockfile, not high-priority source, when the budget runs out", async () => {
    // Eight high-tier files of 190 KB (1.48 MiB) leave 0.52 MiB. A 900 KB lockfile
    // sorts after them (medium), so it is the one that no longer fits.
    const highPaths = Array.from(
      { length: 8 },
      (_, i) => `src/routes/r${i}.ts`,
    );
    const lock = "x".repeat(900 * 1024);
    const contents: Record<string, string> = {
      "package-lock.json": lock,
      "package.json": PACKAGE_JSON,
    };
    for (const path of highPaths) contents[path] = "y".repeat(190 * 1024);

    const entries = [
      file("package.json"),
      file("package-lock.json", lock.length),
      ...highPaths.map((p) => file(p, 190 * 1024)),
    ];
    const loaded = await loadRepositoryWith(
      githubDeps(entries, contents),
      "o",
      "r",
    );
    const total = loaded.files.reduce((sum, f) => sum + bytes(f.content), 0);

    // package.json is high-tier too, so count the eight route files specifically.
    expect(
      loaded.files.filter((f) => f.path.startsWith("src/routes/")),
    ).toHaveLength(8);
    expect(loaded.files.map((f) => f.path)).not.toContain("package-lock.json");
    expect(loaded.skipped.overLimit).toBe(1);
    expect(total).toBeLessThanOrEqual(MAX_TOTAL_BYTES);
  });

  it("keeps the 200 KB limit for every file that is not package-lock.json", async () => {
    const entries = [
      file("package.json"),
      file("src/generated.ts", 500 * 1024),
      file("yarn.lock", 500 * 1024),
      ...SOURCE_ENTRIES,
    ];
    const deps = githubDeps(entries, {
      "package.json": PACKAGE_JSON,
      ...sources,
    });
    const loaded = await loadRepositoryWith(deps, "o", "r");

    expect(deps.fetched).not.toContain("src/generated.ts");
    expect(deps.fetched).not.toContain("yarn.lock");
    expect(loaded.skipped.ignored).toBe(2);
  });
});
