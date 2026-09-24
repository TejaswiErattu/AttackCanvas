import { describe, expect, it } from "vitest";
import {
  FETCH_CONCURRENCY,
  IngestError,
  MAX_FILES,
  MAX_TOTAL_BYTES,
  MAX_TREE_ENTRIES,
  detectLanguages,
  loadRepositoryWith,
  mapWithConcurrency,
  modelBoundFiles,
  type LoaderDeps,
} from "@/server/ingest/loader";
import { MAX_FILE_BYTES } from "@/server/ingest/classifier";
import {
  GitHubMcpError,
  bodyFromResources,
  parseContentsResponse,
  parseFileContent,
  restErrorFor,
  type TreeEntry,
} from "@/server/mcp/githubClient";

const NOW = new Date("2026-09-19T12:00:00.000Z");

/** 60 paths: 10 high, 24 medium (incl. a lockfile), 6 low, 20 ignored. */
const HIGH = [
  "package.json",
  "src/routes/users.ts",
  "src/routes/orders.ts",
  "src/controllers/auth.ts",
  "src/middleware/cors.ts",
  "src/models/user.ts",
  "prisma/schema.prisma",
  "Dockerfile",
  "server.ts",
  ".env.example",
];
const MEDIUM = [
  "src/services/email.ts",
  "src/lib/db.ts",
  "src/lib/logger.ts",
  "src/utils/date.ts",
  "api/health.js",
  "config/default.json",
  "pnpm-lock.yaml",
  ...Array.from({ length: 17 }, (_, i) => `src/features/feature${i}.ts`),
];
const LOW = [
  "tests/users.test.ts",
  "tests/orders.test.ts",
  "docs/guide.md",
  "README.md",
  "examples/basic.ts",
  "scripts/seed.ts",
];
const IGNORED = [
  "node_modules/a/index.js",
  "node_modules/b/index.js",
  "dist/bundle.js",
  "build/out.js",
  ".next/cache/x.js",
  "coverage/lcov.info",
  "vendor/x.php",
  ".git/config",
  "__pycache__/a.pyc",
  ".venv/lib/x.py",
  "public/logo.png",
  "public/index.html",
  "assets/hero.png",
  "src/logo.svg",
  "docs/demo.mp4",
  "src/vendor.min.js",
  ".env",
  ".env.local",
  "fonts/a.woff",
  "src/huge.ts",
];
const FAKE_PATHS = [...IGNORED, ...LOW, ...MEDIUM, ...HIGH]; // deliberately unsorted

function file(path: string, size = 100): TreeEntry {
  return {
    path,
    type: "file",
    size: path === "src/huge.ts" ? 300 * 1024 : size,
  };
}

type Fake = LoaderDeps & {
  fetched: string[];
  refs: string[];
  inFlightPeak: number;
};

function fakeDeps(
  entries: TreeEntry[],
  options: {
    truncated?: boolean;
    languages?: string[];
    defaultBranch?: string;
    fail?: (path: string) => unknown;
    /** What the download actually returns, independent of the tree's claimed size. */
    content?: (path: string) => string | undefined;
  } = {},
): Fake {
  let inFlight = 0;
  const fake: Fake = {
    fetched: [],
    refs: [],
    inFlightPeak: 0,
    now: () => NOW,
    async getRepoMetadata() {
      return {
        defaultBranch: options.defaultBranch ?? "main",
        ...(options.languages ? { languages: options.languages } : {}),
        source: "rest",
      };
    },
    async listTree(_owner, _repo, ref) {
      fake.refs.push(ref);
      return { entries, source: "mcp", truncated: options.truncated ?? false };
    },
    async getFileContent(_owner, _repo, _ref, path) {
      inFlight += 1;
      fake.inFlightPeak = Math.max(fake.inFlightPeak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 1));
      inFlight -= 1;

      fake.fetched.push(path);
      const failure = options.fail?.(path);
      if (failure) throw failure;
      return options.content?.(path) ?? `// ${path}`;
    },
  };
  return fake;
}

function totalBytes(files: readonly { content: string }[]): number {
  return files.reduce(
    (sum, f) => sum + Buffer.byteLength(f.content, "utf8"),
    0,
  );
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("expected a rejection");
}

describe("loadRepositoryWith, a 60-path tree", () => {
  const entries = FAKE_PATHS.map((path) => file(path));

  it("has the tree the tests describe", () => {
    expect(FAKE_PATHS).toHaveLength(60);
  });

  it("loads everything that is not ignored, and counts the rest", async () => {
    const result = await loadRepositoryWith(fakeDeps(entries), "o", "r");

    expect(result.files).toHaveLength(40);
    expect(result.skipped).toEqual({ ignored: 20, overLimit: 0 });
    expect(result.truncated).toBe(false);
  });

  it("orders high, then medium, then low", async () => {
    const { files } = await loadRepositoryWith(fakeDeps(entries), "o", "r");

    const ranks = files.map((f) => ({ high: 0, medium: 1, low: 2 })[f.tier]);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
    expect(files.filter((f) => f.tier === "high")).toHaveLength(10);
    expect(files.filter((f) => f.tier === "medium")).toHaveLength(24);
    expect(files.filter((f) => f.tier === "low")).toHaveLength(6);
  });

  it("never fetches an ignored path, and never fetches .env", async () => {
    const deps = fakeDeps(entries);
    await loadRepositoryWith(deps, "o", "r");

    for (const path of IGNORED) expect(deps.fetched).not.toContain(path);
    expect(deps.fetched).not.toContain(".env");
    expect(deps.fetched).not.toContain(".env.local");
    expect(deps.fetched).toContain(".env.example");
  });

  it("returns content, tier and reason for each file", async () => {
    const { files } = await loadRepositoryWith(fakeDeps(entries), "o", "r");
    const routes = files.find((f) => f.path === "src/routes/users.ts");

    expect(routes).toEqual({
      path: "src/routes/users.ts",
      content: "// src/routes/users.ts",
      tier: "high",
      reason: "routes/",
    });
  });

  it("keeps lockfiles, tagged for dependencies", async () => {
    const { files } = await loadRepositoryWith(fakeDeps(entries), "o", "r");
    const lock = files.find((f) => f.path === "pnpm-lock.yaml");

    expect(lock).toMatchObject({ tier: "medium", reason: "dependencies" });
  });

  it("fetches with a concurrency of at most 5, and actually uses it", async () => {
    const deps = fakeDeps(entries);
    await loadRepositoryWith(deps, "o", "r");

    expect(FETCH_CONCURRENCY).toBe(5);
    expect(deps.inFlightPeak).toBe(5);
  });

  it("builds the summary", async () => {
    const { summary } = await loadRepositoryWith(
      fakeDeps(entries),
      "acme",
      "shop",
    );

    expect(summary).toEqual({
      owner: "acme",
      name: "shop",
      ref: "main",
      languages: ["TypeScript", "JavaScript"],
      frameworks: [],
      fileCountAnalyzed: 40,
      analyzedAt: "2026-09-19T12:00:00.000Z",
    });
  });

  it("prefers the languages GitHub reports", async () => {
    const deps = fakeDeps(entries, { languages: ["Go", "Shell"] });
    const { summary } = await loadRepositoryWith(deps, "o", "r");

    expect(summary.languages).toEqual(["Go", "Shell"]);
  });
});

describe("ref handling", () => {
  const entries = FAKE_PATHS.map((path) => file(path));

  it("uses the default branch when no ref is given", async () => {
    const deps = fakeDeps(entries, { defaultBranch: "trunk" });
    const { summary } = await loadRepositoryWith(deps, "o", "r");

    expect(deps.refs).toEqual(["trunk"]);
    expect(summary.ref).toBe("trunk");
  });

  it("uses an explicit ref over the default branch", async () => {
    const deps = fakeDeps(entries);
    const { summary } = await loadRepositoryWith(deps, "o", "r", "v2");

    expect(deps.refs).toEqual(["v2"]);
    expect(summary.ref).toBe("v2");
  });
});

describe("limits", () => {
  it("keeps at most 300 files and reports the rest as overLimit", async () => {
    const entries = Array.from({ length: 400 }, (_, i) => file(`src/f${i}.ts`));
    const result = await loadRepositoryWith(fakeDeps(entries), "o", "r");

    expect(result.files).toHaveLength(MAX_FILES);
    expect(result.skipped.overLimit).toBe(100);
    expect(result.truncated).toBe(true);
  });

  it("keeps high-tier files when the file limit bites", async () => {
    const entries = [
      ...Array.from({ length: 400 }, (_, i) => file(`src/f${i}.ts`)),
      file("src/routes/critical.ts"),
    ];
    const { files } = await loadRepositoryWith(fakeDeps(entries), "o", "r");

    expect(files[0].path).toBe("src/routes/critical.ts");
    expect(files).toHaveLength(MAX_FILES);
  });

  it("keeps at most 2 MiB in total, measured on downloaded content", async () => {
    const entries = Array.from({ length: 15 }, (_, i) =>
      file(`src/big${i}.ts`, 1),
    );
    const deps = fakeDeps(entries, { content: () => "x".repeat(190 * 1024) });
    const result = await loadRepositoryWith(deps, "o", "r");

    expect(result.files).toHaveLength(10); // 1.95 MiB; an 11th would reach 2.14 MiB
    expect(totalBytes(result.files)).toBeLessThanOrEqual(MAX_TOTAL_BYTES);
    expect(result.skipped.overLimit).toBe(5);
    expect(result.truncated).toBe(true);
  });

  it("does not trust the tree size: a small claimed size cannot smuggle in a big file", async () => {
    const entries = Array.from({ length: 12 }, (_, i) =>
      file(`src/f${i}.ts`, 10),
    );
    const deps = fakeDeps(entries, { content: () => "x".repeat(190 * 1024) });
    const result = await loadRepositoryWith(deps, "o", "r");

    expect(totalBytes(result.files)).toBeLessThanOrEqual(MAX_TOTAL_BYTES);
    expect(result.files).toHaveLength(10);
  });

  it("does not count a missing tree size as zero", async () => {
    const entries: TreeEntry[] = Array.from({ length: 12 }, (_, i) => ({
      path: `src/f${i}.ts`,
      type: "file",
    }));
    const deps = fakeDeps(entries, { content: () => "x".repeat(190 * 1024) });
    const result = await loadRepositoryWith(deps, "o", "r");

    expect(totalBytes(result.files)).toBeLessThanOrEqual(MAX_TOTAL_BYTES);
    expect(result.files).toHaveLength(10);
    expect(result.skipped.overLimit).toBe(2);
    expect(result.truncated).toBe(true);
  });

  it("counts UTF-8 bytes, not characters", async () => {
    // 60,000 euro signs: 60,000 characters but 180,000 bytes each.
    const euro = "\u20ac".repeat(60_000);
    const entries = Array.from({ length: 12 }, (_, i) => file(`src/f${i}.ts`));
    const result = await loadRepositoryWith(
      fakeDeps(entries, { content: () => euro }),
      "o",
      "r",
    );

    expect(Buffer.byteLength(euro, "utf8")).toBe(180_000);
    expect(euro.length * 12).toBeLessThan(MAX_TOTAL_BYTES); // by characters, all 12 would fit
    expect(result.files).toHaveLength(11); // by bytes, only 11 do
    expect(totalBytes(result.files)).toBeLessThanOrEqual(MAX_TOTAL_BYTES);
  });

  it("lets a smaller file fill space a larger one could not", async () => {
    const sizes: Record<string, number> = {
      "src/b-big.ts": 195 * 1024,
      "src/c-small.ts": 100 * 1024,
    };
    const entries = [
      ...Array.from({ length: 10 }, (_, i) => file(`src/a${i}.ts`)),
      file("src/b-big.ts"),
      file("src/c-small.ts"),
    ];
    const deps = fakeDeps(entries, {
      content: (path) => "x".repeat(sizes[path] ?? 190 * 1024),
    });
    const { files, skipped } = await loadRepositoryWith(deps, "o", "r");
    const paths = files.map((f) => f.path);

    expect(paths).not.toContain("src/b-big.ts"); // 1.95 + 0.19 MiB: over
    expect(paths).toContain("src/c-small.ts"); // 1.95 + 0.098 MiB: fits
    expect(skipped.overLimit).toBe(1);
  });

  it("spends the budget on high-tier files first", async () => {
    const entries = [
      ...Array.from({ length: 11 }, (_, i) => file(`src/lib/m${i}.ts`)),
      file("src/routes/critical.ts"),
    ];
    const deps = fakeDeps(entries, { content: () => "x".repeat(190 * 1024) });
    const { files } = await loadRepositoryWith(deps, "o", "r");

    expect(files[0].path).toBe("src/routes/critical.ts");
    expect(files).toHaveLength(10);
  });

  it("ignores a file whose download exceeds 200 KiB despite a small tree size", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("src/c.ts"),
      file("src/liar.ts", 10),
    ];
    const deps = fakeDeps(entries, {
      content: (path) =>
        path === "src/liar.ts" ? "x".repeat(MAX_FILE_BYTES + 1) : undefined,
    });
    const result = await loadRepositoryWith(deps, "o", "r");

    expect(result.files.map((f) => f.path)).not.toContain("src/liar.ts");
    expect(result.skipped.ignored).toBe(1);
  });

  it("fetches at most 300 files even when the byte budget drops some", async () => {
    const entries = Array.from({ length: 400 }, (_, i) => file(`src/f${i}.ts`));
    const deps = fakeDeps(entries, { content: () => "x".repeat(50 * 1024) });
    const result = await loadRepositoryWith(deps, "o", "r");

    expect(deps.fetched).toHaveLength(MAX_FILES);
    expect(totalBytes(result.files)).toBeLessThanOrEqual(MAX_TOTAL_BYTES);
    expect(result.skipped.overLimit).toBe(400 - result.files.length);
  });

  it("reports truncated when GitHub truncated the tree", async () => {
    const entries = FAKE_PATHS.map((path) => file(path));
    const result = await loadRepositoryWith(
      fakeDeps(entries, { truncated: true }),
      "o",
      "r",
    );

    expect(result.truncated).toBe(true);
    expect(result.skipped.overLimit).toBe(0);
  });
});

describe("errors", () => {
  it("throws REPO_TOO_LARGE above 20,000 entries", async () => {
    const entries = Array.from({ length: MAX_TREE_ENTRIES + 1 }, (_, i) =>
      file(`src/f${i}.ts`),
    );
    const deps = fakeDeps(entries);
    const error = await rejection(loadRepositoryWith(deps, "o", "r"));

    expect(error).toBeInstanceOf(IngestError);
    expect((error as IngestError).code).toBe("REPO_TOO_LARGE");
    expect(deps.fetched).toEqual([]); // refused before fetching anything
  });

  it("accepts exactly 20,000 entries", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("src/c.ts"),
      ...Array.from({ length: MAX_TREE_ENTRIES - 3 }, (_, i) =>
        file(`node_modules/p${i}.js`),
      ),
    ];
    const result = await loadRepositoryWith(fakeDeps(entries), "o", "r");

    expect(result.files).toHaveLength(3);
  });

  it("counts directories toward the 20,000 entries", async () => {
    const dirs: TreeEntry[] = Array.from(
      { length: MAX_TREE_ENTRIES },
      (_, i) => ({
        path: `d${i}`,
        type: "dir",
      }),
    );
    const error = await rejection(
      loadRepositoryWith(fakeDeps([...dirs, file("src/a.ts")]), "o", "r"),
    );

    expect((error as IngestError).code).toBe("REPO_TOO_LARGE");
  });

  it("throws INSUFFICIENT_CODE with fewer than 3 source files", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("package.json"),
      file("README.md"),
      file("pnpm-lock.yaml"),
      file("node_modules/x/index.js"),
    ];
    const error = await rejection(
      loadRepositoryWith(fakeDeps(entries), "o", "r"),
    );

    expect(error).toBeInstanceOf(IngestError);
    expect((error as IngestError).code).toBe("INSUFFICIENT_CODE");
  });

  it("accepts exactly 3 source files", async () => {
    const entries = [file("src/a.ts"), file("src/b.ts"), file("src/c.ts")];
    const result = await loadRepositoryWith(fakeDeps(entries), "o", "r");

    expect(result.files).toHaveLength(3);
  });

  it("does not count ignored files toward the minimum", async () => {
    const entries = [file("src/a.ts"), file("src/b.ts"), file("dist/c.ts")];
    const error = await rejection(
      loadRepositoryWith(fakeDeps(entries), "o", "r"),
    );

    expect((error as IngestError).code).toBe("INSUFFICIENT_CODE");
  });

  it("skips a file that turns out to be binary, and counts it as ignored", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("src/c.ts"),
      file("src/d.ts"),
    ];
    const deps = fakeDeps(entries, {
      fail: (path) =>
        path === "src/d.ts"
          ? thrownBy(() => parseContentsResponse(binaryContents, path))
          : undefined,
    });
    const result = await loadRepositoryWith(deps, "o", "r");

    expect(result.files.map((f) => f.path)).not.toContain("src/d.ts");
    expect(result.skipped.ignored).toBe(1);
  });

  // The "not text" errors, produced by githubClient's own functions so the loader's
  // recognition of them is pinned to the real wording.
  const binaryContents = {
    type: "file",
    encoding: "base64",
    content: Buffer.from([0x50, 0x00, 0x4b]).toString("base64"),
  };
  function thrownBy(fn: () => unknown): unknown {
    try {
      fn();
    } catch (error) {
      return error;
    }
    throw new Error("expected a throw");
  }

  it.each([
    ["binary REST content", (p: string) => thrownBy(() => parseContentsResponse(binaryContents, p))],
    ["a binary MCP blob", (p: string) =>
      thrownBy(() => bodyFromResources([{ blob: binaryContents.content }], p))],
    ["a directory", (p: string) => thrownBy(() => parseContentsResponse([], p))],
    ["a submodule", (p: string) => thrownBy(() => parseContentsResponse({ type: "submodule" }, p))],
    ["an unsupported encoding", (p: string) =>
      thrownBy(() => parseContentsResponse({ type: "file", encoding: "utf-8", content: "x" }, p))],
    ["a directory in an MCP text wrapper", () => thrownBy(() => parseFileContent("[]"))],
  ])("skips %s as not text", async (_label, makeError) => {
    const entries = ["src/a.ts", "src/b.ts", "src/c.ts", "src/d.ts"].map((p) => file(p));
    const deps = fakeDeps(entries, {
      fail: (path) => (path === "src/d.ts" ? makeError(path) : undefined),
    });
    const result = await loadRepositoryWith(deps, "o", "r");

    expect(result.files.map((f) => f.path)).toEqual(["src/a.ts", "src/b.ts", "src/c.ts"]);
    expect(result.skipped.ignored).toBe(1);
  });

  it.each([
    ["a 502 from the REST API", (p: string) => restErrorFor(502, null, `/repos/o/r/contents/${p}`)],
    ["a 500 from the REST API", (p: string) => restErrorFor(500, null, `/repos/o/r/contents/${p}`)],
    ["a network failure", (p: string) =>
      new GitHubMcpError("GITHUB_UNAVAILABLE", `GET /repos/o/r/contents/${p} failed: fetch failed`)],
    ["a not-text message for a DIFFERENT path", () =>
      thrownBy(() => parseContentsResponse(binaryContents, "src/other.ts"))],
  ])("does not silently drop a file on %s: the load fails instead", async (_label, makeError) => {
    const entries = ["src/a.ts", "src/b.ts", "src/c.ts", "src/middleware/auth.ts"].map((p) => file(p));
    const deps = fakeDeps(entries, {
      fail: (path) => (path === "src/middleware/auth.ts" ? makeError(path) : undefined),
    });
    const error = await rejection(loadRepositoryWith(deps, "o", "r"));

    expect(error).toBeInstanceOf(GitHubMcpError);
    expect((error as GitHubMcpError).code).toBe("GITHUB_UNAVAILABLE");
  });

  it("rethrows any other fetch failure", async () => {
    const entries = [file("src/a.ts"), file("src/b.ts"), file("src/c.ts")];
    const deps = fakeDeps(entries, {
      fail: (path) =>
        path === "src/b.ts"
          ? new GitHubMcpError("UPSTREAM_RATE_LIMITED", "slow down")
          : undefined,
    });
    const error = await rejection(loadRepositoryWith(deps, "o", "r"));

    expect(error).toBeInstanceOf(GitHubMcpError);
    expect((error as GitHubMcpError).code).toBe("UPSTREAM_RATE_LIMITED");
  });

  it("ignores directory entries when selecting files", async () => {
    const entries: TreeEntry[] = [
      { path: "src", type: "dir" },
      { path: "src/routes", type: "dir" },
      file("src/a.ts"),
      file("src/b.ts"),
      file("src/c.ts"),
    ];
    const deps = fakeDeps(entries);
    const result = await loadRepositoryWith(deps, "o", "r");

    expect(deps.fetched).not.toContain("src/routes");
    expect(result.skipped.ignored).toBe(0);
  });
});

describe("mapWithConcurrency", () => {
  it("preserves input order regardless of completion order", async () => {
    const out = await mapWithConcurrency([30, 1, 15], 3, async (ms) => {
      await new Promise((resolve) => setTimeout(resolve, ms));
      return ms;
    });
    expect(out).toEqual([30, 1, 15]);
  });

  it("handles an empty list", async () => {
    await expect(mapWithConcurrency([], 5, async (x) => x)).resolves.toEqual(
      [],
    );
  });
});

describe("detectLanguages", () => {
  it("orders by file count", () => {
    expect(detectLanguages(["a.py", "b.ts", "c.ts", "d.tsx", "e.md"])).toEqual([
      "TypeScript",
      "Python",
    ]);
  });
});

describe("lockfiles", () => {
  const lockfiles = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "Cargo.lock",
    "poetry.lock",
  ];

  it("do not count toward the three-source-file minimum", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("package.json"),
      ...lockfiles.map((path) => file(path)),
    ];
    const error = await rejection(
      loadRepositoryWith(fakeDeps(entries), "o", "r"),
    );

    expect(error).toBeInstanceOf(IngestError);
    expect((error as IngestError).code).toBe("INSUFFICIENT_CODE");
  });

  it("are still returned, tagged dependencies, once there is enough code", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("src/c.ts"),
      ...lockfiles.map((path) => file(path)),
    ];
    const { files } = await loadRepositoryWith(fakeDeps(entries), "o", "r");

    const locks = files.filter((f) => f.reason === "dependencies");
    expect(locks.map((f) => f.path).sort()).toEqual([...lockfiles].sort());
    for (const lock of locks) expect(lock.tier).toBe("medium");
  });

  it("are excluded from the files a model may see", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("src/c.ts"),
      ...lockfiles.map((path) => file(path)),
    ];
    const { files } = await loadRepositoryWith(fakeDeps(entries), "o", "r");
    const bound = modelBoundFiles(files).map((f) => f.path);

    for (const path of lockfiles) expect(bound).not.toContain(path);
    expect(bound).toEqual(
      expect.arrayContaining(["src/a.ts", "src/b.ts", "src/c.ts"]),
    );
  });

  it("other than package-lock.json, over 200 KB are still ignored and never fetched", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("src/c.ts"),
      file("pnpm-lock.yaml", 900 * 1024),
      file("yarn.lock", 300 * 1024),
    ];
    const deps = fakeDeps(entries);
    const { files, skipped } = await loadRepositoryWith(deps, "o", "r");

    expect(deps.fetched).not.toContain("pnpm-lock.yaml");
    expect(deps.fetched).not.toContain("yarn.lock");
    expect(files.map((f) => f.path)).not.toContain("pnpm-lock.yaml");
    expect(skipped.ignored).toBe(2);
  });
});

describe("assets/ directory", () => {
  it("is never fetched, at any depth", async () => {
    const entries = [
      file("src/a.ts"),
      file("src/b.ts"),
      file("src/c.ts"),
      file("assets/app.js"),
      file("src/assets/x.ts"),
      file("packages/web/assets/y.ts"),
      file("src/assets.ts"), // a name, not the directory: kept
    ];
    const deps = fakeDeps(entries);
    const { skipped } = await loadRepositoryWith(deps, "o", "r");

    expect(deps.fetched).not.toContain("assets/app.js");
    expect(deps.fetched).not.toContain("src/assets/x.ts");
    expect(deps.fetched).not.toContain("packages/web/assets/y.ts");
    expect(deps.fetched).toContain("src/assets.ts");
    expect(skipped.ignored).toBe(3);
  });
});

describe("sensitive nested directories", () => {
  it("load admin and auth directories ahead of ordinary source", async () => {
    const entries = [
      file("src/lib/util.ts"),
      file("src/admin/panel.ts"),
      file("src/auth/helpers.ts"),
      file("src/services/email.ts"),
    ];
    const { files } = await loadRepositoryWith(fakeDeps(entries), "o", "r");

    expect(files.slice(0, 2).map((f) => f.path)).toEqual([
      "src/admin/panel.ts",
      "src/auth/helpers.ts",
    ]);
    expect(files.slice(0, 2).every((f) => f.tier === "high")).toBe(true);
  });
});
