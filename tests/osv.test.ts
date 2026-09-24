import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  BATCH_SIZE,
  DETAIL_CONCURRENCY,
  MAX_EVIDENCE,
  OSV_TIMEOUT_MS,
  collapseAliases,
  collectDependencies,
  fixedVersionFor,
  fixedVersionForGroup,
  isSafeId,
  isValidPackageName,
  parseBatchResponse,
  parseVuln,
  scanDependencies,
  type OsvVuln,
  type ScanFile,
} from "@/server/scanners/osv";
import { EvidenceSchema, zId } from "@/shared/schema";
import { BATCH_RESPONSE, CAPTURED_QUERIES, VULNS } from "./osvResponses";

// ---------------------------------------------------------------------------
// Harness. Nothing here touches the network: fetch is always injected.
// ---------------------------------------------------------------------------

/**
 * A backstop for that promise. If any test forgets to inject fetch, the global one is
 * this, which throws instead of reaching api.osv.dev. Without it a missed injection
 * would pass quietly on a developer's machine and fail (or hit the real API) on CI.
 */
const NO_NETWORK = (() => {
  throw new Error("a test tried to use the real network: inject fetch");
}) as unknown as typeof fetch;

beforeAll(() => {
  vi.stubGlobal("fetch", NO_NETWORK);
});
afterAll(() => {
  vi.unstubAllGlobals();
});

type Call = {
  url: string;
  method: string;
  body?: {
    queries: {
      package: { name: string; ecosystem: string };
      version: string;
    }[];
  };
  headers?: HeadersInit;
  signal?: AbortSignal | null;
};

type Handlers = {
  batch?: (queries: NonNullable<Call["body"]>["queries"]) => unknown;
  vulns?: Record<string, unknown>;
  delayMs?: number;
};

function respond(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function makeFetch(handlers: Handlers = {}) {
  const calls: Call[] = [];
  let inFlight = 0;
  let peak = 0;

  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body =
      typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({
      url,
      method: init?.method ?? "GET",
      body,
      headers: init?.headers,
      signal: init?.signal,
    });

    inFlight += 1;
    peak = Math.max(peak, inFlight);
    try {
      if (handlers.delayMs)
        await new Promise((r) => setTimeout(r, handlers.delayMs));

      if (url.endsWith("/v1/querybatch")) {
        const queries = (body as Call["body"])!.queries;
        const out = handlers.batch?.(queries) ?? {
          results: queries.map(() => ({})),
        };
        return out instanceof Response ? out : respond(out);
      }

      const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
      const record = handlers.vulns?.[id];
      if (record instanceof Response) return record;
      return record
        ? respond(record)
        : respond({ code: 5, message: "not found" }, 404);
    } finally {
      inFlight -= 1;
    }
  }) as unknown as typeof fetch;

  return {
    fetch: fetchFn,
    calls,
    get peak() {
      return peak;
    },
    posts: () => calls.filter((c) => c.method === "POST"),
    gets: () => calls.filter((c) => c.method === "GET"),
  };
}

const PACKAGE_JSON: ScanFile = {
  path: "package.json",
  content: JSON.stringify(
    {
      name: "app",
      dependencies: { lodash: "^4.17.15", "left-pad": "1.3.0" },
      devDependencies: { minimist: "~1.2.0" },
    },
    null,
    2,
  ),
};

const LOCKFILE: ScanFile = {
  path: "package-lock.json",
  content: JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "app" },
      "node_modules/lodash": { version: "4.17.15" },
      "node_modules/left-pad": { version: "1.3.0" },
      "node_modules/minimist": { version: "1.2.0" },
    },
  }),
};

/** The real captured batch + records, served for the three packages above. */
function realFetch(extra: Handlers = {}) {
  return makeFetch({ batch: () => BATCH_RESPONSE, vulns: VULNS, ...extra });
}

/** A hand-made advisory. SYNTHETIC: used only where real data cannot cover the case. */
function synth(
  id: string,
  pkg: string,
  options: {
    label?: string;
    fixed?: string;
    aliases?: string[];
    summary?: string;
    withdrawn?: string;
    ecosystem?: string;
  } = {},
) {
  return {
    id,
    summary: options.summary ?? `Problem in ${pkg}`,
    aliases: options.aliases ?? [],
    ...(options.withdrawn ? { withdrawn: options.withdrawn } : {}),
    database_specific: { severity: options.label ?? "MODERATE" },
    affected: [
      {
        package: { name: pkg, ecosystem: options.ecosystem ?? "npm" },
        ranges: [
          {
            type: "SEMVER",
            events: [
              { introduced: "0" },
              options.fixed
                ? { fixed: options.fixed }
                : { last_affected: "99.0.0" },
            ],
          },
        ],
      },
    ],
  };
}

function manifestOf(
  deps: Record<string, string>,
  dev: Record<string, string> = {},
): ScanFile {
  return {
    path: "package.json",
    content: JSON.stringify(
      { dependencies: deps, devDependencies: dev },
      null,
      2,
    ),
  };
}

const real = (id: string): OsvVuln => parseVuln(VULNS[id]) as OsvVuln;

/**
 * Tests that use a manifest with no lockfile now also get the note about versions inferred
 * from ranges. Those tests are about something else, so they compare everything but it.
 */
const withoutLockfileNote = (limitations: string[]): string[] =>
  limitations.filter((message) => !message.includes("package-lock.json"));

// ---------------------------------------------------------------------------

describe("constants match the specification", () => {
  it("has a 10 s timeout, batches of 500, concurrency 5 and a cap of 40", () => {
    expect(OSV_TIMEOUT_MS).toBe(10_000);
    expect(BATCH_SIZE).toBe(500);
    expect(DETAIL_CONCURRENCY).toBe(5);
    expect(MAX_EVIDENCE).toBe(40);
  });
});

describe("isValidPackageName and isSafeId", () => {
  it.each([
    "lodash",
    "left-pad",
    "@scope/pkg",
    "@a/b.c",
    "a.b",
    "a_b",
    "0abc",
    "~tilde",
  ])("accepts the package name %s", (name) => {
    expect(isValidPackageName(name)).toBe(true);
  });

  it.each([
    "",
    "UPPER",
    "has space",
    "a/b/c",
    "../x",
    "@scope",
    "@/pkg",
    "a\nb",
    'a"b',
    "x".repeat(215),
    ".hidden",
    "_under",
  ])("rejects the package name %j", (name) => {
    expect(isValidPackageName(name)).toBe(false);
  });

  it.each([
    "GHSA-p6mc-m468-83gw",
    "CVE-2020-8203",
    "PYSEC-2021-1",
    "OSV-2020-1",
    "a.b:c_d",
  ])("accepts the id %s", (id) => {
    expect(isSafeId(id)).toBe(true);
  });

  it.each([
    "",
    "../../etc/passwd",
    "a/b",
    "a b",
    "a?b=c",
    "-lead",
    "x".repeat(101),
    "a\nb",
  ])("rejects the id %j, which would go into a URL path", (id) => {
    expect(isSafeId(id)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// collectDependencies
// ---------------------------------------------------------------------------

describe("collectDependencies", () => {
  it("uses the exact version from a lockfile", () => {
    const { dependencies } = collectDependencies([PACKAGE_JSON, LOCKFILE]);
    const lodash = dependencies.find((d) => d.name === "lodash");

    expect(lodash).toMatchObject({
      version: "4.17.15",
      versionExact: true,
      range: "^4.17.15",
    });
  });

  it("prefers the locked version over the range's minimum", () => {
    const lock = {
      path: "package-lock.json",
      content: JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/lodash": { version: "4.17.21" } },
      }),
    };
    const [dep] = collectDependencies([
      manifestOf({ lodash: "^4.17.15" }),
      lock,
    ]).dependencies;

    expect(dep.version).toBe("4.17.21");
    expect(dep.versionExact).toBe(true);
  });

  it("falls back to the range's minimum, marked inexact, with no lockfile", () => {
    const { dependencies } = collectDependencies([PACKAGE_JSON]);

    expect(
      dependencies.map((d) => [d.name, d.version, d.versionExact]),
    ).toEqual([
      ["lodash", "4.17.15", false],
      ["left-pad", "1.3.0", false],
      ["minimist", "1.2.0", false],
    ]);
  });

  it("falls back for a package the lockfile does not list", () => {
    const lock = {
      path: "package-lock.json",
      content: JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }),
    };
    const [dep] = collectDependencies([
      manifestOf({ lodash: "^4.17.15" }),
      lock,
    ]).dependencies;

    expect(dep).toMatchObject({ version: "4.17.15", versionExact: false });
  });

  it("marks devDependencies as dev and everything else as runtime", () => {
    const manifest: ScanFile = {
      path: "package.json",
      content: JSON.stringify({
        dependencies: { a: "1.0.0" },
        optionalDependencies: { b: "1.0.0" },
        devDependencies: { c: "1.0.0" },
        peerDependencies: { d: "1.0.0" },
      }),
    };
    const { dependencies } = collectDependencies([manifest]);

    expect(dependencies.map((d) => [d.name, d.dev])).toEqual([
      ["a", false],
      ["b", false],
      ["c", true],
    ]); // peerDependencies are not installed by this package, so are not scanned
  });

  it("counts a package listed in both sections once, as a runtime dependency", () => {
    const { dependencies } = collectDependencies([
      manifestOf({ zod: "^3.0.0" }, { zod: "^3.0.0" }),
    ]);

    expect(dependencies).toHaveLength(1);
    expect(dependencies[0].dev).toBe(false);
  });

  it("points at the line the dependency is declared on", () => {
    const { dependencies } = collectDependencies([PACKAGE_JSON]);
    const lines = PACKAGE_JSON.content.split("\n");

    for (const dep of dependencies) {
      expect(lines[dep.line - 1]).toContain(`"${dep.name}"`);
    }
  });

  it("points at the dependency's own section, not an earlier key of the same name", () => {
    // "prisma" is a top-level config key (line 3) before it is a devDependency (line 8).
    const content = [
      "{",
      '  "name": "app",',
      '  "prisma": { "seed": "node seed.js" },',
      '  "dependencies": {',
      '    "@prisma/client": "5.0.0"',
      "  },",
      '  "devDependencies": {',
      '    "prisma": "5.0.0"',
      "  }",
      "}",
    ].join("\n");
    const { dependencies } = collectDependencies([
      { path: "package.json", content },
    ]);

    expect(dependencies.map((d) => [d.name, d.line])).toEqual([
      ["@prisma/client", 5],
      ["prisma", 8],
    ]);
  });

  it("ignores a lockfile with no packages map (lockfileVersion 1)", () => {
    const v1 = {
      path: "package-lock.json",
      content: JSON.stringify({
        lockfileVersion: 1,
        dependencies: { lodash: { version: "4.17.99" } },
      }),
    };
    const [dep] = collectDependencies([
      manifestOf({ lodash: "^4.17.15" }),
      v1,
    ]).dependencies;

    expect(dep).toMatchObject({ version: "4.17.15", versionExact: false });
  });

  it("does not take a version from a workspace link", () => {
    const lock = {
      path: "package-lock.json",
      content: JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "node_modules/lib": { resolved: "packages/lib", link: true },
        },
      }),
    };
    const [dep] = collectDependencies([
      manifestOf({ lib: "^2.0.0" }),
      lock,
    ]).dependencies;

    expect(dep).toMatchObject({ version: "2.0.0", versionExact: false });
  });

  it.each([["1.x"], ["latest"], ["not-a-version"]])(
    "ignores a locked version %j that is not a full version",
    (version) => {
      const lock = {
        path: "package-lock.json",
        content: JSON.stringify({
          lockfileVersion: 3,
          packages: { "node_modules/lodash": { version } },
        }),
      };
      const [dep] = collectDependencies([
        manifestOf({ lodash: "^4.17.15" }),
        lock,
      ]).dependencies;

      expect(dep.versionExact).toBe(false);
    },
  );

  describe("workspaces", () => {
    // npm records each workspace member under its own path ("packages/api"), which is
    // how a root lockfile is known to have resolved that member's dependencies.
    const rootLock: ScanFile = {
      path: "package-lock.json",
      content: JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": {},
          "node_modules/lodash": { version: "4.17.21" },
          "packages/api": { name: "api" },
          "packages/api/node_modules/lodash": { version: "4.17.15" },
          "packages/web": { name: "web" },
        },
      }),
    };

    it("resolves a workspace package from the root lockfile, preferring its own copy", () => {
      const api = {
        ...manifestOf({ lodash: "^4.0.0" }),
        path: "packages/api/package.json",
      };
      const [dep] = collectDependencies([api, rootLock]).dependencies;

      expect(dep).toMatchObject({ version: "4.17.15", versionExact: true });
    });

    it("uses the hoisted copy when the workspace package has no copy of its own", () => {
      const web = {
        ...manifestOf({ lodash: "^4.0.0" }),
        path: "packages/web/package.json",
      };
      const [dep] = collectDependencies([web, rootLock]).dependencies;

      expect(dep).toMatchObject({ version: "4.17.21", versionExact: true });
    });

    it("does not apply a parent lockfile to a project that is not one of its members", () => {
      // examples/legacy pins lodash 4.17.4 and has no lockfile of its own (or one too
      // big to load). The root lockfile's 4.17.21 is another project's install; reporting
      // it as exact would hide every advisory that affects 4.17.4.
      const legacy = {
        ...manifestOf({ lodash: "4.17.4" }),
        path: "examples/legacy/package.json",
      };
      const [dep] = collectDependencies([legacy, rootLock]).dependencies;

      expect(dep).toMatchObject({ version: "4.17.4", versionExact: false });
    });

    it("does not take membership from an inherited property name", () => {
      const odd = {
        ...manifestOf({ lodash: "^4.0.0" }),
        path: "constructor/package.json",
      };
      const [dep] = collectDependencies([odd, rootLock]).dependencies;

      expect(dep).toMatchObject({ version: "4.0.0", versionExact: false });
    });

    it("uses the nearest lockfile, not one in a sibling directory", () => {
      const sibling: ScanFile = {
        path: "other/package-lock.json",
        content: JSON.stringify({
          lockfileVersion: 3,
          packages: { "node_modules/lodash": { version: "1.0.0" } },
        }),
      };
      const own: ScanFile = {
        path: "packages/api/package-lock.json",
        content: JSON.stringify({
          lockfileVersion: 3,
          packages: { "node_modules/lodash": { version: "4.17.20" } },
        }),
      };
      const api = {
        ...manifestOf({ lodash: "^4.0.0" }),
        path: "packages/api/package.json",
      };
      const [dep] = collectDependencies([
        api,
        rootLock,
        sibling,
        own,
      ]).dependencies;

      expect(dep.version).toBe("4.17.20");
    });

    it("reports the same package in two manifests as two dependencies", () => {
      const a = {
        ...manifestOf({ lodash: "^4.0.0" }),
        path: "packages/a/package.json",
      };
      const b = {
        ...manifestOf({ lodash: "^4.0.0" }),
        path: "packages/b/package.json",
      };
      const { dependencies } = collectDependencies([b, a]);

      expect(dependencies.map((d) => d.file)).toEqual([
        "packages/a/package.json",
        "packages/b/package.json",
      ]);
    });
  });

  describe("what cannot be checked", () => {
    it.each([
      ["a workspace link", "workspace:*"],
      ["a local path", "file:../local"],
      ["a git dependency", "git+https://github.com/a/b.git"],
      ["a GitHub shorthand", "github:a/b"],
      ["a tarball URL", "https://example.com/x.tgz"],
      ["an alias", "npm:other@^1.0.0"],
      ["a wildcard", "*"],
      ["latest", "latest"],
      ["an upper bound only", "<2.0.0"],
    ])("skips %s and says so", (_label, spec) => {
      const { dependencies, limitations } = collectDependencies([
        manifestOf({ pkg: spec }),
      ]);

      expect(dependencies).toEqual([]);
      expect(limitations).toHaveLength(1);
      expect(limitations[0]).toContain("1 dependency was not checked");
    });

    it.each([
      [
        "an alias",
        "npm:rolldown-vite@7.1.14",
        { name: "rolldown-vite", version: "7.1.14" },
      ],
      [
        "a GitHub fork",
        "github:me/pkg#fix",
        { version: "4.17.4", resolved: "git+ssh://git@github.com/me/pkg.git" },
      ],
      ["a local path", "file:../pkg", { version: "1.0.0" }],
    ])(
      "skips %s even when the lockfile lists a version under its name",
      (_label, spec, entry) => {
        // The lockfile's version is of the package the specifier points at, not of the
        // registry package called "pkg", so asking OSV about pkg@<it> is wrong.
        const lock: ScanFile = {
          path: "package-lock.json",
          content: JSON.stringify({
            lockfileVersion: 3,
            packages: { "": {}, "node_modules/pkg": entry },
          }),
        };
        const { dependencies, limitations } = collectDependencies([
          manifestOf({ pkg: spec }),
          lock,
        ]);

        expect(dependencies).toEqual([]);
        expect(limitations[0]).toContain("1 dependency was not checked");
      },
    );

    it("pluralises the message", () => {
      const { limitations } = collectDependencies([
        manifestOf({ a: "*", b: "latest", c: "1.0.0" }),
      ]);
      expect(limitations[0]).toContain("2 dependencies were not checked");
    });

    it("says nothing when everything could be checked", () => {
      expect(collectDependencies([PACKAGE_JSON, LOCKFILE]).limitations).toEqual(
        [],
      );
    });

    it.each(["UPPER", "has space", "a/b/c", "../x", "x".repeat(215), 'a"b'])(
      "drops the invalid package name %j without ever considering it",
      (name) => {
        const { dependencies } = collectDependencies([
          manifestOf({ [name]: "1.0.0" }),
        ]);
        expect(dependencies).toEqual([]);
      },
    );
  });

  describe("malformed input", () => {
    it.each([
      ["not JSON", "nope"],
      ["a JSON array", "[]"],
      ["null", "null"],
      ["an empty file", ""],
      ["no dependency sections", '{"name":"x"}'],
      ["a section of the wrong type", '{"dependencies":"lodash"}'],
      ["a non-string version", '{"dependencies":{"lodash":42}}'],
    ])("returns nothing for %s", (_label, content) => {
      const result = collectDependencies([{ path: "package.json", content }]);
      expect(result.dependencies).toEqual([]);
    });

    it("survives a broken lockfile and uses the range", () => {
      const broken: ScanFile = { path: "package-lock.json", content: "{{{" };
      const [dep] = collectDependencies([
        manifestOf({ lodash: "^4.17.15" }),
        broken,
      ]).dependencies;

      expect(dep.versionExact).toBe(false);
    });

    it("returns nothing for no files", () => {
      expect(collectDependencies([])).toEqual({
        dependencies: [],
        limitations: [],
      });
    });

    it("ignores files that are neither manifests nor lockfiles", () => {
      const other: ScanFile = {
        path: "src/index.js",
        content: '{"dependencies":{"lodash":"1.0.0"}}',
      };
      expect(collectDependencies([other]).dependencies).toEqual([]);
    });
  });
});

// ---------------------------------------------------------------------------
// parsing OSV responses
// ---------------------------------------------------------------------------

describe("parseBatchResponse", () => {
  it("reads the ids for each query from a real response", () => {
    const ids = parseBatchResponse(BATCH_RESPONSE, 3);

    expect(ids[0]).toHaveLength(6); // lodash
    expect(ids[1]).toEqual([]); // left-pad: {} with no vulns key
    expect(ids[2]).toEqual(["GHSA-vh95-rmgr-6w4m", "GHSA-xvch-5gv4-984h"]); // minimist
  });

  it("treats an empty result and a missing vulns key as no vulnerabilities", () => {
    expect(parseBatchResponse({ results: [{}, { vulns: [] }] }, 2)).toEqual([
      [],
      [],
    ]);
  });

  it.each([
    ["not an object", "x"],
    ["null", null],
    ["no results", {}],
    ["results not an array", { results: {} }],
    ["too few results", { results: [{}] }],
    ["too many results", { results: [{}, {}, {}] }],
  ])("rejects %s", (_label, body) => {
    expect(() => parseBatchResponse(body, 2)).toThrow();
  });

  it("drops ids that are not strings or are not safe to put in a URL", () => {
    const body = {
      results: [
        {
          vulns: [
            { id: "GHSA-ok" },
            { id: 7 },
            { id: "../../x" },
            {},
            null,
            { id: "a/b" },
          ],
        },
      ],
    };
    expect(parseBatchResponse(body, 1)).toEqual([["GHSA-ok"]]);
  });
});

describe("parseVuln", () => {
  it("reads a real record", () => {
    const vuln = real("GHSA-p6mc-m468-83gw");

    expect(vuln.id).toBe("GHSA-p6mc-m468-83gw");
    expect(vuln.summary).toBe("Prototype Pollution in lodash");
    expect(vuln.aliases).toEqual(["CVE-2020-8203"]);
    expect(vuln.withdrawn).toBe(false);
    expect(vuln.severity.score).toBe(7.4);
    expect(vuln.severity.label).toBe("HIGH");
    expect(vuln.affected.map((a) => a.name)).toContain("lodash");
  });

  it("keeps every affected package, including other ecosystems", () => {
    const affected = real("GHSA-p6mc-m468-83gw").affected;

    expect(affected.some((a) => a.ecosystem === "RubyGems")).toBe(true);
    expect(affected.filter((a) => a.name === "lodash")).toHaveLength(1);
  });

  it.each([
    ["null", null],
    ["a string", "x"],
    ["no id", { summary: "x" }],
    ["a non-string id", { id: 5 }],
    ["an unsafe id", { id: "../../etc/passwd" }],
  ])("returns undefined for %s", (_label, body) => {
    expect(parseVuln(body)).toBeUndefined();
  });

  it("tolerates every optional field being absent or the wrong type", () => {
    const vuln = parseVuln({
      id: "X-1",
      summary: 5,
      aliases: "nope",
      severity: "nope",
      affected: [
        null,
        "x",
        { package: null, ranges: "nope" },
        { ranges: [null, { events: "x" }] },
      ],
    }) as OsvVuln;

    expect(vuln.id).toBe("X-1");
    expect(vuln.summary).toBe("");
    expect(vuln.aliases).toEqual([]);
    expect(vuln.severity).toEqual({});
  });

  it("flags a withdrawn advisory", () => {
    expect(
      parseVuln({ id: "X-1", withdrawn: "2024-01-01T00:00:00Z" })?.withdrawn,
    ).toBe(true);
    expect(parseVuln({ id: "X-1", withdrawn: "" })?.withdrawn).toBe(false);
    expect(parseVuln({ id: "X-1" })?.withdrawn).toBe(false);
  });

  it("falls back to the advisory's own severity label when there is no vector", () => {
    expect(
      parseVuln(synth("X-1", "p", { label: "CRITICAL" }))?.severity,
    ).toEqual({
      label: "CRITICAL",
    });
  });
});

// ---------------------------------------------------------------------------
// fixed versions and alias groups, on real data
// ---------------------------------------------------------------------------

describe("fixedVersionFor", () => {
  it("finds the fix for the package asked about", () => {
    expect(
      fixedVersionFor(real("GHSA-p6mc-m468-83gw"), "lodash", "4.17.15"),
    ).toBe("4.17.19");
  });

  it("does not report a different package's fix from the same record", () => {
    // The same record says lodash-es is fixed in 4.17.20. That is not lodash's fix.
    const vuln = real("GHSA-p6mc-m468-83gw");

    expect(fixedVersionFor(vuln, "lodash-es", "4.17.15")).toBe("4.17.20");
    expect(fixedVersionFor(vuln, "lodash", "4.17.15")).toBe("4.17.19");
  });

  it("does not use an entry from another ecosystem that shares the name", () => {
    // lodash-rails is a RubyGems package listed in the npm advisory.
    expect(
      fixedVersionFor(real("GHSA-p6mc-m468-83gw"), "lodash-rails", "4.17.15"),
    ).toBeUndefined();
  });

  it("takes the fix from the range that contains the installed version", () => {
    // minimist has a 0.x range (fixed 0.2.1) and a 1.x range (fixed 1.2.3). For 1.2.0
    // the first APPLICABLE fixed version is 1.2.3, the fix of the range containing it.
    // The first fix listed in the record, 0.2.1, is below the installed version and
    // would be wrong advice.
    const vuln = real("GHSA-vh95-rmgr-6w4m");

    expect(fixedVersionFor(vuln, "minimist", "1.2.0")).toBe("1.2.3");
    expect(fixedVersionFor(vuln, "minimist", "0.1.0")).toBe("0.2.1");
  });

  it("picks correctly whichever order the ranges are listed in", () => {
    // GHSA-xvch lists the 1.x range first and the 0.x range second; vh95 the reverse.
    const vuln = real("GHSA-xvch-5gv4-984h");

    expect(fixedVersionFor(vuln, "minimist", "1.2.0")).toBe("1.2.6");
    expect(fixedVersionFor(vuln, "minimist", "0.0.8")).toBe("0.2.4");
  });

  it("returns undefined once the installed version is at or past the fix", () => {
    const vuln = real("GHSA-p6mc-m468-83gw");

    expect(fixedVersionFor(vuln, "lodash", "4.17.19")).toBeUndefined();
    expect(fixedVersionFor(vuln, "lodash", "4.17.21")).toBeUndefined();
  });

  it("falls back to the lowest fix above the version when no range contains it", () => {
    // Version 0.0.1 predates "introduced": 3.7.0, so no interval contains it.
    expect(
      fixedVersionFor(real("GHSA-p6mc-m468-83gw"), "lodash", "1.0.0"),
    ).toBe("4.17.19");
  });

  it("returns undefined when only last_affected is given, meaning no fix exists", () => {
    const vuln = parseVuln(synth("X-1", "pkg")) as OsvVuln; // last_affected 99.0.0

    expect(fixedVersionFor(vuln, "pkg", "1.0.0")).toBeUndefined();
  });

  it("treats an open-ended introduced like last_affected: the installed line has no fix", () => {
    // 1.x is affected with no fix at all; 2.x is fixed in 2.3.1. For 1.5.0 the range
    // that contains it has no fix, exactly as if it ended in last_affected.
    const record = (first: Record<string, string>[]) =>
      parseVuln({
        id: "X-1",
        affected: [
          {
            package: { name: "p", ecosystem: "npm" },
            ranges: [
              { type: "SEMVER", events: first },
              {
                type: "SEMVER",
                events: [{ introduced: "2.0.0" }, { fixed: "2.3.1" }],
              },
            ],
          },
        ],
      }) as OsvVuln;
    const open = record([{ introduced: "1.0.0" }]);
    const closed = record([
      { introduced: "1.0.0" },
      { last_affected: "1.9.9" },
    ]);

    expect(fixedVersionFor(open, "p", "1.5.0")).toBeUndefined();
    expect(fixedVersionFor(open, "p", "1.5.0")).toBe(
      fixedVersionFor(closed, "p", "1.5.0"),
    );
    expect(fixedVersionFor(open, "p", "2.1.0")).toBe("2.3.1"); // its own range's fix
    expect(fixedVersionFor(open, "p", "0.5.0")).toBe("2.3.1"); // below both: next fix
  });

  it("returns undefined for a package the record does not mention", () => {
    expect(
      fixedVersionFor(real("GHSA-p6mc-m468-83gw"), "express", "4.0.0"),
    ).toBeUndefined();
  });

  it("handles a record with several introduced/fixed pairs in one range", () => {
    const vuln = parseVuln({
      id: "X-1",
      affected: [
        {
          package: { name: "p", ecosystem: "npm" },
          ranges: [
            {
              type: "SEMVER",
              events: [
                { introduced: "1.0.0" },
                { fixed: "1.5.0" },
                { introduced: "2.0.0" },
                { fixed: "2.3.0" },
              ],
            },
          ],
        },
      ],
    }) as OsvVuln;

    expect(fixedVersionFor(vuln, "p", "1.2.0")).toBe("1.5.0");
    expect(fixedVersionFor(vuln, "p", "2.1.0")).toBe("2.3.0");
    expect(fixedVersionFor(vuln, "p", "1.7.0")).toBe("2.3.0"); // between: next fix above
  });
});

describe("collapseAliases", () => {
  const lodashVulns = [
    "GHSA-29mw-wpgm-hmr9",
    "GHSA-35jh-r3h4-6jhm",
    "GHSA-f23m-r3pf-42rh",
    "GHSA-p6mc-m468-83gw",
    "GHSA-r5fr-rjxr-66jc",
    "GHSA-xxjr-mmjv-4gpg",
  ].map(real);

  it("turns lodash's six real advisories into four issues", () => {
    expect(collapseAliases(lodashVulns)).toHaveLength(4);
  });

  it("groups the advisories that list each other as aliases", () => {
    const groups = collapseAliases(lodashVulns);
    const idsOf = (group: { members: OsvVuln[] }) =>
      group.members.map((m) => m.id).sort();

    expect(groups.map(idsOf)).toEqual(
      expect.arrayContaining([
        ["GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"],
        ["GHSA-f23m-r3pf-42rh", "GHSA-xxjr-mmjv-4gpg"],
        ["GHSA-29mw-wpgm-hmr9"],
        ["GHSA-p6mc-m468-83gw"],
      ]),
    );
  });

  it("represents a group by its highest-severity member", () => {
    const group = collapseAliases(lodashVulns).find((g) =>
      g.members.some((m) => m.id === "GHSA-35jh-r3h4-6jhm"),
    );
    // r5fr scores 8.1 against 35jh's 7.2.
    expect(group?.vuln.id).toBe("GHSA-r5fr-rjxr-66jc");
  });

  it("gives a group the highest fix any member needs, so one upgrade resolves them all", () => {
    const group = collapseAliases(lodashVulns).find((g) =>
      g.members.some((m) => m.id === "GHSA-35jh-r3h4-6jhm"),
    ) as { vuln: OsvVuln; members: OsvVuln[] };

    // 35jh alone says 4.17.21; r5fr says 4.18.0. Stopping at 4.17.21 would leave r5fr.
    expect(
      fixedVersionFor(real("GHSA-35jh-r3h4-6jhm"), "lodash", "4.17.15"),
    ).toBe("4.17.21");
    expect(fixedVersionForGroup(group, "lodash", "4.17.15")).toBe("4.18.0");
  });

  it("links advisories transitively", () => {
    const a = parseVuln({ id: "A-1", aliases: ["B-1"] }) as OsvVuln;
    const b = parseVuln({ id: "B-1", aliases: ["C-1"] }) as OsvVuln;
    const c = parseVuln({ id: "C-1", aliases: [] }) as OsvVuln;

    expect(collapseAliases([a, b, c])).toHaveLength(1);
  });

  it("links through a shared alias even when neither lists the other", () => {
    const a = parseVuln({ id: "A-1", aliases: ["CVE-2020-1"] }) as OsvVuln;
    const b = parseVuln({ id: "B-1", aliases: ["CVE-2020-1"] }) as OsvVuln;

    expect(collapseAliases([a, b])).toHaveLength(1);
  });

  it("keeps unrelated advisories apart", () => {
    const a = parseVuln({ id: "A-1", aliases: ["CVE-1"] }) as OsvVuln;
    const b = parseVuln({ id: "B-1", aliases: ["CVE-2"] }) as OsvVuln;

    expect(collapseAliases([a, b])).toHaveLength(2);
  });

  it("breaks a severity tie by the lowest id, whatever the input order", () => {
    const a = parseVuln({ id: "A-1", aliases: ["B-1"] }) as OsvVuln;
    const b = parseVuln({ id: "B-1", aliases: ["A-1"] }) as OsvVuln;

    expect(collapseAliases([a, b])[0].vuln.id).toBe("A-1");
    expect(collapseAliases([b, a])[0].vuln.id).toBe("A-1");
  });

  it("returns nothing for nothing", () => {
    expect(collapseAliases([])).toEqual([]);
  });

  it("reports no fix for a group where no member lists one", () => {
    const group = collapseAliases([
      parseVuln(synth("X-1", "pkg")) as OsvVuln,
    ])[0];
    expect(fixedVersionForGroup(group, "pkg", "1.0.0")).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// scanDependencies, against the real captured responses
// ---------------------------------------------------------------------------

describe("scanDependencies: the requests it makes", () => {
  it("posts one querybatch with a query per package, in order", async () => {
    const http = realFetch();
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(http.posts()).toHaveLength(1);
    const [post] = http.posts();

    expect(post.url).toBe("https://api.osv.dev/v1/querybatch");
    expect(post.body).toEqual({
      queries: CAPTURED_QUERIES.map(({ name, version }) => ({
        package: { name, ecosystem: "npm" },
        version,
      })),
    });
  });

  it("sends JSON", async () => {
    const http = realFetch();
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(http.posts()[0].headers).toMatchObject({
      "Content-Type": "application/json",
    });
  });

  it("fetches each returned advisory exactly once, at /v1/vulns/{id}", async () => {
    const http = realFetch();
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: http.fetch,
      cache: new Map(),
    });

    const urls = http
      .gets()
      .map((c) => c.url)
      .sort();
    expect(urls).toEqual(
      Object.keys(VULNS)
        .sort()
        .map((id) => `https://api.osv.dev/v1/vulns/${id}`),
    );
    expect(http.calls).toHaveLength(9); // 1 batch + 8 advisories
  });

  it("gives every request a timeout signal", async () => {
    const http = realFetch();
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: http.fetch,
      cache: new Map(),
    });

    for (const call of http.calls)
      expect(call.signal).toBeInstanceOf(AbortSignal);
  });

  it("runs at most five advisory fetches at once, and uses all five", async () => {
    const http = realFetch({ delayMs: 5 });
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(http.peak).toBe(DETAIL_CONCURRENCY);
  });

  it("caches advisories by id, so a second scan fetches none", async () => {
    const cache = new Map();
    const first = realFetch();
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: first.fetch,
      cache,
    });
    expect(first.gets()).toHaveLength(8);

    const second = realFetch();
    const result = await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: second.fetch,
      cache,
    });

    expect(second.gets()).toHaveLength(0);
    expect(second.posts()).toHaveLength(1); // the batch is per-scan; only records are cached
    expect(result.evidence).toHaveLength(6);
  });

  it("fetches an advisory once even when several packages return it", async () => {
    const http = makeFetch({
      batch: (queries) => ({
        results: queries.map(() => ({ vulns: [{ id: "SHARED-1" }] })),
      }),
      vulns: { "SHARED-1": synth("SHARED-1", "a") },
    });
    await scanDependencies(
      [manifestOf({ a: "1.0.0", b: "1.0.0", c: "1.0.0" })],
      {
        fetch: http.fetch,
        cache: new Map(),
      },
    );

    expect(http.gets()).toHaveLength(1);
  });

  it("sends one query per distinct name@version, however many manifests declare it", async () => {
    const http = makeFetch();
    const a = {
      ...manifestOf({ lodash: "4.17.15" }),
      path: "packages/a/package.json",
    };
    const b = {
      ...manifestOf({ lodash: "4.17.15" }),
      path: "packages/b/package.json",
    };
    await scanDependencies([a, b], { fetch: http.fetch, cache: new Map() });

    expect(http.posts()[0].body?.queries).toHaveLength(1);
  });

  it("makes no request at all when there is nothing to look up", async () => {
    const http = makeFetch();
    const result = await scanDependencies(
      [{ path: "src/a.js", content: "x" }],
      {
        fetch: http.fetch,
        cache: new Map(),
      },
    );

    expect(http.calls).toHaveLength(0);
    expect(result).toEqual({ evidence: [], limitations: [] });
  });

  it("makes no request when every dependency is unresolvable, but still says so", async () => {
    const http = makeFetch();
    const result = await scanDependencies(
      [manifestOf({ a: "*", b: "workspace:*" })],
      {
        fetch: http.fetch,
        cache: new Map(),
      },
    );

    expect(http.calls).toHaveLength(0);
    expect(result.evidence).toEqual([]);
    expect(result.limitations).toHaveLength(1);
  });
});

describe("scanDependencies: batching", () => {
  function manyDeps(count: number): ScanFile {
    const deps: Record<string, string> = {};
    for (let i = 0; i < count; i++)
      deps[`pkg-${String(i).padStart(4, "0")}`] = "1.0.0";
    return manifestOf(deps);
  }

  it("splits 1,200 packages into batches of 500, 500 and 200", async () => {
    const http = makeFetch();
    await scanDependencies([manyDeps(1200)], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(http.posts().map((p) => p.body?.queries.length)).toEqual([
      500, 500, 200,
    ]);
  });

  it("sends exactly 500 in one batch, and 501 in two", async () => {
    const exact = makeFetch();
    await scanDependencies([manyDeps(500)], {
      fetch: exact.fetch,
      cache: new Map(),
    });
    expect(exact.posts()).toHaveLength(1);

    const over = makeFetch();
    await scanDependencies([manyDeps(501)], {
      fetch: over.fetch,
      cache: new Map(),
    });
    expect(over.posts().map((p) => p.body?.queries.length)).toEqual([500, 1]);
  });

  it("keeps the results of a good batch when a later one fails", async () => {
    const http = makeFetch({
      batch: (queries) =>
        queries[0].package.name === "pkg-0000"
          ? {
              results: queries.map((_, i) =>
                i === 0 ? { vulns: [{ id: "GOOD-1" }] } : {},
              ),
            }
          : new Response("down", { status: 503 }),
      vulns: {
        "GOOD-1": synth("GOOD-1", "pkg-0000", {
          label: "HIGH",
          fixed: "2.0.0",
        }),
      },
    });
    const result = await scanDependencies([manyDeps(600)], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(result.evidence).toHaveLength(1);
    expect(withoutLockfileNote(result.limitations)).toEqual([
      "OSV could not be reached for 100 of 600 dependencies (HTTP 503), so those were not checked.",
    ]);
  });
});

describe("scanDependencies: evidence from the real responses", () => {
  const run = () =>
    scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: realFetch().fetch,
      cache: new Map(),
    });

  it("turns lodash's six advisories and minimist's two into six findings", async () => {
    const { evidence, limitations } = await run();

    expect(evidence).toHaveLength(6);
    expect(limitations).toEqual([]);
  });

  it("writes the summary in the format the specification gives", async () => {
    const { evidence } = await run();
    const proto = evidence.find((e) => e.ruleId === "GHSA-p6mc-m468-83gw");

    expect(proto?.summary).toBe(
      "lodash@4.17.15 affected by CVE-2020-8203 (Prototype Pollution), fixed in 4.17.19",
    );
  });

  it("is kind dependency and source osv, with the file, line, rule id and osv.dev url", async () => {
    const { evidence } = await run();
    const proto = evidence.find((e) => e.ruleId === "GHSA-p6mc-m468-83gw");

    expect(proto).toMatchObject({
      kind: "dependency",
      source: "osv",
      filePath: "package.json",
      ruleId: "GHSA-p6mc-m468-83gw",
      url: "https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw",
    });
    expect(
      PACKAGE_JSON.content.split("\n")[(proto?.lineStart as number) - 1],
    ).toContain('"lodash"');
  });

  it("produces items the Evidence schema accepts, with kebab-case ids", async () => {
    const { evidence } = await run();

    expect(evidence.map((e) => e.id)).toEqual(
      evidence.map((_, i) => `ev-osv-${i + 1}`),
    );
    for (const item of evidence) {
      expect(EvidenceSchema.safeParse(item).success).toBe(true);
      expect(zId.safeParse(item.id).success).toBe(true);
    }
  });

  it("orders highest severity first", async () => {
    const { evidence } = await run();
    const scores = evidence.map((e) => e.metadata.severityScore ?? 0);

    expect(scores).toEqual([...scores].sort((a, b) => b - a));
    expect(evidence[0].metadata.severityLabel).toBe("CRITICAL");
    expect(evidence[0].metadata.package).toBe("minimist");
  });

  it("reports one finding for advisories that are the same issue", async () => {
    const { evidence } = await run();
    const ids = evidence.map((e) => e.ruleId);
    const has = (id: string) => ids.includes(id);

    expect(
      evidence.filter((e) => e.metadata.package === "lodash"),
    ).toHaveLength(4);
    expect(has("GHSA-35jh-r3h4-6jhm") && has("GHSA-r5fr-rjxr-66jc")).toBe(
      false,
    );
    expect(has("GHSA-f23m-r3pf-42rh") && has("GHSA-xxjr-mmjv-4gpg")).toBe(
      false,
    );
  });

  it("reports the first applicable fixed version for each package, not the first fix listed in the record", async () => {
    const { evidence } = await run();
    const fixed = (cve: string) =>
      evidence.find((e) => e.metadata.cve.includes(cve))?.metadata.fixedVersion;

    expect(fixed("CVE-2020-8203")).toBe("4.17.19"); // lodash, not lodash-es's 4.17.20
    expect(fixed("CVE-2021-44906")).toBe("1.2.6"); // minimist 1.x, not the 0.x fix 0.2.4
    expect(fixed("CVE-2020-7598")).toBe("1.2.3"); // minimist 1.x, not the 0.x fix 0.2.1
    expect(fixed("CVE-2021-23337")).toBe("4.18.0"); // highest across the alias group
    expect(fixed("CVE-2025-13465")).toBe("4.18.0");
    expect(fixed("CVE-2020-28500")).toBe("4.17.21");
  });

  it("never advises a version at or below the one installed", async () => {
    const { evidence } = await run();

    for (const item of evidence) {
      const { compareVersions } = await import("@/server/scanners/versions");
      expect(
        compareVersions(
          item.metadata.fixedVersion as string,
          item.metadata.version,
        ),
      ).toBeGreaterThan(0);
    }
  });

  it("reports nothing for a package with no vulnerabilities", async () => {
    const { evidence } = await run();
    expect(evidence.some((e) => e.metadata.package === "left-pad")).toBe(false);
  });

  it("puts the specification's metadata on each item", async () => {
    const { evidence } = await run();
    const proto = evidence.find((e) => e.ruleId === "GHSA-p6mc-m468-83gw");

    expect(proto?.metadata).toEqual({
      package: "lodash",
      version: "4.17.15",
      versionExact: true,
      dev: false,
      vulnId: "GHSA-p6mc-m468-83gw",
      cve: ["CVE-2020-8203"],
      aliases: ["CVE-2020-8203"],
      severityScore: 7.4,
      severityLabel: "HIGH",
      fixedVersion: "4.17.19",
    });
  });

  it("marks a dev dependency as dev in the metadata", async () => {
    const { evidence } = await run();
    expect(
      evidence.find((e) => e.metadata.package === "minimist")?.metadata.dev,
    ).toBe(true);
  });

  it("marks a version taken from a range as inexact, in both summary and metadata", async () => {
    const http = realFetch();
    const { evidence } = await scanDependencies([PACKAGE_JSON], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(http.posts()[0].body?.queries.map((q) => q.version)).toEqual([
      "4.17.15",
      "1.3.0",
      "1.2.0",
    ]);
    for (const item of evidence) {
      expect(item.metadata.versionExact).toBe(false);
      expect(item.summary).toContain("(inferred from range)");
    }
    expect(
      evidence.find((e) => e.ruleId === "GHSA-p6mc-m468-83gw")?.summary,
    ).toBe(
      "lodash@4.17.15 (inferred from range) affected by CVE-2020-8203 (Prototype Pollution), fixed in 4.17.19",
    );
  });

  it("does not say inferred when the version is exact", async () => {
    const { evidence } = await run();
    for (const item of evidence) expect(item.summary).not.toContain("inferred");
  });

  it("is deterministic across runs", async () => {
    const [a, b] = await Promise.all([run(), run()]);
    expect(a).toEqual(b);
  });
});

describe("scanDependencies: aliased advisories", () => {
  it("advises the highest fix in a group, even when the higher-severity member needs less", async () => {
    // SYNTHETIC, because the real lodash data happens to have the more severe advisory
    // also carry the higher fix. Here the representative (HIGH) is fixed in 1.5.0 but
    // its alias (LOW) needs 2.0.0; advising 1.5.0 would leave the alias unresolved.
    const http = makeFetch({
      batch: () => ({
        results: [{ vulns: [{ id: "A-HIGH" }, { id: "B-LOW" }] }],
      }),
      vulns: {
        "A-HIGH": synth("A-HIGH", "pkg", {
          label: "HIGH",
          fixed: "1.5.0",
          aliases: ["B-LOW"],
        }),
        "B-LOW": synth("B-LOW", "pkg", {
          label: "LOW",
          fixed: "2.0.0",
          aliases: ["A-HIGH"],
        }),
      },
    });
    const { evidence } = await scanDependencies(
      [manifestOf({ pkg: "1.0.0" })],
      {
        fetch: http.fetch,
        cache: new Map(),
      },
    );

    expect(evidence).toHaveLength(1);
    expect(evidence[0].ruleId).toBe("A-HIGH"); // the higher-severity record stands for the group
    expect(evidence[0].metadata.fixedVersion).toBe("2.0.0");
    expect(evidence[0].summary).toContain("fixed in 2.0.0");
  });

  it("does not merge advisories for different packages that share an alias", async () => {
    const http = makeFetch({
      batch: (queries) => ({
        results: queries.map((q) => ({
          vulns: [{ id: `V-${q.package.name}` }],
        })),
      }),
      vulns: {
        "V-a": synth("V-a", "a", { fixed: "2.0.0", aliases: ["CVE-2020-1"] }),
        "V-b": synth("V-b", "b", { fixed: "2.0.0", aliases: ["CVE-2020-1"] }),
      },
    });
    const { evidence } = await scanDependencies(
      [manifestOf({ a: "1.0.0", b: "1.0.0" })],
      {
        fetch: http.fetch,
        cache: new Map(),
      },
    );

    // The grouping is per dependency: one CVE affecting two packages is two findings.
    expect(evidence.map((e) => e.metadata.package).sort()).toEqual(["a", "b"]);
  });
});

describe("scanDependencies: ordering and the cap", () => {
  it("lists a runtime dependency before a dev one of equal severity", async () => {
    const http = makeFetch({
      batch: (queries) => ({
        results: queries.map((q) => ({
          vulns: [{ id: `V-${q.package.name}` }],
        })),
      }),
      vulns: {
        "V-a-dev": synth("V-a-dev", "a-dev", { label: "HIGH", fixed: "2.0.0" }),
        "V-z-runtime": synth("V-z-runtime", "z-runtime", {
          label: "HIGH",
          fixed: "2.0.0",
        }),
      },
    });
    const { evidence } = await scanDependencies(
      [manifestOf({ "z-runtime": "1.0.0" }, { "a-dev": "1.0.0" })],
      { fetch: http.fetch, cache: new Map() },
    );

    expect(evidence.map((e) => e.metadata.package)).toEqual([
      "z-runtime",
      "a-dev",
    ]);
  });

  it("caps at 40 items, keeps the most severe, and says how many were dropped", async () => {
    // 45 packages: the five CRITICAL ones sort LAST alphabetically, so only a
    // severity-first cap keeps them.
    const names = Array.from(
      { length: 45 },
      (_, i) => `pkg-${String(i).padStart(2, "0")}`,
    );
    const vulns: Record<string, unknown> = {};
    for (const [i, name] of names.entries()) {
      vulns[`V-${name}`] = synth(`V-${name}`, name, {
        label: i >= 40 ? "CRITICAL" : "LOW",
        fixed: "2.0.0",
      });
    }
    const http = makeFetch({
      batch: (queries) => ({
        results: queries.map((q) => ({
          vulns: [{ id: `V-${q.package.name}` }],
        })),
      }),
      vulns,
    });
    const deps = Object.fromEntries(names.map((n) => [n, "1.0.0"]));
    const { evidence, limitations } = await scanDependencies(
      [manifestOf(deps)],
      {
        fetch: http.fetch,
        cache: new Map(),
      },
    );

    expect(evidence).toHaveLength(MAX_EVIDENCE);
    expect(
      evidence
        .slice(0, 5)
        .every((e) => e.metadata.severityLabel === "CRITICAL"),
    ).toBe(true);
    expect(
      evidence
        .slice(0, 5)
        .map((e) => e.metadata.package)
        .sort(),
    ).toEqual(names.slice(40));
    expect(withoutLockfileNote(limitations)).toEqual([
      "5 lower-severity dependency findings were omitted (the report keeps the 40 most severe).",
    ]);
  });

  it("does not mention a cap when there are exactly 40", async () => {
    const names = Array.from(
      { length: 40 },
      (_, i) => `pkg-${String(i).padStart(2, "0")}`,
    );
    const vulns = Object.fromEntries(
      names.map((n) => [`V-${n}`, synth(`V-${n}`, n, { fixed: "2.0.0" })]),
    );
    const http = makeFetch({
      batch: (queries) => ({
        results: queries.map((q) => ({
          vulns: [{ id: `V-${q.package.name}` }],
        })),
      }),
      vulns,
    });
    const { evidence, limitations } = await scanDependencies(
      [manifestOf(Object.fromEntries(names.map((n) => [n, "1.0.0"])))],
      { fetch: http.fetch, cache: new Map() },
    );

    expect(evidence).toHaveLength(40);
    expect(withoutLockfileNote(limitations)).toEqual([]);
  });
});

describe("scanDependencies: when OSV misbehaves, the analysis carries on", () => {
  const files = [PACKAGE_JSON, LOCKFILE];

  it.each([
    [
      "a network error",
      () => Promise.reject(new TypeError("fetch failed")),
      "network error",
    ],
    [
      "HTTP 500",
      () => Promise.resolve(new Response("boom", { status: 500 })),
      "HTTP 500",
    ],
    [
      "HTTP 503",
      () => Promise.resolve(new Response("", { status: 503 })),
      "HTTP 503",
    ],
    [
      "HTTP 429",
      () => Promise.resolve(new Response("", { status: 429 })),
      "HTTP 429",
    ],
    [
      "invalid JSON",
      () => Promise.resolve(new Response("<html>oops</html>")),
      "invalid JSON",
    ],
    [
      "an unexpected shape",
      () => Promise.resolve(respond({ results: "nope" })),
      "unexpected querybatch shape",
    ],
    [
      "the wrong number of results",
      () => Promise.resolve(respond({ results: [] })),
      "unexpected querybatch shape",
    ],
  ])(
    "returns no evidence and a limitation for %s",
    async (_label, behaviour, reason) => {
      const result = await scanDependencies(files, {
        fetch: (() => behaviour()) as unknown as typeof fetch,
        cache: new Map(),
      });

      expect(result.evidence).toEqual([]);
      expect(result.limitations).toEqual([
        `OSV (api.osv.dev) could not be reached (${reason}), so dependencies were not checked for known vulnerabilities.`,
      ]);
    },
  );

  it("never throws, whatever fetch does", async () => {
    for (const thrown of [new Error("x"), "a string", 42, undefined, null]) {
      await expect(
        scanDependencies(files, {
          fetch: (() => Promise.reject(thrown)) as unknown as typeof fetch,
          cache: new Map(),
        }),
      ).resolves.toBeDefined();
    }
  });

  it("gives up on a request after the timeout, and says so", async () => {
    // A fetch that never answers, and honours the abort signal like the real one.
    const hanging = ((_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(init.signal?.reason),
        );
      })) as unknown as typeof fetch;

    const started = Date.now();
    const result = await scanDependencies(files, {
      fetch: hanging,
      cache: new Map(),
      timeoutMs: 40,
    });

    expect(Date.now() - started).toBeLessThan(2000);
    expect(result.evidence).toEqual([]);
    expect(result.limitations[0]).toContain("timed out after 40ms");
  });

  it("does not put the response body in the limitation", async () => {
    const result = await scanDependencies(files, {
      fetch: (() =>
        Promise.resolve(
          new Response("SECRET-LOOKING-BODY-abc123", { status: 500 }),
        )) as unknown as typeof fetch,
      cache: new Map(),
    });

    expect(JSON.stringify(result)).not.toContain("SECRET-LOOKING-BODY");
  });

  it("refuses an absurdly large response rather than parsing it", async () => {
    const huge = "x".repeat(2_000_001);
    const result = await scanDependencies(files, {
      fetch: (() =>
        Promise.resolve(new Response(huge))) as unknown as typeof fetch,
      cache: new Map(),
    });

    expect(result.limitations[0]).toContain("response too large");
  });

  it("keeps everything else when one advisory cannot be fetched", async () => {
    const rest = Object.fromEntries(
      Object.entries(VULNS).filter(([id]) => id !== "GHSA-29mw-wpgm-hmr9"),
    );
    const http = realFetch({ vulns: rest });
    const result = await scanDependencies(files, {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(result.evidence).toHaveLength(5);
    expect(result.limitations).toEqual([
      "1 advisory could not be retrieved from OSV and is missing from the results.",
    ]);
  });

  it("pluralises when several advisories cannot be fetched", async () => {
    const http = realFetch({ vulns: {} });
    const result = await scanDependencies(files, {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(result.evidence).toEqual([]);
    expect(result.limitations).toEqual([
      "8 advisories could not be retrieved from OSV and are missing from the results.",
    ]);
  });

  it("counts an advisory it cannot parse as unavailable", async () => {
    const http = makeFetch({
      batch: () => ({ results: [{ vulns: [{ id: "BAD-1" }] }] }),
      vulns: { "BAD-1": { not: "a record" } },
    });
    const result = await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(result.evidence).toEqual([]);
    expect(withoutLockfileNote(result.limitations)[0]).toContain(
      "1 advisory could not be retrieved",
    );
  });

  it("does not cache a failed fetch, so a later scan can succeed", async () => {
    const cache = new Map();
    await scanDependencies(files, {
      fetch: realFetch({ vulns: {} }).fetch,
      cache,
    });
    expect(cache.size).toBe(0);

    const later = await scanDependencies(files, {
      fetch: realFetch().fetch,
      cache,
    });
    expect(later.evidence).toHaveLength(6);
  });

  it("skips a withdrawn advisory", async () => {
    const http = makeFetch({
      batch: () => ({ results: [{ vulns: [{ id: "W-1" }, { id: "OK-1" }] }] }),
      vulns: {
        "W-1": synth("W-1", "a", {
          withdrawn: "2024-01-01T00:00:00Z",
          label: "CRITICAL",
        }),
        "OK-1": synth("OK-1", "a", { label: "LOW", fixed: "2.0.0" }),
      },
    });
    const { evidence } = await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(evidence.map((e) => e.ruleId)).toEqual(["OK-1"]);
  });

  it("never requests an id that is not safe to put in a URL", async () => {
    const http = makeFetch({
      batch: () => ({
        results: [
          {
            vulns: [
              { id: "../../etc/passwd" },
              { id: "a/b" },
              { id: "GOOD-1" },
            ],
          },
        ],
      }),
      vulns: { "GOOD-1": synth("GOOD-1", "a", { fixed: "2.0.0" }) },
    });
    await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(http.gets().map((c) => c.url)).toEqual([
      "https://api.osv.dev/v1/vulns/GOOD-1",
    ]);
  });
});

describe("scanDependencies: what is sent, and what is trusted", () => {
  it("sends only package names and versions, never file content or paths", async () => {
    const manifest: ScanFile = {
      path: "internal/secret-service/package.json",
      content: JSON.stringify({
        name: "very-private-name",
        description: "token AKIAIOSFODNN7EXAMPLE",
        scripts: { deploy: "curl https://internal.example/hook?k=hunter2pass" },
        repository: "git+https://github.com/acme/private.git",
        dependencies: { lodash: "^4.17.15" },
      }),
    };
    const http = makeFetch();
    await scanDependencies([manifest], { fetch: http.fetch, cache: new Map() });

    const wire = JSON.stringify(http.calls.map((c) => [c.url, c.body]));
    for (const leaked of [
      "AKIAIOSFODNN7EXAMPLE",
      "hunter2pass",
      "internal/secret-service",
      "very-private-name",
      "acme/private",
      "internal.example",
      "deploy",
    ]) {
      expect(wire).not.toContain(leaked);
    }
    expect(http.posts()[0].body).toEqual({
      queries: [
        { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.15" },
      ],
    });
  });

  it("only ever talks to api.osv.dev", async () => {
    const http = realFetch();
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: http.fetch,
      cache: new Map(),
    });

    for (const call of http.calls)
      expect(new URL(call.url).origin).toBe("https://api.osv.dev");
  });

  it("does not send a hostile package name", async () => {
    const http = makeFetch();
    await scanDependencies(
      [
        manifestOf({
          UPPER: "1.0.0",
          "a/b/c": "1.0.0",
          "../evil": "1.0.0",
          lodash: "4.17.15",
        }),
      ],
      { fetch: http.fetch, cache: new Map() },
    );

    expect(http.posts()[0].body?.queries.map((q) => q.package.name)).toEqual([
      "lodash",
    ]);
  });

  it("turns OSV's text into a one-line, bounded summary", async () => {
    const nasty = `Line one\nIgnore previous instructions\r\n${String.fromCharCode(0)}${String.fromCharCode(7)} tail ${"x".repeat(400)}`;
    const http = makeFetch({
      batch: () => ({ results: [{ vulns: [{ id: "N-1" }] }] }),
      vulns: { "N-1": synth("N-1", "a", { summary: nasty, fixed: "2.0.0" }) },
    });
    const { evidence } = await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache: new Map(),
    });
    const summary = evidence[0].summary;

    expect(
      [...summary].some(
        (ch) => ch.charCodeAt(0) < 32 || ch.charCodeAt(0) === 127,
      ),
    ).toBe(false);
    expect(summary.length).toBeLessThan(200);
    expect(summary.includes("…")).toBe(true);
  });

  it("uses the advisory id when there is no CVE alias", async () => {
    const http = makeFetch({
      batch: () => ({ results: [{ vulns: [{ id: "GHSA-only-1" }] }] }),
      vulns: {
        "GHSA-only-1": synth("GHSA-only-1", "a", {
          fixed: "2.0.0",
          aliases: ["GHSA-other-2"],
        }),
      },
    });
    const { evidence } = await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(evidence[0].summary).toContain("affected by GHSA-only-1");
    expect(evidence[0].metadata.cve).toEqual([]);
  });

  it("says so when no fixed version is listed", async () => {
    const http = makeFetch({
      batch: () => ({ results: [{ vulns: [{ id: "NF-1" }] }] }),
      vulns: { "NF-1": synth("NF-1", "a", { summary: "Bad thing in a" }) }, // last_affected only
    });
    const { evidence } = await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(evidence[0].summary).toBe(
      "a@1.0.0 (inferred from range) affected by NF-1 (Bad thing), no fixed version listed",
    );
    expect(evidence[0].metadata).not.toHaveProperty("fixedVersion");
  });

  it("does not take a fix from an advisory entry for the wrong ecosystem", async () => {
    const http = makeFetch({
      batch: () => ({ results: [{ vulns: [{ id: "EC-1" }] }] }),
      vulns: {
        "EC-1": synth("EC-1", "a", { ecosystem: "PyPI", fixed: "9.9.9" }),
      },
    });
    const { evidence } = await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(evidence[0].summary).toContain("no fixed version listed");
  });
});

// ---------------------------------------------------------------------------
// Audit additions: requirements that were true of the code but not pinned by a test
// ---------------------------------------------------------------------------

describe("lockfile versions 2 and 3 are read through the packages map", () => {
  const manifest = manifestOf({ lodash: "^4.17.15" });
  const lock = (content: object): ScanFile => ({
    path: "package-lock.json",
    content: JSON.stringify(content),
  });

  it("supports lockfileVersion 3", () => {
    const [dep] = collectDependencies([
      manifest,
      lock({
        lockfileVersion: 3,
        packages: { "node_modules/lodash": { version: "4.17.21" } },
      }),
    ]).dependencies;

    expect(dep).toMatchObject({ version: "4.17.21", versionExact: true });
  });

  it("supports lockfileVersion 2, which carries the packages map beside the legacy one", () => {
    const [dep] = collectDependencies([
      manifest,
      lock({
        lockfileVersion: 2,
        packages: { "node_modules/lodash": { version: "4.17.21" } },
        dependencies: { lodash: { version: "4.17.99" } }, // the v1-style map must not win
      }),
    ]).dependencies;

    expect(dep).toMatchObject({ version: "4.17.21", versionExact: true });
  });

  it("supports lockfileVersion 2 with only a packages map", () => {
    const [dep] = collectDependencies([
      manifest,
      lock({
        lockfileVersion: 2,
        packages: { "node_modules/lodash": { version: "4.17.20" } },
      }),
    ]).dependencies;

    expect(dep).toMatchObject({ version: "4.17.20", versionExact: true });
  });

  it("does not read the legacy dependencies map (lockfileVersion 1), and falls back to the range", () => {
    const [dep] = collectDependencies([
      manifest,
      lock({
        lockfileVersion: 1,
        dependencies: { lodash: { version: "4.17.99" } },
      }),
    ]).dependencies;

    expect(dep).toMatchObject({ version: "4.17.15", versionExact: false });
  });
});

describe("the 10 second timeout is what every request actually gets", () => {
  it("passes 10,000 ms to AbortSignal.timeout for the batch and for every advisory", async () => {
    const spy = vi.spyOn(AbortSignal, "timeout");
    try {
      const http = realFetch();
      await scanDependencies([PACKAGE_JSON, LOCKFILE], {
        fetch: http.fetch,
        cache: new Map(),
      });

      expect(http.calls).toHaveLength(9);
      expect(spy).toHaveBeenCalledTimes(9);
      for (const [ms] of spy.mock.calls) expect(ms).toBe(10_000);
    } finally {
      spy.mockRestore();
    }
  });

  it("uses a different timeout only when one is asked for", async () => {
    const spy = vi.spyOn(AbortSignal, "timeout");
    try {
      const http = realFetch();
      await scanDependencies([PACKAGE_JSON, LOCKFILE], {
        fetch: http.fetch,
        cache: new Map(),
        timeoutMs: 1234,
      });
      for (const [ms] of spy.mock.calls) expect(ms).toBe(1234);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("advisory details are cached in memory by id", () => {
  it("keys the cache by advisory id, holding every advisory fetched", async () => {
    const cache = new Map<string, OsvVuln>();
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: realFetch().fetch,
      cache,
    });

    expect([...cache.keys()].sort()).toEqual(Object.keys(VULNS).sort());
    for (const [id, vuln] of cache) expect(vuln.id).toBe(id);
  });

  it("uses a process-wide cache when none is supplied, so a later scan refetches nothing", async () => {
    const first = realFetch();
    vi.stubGlobal("fetch", first.fetch);
    try {
      await scanDependencies([PACKAGE_JSON, LOCKFILE]);
      expect(first.gets()).toHaveLength(8);

      const second = realFetch();
      vi.stubGlobal("fetch", second.fetch);
      const result = await scanDependencies([PACKAGE_JSON, LOCKFILE]);

      expect(second.gets()).toHaveLength(0);
      expect(result.evidence).toHaveLength(6);
    } finally {
      vi.stubGlobal("fetch", NO_NETWORK);
    }
  });

  it("evicts the oldest entry rather than growing without bound", async () => {
    const cache = new Map<string, OsvVuln>();
    const ids = Array.from({ length: 5001 }, (_, i) => `V-${i}`);
    const http = makeFetch({
      batch: () => ({ results: [{ vulns: ids.map((id) => ({ id })) }] }),
      vulns: Object.fromEntries(
        ids.map((id) => [id, synth(id, "a", { fixed: "2.0.0" })]),
      ),
    });
    await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache,
    });

    expect(cache.size).toBeLessThanOrEqual(5000);
    expect(cache.has("V-0")).toBe(false); // the oldest went first
    expect(cache.has("V-5000")).toBe(true);
  });
});

describe("every returned vulnerability id is fetched", () => {
  it("fetches exactly the union of the ids returned, once each, across overlapping queries", async () => {
    const http = makeFetch({
      batch: () => ({
        results: [
          { vulns: [{ id: "A-1" }, { id: "B-1" }, { id: "C-1" }] },
          { vulns: [{ id: "B-1" }, { id: "C-1" }, { id: "D-1" }] },
        ],
      }),
      vulns: Object.fromEntries(
        ["A-1", "B-1", "C-1", "D-1"].map((id) => [
          id,
          synth(id, "a", { fixed: "2.0.0" }),
        ]),
      ),
    });
    await scanDependencies([manifestOf({ a: "1.0.0", b: "1.0.0" })], {
      fetch: http.fetch,
      cache: new Map(),
    });

    const fetched = http
      .gets()
      .map((c) => decodeURIComponent(c.url.split("/v1/vulns/")[1]));
    expect(fetched.sort()).toEqual(["A-1", "B-1", "C-1", "D-1"]);
  });

  it("fetches an id for a dev dependency as well as a runtime one", async () => {
    const http = realFetch();
    await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: http.fetch,
      cache: new Map(),
    });

    const fetched = new Set(
      http.gets().map((c) => c.url.split("/v1/vulns/")[1]),
    );
    expect(fetched.has("GHSA-vh95-rmgr-6w4m")).toBe(true); // minimist is a devDependency
    expect(fetched.has("GHSA-p6mc-m468-83gw")).toBe(true); // lodash is a runtime dependency
  });

  it("still uses an already-cached advisory in the results without refetching it", async () => {
    const cache = new Map<string, OsvVuln>([
      ["C-1", real("GHSA-p6mc-m468-83gw")],
    ]);
    const http = makeFetch({
      batch: () => ({ results: [{ vulns: [{ id: "C-1" }, { id: "N-1" }] }] }),
      vulns: { "N-1": synth("N-1", "a", { fixed: "2.0.0" }) },
    });
    const { evidence } = await scanDependencies([manifestOf({ a: "1.0.0" })], {
      fetch: http.fetch,
      cache,
    });

    expect(http.gets().map((c) => c.url)).toEqual([
      "https://api.osv.dev/v1/vulns/N-1",
    ]);
    expect(evidence).toHaveLength(2);
  });
});

describe("advisory detail requests never exceed the concurrency limit", () => {
  const advisories = (count: number) => {
    const ids = Array.from(
      { length: count },
      (_, i) => `V-${String(i).padStart(3, "0")}`,
    );
    return {
      ids,
      http: (delayMs: number) =>
        makeFetch({
          delayMs,
          batch: () => ({ results: [{ vulns: ids.map((id) => ({ id })) }] }),
          vulns: Object.fromEntries(
            ids.map((id) => [id, synth(id, "a", { fixed: "2.0.0" })]),
          ),
        }),
    };
  };

  it.each([1, 3, 5, 6, 40])(
    "with %i advisories, the peak is min(count, 5)",
    async (count) => {
      const { http } = advisories(count);
      const run = http(4);
      await scanDependencies([manifestOf({ a: "1.0.0" })], {
        fetch: run.fetch,
        cache: new Map(),
      });

      expect(run.gets()).toHaveLength(count);
      expect(run.peak).toBeLessThanOrEqual(DETAIL_CONCURRENCY);
      expect(run.peak).toBe(Math.min(count, DETAIL_CONCURRENCY));
    },
  );
});

describe("querybatch chunks are never larger than 500", () => {
  const many = (count: number): ScanFile => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < count; i++)
      deps[`pkg-${String(i).padStart(5, "0")}`] = "1.0.0";
    return manifestOf(deps);
  };

  it.each([1, 2, 499, 500, 501, 999, 1000, 1001, 1499, 1500, 1501])(
    "splits %i packages into ceil(n/500) chunks, none over 500, losing none",
    async (count) => {
      const http = makeFetch();
      await scanDependencies([many(count)], {
        fetch: http.fetch,
        cache: new Map(),
      });

      const sizes = http.posts().map((p) => p.body?.queries.length ?? 0);
      expect(Math.max(...sizes)).toBeLessThanOrEqual(BATCH_SIZE);
      expect(sizes).toHaveLength(Math.ceil(count / BATCH_SIZE));
      expect(sizes.reduce((a, b) => a + b, 0)).toBe(count);
    },
  );

  it("never repeats a query across chunks", async () => {
    const http = makeFetch();
    await scanDependencies([many(1200)], {
      fetch: http.fetch,
      cache: new Map(),
    });

    const names = http
      .posts()
      .flatMap((p) => p.body?.queries.map((q) => q.package.name) ?? []);
    expect(new Set(names).size).toBe(names.length);
  });
});

describe("advisory detail failures follow the scanner contract", () => {
  const wrap = (
    inner: typeof fetch,
    misbehave: (
      url: string,
      init?: RequestInit,
    ) => Promise<Response> | undefined,
  ) =>
    ((url: RequestInfo | URL, init?: RequestInit) =>
      misbehave(String(url), init) ??
      inner(url, init)) as unknown as typeof fetch;

  it("survives one advisory request failing with a network error", async () => {
    const inner = realFetch();
    const flaky = wrap(inner.fetch, (url) =>
      url.includes("GHSA-29mw-wpgm-hmr9")
        ? Promise.reject(new TypeError("fetch failed"))
        : undefined,
    );
    const result = await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: flaky,
      cache: new Map(),
    });

    expect(result.evidence).toHaveLength(5);
    expect(result.limitations).toEqual([
      "1 advisory could not be retrieved from OSV and is missing from the results.",
    ]);
  });

  it("survives one advisory request timing out, without holding up the others", async () => {
    const inner = realFetch();
    const hangs = wrap(inner.fetch, (url, init) =>
      url.includes("GHSA-29mw-wpgm-hmr9")
        ? new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () =>
              reject(init.signal?.reason),
            );
          })
        : undefined,
    );
    const started = Date.now();
    const result = await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: hangs,
      cache: new Map(),
      timeoutMs: 60,
    });

    expect(Date.now() - started).toBeLessThan(2000);
    expect(result.evidence).toHaveLength(5);
    expect(result.limitations[0]).toContain(
      "1 advisory could not be retrieved",
    );
  });

  it("never throws, whatever the advisory endpoint does", async () => {
    for (const behaviour of [
      () => Promise.reject(new Error("boom")),
      () => Promise.resolve(new Response("nope", { status: 500 })),
      () => Promise.resolve(new Response("<html>", { status: 200 })),
      () => Promise.resolve(new Response(JSON.stringify(null))),
    ]) {
      const inner = realFetch();
      const broken = wrap(inner.fetch, (url) =>
        url.includes("/v1/vulns/") ? behaviour() : undefined,
      );

      await expect(
        scanDependencies([PACKAGE_JSON, LOCKFILE], {
          fetch: broken,
          cache: new Map(),
        }),
      ).resolves.toMatchObject({ evidence: [] });
    }
  });
});

describe("dependency evidence points at osv.dev", () => {
  it("has an https osv.dev vulnerability URL for the advisory it names", async () => {
    const { evidence } = await scanDependencies([PACKAGE_JSON, LOCKFILE], {
      fetch: realFetch().fetch,
      cache: new Map(),
    });

    expect(evidence.length).toBeGreaterThan(0);
    for (const item of evidence) {
      const url = new URL(item.url as string);
      expect(url.protocol).toBe("https:");
      expect(url.hostname).toBe("osv.dev");
      expect(url.pathname).toBe(`/vulnerability/${item.ruleId}`);
    }
  });
});

describe("the tests in this file cannot reach the real network", () => {
  it("makes an un-injected scan fail safely instead of calling api.osv.dev", async () => {
    // fetch is not injected here, so the file-wide guard is what answers. The scan must
    // degrade to a limitation exactly as it would for a real outage.
    const result = await scanDependencies([PACKAGE_JSON, LOCKFILE]);

    expect(result.evidence).toEqual([]);
    expect(result.limitations[0]).toContain(
      "could not be reached (network error)",
    );
  });
});

describe("the note about versions inferred from ranges", () => {
  const lockWith = (
    packages: Record<string, { version: string }>,
  ): ScanFile => ({
    path: "package-lock.json",
    content: JSON.stringify({ lockfileVersion: 3, packages }),
  });
  const note = (limitations: string[]) =>
    limitations.find((m) => m.includes("package-lock.json"));

  it("is absent when every dependency has an exact locked version", () => {
    const { limitations } = collectDependencies([PACKAGE_JSON, LOCKFILE]);
    expect(note(limitations)).toBeUndefined();
  });

  it("names one dependency in the singular", () => {
    const { limitations } = collectDependencies([
      manifestOf({ lodash: "^4.17.15" }),
    ]);

    expect(note(limitations)).toBe(
      "1 dependency was checked at the lowest version of its declared range (versionExact is false) " +
        "because no exact version was available from a package-lock.json. The lockfile may be missing, " +
        "larger than the 1 MiB that can be fetched, or not list it.",
    );
  });

  it("counts several in the plural", () => {
    const { limitations } = collectDependencies([
      manifestOf({ a: "^1.0.0", b: "^2.0.0", c: "^3.0.0" }),
    ]);

    expect(note(limitations)).toContain(
      "3 dependencies were checked at the lowest version of their declared range",
    );
    expect(note(limitations)).toContain("or not list them.");
  });

  it("counts only the dependencies that fell back, when the lockfile covers the others", () => {
    const { dependencies, limitations } = collectDependencies([
      manifestOf({ a: "^1.0.0", b: "^2.0.0", c: "^3.0.0" }),
      lockWith({
        "node_modules/a": { version: "1.4.0" },
        "node_modules/b": { version: "2.1.0" },
      }),
    ]);

    expect(dependencies.map((d) => [d.name, d.versionExact])).toEqual([
      ["a", true],
      ["b", true],
      ["c", false],
    ]);
    expect(note(limitations)).toContain("1 dependency was checked");
  });

  it("appears when a lockfile exists but is not usable (no packages map)", () => {
    const v1: ScanFile = {
      path: "package-lock.json",
      content: JSON.stringify({ lockfileVersion: 1 }),
    };
    expect(
      note(collectDependencies([manifestOf({ a: "^1.0.0" }), v1]).limitations),
    ).toBeDefined();
  });

  it("is separate from, and comes after, the note about dependencies that could not be checked", () => {
    const { limitations } = collectDependencies([
      manifestOf({ a: "^1.0.0", b: "workspace:*" }),
    ]);

    expect(limitations).toHaveLength(2);
    expect(limitations[0]).toContain("not checked against OSV");
    expect(limitations[1]).toContain("package-lock.json");
  });

  it("does not count a dependency that was skipped as one that was inferred", () => {
    const { limitations } = collectDependencies([
      manifestOf({ a: "workspace:*", b: "latest" }),
    ]);
    expect(note(limitations)).toBeUndefined();
  });

  it("reaches scanDependencies' result, alongside the evidence", async () => {
    const http = realFetch();
    const result = await scanDependencies([PACKAGE_JSON], {
      fetch: http.fetch,
      cache: new Map(),
    });

    expect(result.evidence.length).toBeGreaterThan(0);
    expect(note(result.limitations)).toContain("3 dependencies were checked");
  });
});
