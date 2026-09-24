import { describe, expect, it } from "vitest";
import { runDetectors } from "@/server/detect";
import { detectGaps, isScannable } from "@/server/detect/gaps";
import type { DetectorInput, GapKind } from "@/server/detect/types";
import { isAdminPath, maskCode, maskComments } from "@/server/detect/shared";
import { assertNoSecrets } from "@/server/security/redactor";
import { EvidenceSchema, Owasp2025Schema, zId } from "@/shared/schema";
import { SAMPLE_REPO } from "./detectSamples";
import {
  GAP_MARKER,
  LOCKFILE,
  MARKED_REPO,
  expressApp,
  expressRepo,
  file,
  manifest,
} from "./gapSamples";

const gapsOf = (files: DetectorInput[]) => runDetectors(files).gaps;
const kindsOf = (files: DetectorInput[]) =>
  new Set(gapsOf(files).map((gap) => gap.kind));
const certaintyOf = (files: DetectorInput[], kind: GapKind) =>
  gapsOf(files).find((gap) => gap.kind === kind)?.certainty;

function stringLeaves(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringLeaves);
  if (value && typeof value === "object") {
    return Object.values(value).flatMap(stringLeaves);
  }
  return [];
}

// ---------------------------------------------------------------------------
// One positive and one negative per kind. The negative is the real test.
// ---------------------------------------------------------------------------

const HANDLER = "async (req, res) => { res.end(); }";
const NEXT_DEP = { "express-session": "^1.17.0" };

type Case = {
  kind: GapKind;
  absent: DetectorInput[];
  present: DetectorInput[];
};

const CASES: Case[] = [
  {
    kind: "authz_missing",
    absent: expressRepo(`app.get("/users/:id", requireAuth, ${HANDLER});`),
    present: expressRepo(
      `app.get("/users/:id", requireAuth, requireRole("admin"), ${HANDLER});`,
    ),
  },
  {
    kind: "authn_missing",
    absent: expressRepo(`app.post("/orders", ${HANDLER});`),
    present: expressRepo(`app.post("/orders", requireAuth, ${HANDLER});`),
  },
  {
    kind: "rate_limit_missing",
    absent: expressRepo(`app.post("/login", ${HANDLER});`),
    present: expressRepo(`app.post("/login", ${HANDLER});`, {
      "express-rate-limit": "^7.0.0",
    }),
  },
  {
    kind: "csrf_missing",
    absent: expressRepo(`app.post("/checkout", ${HANDLER});`, NEXT_DEP),
    present: expressRepo(`app.post("/checkout", ${HANDLER});`, {
      ...NEXT_DEP,
      csurf: "^1.11.0",
    }),
  },
  {
    kind: "security_headers_missing",
    absent: expressRepo(`app.get("/x", ${HANDLER});`),
    present: expressRepo(`app.use(helmet());`, { helmet: "^7.0.0" }),
  },
  {
    kind: "input_validation_missing",
    absent: expressRepo(
      `app.post("/x", async (req, res) => { res.json(JSON.parse(req.body)); });`,
    ),
    present: [
      manifest({ express: "^4.0.0", zod: "^3.0.0" }),
      LOCKFILE,
      expressApp(
        `const { z } = require("zod");\napp.post("/x", async (req, res) => { res.json(z.string().parse(req.body)); });`,
      ),
    ],
  },
  {
    kind: "transport_insecure",
    absent: [file("src/c.js", `fetch("http://api.acme-corp.com/v1");`)],
    present: [
      file(
        "src/c.js",
        `fetch("https://api.acme-corp.com/v1"); fetch("http://localhost:3000");`,
      ),
    ],
  },
  {
    kind: "password_storage_weak",
    absent: expressRepo(`app.post("/login", ${HANDLER});`, { pg: "^8.0.0" }),
    present: expressRepo(`app.post("/login", ${HANDLER});`, {
      pg: "^8.0.0",
      bcrypt: "^5.0.0",
    }),
  },
  {
    kind: "logging_missing",
    absent: expressRepo(`app.post("/login", ${HANDLER});`),
    present: expressRepo(`app.post("/login", ${HANDLER});`, { pino: "^9.0.0" }),
  },
  {
    kind: "error_handling_gap",
    absent: expressRepo(
      `app.get("/a", async (req, res) => { await load(); res.end(); });`,
    ),
    present: expressRepo(
      `app.get("/a", async (req, res) => { await load(); res.end(); });\napp.use((err, req, res, next) => { res.status(500).end(); });`,
    ),
  },
  {
    kind: "cors_permissive",
    absent: expressRepo(`app.use(cors());`, { cors: "^2.8.5" }),
    present: expressRepo(
      `app.use(cors({ origin: "https://app.example.com" }));`,
      { cors: "^2.8.5" },
    ),
  },
  {
    kind: "supply_chain_integrity",
    absent: [manifest({ express: "^4.0.0" })],
    present: [manifest({ express: "^4.0.0" }), LOCKFILE],
  },
];

describe.each(CASES)("detectGaps: $kind", ({ kind, absent, present }) => {
  it("reports the gap when the control is absent", () => {
    expect(kindsOf(absent)).toContain(kind);
  });

  it("stays silent when the control is present", () => {
    expect(kindsOf(present)).not.toContain(kind);
  });
});

it("covers every gap kind", () => {
  expect(new Set(CASES.map((c) => c.kind)).size).toBe(12);
});

// ---------------------------------------------------------------------------
// Certainty and expectation details
// ---------------------------------------------------------------------------

describe("detectGaps: certainty", () => {
  it("raises authz certainty on an administrative path", () => {
    const repo = expressRepo(`app.get("/admin/x", requireAuth, ${HANDLER});`);
    expect(certaintyOf(repo, "authz_missing")).toBe(0.85);
  });

  it("uses 0.7 for a record id outside an admin path", () => {
    const repo = expressRepo(`app.get("/users/:id", requireAuth, ${HANDLER});`);
    expect(certaintyOf(repo, "authz_missing")).toBe(0.7);
  });

  it("does not treat /badminton as an administrative path", () => {
    const repo = expressRepo(
      `app.get("/badminton/:id", requireAuth, ${HANDLER});`,
    );
    expect(certaintyOf(repo, "authz_missing")).toBe(0.7);
  });

  it("lowers authn certainty when middleware could not be resolved", () => {
    const repo = expressRepo(
      `const { audit } = require("./audit");\napp.post("/orders", audit, ${HANDLER});`,
    );
    expect(certaintyOf(repo, "authn_missing")).toBe(0.45);
  });

  it("flags an unauthenticated GET on an administrative path", () => {
    const repo = expressRepo(`app.get("/admin/users", ${HANDLER});`);
    expect(certaintyOf(repo, "authn_missing")).toBe(0.9);
  });

  it("lowers csrf certainty when only SameSite strict is set", () => {
    const repo = expressRepo(
      `app.use(session({ cookie: { sameSite: "strict" } }));\napp.post("/checkout", ${HANDLER});`,
      NEXT_DEP,
    );
    expect(certaintyOf(repo, "csrf_missing")).toBe(0.5);
  });

  it("raises password certainty when a fast digest sits near a password", () => {
    const repo = [
      ...expressRepo(`app.post("/login", ${HANDLER});`, { pg: "^8.0.0" }),
      file(
        "src/hash.js",
        `const crypto = require("crypto");\nconst password = req.body.p;\nconst h = crypto.createHash("md5").update(password);\n`,
      ),
    ];
    expect(certaintyOf(repo, "password_storage_weak")).toBe(0.95);
  });

  it("pins the fixed certainties of the route-independent kinds", () => {
    expect(certaintyOf(CASES[2].absent, "rate_limit_missing")).toBe(0.85);
    expect(certaintyOf(CASES[4].absent, "security_headers_missing")).toBe(0.9);
    expect(certaintyOf(CASES[5].absent, "input_validation_missing")).toBe(0.55);
    expect(certaintyOf(CASES[9].absent, "error_handling_gap")).toBe(0.5);
    expect(certaintyOf(CASES[10].absent, "cors_permissive")).toBe(0.9);
  });

  it("reports a missing lockfile at 0.5 and a postinstall script at 0.9", () => {
    expect(certaintyOf([manifest()], "supply_chain_integrity")).toBe(0.5);
    expect(
      certaintyOf(
        [manifest({}, { postinstall: "node x.js" }), LOCKFILE],
        "supply_chain_integrity",
      ),
    ).toBe(0.9);
  });

  it("keeps every certainty within 0..1", () => {
    for (const gap of gapsOf(MARKED_REPO)) {
      expect(gap.certainty).toBeGreaterThan(0);
      expect(gap.certainty).toBeLessThanOrEqual(1);
    }
  });
});

// ---------------------------------------------------------------------------
// False positives: the cases the regexes are most likely to get wrong
// ---------------------------------------------------------------------------

describe("detectGaps: false positives", () => {
  it.each<[string, DetectorInput[], GapKind]>([
    [
      "http:// in an XML namespace",
      [file("src/x.js", `const NS = "http://www.w3.org/2000/svg";`)],
      "transport_insecure",
    ],
    [
      "http:// to localhost",
      [file("src/x.js", `fetch("http://localhost:3000/x");`)],
      "transport_insecure",
    ],
    [
      "http:// to a compose service name",
      [file("src/x.js", `fetch("http://api:3000/x");`)],
      "transport_insecure",
    ],
    [
      "http:// to a private address",
      [file("src/x.js", `fetch("http://10.0.0.5/x");`)],
      "transport_insecure",
    ],
    [
      "http:// inside a comment",
      [file("src/x.js", `// old: http://api.acme-corp.com/v1\n`)],
      "transport_insecure",
    ],
    [
      "http:// in a markdown file",
      [file("README.md", "see http://api.acme-corp.com")],
      "transport_insecure",
    ],
    [
      "http:// in a test file",
      [file("tests/a.test.js", `fetch("http://api.acme-corp.com/v1");`)],
      "transport_insecure",
    ],
    [
      "a database port bound to loopback",
      [
        file(
          "docker-compose.yml",
          `services:\n  db:\n    image: postgres:16\n    ports:\n      - "127.0.0.1:5432:5432"\n`,
        ),
      ],
      "transport_insecure",
    ],
    [
      "cors() inside a comment",
      expressRepo(`// app.use(cors());`, { cors: "^2.8.5" }),
      "cors_permissive",
    ],
    [
      "cors declared but never called",
      expressRepo(`app.get("/x", ${HANDLER});`, { cors: "^2.8.5" }),
      "cors_permissive",
    ],
    [
      "cors() in a test file",
      [file("tests/a.test.js", `app.use(cors());`)],
      "cors_permissive",
    ],
    [
      "an Access-Control-Allow-Headers wildcard",
      [file("src/x.js", `res.set("Access-Control-Allow-Headers", "*");`)],
      "cors_permissive",
    ],
    [
      "a TypeScript-annotated error handler",
      expressRepo(
        `app.get("/a", async (req, res) => { await load(); });\napp.use((err: Error, req: Request, res: Response, next: NextFunction) => {});`,
      ),
      "error_handling_gap",
    ],
    [
      "a handler that catches",
      expressRepo(
        `app.get("/a", async (req, res) => { try { await load(); } catch (e) {} });`,
      ),
      "error_handling_gap",
    ],
    [
      "login, which must be reachable unauthenticated",
      expressRepo(`app.post("/login", ${HANDLER});`),
      "authn_missing",
    ],
    [
      "a signed webhook",
      expressRepo(`app.post("/webhooks/stripe", ${HANDLER});`),
      "authn_missing",
    ],
    [
      "a route behind app-level auth middleware",
      expressRepo(`app.use(requireAuth);\napp.post("/orders", ${HANDLER});`),
      "authn_missing",
    ],
    [
      "next-auth imported but not declared",
      [
        manifest({ express: "^4.0.0" }),
        LOCKFILE,
        expressApp(
          `const NextAuth = require("next-auth");\napp.post("/checkout", ${HANDLER});`,
        ),
      ],
      "csrf_missing",
    ],
    [
      "delegated authentication",
      expressRepo(`app.post("/login", ${HANDLER});`, {
        pg: "^8.0.0",
        "@clerk/nextjs": "^5.0.0",
      }),
      "password_storage_weak",
    ],
    [
      "an installed rate limiter the curated list does not track",
      expressRepo(`app.post("/login", ${HANDLER});`, {
        "rate-limiter-flexible": "^5.0.0",
      }),
      "rate_limit_missing",
    ],
    [
      "an installed logger the curated list does not track",
      expressRepo(`app.post("/login", ${HANDLER});`, { winston: "^3.0.0" }),
      "logging_missing",
    ],
    [
      "console output inside the auth handler",
      expressRepo(
        `app.post("/login", async (req, res) => { console.log("attempt"); });`,
      ),
      "logging_missing",
    ],
    [
      "a lockfile with a different package manager",
      [manifest(), file("pnpm-lock.yaml", "lockfileVersion: 9")],
      "supply_chain_integrity",
    ],
    [
      "a commented-out route",
      expressRepo(`// app.post("/orders", createOrder);`),
      "authn_missing",
    ],
    [
      "a guard after a comment inside the route call",
      expressRepo(
        `app.post(\n  "/orders",\n  // must be logged in\n  protect,\n  ${HANDLER},\n);`,
      ),
      "authn_missing",
    ],
    [
      "an error handler registered below a regex containing an escaped slash-star",
      // /\/*$/ used to open a block comment that blanked the error handler below it.
      expressRepo(
        `app.get("/a", async (req, res) => { await load(); });\nconst trim = (p) => p.replace(/\\/*$/, "");\napp.use((err, req, res, next) => { res.status(500).end(); });`,
      ),
      "error_handling_gap",
    ],
    [
      "headers set in vercel.json",
      [
        ...expressRepo(`app.get("/x", ${HANDLER});`),
        file(
          "vercel.json",
          JSON.stringify({
            headers: [
              {
                source: "/(.*)",
                headers: [
                  {
                    key: "Strict-Transport-Security",
                    value: "max-age=63072000",
                  },
                ],
              },
            ],
          }),
        ),
      ],
      "security_headers_missing",
    ],
    [
      "a Netlify _headers file, which opens with /*",
      [
        ...expressRepo(`app.get("/x", ${HANDLER});`),
        file("_headers", "/*\n  Referrer-Policy: no-referrer\n"),
      ],
      "security_headers_missing",
    ],
    [
      "Express 5, which forwards a rejected handler to the error handler",
      expressRepo(
        `app.get("/a", async (req, res) => { await load(); res.end(); });`,
        { express: "^5.1.0" },
      ),
      "error_handling_gap",
    ],
    [
      "Express 4 patched by express-async-errors",
      expressRepo(
        `app.get("/a", async (req, res) => { await load(); res.end(); });`,
        { "express-async-errors": "^3.1.1" },
      ),
      "error_handling_gap",
    ],
    [
      "zod imported through a subpath",
      expressRepo(
        `const { z } = require("zod/v4");\napp.post("/x", async (req, res) => { res.json(z.string().parse(req.body)); });`,
      ),
      "input_validation_missing",
    ],
    [
      "a scoped validation library imported through a subpath",
      expressRepo(
        `const { Value } = require("@sinclair/typebox/value");\napp.post("/x", async (req, res) => { res.json(Value.Check(S, req.body)); });`,
      ),
      "input_validation_missing",
    ],
  ])("does not fire on %s", (_label, files, kind) => {
    expect(kindsOf(files)).not.toContain(kind);
  });

  it("does not let a router merely named auth suppress authn_missing", () => {
    const repo = expressRepo(
      `app.use("/x", authRouter);\napp.post("/orders", ${HANDLER});`,
    );
    expect(kindsOf(repo)).toContain("authn_missing");
  });

  it("does not let an app-level rate limiter named auth suppress authn_missing", () => {
    const repo = expressRepo(
      `const authLimiter = rateLimit({ max: 5 });\napp.use(authLimiter);\napp.post("/orders", ${HANDLER});`,
    );
    expect(kindsOf(repo)).toContain("authn_missing");
  });

  it("applies a path-scoped guard only under its own prefix", () => {
    // app.use("/admin", requireAuth) used to silence authn_missing for every route.
    const repo = expressRepo(
      [
        `app.use("/admin/", requireAuth);`,
        `app.post("/admin", ${HANDLER});`,
        `app.post("/admin/users", ${HANDLER});`,
        `app.post("/administrators", ${HANDLER});`,
        `app.post("/orders", ${HANDLER});`,
      ].join("\n"),
    );
    const flagged = runDetectors(repo)
      .evidence.filter((e) => e.ruleId === "gap:authn_missing")
      .map((e) => e.summary.split(" ").slice(0, 2).join(" "));

    expect(flagged).toEqual(["POST /administrators", "POST /orders"]);
  });

  it.each([
    [`app.use("/", requireAuth);`],
    [`app.use("/*", requireAuth);`],
    [`app.use("*", requireAuth);`],
  ])("treats %s as a global guard", (use) => {
    expect(
      kindsOf(expressRepo(`${use}\napp.post("/orders", ${HANDLER});`)),
    ).not.toContain("authn_missing");
  });

  it("still reports header gaps when vercel.json sets no headers", () => {
    const repo = [
      ...expressRepo(`app.get("/x", ${HANDLER});`),
      file("vercel.json", JSON.stringify({ rewrites: [] })),
    ];
    expect(kindsOf(repo)).toContain("security_headers_missing");
  });

  it("keeps the error handling check while any express is below 5", () => {
    const route = `app.get("/a", async (req, res) => { await load(); res.end(); });`;
    expect(
      kindsOf(expressRepo(route, { express: "^4.0.0 || ^5.0.0" })),
    ).toContain("error_handling_gap");
    expect(
      kindsOf([
        ...expressRepo(route, { express: "^5.1.0" }),
        file(
          "services/legacy/package.json",
          JSON.stringify({ dependencies: { express: "^4.18.2" } }),
        ),
      ]),
    ).toContain("error_handling_gap");
  });

  it("still fires input validation when JSON.parse is the only handling", () => {
    // JSON.parse is the opposite of validation: it must not count as a control.
    expect(kindsOf(CASES[5].absent)).toContain("input_validation_missing");
  });

  it("flags a bare cors call and a wildcard origin", () => {
    const bare = expressRepo(`app.use(cors());`, { cors: "^2.8.5" });
    const wildcard = expressRepo(`app.use(cors({ origin: "*" }));`, {
      cors: "^2.8.5",
    });
    expect(kindsOf(bare)).toContain("cors_permissive");
    expect(kindsOf(wildcard)).toContain("cors_permissive");
  });

  it("flags disabled TLS verification and an exposed database port", () => {
    expect(
      kindsOf([file("src/x.js", `const a = { rejectUnauthorized: false };`)]),
    ).toContain("transport_insecure");
    expect(kindsOf(MARKED_REPO)).toContain("transport_insecure");
  });

  it("does not report a gap for an empty repository", () => {
    expect(detectGaps([], runDetectors([]))).toEqual({
      gaps: [],
      evidence: [],
    });
  });

  it("survives files that are nothing but noise", () => {
    expect(() =>
      runDetectors([
        file("a.ts", "\0\0\0"),
        file("b.js", '"unterminated'),
        file("c.js", "/* never closed"),
        file("d.js", "`open template"),
        file("package.json", "{{{"),
        file("docker-compose.yml", ":::"),
      ]),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Shape: gaps and their evidence
// ---------------------------------------------------------------------------

describe("detectGaps: shape", () => {
  const { gaps, evidence } = runDetectors(MARKED_REPO);
  const gapEvidence = evidence.filter((e) => e.id.startsWith("ev-gap-"));

  it("produces gaps to test against", () => {
    expect(gaps.length).toBeGreaterThan(5);
  });

  it("gives every gap a contiguous kebab-case id", () => {
    expect(gaps.map((gap) => gap.id)).toEqual(
      gaps.map((_, index) => `gap-${index + 1}`),
    );
    for (const gap of gaps) expect(zId.safeParse(gap.id).success).toBe(true);
  });

  it("emits exactly one evidence item per gap, numbered the same", () => {
    expect(gapEvidence).toHaveLength(gaps.length);
    for (const [index, gap] of gaps.entries()) {
      expect(gapEvidence[index].id).toBe(`ev-gap-${index + 1}`);
      expect(gapEvidence[index].filePath).toBe(gap.file);
      expect(gapEvidence[index].lineStart).toBe(gap.line);
    }
  });

  it("tags evidence with gap:<kind> and the OWASP 2025 categories", () => {
    for (const [index, gap] of gaps.entries()) {
      const item = gapEvidence[index];
      expect(item.ruleId).toBe(`gap:${gap.kind}`);
      expect(item.metadata?.owasp2025).toEqual(gap.owasp);
      for (const code of gap.owasp) {
        expect(Owasp2025Schema.safeParse(code).success).toBe(true);
      }
    }
  });

  it("is schema-valid, detector-sourced, and never carries a snippet", () => {
    for (const item of gapEvidence) {
      expect(EvidenceSchema.safeParse(item).success).toBe(true);
      expect(item.source).toBe("detector");
      expect(["code", "config"]).toContain(item.kind);
      expect(item.snippet).toBeUndefined();
      expect(item.filePath).toBeTruthy();
      expect(item.lineStart).toBeGreaterThanOrEqual(1);
    }
  });

  it("gives every gap a mapping and at least one basis fact", () => {
    for (const gap of gaps) {
      expect(gap.owasp.length).toBeGreaterThan(0);
      expect(gap.stride.length).toBeGreaterThan(0);
      expect(gap.cwe.every((c) => /^CWE-\d+$/.test(c))).toBe(true);
      expect(gap.basisFacts.length).toBeGreaterThan(0);
      expect(gap.line).toBeGreaterThanOrEqual(1);
    }
  });

  it("leaves the other evidence categories without a ruleId", () => {
    for (const item of evidence.filter((e) => !e.id.startsWith("ev-gap-"))) {
      expect(item.ruleId).toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// Untrusted content (CLAUDE.md rule 3)
// ---------------------------------------------------------------------------

describe("detectGaps: no repository content reaches a gap", () => {
  const result = runDetectors(MARKED_REPO);
  const leaves = stringLeaves([result.gaps, result.evidence]);

  it("has the marker in every source the gaps are built from", () => {
    // Guards the guard: a marker that is not in the samples proves nothing.
    const samples = stringLeaves(MARKED_REPO).join("\n");
    expect(samples).toContain(GAP_MARKER);
    expect(result.gaps.length).toBeGreaterThan(0);
  });

  it("copies no marker into a gap or its evidence", () => {
    expect(leaves.join("\n")).not.toContain(GAP_MARKER);
  });

  it("produces text that passes the secret sweep", () => {
    expect(() => assertNoSecrets(leaves.join("\n"))).not.toThrow();
  });

  it("would notice if a gap did start copying content", () => {
    const samples = stringLeaves(MARKED_REPO).join("\n");
    expect(() => assertNoSecrets(samples)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Stability
// ---------------------------------------------------------------------------

describe("detectGaps: stability", () => {
  const baseline = runDetectors(MARKED_REPO);

  it("is identical however the input is ordered", () => {
    expect(runDetectors([...MARKED_REPO].reverse())).toEqual(baseline);
    expect(
      runDetectors(
        [...MARKED_REPO].sort((a, b) => b.path.length - a.path.length),
      ),
    ).toEqual(baseline);
  });

  it("is deterministic across repeated runs", () => {
    expect(runDetectors(MARKED_REPO)).toEqual(baseline);
  });
});

// ---------------------------------------------------------------------------
// The shared sample repository: a regression net
// ---------------------------------------------------------------------------

describe("detectGaps: the sample repository", () => {
  const kinds = kindsOf(SAMPLE_REPO);

  it("reports the kinds its routes and config actually earn", () => {
    expect([...kinds].sort()).toEqual(
      [
        "authn_missing",
        "authz_missing",
        "error_handling_gap",
        "input_validation_missing",
        "logging_missing",
        "rate_limit_missing",
        "supply_chain_integrity",
        "transport_insecure",
      ].sort(),
    );
  });

  it.each<[string, GapKind]>([
    ["helmet is declared and called", "security_headers_missing"],
    ["cors is declared but never called", "cors_permissive"],
    ["no session dependency is declared", "csrf_missing"],
    ["passwords are delegated to Clerk", "password_storage_weak"],
  ])("stays silent because %s", (_why, kind) => {
    expect(kinds).not.toContain(kind);
  });

  it("does not report the login route as unauthenticated", () => {
    const authn = gapsOf(SAMPLE_REPO).filter((g) => g.kind === "authn_missing");
    expect(authn.every((g) => !g.basisFacts.join().includes("login"))).toBe(
      true,
    );
    expect(
      runDetectors(SAMPLE_REPO).evidence.some(
        (e) => e.ruleId === "gap:authn_missing" && /\/login\b/.test(e.summary),
      ),
    ).toBe(false);
  });

  it("puts the admin role check on GET /admin/users out of authz scope", () => {
    const authz = runDetectors(SAMPLE_REPO).evidence.filter(
      (e) => e.ruleId === "gap:authz_missing",
    );
    expect(authz.some((e) => e.summary.includes("/admin/users"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Helpers this module adds
// ---------------------------------------------------------------------------

describe("isAdminPath", () => {
  it.each([
    ["/admin", true],
    ["/api/admin/users", true],
    ["/admin-panel/x", true],
    ["/administrator", true],
    ["/badminton", false],
    ["/api/administrative-notes", false],
    ["/sysadminish", false],
    ["/users/:id", false],
  ])("classifies %s as %s", (path, expected) => {
    expect(isAdminPath(path)).toBe(expected);
  });
});

describe("maskCode and maskComments", () => {
  const source = `a();\n// b()\n/* c() */ d("e()");\n`;

  it("blanks comments and keeps strings in maskComments", () => {
    const masked = maskComments(source);
    expect(masked).not.toContain("b()");
    expect(masked).not.toContain("c()");
    expect(masked).toContain('"e()"');
  });

  it("blanks comments and string bodies in maskCode", () => {
    const masked = maskCode(source);
    expect(masked).toContain("a()");
    expect(masked).toContain("d(");
    expect(masked).not.toContain("e()");
  });

  it("preserves length and every newline, so line numbers hold", () => {
    for (const masked of [maskCode(source), maskComments(source)]) {
      expect(masked).toHaveLength(source.length);
      expect(masked.split("\n")).toHaveLength(source.split("\n").length);
    }
  });

  it("does not treat // inside a string as a comment", () => {
    expect(maskComments(`const u = "http://a.b"; x();`)).toContain("x();");
  });

  it.each([
    ["an escaped slash before a star", `p.replace(/\\/*$/, "");\nguard();\n`],
    ["escaped slashes in a URL regex", `/^https?:\\/\\//.test(s); guard();\n`],
  ])("does not open a comment at %s inside a regex", (_label, source) => {
    for (const masked of [maskCode(source), maskComments(source)]) {
      expect(masked).toContain("guard();");
    }
  });

  it("still blanks a real comment that follows a regex", () => {
    const masked = maskComments(
      `/\\/*$/.test(p); // gone()\n/* gone() */ kept();`,
    );
    expect(masked).not.toContain("gone()");
    expect(masked).toContain("kept();");
  });

  it.each(["/* never closed", '"open quote', "`open template", "\0\0", ""])(
    "terminates on unterminated input %j",
    (input) => {
      expect(() => maskCode(input)).not.toThrow();
      expect(maskCode(input)).toHaveLength(input.length);
    },
  );
});

describe("isScannable", () => {
  it.each([
    ["src/app.ts", true],
    ["app/api/x/route.js", true],
    ["tests/a.test.ts", false],
    ["src/a.spec.ts", false],
    ["__mocks__/db.js", false],
    ["examples/demo.js", false],
    ["node_modules/x/index.js", false],
    ["README.md", false],
  ])("treats %s as scannable=%s", (path, expected) => {
    expect(isScannable(path)).toBe(expected);
  });
});
