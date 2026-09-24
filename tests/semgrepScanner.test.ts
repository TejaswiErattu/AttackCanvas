import { describe, expect, it } from "vitest";
import {
  SNIPPET_MAX_LINES,
  SUMMARY_MAX_CHARS,
  dedupeKey,
  normalizeSemgrep,
} from "@/server/scanners/semgrep";
import {
  parseScanResponse,
  type RawSemgrepFinding,
} from "@/server/mcp/semgrepClient";
import { assertNoSecrets } from "@/server/security/redactor";
import { OWASP_2021_TO_2025 } from "@/shared/owaspMap";
import { EvidenceSchema, OWASP_LABELS, zId } from "@/shared/schema";
import { SAMPLE_FILES, SCAN_RESPONSE_TEXT } from "./semgrepResponses";

/** Every credential here is fabricated. */
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

function finding(
  overrides: Partial<RawSemgrepFinding> = {},
): RawSemgrepFinding {
  return {
    ruleId: "rule.one",
    path: "src/a.js",
    startLine: 10,
    endLine: 10,
    message: "Something is wrong here.",
    severity: "error",
    cwe: ["CWE-89: SQL Injection"],
    owasp: ["A03:2021 - Injection"],
    ...overrides,
  };
}

// The saved live response from the Semgrep MCP server, parsed by the real client code.
const contentByPath = new Map(
  SAMPLE_FILES.map((file) => [file.path, file.content]),
);
const REAL = parseScanResponse(SCAN_RESPONSE_TEXT, contentByPath);
const real = normalizeSemgrep(REAL);

describe("normalizeSemgrep: the saved live response", () => {
  it("turns every finding into evidence", () => {
    expect(REAL).toHaveLength(7);
    expect(real).toHaveLength(7);
  });

  it("emits kind scanner and source semgrep, with rule, file and lines", () => {
    for (const evidence of real) {
      expect(evidence.kind).toBe("scanner");
      expect(evidence.source).toBe("semgrep");
      expect(evidence.ruleId).toMatch(/^attackcanvas-/);
      expect(evidence.filePath).toMatch(/^src\//);
      expect(evidence.lineStart).toBeGreaterThanOrEqual(1);
      expect(evidence.lineEnd).toBeGreaterThanOrEqual(
        evidence.lineStart as number,
      );
      expect(evidence.summary.length).toBeGreaterThan(0);
    }
  });

  it("produces items the Evidence schema accepts", () => {
    for (const evidence of real) {
      expect(EvidenceSchema.safeParse(evidence).success).toBe(true);
    }
  });

  it("keeps the multi-line span of a multi-line finding", () => {
    const span = real.find(
      (e) => e.filePath === "src/db.js" && e.lineStart === 13,
    );

    expect(span?.lineEnd).toBe(15);
    expect(span?.snippet?.split("\n")).toHaveLength(3);
  });

  it("carries a snippet for each finding, from the code we sent", () => {
    const evalHit = real.find((e) => e.ruleId === "attackcanvas-eval-user-input");
    expect(evalHit?.snippet).toContain("eval(");
  });

  it("gives ids that are sequential and valid under zId", () => {
    expect(real.map((e) => e.id)).toEqual(
      real.map((_, i) => `ev-semgrep-${i + 1}`),
    );
    for (const evidence of real)
      expect(zId.safeParse(evidence.id).success).toBe(true);
  });

  it("orders by file then line", () => {
    const keys = real.map(
      (e) => `${e.filePath}:${String(e.lineStart).padStart(6, "0")}`,
    );
    expect(keys).toEqual([...keys].sort());
  });
});

describe("normalizeSemgrep: OWASP mapping", () => {
  it("maps the 2021 tags a rule carries onto 2025", () => {
    const sql = real.find((e) => e.ruleId === "attackcanvas-sql-string-concat");
    const jwt = real.find(
      (e) => e.ruleId === "attackcanvas-hardcoded-jwt-secret",
    );
    const hash = real.find((e) => e.ruleId === "attackcanvas-weak-hash");

    expect(sql?.metadata?.owasp2025).toEqual(["A05:2025"]); // Injection
    expect(jwt?.metadata?.owasp2025).toEqual(["A07:2025"]); // Authentication Failures
    expect(hash?.metadata?.owasp2025).toEqual(["A04:2025"]); // Cryptographic Failures
  });

  it.each([
    ["A01:2021 - Broken Access Control", "A01:2025"],
    ["A02:2021 - Cryptographic Failures", "A04:2025"],
    ["A03:2021 - Injection", "A05:2025"],
    ["A04:2021 - Insecure Design", "A06:2025"],
    ["A05:2021 - Security Misconfiguration", "A02:2025"],
    ["A06:2021 - Vulnerable and Outdated Components", "A03:2025"],
    ["A07:2021 - Identification and Authentication Failures", "A07:2025"],
    ["A08:2021 - Software and Data Integrity Failures", "A08:2025"],
    ["A09:2021 - Security Logging and Monitoring Failures", "A09:2025"],
    ["A10:2021 - Server-Side Request Forgery (SSRF)", "A01:2025"],
  ])("maps the tag %s to %s", (tag, expected) => {
    const [evidence] = normalizeSemgrep([finding({ owasp: [tag] })]);
    expect(evidence.metadata?.owasp2025).toEqual([expected]);
  });

  it("stores the mapped codes in metadata.owasp2025 and nothing else", () => {
    const [evidence] = normalizeSemgrep([
      finding({
        owasp: ["A03:2021 - Injection"],
        cwe: ["CWE-89"],
        severity: "warning",
      }),
    ]);

    // The schema's metadata is closed. The rule's CWE list, its 2021 tags and Semgrep's
    // own severity have no field, and severity is computed in scoring anyway.
    expect(evidence.metadata).toEqual({ owasp2025: ["A05:2025"] });
    expect(Object.keys(evidence.metadata ?? {})).toEqual(["owasp2025"]);
  });

  it("omits metadata entirely for a rule with no OWASP tag", () => {
    const [evidence] = normalizeSemgrep([finding({ owasp: [] })]);
    expect("metadata" in evidence).toBe(false);
  });

  it("omits metadata for tags that carry no code", () => {
    const [evidence] = normalizeSemgrep([finding({ owasp: ["Injection"] })]);
    expect("metadata" in evidence).toBe(false);
  });

  it("passes a rule already written in 2025 terms through", () => {
    const [evidence] = normalizeSemgrep([
      finding({ owasp: ["A05:2025 - Injection"] }),
    ]);
    expect(evidence.metadata?.owasp2025).toEqual(["A05:2025"]);
  });

  it("de-duplicates codes that several tags map to, and sorts them", () => {
    const [evidence] = normalizeSemgrep([
      finding({
        owasp: [
          "A10:2021 - Server-Side Request Forgery (SSRF)",
          "A03:2021 - Injection",
          "A01:2021 - Broken Access Control",
        ],
      }),
    ]);
    expect(evidence.metadata?.owasp2025).toEqual(["A01:2025", "A05:2025"]);
  });

  it("returns evidence that EvidenceSchema.parse leaves exactly as it was", () => {
    const [evidence] = normalizeSemgrep([finding()]);
    const parsed = EvidenceSchema.parse(evidence);

    // The whole point of this being a schema field: parsing used to strip it.
    expect(parsed).toEqual(evidence);
    expect(parsed.metadata?.owasp2025).toEqual(["A05:2025"]);
  });

  it("keeps the mapping through parsing for every finding in the live response", () => {
    for (const evidence of real) {
      const parsed = EvidenceSchema.parse(evidence);

      expect(parsed).toEqual(evidence);
      expect(parsed.metadata?.owasp2025?.length).toBeGreaterThan(0);
    }
  });

  it("produces only codes the schema accepts, each with a display label", () => {
    for (const tag of Object.keys(OWASP_2021_TO_2025)) {
      const [evidence] = normalizeSemgrep([finding({ owasp: [tag] })]);
      const [code] = EvidenceSchema.parse(evidence).metadata?.owasp2025 ?? [];

      expect(code).toBeDefined();
      expect(OWASP_LABELS[code as keyof typeof OWASP_LABELS]).toBeTruthy();
    }
  });
});

describe("normalizeSemgrep: de-duplication", () => {
  it("collapses findings sharing ruleId, path and startLine", () => {
    const result = normalizeSemgrep([
      finding({ endLine: 10 }),
      finding({ endLine: 12 }),
      finding({ message: "A different message." }),
    ]);

    expect(result).toHaveLength(1);
  });

  it("keeps the widest of the duplicates", () => {
    const [kept] = normalizeSemgrep([
      finding({ endLine: 10 }),
      finding({ endLine: 14 }),
    ]);
    expect(kept.lineEnd).toBe(14);
  });

  it.each([
    ["a different rule", { ruleId: "rule.two" }],
    ["a different file", { path: "src/b.js" }],
    ["a different start line", { startLine: 11, endLine: 11 }],
  ])("keeps findings that differ by %s", (_label, change) => {
    expect(normalizeSemgrep([finding(), finding(change)])).toHaveLength(2);
  });

  it("does not let a delimiter in a path forge a collision", () => {
    const a = finding({ ruleId: "r", path: "a b", startLine: 1 });
    const b = finding({ ruleId: "r a", path: "b", startLine: 1 });

    expect(dedupeKey(a)).not.toBe(dedupeKey(b));
    expect(normalizeSemgrep([a, b])).toHaveLength(2);
  });

  it("is stable however the input is ordered", () => {
    const input = [
      finding({ path: "src/z.js", startLine: 1, endLine: 1 }),
      finding({ path: "src/a.js", startLine: 9, endLine: 9 }),
      finding({
        path: "src/a.js",
        startLine: 2,
        endLine: 2,
        ruleId: "rule.two",
      }),
      finding({
        path: "src/a.js",
        startLine: 2,
        endLine: 2,
        ruleId: "rule.one",
      }),
    ];

    expect(normalizeSemgrep([...input].reverse())).toEqual(
      normalizeSemgrep(input),
    );
  });

  it("does not mutate its input", () => {
    const input = [finding({ startLine: 5 }), finding({ startLine: 1 })];
    const before = JSON.stringify(input);

    normalizeSemgrep(input);
    expect(JSON.stringify(input)).toBe(before);
  });

  it("returns nothing for no findings", () => {
    expect(normalizeSemgrep([])).toEqual([]);
  });
});

describe("normalizeSemgrep: redaction (repository content is untrusted)", () => {
  it("redacts a secret in the snippet", () => {
    const [evidence] = normalizeSemgrep([
      finding({ snippet: `const id = "${AWS_KEY}";\nuse(id);` }),
    ]);

    expect(evidence.snippet).not.toContain(AWS_KEY);
    expect(evidence.snippet).toContain("[REDACTED:aws_access_key]");
    expect(evidence.snippet).toContain("use(id);"); // the rest survives
  });

  it("redacts a secret Semgrep interpolated into the message", () => {
    const [evidence] = normalizeSemgrep([
      finding({ message: `Hardcoded credential ${AWS_KEY} passed to sign().` }),
    ]);

    expect(evidence.summary).not.toContain(AWS_KEY);
    expect(evidence.summary).toContain("[REDACTED:aws_access_key]");
  });

  it("redacts a password assignment in a snippet, keeping the variable name", () => {
    const [evidence] = normalizeSemgrep([
      finding({ snippet: 'const DB_PASSWORD = "hunter2pass";' }),
    ]);

    expect(evidence.snippet).toBe(
      'const DB_PASSWORD = "[REDACTED:generic_secret]";',
    );
  });

  it("redacts a connection string, keeping scheme and host", () => {
    const [evidence] = normalizeSemgrep([
      finding({
        snippet: 'connect("postgres://admin:hunter2pass@db.internal/app");',
      }),
    ]);

    expect(evidence.snippet).not.toContain("hunter2pass");
    expect(evidence.snippet).toContain("postgres://");
    expect(evidence.snippet).toContain("@db.internal/app");
  });

  it("produces text that passes assertNoSecrets, for every field it fills", () => {
    const result = normalizeSemgrep([
      finding({
        message: `Found ${AWS_KEY}`,
        snippet: `const a = "${AWS_KEY}";\nconst DB_PASSWORD = "hunter2pass";`,
      }),
    ]);

    for (const evidence of result) {
      expect(() => assertNoSecrets(evidence.summary)).not.toThrow();
      expect(() => assertNoSecrets(evidence.snippet ?? "")).not.toThrow();
    }
  });

  it("never lets the planted key appear anywhere in the serialised result", () => {
    const result = normalizeSemgrep([
      finding({ message: AWS_KEY, snippet: `x = "${AWS_KEY}"` }),
    ]);
    expect(JSON.stringify(result)).not.toContain(AWS_KEY);
  });

  it("leaves a snippet with nothing secret in it exactly as it was", () => {
    const snippet = "  return jwt.sign(payload, key);";
    expect(normalizeSemgrep([finding({ snippet })])[0].snippet).toBe(snippet);
  });
});

describe("normalizeSemgrep: snippet and summary handling", () => {
  it("caps a snippet at six lines", () => {
    const snippet = Array.from({ length: 12 }, (_, i) => `line ${i + 1}`).join(
      "\n",
    );
    const [evidence] = normalizeSemgrep([finding({ snippet })]);

    expect(evidence.snippet?.split("\n")).toHaveLength(SNIPPET_MAX_LINES);
    expect(evidence.snippet?.split("\n").at(-1)).toBe("line 6");
  });

  it.each([
    ["absent", undefined],
    ["empty", ""],
    ["only whitespace", "  \n \n"],
  ])("omits the snippet when it is %s", (_label, snippet) => {
    const [evidence] = normalizeSemgrep([finding({ snippet })]);
    expect("snippet" in evidence).toBe(false);
  });

  it("collapses a multi-line message to one line", () => {
    const [evidence] = normalizeSemgrep([
      finding({ message: "First line.\n\n  Second   line.\n" }),
    ]);
    expect(evidence.summary).toBe("First line. Second line.");
  });

  it("truncates a very long message", () => {
    const [evidence] = normalizeSemgrep([
      finding({ message: "word ".repeat(200) }),
    ]);

    expect(evidence.summary.length).toBeLessThanOrEqual(SUMMARY_MAX_CHARS);
    expect(evidence.summary.endsWith("…")).toBe(true);
  });

  it("falls back to naming the rule when the message is empty", () => {
    const [evidence] = normalizeSemgrep([
      finding({ message: "   ", ruleId: "rule.x" }),
    ]);
    expect(evidence.summary).toBe("Semgrep rule rule.x matched");
  });

  it("never produces a lineEnd before its lineStart", () => {
    const [evidence] = normalizeSemgrep([
      finding({ startLine: 20, endLine: 5 }),
    ]);
    expect(evidence.lineEnd).toBe(20);
  });
});
