import { describe, expect, it } from "vitest";
import {
  ALLOWED_TOOLS,
  BATCH_SIZE,
  SNIPPET_MAX_LINES,
  SemgrepClientConfigError,
  SemgrepMcpError,
  TIMEOUT_MS,
  batch,
  callToolWith,
  parseScanResponse,
  scanFilesWith,
  type RedactedFile,
  type ToolCaller,
} from "@/server/mcp/semgrepClient";
import { RULE_IDS, SECURITY_RULESET } from "@/server/mcp/semgrepRules";
import { SAMPLE_FILES, SCAN_RESPONSE_TEXT } from "./semgrepResponses";

/** A ToolCaller that records its calls and replays canned results. */
function stubClient(
  results: unknown[] | unknown,
  options: { throws?: unknown } = {},
): ToolCaller & { calls: { name: string; args: Record<string, unknown>; timeout?: number }[] } {
  const queue = Array.isArray(results) ? [...results] : [results];
  const calls: { name: string; args: Record<string, unknown>; timeout?: number }[] = [];

  return {
    calls,
    async callTool(params, _schema, opts) {
      calls.push({
        name: params.name,
        args: params.arguments ?? {},
        ...(opts?.timeout !== undefined ? { timeout: opts.timeout } : {}),
      });
      if (options.throws) throw options.throws;
      return queue.length > 1 ? queue.shift() : queue[0];
    },
  };
}

function textResult(text: string, isError = false) {
  return { content: [{ type: "text", text }], isError };
}

const contentByPath = new Map(SAMPLE_FILES.map((file) => [file.path, file.content]));

// ---------------------------------------------------------------------------
// Parser, against the saved response
// ---------------------------------------------------------------------------

describe("parseScanResponse, saved response", () => {
  const findings = parseScanResponse(SCAN_RESPONSE_TEXT, contentByPath);

  it("reads every result in the response", () => {
    expect(findings).toHaveLength(7);
  });

  it("finds the three planted flaws", () => {
    const byRule = new Map(findings.map((finding) => [finding.ruleId, finding]));

    expect(byRule.get("attackcanvas-sql-string-concat")?.path).toBe("src/db.js");
    expect(byRule.get("attackcanvas-eval-user-input")?.path).toBe("src/eval.js");
    expect(byRule.get("attackcanvas-hardcoded-jwt-secret")?.path).toBe("src/auth.js");
  });

  it("carries CWE and OWASP from the rule metadata", () => {
    for (const finding of findings) {
      expect(finding.cwe.length).toBeGreaterThan(0);
      expect(finding.owasp.length).toBeGreaterThan(0);
    }

    const sql = findings.find((f) => f.ruleId === "attackcanvas-sql-string-concat");
    expect(sql?.cwe[0]).toMatch(/^CWE-89:/);
    expect(sql?.owasp[0]).toMatch(/^A03:/);
  });

  it("reads line spans, including a multi-line match", () => {
    const spans = findings
      .filter((f) => f.path === "src/db.js")
      .map((f) => [f.startLine, f.endLine]);

    expect(spans).toContainEqual([9, 9]);
    expect(spans).toContainEqual([13, 15]);
  });

  it("normalises severity to lower case", () => {
    for (const finding of findings) {
      expect(["error", "warning", "info"]).toContain(finding.severity);
    }
  });

  it("takes the snippet from our content, not from the response", () => {
    // Semgrep reports "requires login" for extra.lines when logged out.
    expect(SCAN_RESPONSE_TEXT).toContain("requires login");

    const evalFinding = findings.find((f) => f.ruleId === "attackcanvas-eval-user-input");
    expect(evalFinding?.snippet).toContain("eval(req.query.expr)");
    expect(evalFinding?.snippet).not.toContain("requires login");
  });

  it("keeps every message non-empty", () => {
    for (const finding of findings) expect(finding.message.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Parser edge cases
// ---------------------------------------------------------------------------

function envelope(results: unknown[]): string {
  return JSON.stringify({ version: "1.176.0", results, errors: [], paths: {} });
}

function result(overrides: Record<string, unknown> = {}) {
  return {
    check_id: "r1",
    path: "a.js",
    start: { line: 2, col: 1 },
    end: { line: 2, col: 9 },
    extra: {
      message: "boom",
      severity: "ERROR",
      metadata: { cwe: ["CWE-1"], owasp: ["A01"] },
    },
    ...overrides,
  };
}

describe("parseScanResponse, edge cases", () => {
  it("reads JSON out of a fenced block", () => {
    const text = "Here are the findings:\n```json\n" + envelope([result()]) + "\n```\n";
    expect(parseScanResponse(text)).toHaveLength(1);
  });

  it("accepts an empty result set", () => {
    expect(parseScanResponse(envelope([]))).toEqual([]);
  });

  describe("a repository path cannot pose as the response's own fence", () => {
    // The response echoes every scanned path; git allows backticks in a file name.
    const withScannedPath = (path: string) =>
      SCAN_RESPONSE_TEXT.replace('"scanned": [', `"scanned": [\n      ${JSON.stringify(path)},`);
    const byPath = new Map(SAMPLE_FILES.map((f) => [f.path, f.content]));
    const baseline = parseScanResponse(SCAN_RESPONSE_TEXT, byPath);

    it.each([
      ["an empty object between fences", "src/a```{}```.js"],
      ["plain text between fences", "src/a```b```.js"],
      ["a json fence opener", "src/```json {} ```.js"],
    ])("keeps every finding when a path holds %s", (_label, path) => {
      const text = withScannedPath(path);
      expect(text).toContain(path);
      expect(baseline.length).toBeGreaterThan(0);
      expect(parseScanResponse(text, byPath)).toEqual(baseline);
    });

    it("keeps every finding when the whole response is fenced and a path holds a fence", () => {
      const text = "```json\n" + withScannedPath("src/a```{}```.js") + "\n```";
      expect(parseScanResponse(text, byPath)).toEqual(baseline);
    });
  });

  it("accepts a response with no results key at all", () => {
    expect(parseScanResponse(JSON.stringify({ errors: [] }))).toEqual([]);
  });

  it("tolerates a missing extra.metadata", () => {
    const text = envelope([result({ extra: { message: "m", severity: "WARNING" } })]);
    const [finding] = parseScanResponse(text);

    expect(finding.cwe).toEqual([]);
    expect(finding.owasp).toEqual([]);
    expect(finding.severity).toBe("warning");
  });

  it("accepts cwe and owasp as bare strings", () => {
    const text = envelope([
      result({
        extra: {
          message: "m",
          severity: "ERROR",
          metadata: { cwe: "CWE-89", owasp: "A03" },
        },
      }),
    ]);
    const [finding] = parseScanResponse(text);

    expect(finding.cwe).toEqual(["CWE-89"]);
    expect(finding.owasp).toEqual(["A03"]);
  });

  it("de-duplicates repeated metadata entries", () => {
    const text = envelope([
      result({
        extra: {
          message: "m",
          severity: "ERROR",
          metadata: { cwe: ["CWE-89", "CWE-89"], owasp: [] },
        },
      }),
    ]);
    expect(parseScanResponse(text)[0].cwe).toEqual(["CWE-89"]);
  });

  it("maps an unknown severity to info", () => {
    const text = envelope([result({ extra: { message: "m", severity: "NOPE" } })]);
    expect(parseScanResponse(text)[0].severity).toBe("info");
  });

  it("truncates a snippet to six lines", () => {
    const content = Array.from({ length: 20 }, (_, i) => `line ${i + 1}`).join("\n");
    const text = envelope([
      result({ path: "big.js", start: { line: 3 }, end: { line: 19 } }),
    ]);

    const [finding] = parseScanResponse(text, new Map([["big.js", content]]));
    const lines = finding.snippet?.split("\n") ?? [];

    expect(lines).toHaveLength(SNIPPET_MAX_LINES);
    expect(lines[0]).toBe("line 3");
    expect(lines.at(-1)).toBe("line 8");
  });

  it("omits the snippet when the file content is unknown", () => {
    expect(parseScanResponse(envelope([result()]))[0].snippet).toBeUndefined();
  });

  it("omits the snippet when the start line is past the end of the file", () => {
    const text = envelope([result({ path: "a.js", start: { line: 99 } })]);
    const [finding] = parseScanResponse(text, new Map([["a.js", "one\ntwo\n"]]));
    expect(finding.snippet).toBeUndefined();
  });

  it("falls back to the start line when the end line is missing or before it", () => {
    const text = envelope([
      result({ end: undefined }),
      result({ check_id: "r2", end: { line: 1 } }),
    ]);
    const findings = parseScanResponse(text);

    expect(findings[0].endLine).toBe(2);
    expect(findings[1].endLine).toBe(2);
  });

  it.each([
    ["a missing check_id", result({ check_id: undefined })],
    ["a missing path", result({ path: undefined })],
    ["a missing start line", result({ start: {} })],
    ["a zero start line", result({ start: { line: 0 } })],
    ["a non-object result", "nonsense"],
  ])("skips a result with %s rather than throwing", (_label, bad) => {
    const findings = parseScanResponse(envelope([bad, result({ check_id: "good" })]));

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("good");
  });

  it.each([
    ["empty text", ""],
    ["prose with no JSON", "Semgrep could not run."],
    ["a truncated object", '{"results": [ {'],
  ])("throws a typed error on %s", (_label, text) => {
    try {
      parseScanResponse(text);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(SemgrepMcpError);
      expect((error as SemgrepMcpError).code).toBe("AI_FAILURE");
    }
  });

  it("throws when the envelope is not an object", () => {
    expect(() => parseScanResponse("[1, 2, 3]")).toThrow(SemgrepMcpError);
  });
});

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

describe("allowlist", () => {
  it.each(ALLOWED_TOOLS)("allows %s", async (name) => {
    const client = stubClient(textResult("{}"));
    await expect(callToolWith(client, name)).resolves.toBe("{}");
  });

  it.each([
    "semgrep_scan",
    "semgrep_scan_supply_chain",
    "semgrep_findings",
    "semgrep_rule_schema",
    "get_abstract_syntax_tree",
    "deprecation_notice",
  ])("rejects %s before calling the server", async (name) => {
    const client = stubClient(textResult("{}"));

    await expect(callToolWith(client, name)).rejects.toThrow(SemgrepClientConfigError);
    expect(client.calls).toEqual([]);
  });

  it("never allows a tool that reads paths off disk or reaches the platform", () => {
    const banned = ["semgrep_scan", "semgrep_scan_supply_chain", "semgrep_findings"];
    for (const name of banned) {
      expect(ALLOWED_TOOLS as readonly string[]).not.toContain(name);
    }
  });
});

// ---------------------------------------------------------------------------
// Errors from the server
// ---------------------------------------------------------------------------

describe("tool errors", () => {
  it("maps an isError result to a typed error", async () => {
    const client = stubClient(textResult("request timed out", true));

    try {
      await callToolWith(client, "get_supported_languages");
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(SemgrepMcpError);
      expect((error as SemgrepMcpError).code).toBe("TIMEOUT");
    }
  });

  it("wraps a transport failure as a typed error", async () => {
    const client = stubClient(null, { throws: new Error("socket closed") });

    try {
      await callToolWith(client, "get_supported_languages");
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(SemgrepMcpError);
      expect((error as SemgrepMcpError).code).toBe("AI_FAILURE");
    }
  });

  it("rejects an oversized response", async () => {
    const huge = "x".repeat(5 * 1024 * 1024);
    const client = stubClient(textResult(huge));

    try {
      await callToolWith(client, "get_supported_languages");
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(SemgrepMcpError);
      expect((error as SemgrepMcpError).code).toBe("REPO_TOO_LARGE");
    }
  });
});

// ---------------------------------------------------------------------------
// Batching
// ---------------------------------------------------------------------------

function files(count: number, prefix = "f"): RedactedFile[] {
  return Array.from({ length: count }, (_, i) => ({
    path: `${prefix}${i}.js`,
    content: `const x${i} = 1;\n`,
  }));
}

describe("batch", () => {
  it("splits into fixed-size groups, preserving order", () => {
    expect(batch([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });

  it("returns nothing for an empty list", () => {
    expect(batch([], 40)).toEqual([]);
  });

  it("refuses a size below one", () => {
    expect(() => batch([1], 0)).toThrow(SemgrepClientConfigError);
  });
});

describe("scanFilesWith", () => {
  it("sends one batch of 40 and one of 1 for 41 files", async () => {
    const client = stubClient(textResult(envelope([])));
    await scanFilesWith(client, files(41));

    expect(client.calls).toHaveLength(2);
    expect((client.calls[0].args.code_files as unknown[]).length).toBe(BATCH_SIZE);
    expect((client.calls[1].args.code_files as unknown[]).length).toBe(1);
  });

  it("calls the content-based scan tool with the ruleset", async () => {
    const client = stubClient(textResult(envelope([])));
    await scanFilesWith(client, files(1));

    expect(client.calls[0].name).toBe("semgrep_scan_with_custom_rule");
    expect(client.calls[0].args.rule).toBe(SECURITY_RULESET);
  });

  it("passes path and content only, and nothing else", async () => {
    const client = stubClient(textResult(envelope([])));
    await scanFilesWith(client, [{ path: "a.js", content: "const a = 1;\n" }]);

    const sent = client.calls[0].args.code_files as Record<string, unknown>[];
    expect(sent).toEqual([{ path: "a.js", content: "const a = 1;\n" }]);
    expect(Object.keys(sent[0])).toEqual(["path", "content"]);
  });

  it("applies the per-batch timeout to every call", async () => {
    const client = stubClient(textResult(envelope([])));
    await scanFilesWith(client, files(41));

    for (const call of client.calls) expect(call.timeout).toBe(TIMEOUT_MS);
  });

  it("concatenates findings across batches", async () => {
    const client = stubClient([
      textResult(envelope([result({ check_id: "first" })])),
      textResult(envelope([result({ check_id: "second" })])),
    ]);

    const findings = await scanFilesWith(client, files(41));
    expect(findings.map((f) => f.ruleId)).toEqual(["first", "second"]);
  });

  it("does not call the server for an empty list", async () => {
    const client = stubClient(textResult(envelope([])));

    await expect(scanFilesWith(client, [])).resolves.toEqual([]);
    expect(client.calls).toEqual([]);
  });

  it("drops files with empty content rather than sending them", async () => {
    const client = stubClient(textResult(envelope([])));
    await scanFilesWith(client, [
      { path: "a.js", content: "" },
      { path: "b.js", content: "const b = 1;\n" },
    ]);

    const sent = client.calls[0].args.code_files as { path: string }[];
    expect(sent.map((f) => f.path)).toEqual(["b.js"]);
  });

  it("does not call the server when every file was dropped", async () => {
    const client = stubClient(textResult(envelope([])));

    await expect(scanFilesWith(client, [{ path: "a.js", content: "" }])).resolves.toEqual([]);
    expect(client.calls).toEqual([]);
  });

  it("names the failing batch without leaking file content", async () => {
    const secret = "const apiKey = 'sk_live_do_not_log';";
    const client = stubClient(null, { throws: new Error("server exploded") });

    try {
      await scanFilesWith(client, [{ path: "a.js", content: secret }]);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(SemgrepMcpError);
      expect((error as Error).message).toContain("batch 1 of 1");
      expect((error as Error).message).not.toContain("sk_live_do_not_log");
    }
  });

  it("preserves the error code of a timed-out batch", async () => {
    const client = stubClient(textResult("the request timed out", true));

    try {
      await scanFilesWith(client, files(1));
      expect.unreachable("should have thrown");
    } catch (error) {
      expect((error as SemgrepMcpError).code).toBe("TIMEOUT");
    }
  });

  it("attaches snippets from the content it sent", async () => {
    const client = stubClient(
      textResult(envelope([result({ path: "a.js", start: { line: 1 }, end: { line: 1 } })])),
    );

    const findings = await scanFilesWith(client, [
      { path: "a.js", content: "const a = 1;\nconst b = 2;\n" },
    ]);
    expect(findings[0].snippet).toBe("const a = 1;");
  });
});

// ---------------------------------------------------------------------------
// The ruleset itself
// ---------------------------------------------------------------------------

describe("SECURITY_RULESET", () => {
  it("declares every rule id the pack advertises", () => {
    for (const ruleId of RULE_IDS) {
      expect(SECURITY_RULESET).toContain(`id: ${ruleId}`);
    }
  });

  it("gives every rule a cwe and an owasp entry", () => {
    const ruleCount = SECURITY_RULESET.match(/^\s+- id: /gm)?.length ?? 0;
    const cweCount = SECURITY_RULESET.match(/^\s+cwe: /gm)?.length ?? 0;
    const owaspCount = SECURITY_RULESET.match(/^\s+owasp: /gm)?.length ?? 0;

    expect(ruleCount).toBe(RULE_IDS.length);
    expect(cweCount).toBe(ruleCount);
    expect(owaspCount).toBe(ruleCount);
  });

  it("names no registry ruleset, which the MCP tools cannot accept", () => {
    expect(SECURITY_RULESET).not.toMatch(/\bp\/[a-z-]+/);
  });
});
