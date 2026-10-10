/**
 * The threat list as CSV, and the names of the files the dashboard offers to download.
 *
 * Pure and DOM-free. Every field is repository- or model-derived text (CLAUDE.md rule 3),
 * and a spreadsheet will run a cell that starts with = + - @ (or a tab or carriage return)
 * as a formula, so csvField() does two things to every field: it prefixes such a cell with a
 * single quote, which a spreadsheet shows as plain text, and it wraps the cell in double
 * quotes with embedded quotes doubled. Nothing here decides severity, confidence, priority
 * or basis; they are copied from the view model as the server computed them (rule 2).
 */

import type { FindingStatus } from "@/client/findingStatus";
import type { ThreatCardData } from "@/shared/viewModel";

export const CSV_COLUMNS = [
  "id",
  "title",
  "severity",
  "confidence",
  "priority",
  "basis",
  "STRIDE",
  "OWASP",
  "CWE",
  "components",
  "status",
  "evidence",
  "mitigation",
] as const;

/** First characters that make a spreadsheet read a cell as a formula. */
const FORMULA_START = /^[=+\-@\t\r]/;

/** One field: formula-neutralised, wrapped in quotes, embedded quotes doubled. */
export function csvField(value: string | number): string {
  const text = String(value);
  const safe = FORMULA_START.test(text) ? `'${text}` : text;
  return `"${safe.replace(/"/g, '""')}"`;
}

const joined = (items: readonly string[] | undefined): string => (items ?? []).join("; ");

/** One threat as a row of raw (unquoted) values, in CSV_COLUMNS order. */
export function csvRow(threat: ThreatCardData, status: FindingStatus): string[] {
  return [
    threat.id,
    threat.title,
    threat.severity,
    String(threat.confidence),
    threat.priority,
    threat.basis,
    joined((threat.stride ?? []).map((s) => s.code)),
    joined((threat.owasp ?? []).map((o) => o.code)),
    joined(threat.cwe),
    joined(threat.componentNames),
    status,
    joined(
      (threat.evidence ?? []).flatMap((e) => (e.location ? [e.location] : [])),
    ),
    threat.mitigation?.summary ?? "",
  ];
}

/**
 * The CSV text: a header row, then one row per threat in the order given, lines ended with
 * CRLF. `statuses` maps threat ids to the reader's own status; a missing id is "open".
 */
export function buildThreatsCsv(
  threats: readonly ThreatCardData[],
  statuses: Readonly<Record<string, FindingStatus>> = {},
): string {
  const lines = [
    CSV_COLUMNS.map(csvField).join(","),
    ...threats.map((t) => csvRow(t, statuses[t.id] ?? "open").map(csvField).join(",")),
  ];
  return lines.join("\r\n") + "\r\n";
}

/**
 * "owner/repo" -> "owner-repo-threats.csv" or "owner-repo-threat-model.json": letters, digits,
 * dots and dashes only.
 */
export function exportFileName(fullName: string | undefined, extension: "csv" | "json"): string {
  const base = (fullName ?? "")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^[-.]+|-+$/g, "");
  return `${base || "attackcanvas"}-${extension === "csv" ? "threats" : "threat-model"}.${extension}`;
}
