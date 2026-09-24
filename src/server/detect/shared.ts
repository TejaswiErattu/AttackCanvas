import type { Evidence, EvidenceKind, EvidenceMetadata } from "@/shared/schema";
import type { DetectorInput } from "@/server/detect/types";

/**
 * Small helpers every detector shares. Pure, no I/O.
 */

// ---------------------------------------------------------------------------
// Lines
// ---------------------------------------------------------------------------

/**
 * Offsets where each line starts, for turning a match offset into a line number.
 * Built once per file and binary-searched, so a file with many matches stays linear.
 *
 * redactor.ts has the same pair privately. Duplicated rather than exported from there
 * because detect has no other reason to depend on security, and it is ~15 lines.
 */
export function lineStarts(content: string): number[] {
  const starts = [0];
  for (let index = 0; index < content.length; index++) {
    if (content[index] === "\n") starts.push(index + 1);
  }
  return starts;
}

/** 1-based line number for an offset. */
export function lineAt(starts: readonly number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (starts[mid] <= offset) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

/** 1-based line of the first occurrence of `needle`, or 1 when it is absent. */
export function lineOf(content: string, needle: string): number {
  const offset = content.indexOf(needle);
  if (offset === -1) return 1;
  return lineAt(lineStarts(content), offset);
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/** "a\\b/C.TS" -> "a/b/C.TS". Separators only; case is preserved. */
export function normalizeSeparators(path: string): string {
  return path.replace(/\\/g, "/").replace(/^\.\//, "");
}

export function basename(path: string): string {
  const parts = normalizeSeparators(path).split("/");
  return parts[parts.length - 1] ?? "";
}

/**
 * Framework-native route path to one shared vocabulary:
 * "[id]" -> ":id", "[...slug]" and "[[...slug]]" -> "*". Express paths are unchanged.
 */
export function normalizeRoutePath(path: string): string {
  return path
    .replace(/\[\[?\.\.\.([^\]]+)\]?\]/g, "*")
    .replace(/\[([^\]]+)\]/g, ":$1");
}

/** Sorted by path, so detector output never depends on the loader's fetch order. */
export function byPath<T extends DetectorInput>(files: readonly T[]): T[] {
  return [...files].sort((a, b) => a.path.localeCompare(b.path));
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/**
 * Hands out "ev-<prefix>-<n>" ids, counted per prefix so they stay stable and readable
 * ("ev-route-3"). Kebab-case throughout, because zId requires it.
 *
 * Never sets `snippet`: a snippet is raw repository content and could carry a secret
 * (CLAUDE.md rules 3 and 8). Summaries are built from derived facts only.
 */
export class EvidenceBuilder {
  private readonly counts = new Map<string, number>();
  private readonly items: Evidence[] = [];

  add(
    prefix: string,
    kind: EvidenceKind,
    summary: string,
    filePath: string,
    lineStart: number,
    extras?: { ruleId?: string; metadata?: EvidenceMetadata },
  ): Evidence {
    const next = (this.counts.get(prefix) ?? 0) + 1;
    this.counts.set(prefix, next);

    // Conditional spreads keep an absent field absent rather than `undefined`, which
    // would otherwise show up as a key in the serialised evidence.
    const evidence: Evidence = {
      id: `ev-${prefix}-${next}`,
      kind,
      source: "detector",
      summary,
      filePath,
      lineStart: Math.max(1, Math.floor(lineStart)),
      ...(extras?.ruleId ? { ruleId: extras.ruleId } : {}),
      ...(extras?.metadata ? { metadata: extras.metadata } : {}),
    };
    this.items.push(evidence);
    return evidence;
  }

  all(): Evidence[] {
    return [...this.items];
  }
}

// ---------------------------------------------------------------------------
// Admin paths
// ---------------------------------------------------------------------------

/** "admin", "admins", "administrator(s)", or a hyphenated form like "admin-panel". */
const ADMIN_SEGMENT = /^(?:admins?|administrators?)$|^admin[-_.]|[-_.]admin$/i;

/**
 * True when a path has an administrative *segment*. A substring test matched
 * "/badminton" and "/api/administrative-notes", and an admin path raises a gap's
 * certainty, so the bug would have become a confident false finding.
 */
export function isAdminPath(path: string): boolean {
  return path.split("/").some((segment) => ADMIN_SEGMENT.test(segment));
}

// ---------------------------------------------------------------------------
// Masking
// ---------------------------------------------------------------------------

/**
 * Blanks comments, and optionally string bodies, with spaces. Offsets and newlines are
 * preserved, so `lineAt` on the result gives the same line numbers as on the original.
 *
 * Purpose: a `// app.use(cors())` comment or a `"helmet("` string must not count as a
 * control being present or absent. Repository content is untrusted, so this never
 * throws and always terminates: an unterminated comment or backtick string runs to the
 * end of the file, an unterminated quote ends at its line.
 *
 * It does not lex regex literals (`a / b / c` is the classic trap), so a regex body is
 * left as code. That is harmless unless the body looks like a comment opener: `/\/*$/`
 * would blank every line up to the next `*` `/`, real guards included, and turn them
 * into confident false gaps. A slash right after a backslash therefore never opens a
 * comment, which covers the common escaped forms (`\/*`, `:\/\/`). An unescaped quote
 * inside a regex still opens a string, but that string ends at its line.
 *
 * Template literals are masked whole, `${...}` included, which can hide a call inside
 * one; that is the safe direction for a detector that reports absence only when it is
 * sure.
 */
function maskSource(content: string, maskStrings: boolean): string {
  const out = content.split("");
  const blank = (from: number, to: number): void => {
    for (let index = from; index < to && index < out.length; index++) {
      if (out[index] !== "\n") out[index] = " ";
    }
  };

  let index = 0;
  while (index < content.length) {
    const character = content[index];
    const next = content[index + 1];
    const escaped = content[index - 1] === "\\";

    if (character === "/" && next === "/" && !escaped) {
      let end = content.indexOf("\n", index);
      if (end === -1) end = content.length;
      blank(index, end);
      index = end;
    } else if (character === "/" && next === "*" && !escaped) {
      const close = content.indexOf("*/", index + 2);
      const end = close === -1 ? content.length : close + 2;
      blank(index, end);
      index = end;
    } else if (character === '"' || character === "'" || character === "`") {
      let end = index + 1;
      while (end < content.length) {
        if (content[end] === "\\") {
          end += 2;
          continue;
        }
        if (content[end] === character) break;
        if (content[end] === "\n" && character !== "`") break;
        end += 1;
      }
      if (maskStrings) blank(index + 1, end);
      index = end + 1;
    } else {
      index += 1;
    }
  }

  return out.join("");
}

/** Comments blanked, strings kept: for checks whose signal lives in a string. */
export function maskComments(content: string): string {
  return maskSource(content, false);
}

/** Comments and string bodies blanked: for checks that look for calls and names. */
export function maskCode(content: string): string {
  return maskSource(content, true);
}
