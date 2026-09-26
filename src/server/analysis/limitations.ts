/**
 * What the "Limitations" section of a threat model says, and what stays in diagnostics.
 *
 * Every stage of the pipeline records what it did that a developer debugging the run
 * would want to know: a component dropped during the architecture merge, a detector fact
 * that matched two components, a gap bound by fallback, a threat discarded for citing
 * evidence it was not shown. Those messages name component ids, schema types and batch
 * numbers, and are exact on purpose. They are diagnostics: kept on the job, written to
 * development logs and to the eval runner's output, never shown as a limitation.
 *
 * A reader of the threat model needs something else: what is uncertain about the result
 * and what that means for them, once, in plain words. So each stage records a Note with a
 * code beside its diagnostic text, and userLimitations() turns the notes into at most one
 * sentence per code, counting and naming what it groups. A code with no reader-facing
 * meaning (an internal id collision, a capped list) produces no sentence at all.
 *
 * Pure: no I/O, and the output depends only on the input order-insensitively, so the same
 * run always yields the same section.
 */

export type LimitationCode =
  /** A CI or deployment config was drawn as an external system: the schema has no such type. */
  | "deployment_modelled_as_external"
  /** A component the code shows was added because the architecture draft left it out. */
  | "component_added_from_code"
  /** A proposed component, flow or boundary could not be tied to loaded code and was left out. */
  | "architecture_item_dropped"
  /** A possible missing control could not be tied to one component. */
  | "gap_bound_broadly"
  /** A candidate threat was discarded because it could not be verified. */
  | "threat_discarded"
  /** A developer answer could not be applied and was treated as skipped. */
  | "answer_not_applied"
  /** A developer answer removed everything a threat rested on. */
  | "threat_ruled_out_by_answer"
  /** Bookkeeping with no effect on how the result should be read. */
  | "internal";

export type Note = {
  code: LimitationCode;
  /** The exact diagnostic message, ids and all. Never shown as a limitation. */
  detail: string;
  /** A plain name for what the note is about, e.g. "GitHub Actions workflow lint.yml". */
  subject?: string;
};

export function note(code: LimitationCode, detail: string, subject?: string): Note {
  return subject === undefined ? { code, detail } : { code, detail, subject };
}

/** Distinct subjects in first-seen order. */
function subjectsOf(notes: readonly Note[]): string[] {
  return [...new Set(notes.flatMap((n) => (n.subject ? [n.subject] : [])))];
}

/** "a", "a and b", "a, b and c"; longer lists are cut to the first four and "N more". */
function listOf(items: readonly string[]): string {
  const shown = items.length > 5 ? [...items.slice(0, 4), `${items.length - 4} more`] : [...items];
  if (shown.length <= 1) return shown.join("");
  return `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
}

const plural = (n: number, one: string, many: string): string => (n === 1 ? one : many);

/** One reader-facing sentence for the notes that share a code, or undefined for none. */
function sentenceFor(code: LimitationCode, notes: readonly Note[]): string | undefined {
  const subjects = subjectsOf(notes);
  const count = subjects.length || notes.length;
  switch (code) {
    case "deployment_modelled_as_external":
      return (
        `The diagram shows ${subjects.length ? listOf(subjects) : "the build and deployment configuration"} ` +
        `as ${plural(count, "an external system", "external systems")} because it has no separate type for ` +
        "build and deployment tooling. Read these as part of your own release pipeline, not as " +
        "third-party services; threats against them concern how code is built and shipped."
      );
    case "component_added_from_code":
      return (
        `${subjects.length ? `The ${listOf(subjects)}` : `${count} ${plural(count, "component", "components")}`} ` +
        `${plural(count, "was", "were")} added from what the code shows because the inferred ` +
        "architecture left it out, so its connections to other components may be incomplete."
      );
    case "architecture_item_dropped":
      return (
        `${count} ${plural(count, "part", "parts")} of the inferred architecture could not be tied to the ` +
        `analysed code and ${plural(count, "was", "were")} left out, so the diagram may be missing ` +
        "a component or a data flow."
      );
    case "gap_bound_broadly":
      return (
        `${count} possible missing ${plural(count, "control", "controls")} could not be tied to a single ` +
        `component and ${plural(count, "is", "are")} attributed to the application as a whole; the ` +
        "control may apply to only part of it."
      );
    case "threat_discarded":
      return (
        `${count} candidate ${plural(count, "threat was", "threats were")} discarded because ` +
        `${plural(count, "it", "they")} could not be checked against the evidence the analysis ` +
        "had, so the list may be missing a real threat."
      );
    case "answer_not_applied":
      return (
        `${count} of your ${plural(count, "answer", "answers")} could not be applied and ` +
        `${plural(count, "was", "were")} treated as skipped, so the default assumption stands for ` +
        `${plural(count, "that question", "those questions")}.`
      );
    case "threat_ruled_out_by_answer":
      return subjects.length
        ? `Your answers ruled out ${plural(subjects.length, "a threat", "threats")} that rested only on what you answered: ${listOf(subjects.map((t) => `"${t}"`))}.`
        : `Your answers ruled out ${count} ${plural(count, "threat", "threats")} that rested only on what you answered.`;
    case "internal":
      return undefined;
  }
}

/** Codes in the order their sentences appear: the architecture first, then the findings. */
const CODE_ORDER: readonly LimitationCode[] = [
  "deployment_modelled_as_external",
  "component_added_from_code",
  "architecture_item_dropped",
  "gap_bound_broadly",
  "threat_discarded",
  "answer_not_applied",
  "threat_ruled_out_by_answer",
];

/**
 * The Limitations section: one sentence per code that has any notes, in CODE_ORDER, then
 * `plain` (messages already written for a reader, such as the OSV caveats), with exact
 * duplicates and blanks removed and the first occurrence's order kept.
 */
export function userLimitations(notes: readonly Note[], plain: readonly string[] = []): string[] {
  const sentences = CODE_ORDER.flatMap((code) => {
    const matching = notes.filter((n) => n.code === code);
    const sentence = matching.length ? sentenceFor(code, matching) : undefined;
    return sentence ? [sentence] : [];
  });
  return dedupe([...sentences, ...plain]);
}

/** Every note's diagnostic text, in order, duplicates removed. */
export function diagnosticsOf(notes: readonly Note[], extra: readonly string[] = []): string[] {
  return dedupe([...notes.map((n) => n.detail), ...extra]);
}

/** Trims, drops blanks and exact repeats, keeps the first occurrence's position. */
export function dedupe(lines: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of lines) {
    const line = raw.trim();
    if (line === "" || seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out;
}
