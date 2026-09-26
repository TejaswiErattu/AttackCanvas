/**
 * The Limitations section a reader sees, versus the diagnostics a developer keeps.
 *
 * The regression case is the one a mentor reported from a real NodeGoat run
 * (eval/baselines/nodegoat-a3118b6): the section listed each GitHub Actions workflow as
 * "represented as component ... of type external_service: the schema has no deployment
 * component type", then a detector's ambiguous match naming internal component ids, then
 * dropped-threat lines with batch numbers. Those diagnostic lines are reproduced here
 * verbatim as notes; the section must say the workflow point once, in plain words, and
 * keep the rest out.
 */

import { describe, expect, it } from "vitest";
import {
  dedupe,
  diagnosticsOf,
  note,
  userLimitations,
  type Note,
} from "@/server/analysis/limitations";

/** The saved run's limitation lines, as the merge and the engine now code them. */
const REAL_RUN_NOTES: Note[] = [
  note(
    "component_added_from_code",
    "Added component datastore-mongodb for the detected datastore mongodb; the draft did not include it.",
    "mongodb datastore",
  ),
  note(
    "deployment_modelled_as_external",
    "Deployment target compose web is represented as component deployment-compose-web of type external_service: the schema has no deployment component type, so this is the closest valid type, not a claim that it is a third-party service.",
    "the Docker Compose service web",
  ),
  note(
    "internal",
    "Detected deployment compose matched express-app, db-reset-seeder ambiguously; nothing was merged and component deployment-compose-web was added from the detector fact.",
  ),
  note(
    "deployment_modelled_as_external",
    "Deployment target github_actions e2e-test.yml:e2e-test is represented as component deployment-github-actions-e2e-test-yml-e2e-test of type external_service: the schema has no deployment component type, so this is the closest valid type, not a claim that it is a third-party service.",
    "the GitHub Actions workflow e2e-test.yml",
  ),
  note(
    "internal",
    "Detected deployment github_actions matched github-actions-ci ambiguously; nothing was merged and component deployment-github-actions-e2e-test-yml-e2e-test was added from the detector fact.",
  ),
  note(
    "deployment_modelled_as_external",
    "Deployment target github_actions lint.yml:lint is represented as component deployment-github-actions-lint-yml-lint of type external_service: the schema has no deployment component type, so this is the closest valid type, not a claim that it is a third-party service.",
    "the GitHub Actions workflow lint.yml",
  ),
  note(
    "internal",
    "Detected deployment github_actions matched github-actions-ci ambiguously; nothing was merged and component deployment-github-actions-lint-yml-lint was added from the detector fact.",
  ),
  note("internal", "1 lower-ranked unknown(s) were dropped to keep the cap of 12."),
  note(
    "threat_discarded",
    'Dropped threat "Credential stuffing and account enumeration against POST /login and POST /signup" from batch 7: dependsOnUnknownIds offered only to another element of the batch: unknown-security-logging.',
  ),
  note(
    "threat_discarded",
    'Dropped threat "End user actions cannot be attributed because authenticated requests are not lo…" from batch 7: dependsOnUnknownIds offered only to another element of the batch: unknown-security-logging.',
  ),
];

const OSV_LINE =
  "1 dependency was not checked against OSV because no version could be determined (a workspace, git or file specifier, or a range with no lower bound).";

/** Words and shapes that belong to the pipeline, not to a reader. */
const INTERNAL =
  /external_service|schema|component id|deployment-[a-z0-9-]+|datastore-[a-z0-9-]+|github-actions-ci|express-app|ambiguous|detector fact|batch \d|dependsOnUnknownIds|unknown-[a-z-]+|evidenceRefs|draft/i;

describe("userLimitations: the reported NodeGoat section", () => {
  const section = userLimitations(REAL_RUN_NOTES, [OSV_LINE, OSV_LINE]);

  it("says the CI and deployment point once, naming the workflows in plain words", () => {
    const deployment = section.filter((line) => /GitHub Actions/.test(line));
    expect(deployment).toHaveLength(1);
    expect(deployment[0]).toBe(
      "The diagram shows the Docker Compose service web, the GitHub Actions workflow e2e-test.yml and the GitHub Actions workflow lint.yml as external systems because it has no separate type for build and deployment tooling. Read these as part of your own release pipeline, not as third-party services; threats against them concern how code is built and shipped.",
    );
  });

  it("keeps schema fallbacks, detector routing and component ids out of every line", () => {
    for (const line of section) expect(line).not.toMatch(INTERNAL);
  });

  it("keeps the meaningful uncertainty, as counts, and passes plain caveats through once", () => {
    expect(section).toEqual([
      expect.stringContaining("GitHub Actions workflow lint.yml"),
      "The mongodb datastore was added from what the code shows because the inferred architecture left it out, so its connections to other components may be incomplete.",
      "2 candidate threats were discarded because they could not be checked against the evidence the analysis had, so the list may be missing a real threat.",
      OSV_LINE,
    ]);
  });

  it("is much shorter than the diagnostics, which keep every original line", () => {
    const diagnostics = diagnosticsOf(REAL_RUN_NOTES);
    expect(diagnostics).toHaveLength(REAL_RUN_NOTES.length);
    expect(diagnostics.some((l) => l.includes("of type external_service"))).toBe(true);
    expect(section.length).toBeLessThan(diagnostics.length / 2);
  });
});

describe("userLimitations: grouping and wording", () => {
  it("produces nothing for internal notes alone", () => {
    expect(userLimitations([note("internal", "x"), note("internal", "y")])).toEqual([]);
  });

  it("counts unnamed notes and uses the singular for one", () => {
    const one = userLimitations([note("architecture_item_dropped", "Dropped data flow a-b: ...")]);
    expect(one).toEqual([
      "1 part of the inferred architecture could not be tied to the analysed code and was left out, so the diagram may be missing a component or a data flow.",
    ]);
    const three = userLimitations(
      ["a", "b", "c"].map((id) => note("gap_bound_broadly", `Gap ${id} ... fallback binding used`)),
    );
    expect(three[0]).toMatch(/^3 possible missing controls could not be tied to a single component/);
  });

  it("names a long list of subjects by its first four and a count", () => {
    const notes = ["a", "b", "c", "d", "e", "f"].map((n) =>
      note("deployment_modelled_as_external", `d ${n}`, `the GitHub Actions workflow ${n}.yml`),
    );
    expect(userLimitations(notes)[0]).toMatch(/d\.yml and 2 more as external systems/);
  });

  it("is independent of note order", () => {
    const reversed = [...REAL_RUN_NOTES].reverse();
    expect(userLimitations(reversed).map((l) => l.replace(/the .*? as external/, "X"))).toEqual(
      userLimitations(REAL_RUN_NOTES).map((l) => l.replace(/the .*? as external/, "X")),
    );
  });
});

describe("dedupe", () => {
  it("trims, drops blanks and repeats, and keeps first positions", () => {
    expect(dedupe([" a ", "b", "", "a", "c", "b"])).toEqual(["a", "b", "c"]);
  });
});
