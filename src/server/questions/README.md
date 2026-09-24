# server/questions

Selects 0-3 developer questions and applies answers to confidence.

`engine.ts` holds the pure logic (no model, no I/O); `index.ts` is the orchestrator
that wraps it with the `callStructured` call to Prompt M (`prompts/questions.v1.md`)
and re-exports everything from `engine.ts` so callers only ever import from
`@/server/questions`.

## Selection pipeline (`selectCandidates` in engine.ts)

For each unknown, in order:

1. **Link it to threats** (`linkUnknowns`): a threat counts if it names the unknown in
   `dependsOnUnknownIds` (`dependentThreatIds`), OR if it shares a component with the
   unknown's `affectsComponentIds` (folded into the wider `affectedThreatIds`). Only
   `dependentThreatIds` is what an applied answer is allowed to re-score
   (`QuestionEffects.appliesToThreatIds`) -- a component-only link makes the unknown
   worth asking about without letting its answer touch an unrelated threat that merely
   shares a component.
2. **Drop it if it affects no threats** (`no_affected_threats`).
3. **Drop it if the repository's own facts already answer it** (`answered_by_facts`,
   `answeredByFacts`): today this is narrow and conservative -- an exposure-worded
   unknown whose every affected component maps by name to a Compose service with no
   published host port.
4. **Score it**: `value = maxSeverityWeight * uncertainty * log2(1 + affectedCount)`,
   weights critical 4 / high 3 / medium 2 / low 1, `uncertainty = 1 - mean(confidence)`
   over the affected threats. Raw, NOT clamped to 0..1 -- `toStoredValueScore` fits it
   into the frozen `DeveloperQuestion.valueScore` field only when a question is
   actually returned. Drop it if raw value < `MIN_VALUE` (1.5) (`below_threshold`).
5. **Keep the top `MAX_QUESTIONS` (3)** by raw value, ties broken by unknown id;
   anything past the cap is `over_cap`.

Every drop -- including a post-model one (`no_usable_draft`, `no_cautious_default`) --
is recorded in `SelectQuestionsResult.skippedReasons`, for debugging and for this
README rather than surfaced to the developer.

## What Prompt M is and isn't allowed to decide

Prompt M (`prompts/questions.v1.md`) only words the survivors: `text`, `whyAsking`,
`options`, `allowsUnsure`, `defaultAssumption`, and one `optionMeaning` per option
(`control_absent` / `control_present` / `partial` / `not_applicable`). Everything an
option DOES to a threat -- `likelihoodDelta`, `impactDelta`, `certaintyResolution` --
is looked up from the fixed `MEANING_EFFECT` table in code (CLAUDE.md rule 2); the
model never returns a number.

## Applying answers

`src/server/analysis/answers.ts` is the other half: given the developer's actual
answers, it looks up each question's `QuestionEffects`, applies the chosen option's
(or, on skip/unsure, the precomputed cautious default's) deltas to
`effect.appliesToThreatIds` only, and re-scores with `src/server/scoring`.

`src/server/questions/answers.ts` is a text-answer front door to that same code:
`applyAnswers(state, [{ questionId, answer }])` takes the developer's raw reply (an
option's text, or `"skip"` / `"unsure"`), maps it to an option index, delegates to
`analysis/answers.ts`, and re-validates the whole model. Only the explicit `"skip"` / `"unsure"`
take the cautious default. An unknown question id, an option worded "skip" /
"unsure", or an answer matching no option or several throws `AnswerValidationError`;
`analysis/answers.ts` itself is unchanged for its other callers.
