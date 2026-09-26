# Cost per analysis

The level picker shows "about $X to $Y for a small repository" next to each level. Those
numbers come from `LEVEL_COST_RANGES` in `src/shared/levelCost.ts`. This page shows where
they come from. What each level does is in `LEVEL_PLANS` (`src/server/ai/levels.ts`).

All figures are Claude API usage at list price (`PRICES` in `src/server/ai/models.ts`),
with the cache discounts applied. The invoice is the real number.

## Measured: six NodeGoat runs

OWASP NodeGoat at `c5cb68a`, demo profile, level 2. The source is the `cost` block in each
`eval/results/*.json`.

| Run | Date (UTC) | Calls | Cost (USD) |
|---|---|---:|---:|
| `nodegoat` | 2026-09-25 03:33 | 18 | 2.84 |
| `nodegoat-after-fix` | 2026-09-25 04:13 | 23 | 3.19 |
| `nodegoat-7f7211d` | 2026-09-25 18:59 | 24 | 3.56 |
| `nodegoat-7a0fb27` | 2026-09-25 19:40 | 19 | 3.38 |
| `nodegoat-f64cfa8` | 2026-09-25 20:55 | 18 | 3.16 |
| `nodegoat-a3118b6` | 2026-09-25 21:40 | 25 | 4.07 |

Range $2.84 to $4.07, mean $3.37. Calls vary with the number of STRIDE batches and with
retries.

## By level

| Level | Models (demo) | What changes | Shown range | Measured | Estimated |
|---|---|---|---|---|---|
| 0 Snapshot | Sonnet 5 | context 20,000, at most 3 STRIDE batches, no questions | $0.30 to $0.60 | *(Prompt I)* | $0.30 to $0.60 |
| 1 Basic | Sonnet 5, Haiku on classify | same budgets as level 2 | $1 to $1.50 | *(Prompt I)* | $1.10 to $1.60 |
| 2 Standard | Opus 5 on architecture and STRIDE | today's demo profile | $3 to $4 | $2.84 to $4.07 | — |
| 3 Deep | as level 2 | architecture context 90,000 | $3.50 to $5 | — | $3.20 to $4.60 |
| 4 Exhaustive | as level 2 | level 3 plus adaptive thinking on STRIDE, output budget 16,000 | $4 to $6 | — | $3.50 to $5.90 |

With `ATTACKCANVAS_MODEL_PROFILE=dev` (or unset) every level runs on the dev models, so
levels 2 to 4 cost about the same as level 1.

## Differences from the playbook

- **Dev profile keeps Haiku on classify.** The playbook says `dev` puts Sonnet on
  every stage. This sprint keeps the existing dev default instead (`MODELS.dev`: Sonnet
  on architecture, STRIDE, questions and remediation, Haiku on classify), so a dev run
  at any level is the same as a dev run before levels existed.
- **Level 4 uses adaptive thinking, not a 4,000-token thinking budget.** The playbook
  asks for extended thinking with a budget of 4,000. `claude-opus-5` and
  `claude-sonnet-5` reject `thinking: {type: "enabled", budget_tokens}` with HTTP 400.
  Level 4 therefore sends `thinking: {type: "adaptive"}`, and the model decides how much
  to think. `EXHAUSTIVE_THINKING_BUDGET` (4,000) is only extra room added to the STRIDE
  output budget, from 12,000 to 16,000. It is not a limit on thinking, and level 4's
  cost is an estimate, not a measurement.
- **Remediation and classify stay profile-routed.** No code calls either stage today.
  If one is added, `callStructured` falls back to `modelFor(stage)`, which is Sonnet for
  remediation and Haiku for classify under both profiles. That is also what every level
  plan names, and `tests/ai.levels.test.ts` checks that they agree. A new call site
  should still pass `plan.models.<stage>`.

## How the estimates were made

The starting point is level 2's measured range. Each level is scaled from it using list
prices.

- **Model swap (levels 0, 1).** Architecture and STRIDE make up nearly all of the spend,
  and both move from Opus 5 ($5 / $25 per million tokens) to Sonnet 5 ($2 / $10). That is
  0.4 times the price for the same tokens: $2.84 to $4.07 becomes $1.14 to $1.63. Questions
  already run on Sonnet at level 2, so they do not change.
- **Level 0.** The architecture input drops to a third (20,000 of 60,000 context tokens).
  STRIDE runs 3 batches instead of every batch. NodeGoat needs about 7 to 12, so this is
  roughly a quarter to two fifths of STRIDE. No question call. Applied to level 1's range,
  the result is about $0.30 to $0.60.
- **Level 3.** Only the architecture call's input grows, to 1.5 times. That call is about
  a fifth of a level-2 run. Its input is cheap next to STRIDE's output, and the prompt
  cache discounts repeat reads, so the run costs about 5 to 15% more. Result: $3.20 to $4.60.
- **Level 4.** Level 3 plus up to 4,000 extra STRIDE output tokens per batch for thinking.
  At Opus 5's $25 per million, that is at most $0.10 per batch. Over 7 to 12 batches it
  adds $0.30 to $1.30. Result: $3.50 to $5.90. This assumes adaptive thinking uses all
  of the extra room. It has not been measured.
- **Shown ranges** are rounded outward to amounts that read easily.

"Small repository" means NodeGoat-sized: a few dozen source files and about ten
architecture components. A larger repository has more components, so it needs more
STRIDE batches and costs more at every level. Level 0's cap is the exception: it still
runs only 3 batches.

Replace the estimates once Prompt I measures levels 0 and 1 (and 3 and 4, if they are run).
