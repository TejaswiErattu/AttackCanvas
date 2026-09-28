# Testing

Every number here comes from one run of `pnpm test:coverage` with the JSON reporter on
2026-09-26 at commit `3cfe15e` (branch `final-sprint`). The run used Node 26.5.0, Vitest 5.0.1
and `@vitest/coverage-v8` 5.0.1, with semgrep on PATH and no `ANTHROPIC_API_KEY`. None of the
tests calls a model; the one live test is skipped without a key.

## Commands

```bash
pnpm test             # every test, no coverage
pnpm test:coverage    # the same run with v8 coverage over src/**
pnpm bench            # the seeded bench (not a Vitest run): eval/bench/report.md
```

## Totals

From `pnpm test:coverage`:

```
 Test Files  100 passed (100)
      Tests  3953 passed | 1 skipped (3954)
```

- **100 test files, 3,954 tests**: 3,953 passed and 1 skipped.
- The skipped test is in `canary.live.test.ts`. It makes paid model calls and runs only when
  `ANTHROPIC_API_KEY` is set.
- `semgrepRules.test.ts` skips itself when `semgrep` is not installed. It ran here.

## Coverage

The coverage summary for everything under `src/` is pasted as printed:

```
=============================== Coverage summary ===============================
Statements   : 96.05% ( 6669/6943 )
Branches     : 89.53% ( 4297/4799 )
Functions    : 94.83% ( 1578/1664 )
Lines        : 96.85% ( 5799/5987 )
================================================================================
```

These are the directory rows from the same report, with the covered/total counts from
`coverage/coverage-summary.json`:

| Directory | Files | Lines | Branches | Statements | Functions |
|---|---:|---:|---:|---:|---:|
| `src/server/detect` | 12 | 98.41% (1360/1382) | 91.26% (1054/1155) | 96.50% (1601/1659) | 98.34% (297/302) |
| `src/server/scoring` | 1 | 100% (20/20) | 100% (25/25) | 100% (29/29) | 100% (8/8) |
| `src/server/security` | 3 | 99.12% (225/227) | 94.57% (122/129) | 98.88% (265/268) | 100% (54/54) |
| `src/client` | 10 | 100% (495/495) | 87.06% (397/456) | 99% (593/599) | 98.70% (227/230) |
| `src/components` | 17 | 80.73% (289/358) | 69.88% (355/508) | 79.69% (306/384) | 74.38% (119/160) |
| `src/shared/confidence.ts` | 1 | 97.02% | 96.80% | 97.41% | 100% |

These are the rows as the text reporter prints them:

```
File               | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s
 client            |   98.99 |    87.06 |   98.69 |     100 |
 components        |   79.68 |    69.88 |   74.37 |   80.72 |
 server/detect     |    96.5 |    91.25 |   98.34 |    98.4 |
 server/scoring    |     100 |      100 |     100 |     100 |
 server/security   |   98.88 |    94.57 |     100 |   99.11 |
  confidence.ts    |   97.41 |     96.8 |     100 |   97.02 | 98-102
```

Notes on reading them:

- **`src/server/scoring` is one small file.** It computes severity, priority and basis, and
  re-exports the confidence functions. The confidence arithmetic itself (CLAUDE.md rule 2)
  lives in `src/shared/confidence.ts`, so that file gets its own row.
- **`src/client` holds the pure client logic only.** The React components are in
  `src/components` (79.68% statements, 69.88% branches). `ArchitectureGraph.tsx` is at 0%
  because React Flow does not render in jsdom.
- **`src/server/detect/types.ts` is types only.** It has no statements, so it shows 0/0.
- **The weakest branch coverage in the four directories** (excluding `src/components`) is
  `src/client/drift.ts` (74%), `src/server/detect/datastores.ts` (76.47%),
  `src/server/detect/sessionCookies.ts` (79.54%) and `src/server/detect/web.ts` (79.54%).

## What each test group proves

The test files are grouped by the code they protect. The counts are from the Vitest JSON
reporter for the same run.

| Group | Files | Tests | What it proves |
|---|---:|---:|---|
| Detectors | 8 | 335 | Frameworks, routes (Express mounts, App Router, Pages API, Workers), per-route auth status, datastores, env names, deployment files and session cookies are extracted from source. Output is stable across runs, and no secret or matched text reaches a fact (`detect.index.test.ts`). |
| Gap detector | 3 | 270 | Each of the 13 gap kinds fires when the control is absent and stays silent for the adversarial-review sketches (`detect.gaps.test.ts`, one `describe` per kind). A declared but inactive protection is still a gap (`detect.activeProtection.test.ts`). The gap floor applies only when the gaps assert every CWE the threat claims (`gapFloorCwe.test.ts`). |
| Seeded bench | 2 | 36 | Matching, precision and recall, false gaps, marker checks and report merging are correct (`benchLib.test.ts`). The three seeded repositories hold recall, the false-gap rate and determinism at the 2026-09-25 baseline (`bench.test.ts`). |
| Scoring and confidence | 5 | 185 | Severity bands, every confidence point in rule 2, the same-location merge, the gap floor, CVSS arithmetic and the question value formula (`scoring.test.ts`, `confidence*.test.ts`, `cvss.test.ts`, `questions.test.ts`). |
| Security, injection and redaction | 6 | 391 | Repository content reaches the model only inside `<repo_file>` tags, with the security preamble and no tool surface. The canary repository's planted injections are neutralised (`security.test.ts`). The threat engine refuses an unclean batch (`threats.boundary.test.ts`). Every redaction pattern fires, and nothing that must survive is redacted (`redactor.test.ts`). Lone surrogates are made well-formed (`unicode.test.ts`). Logs strip authorization headers and escaped secrets (`log.test.ts`). The live canary run is skipped without a key. |
| Ingest and loader | 5 | 371 | Path classification, file and byte caps, the fixture loader's symlink and root containment, the 1 MiB `package-lock.json` exemption, and GitHub URL parsing. |
| Scanners (OSV, versions) | 2 | 333 | OSV request building, package and advisory id validation, workspace dependency collection and semver range handling. |
| MCP clients and Semgrep | 9 | 256 | Tool allowlists, timeouts and response size caps for the GitHub and Semgrep MCP clients (CLAUDE.md rule 4). Saved-response parsing, a path cannot pose as a response fence, Semgrep evidence normalisation, and every rule's positive and negative cases against a real local semgrep (`semgrepRules.test.ts`). Clean shutdown on SIGTERM. |
| AI calls and prompt validation | 10 | 495 | Every model reply is Zod-validated with one retry carrying the error, and a max_tokens cutoff retries with a larger budget (rule 5). Refusals and provider errors become safe typed errors. Model profiles, prices, the usage ledger, prompt loading, and the architecture and threat request shapes are covered. |
| Analysis and assembly | 8 | 282 | Architecture reconciliation (invented components dropped, detected facts restored), assembly and OWASP year translation, context building, route-scoped citations, how developer answers confirm or clear gaps, and the limitations text. |
| Schema and shared contract | 4 | 268 | `src/shared/schema` validation, evidence metadata, the OWASP 2021→2025 map, and that the demo fixtures validate and score as documented. |
| Pipeline and API routes | 8 | 240 | The analysis pipeline's stages, deadlines and failure logging. The `/api/analyze` routes, rate limits and concurrency caps. Demo seeding. |
| Client logic (`src/client`) | 11 | 228 | The dashboard view model, diagram views, run-to-run drift, exposure, filters, finding status, graph edges and layout, the GitHub issue body cap, and the analysis state reducer. |
| UI components (jsdom) | 10 | 103 | The dashboard, threat card, question panel, analysis view and home page render and respond to input. The UI never recomputes severity, priority or confidence (`noRecompute.test.tsx`). |
| Evaluation scripts and doc checks | 9 | 161 | Label-sheet and gap-sheet CSV handling, metric formulas, the eval runner's argument parsing, stage tracking and overwrite guard, the consistency check, the try-script formatting, the NodeGoat sample, and that `docs/coverage.md` agrees with the detector and Semgrep code. |

Total: 100 files and 3,954 tests. The groups add up exactly.

## Seeded bench

`pnpm bench` is a Vitest-independent measurement; `tests/bench.test.ts` is its regression
gate. The latest result (from `eval/bench/report.md`, commit `1d3237a`):

```
| 2026-09-25 | 1d3237a | detectors | 15/1/0 | 93.8% | 100.0% | 1/17 (5.9%) | yes |
| 2026-09-25 | 1d3237a | detectors+semgrep | 18/1/0 | 94.7% | 100.0% | 1/17 (5.9%) | yes |
```

The columns are TP/FP/FN, precision, recall, false-gap rate and deterministic. Read the
report's notes before quoting the recall: the seeded apps were written with the detectors in
view.
