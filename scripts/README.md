# scripts

Dev scripts run with pnpm try (tsx).

`try-architecture.ts` makes one **paid** model call. It loads a repository, runs the
detectors, builds the context and asks for an architecture draft, then prints the
components, flows, boundaries and unknowns plus the cost. Needs `ANTHROPIC_API_KEY`,
`GITHUB_PERSONAL_ACCESS_TOKEN` and Docker.

```
pnpm try scripts/try-architecture.ts <owner>/<repo>
```

Read the "possible gap duplicates" line: it should be empty. An unknown restating a gap
the detector already proved means the prompt is asking the developer something the
tools have already answered.

`try-threats.ts` runs the threat engine (Prompt P2). It reuses the saved architecture draft in
`.debug/<repo>/architecture.draft.json` when one exists (`--fresh` makes the N1 call too), then makes one **paid**
call per batch of at most four elements, and prints each threat as confirmed, gap-only or assumption-only with its
citations, plus the drops, the pass-2 rate and the cost. It refuses more than six batches without `--allow-large`.

```
pnpm try scripts/try-threats.ts <owner>/<repo>
```

`verify-threat-payloads.ts` renders every threat batch for a repository **locally, with no model call**, and
reports whether any credential-shaped literal from the sample config files survives into a model-bound
payload. It prints counts, field names and file/line locations only, never a value.

```
pnpm try scripts/verify-threat-payloads.ts <owner>/<repo>
```

It exits 2 if any sentinel is found, so it can gate a change to the redactor or the payload builder.

`try-pipeline.ts` runs the whole orchestrator (Prompt V): load, scan, architecture,
threats, questions, and (answering every question "skipped") finalize. **Paid** -- makes
several model calls -- and needs `ANTHROPIC_API_KEY`, `GITHUB_PERSONAL_ACCESS_TOKEN` and
Docker, plus the semgrep CLI on `PATH` (a missing Semgrep degrades the run rather than
failing it). Prints every stage transition and a final summary: threat count, basis
counts, gaps, limitations and cost.

```
pnpm try scripts/try-pipeline.ts <owner>/<repo>
pnpm try scripts/try-pipeline.ts <owner>/<repo> --timeout 600000   # override the 10-minute budget
```

## Working without paying

Three development-only switches, all ignored when `NODE_ENV=production`. Each one reads
from or writes to local files; keep those under `.cache/`, which is gitignored.

**Replay mode** (`ATTACKCANVAS_REPLAY_DIR`). `POST /api/analyze` looks for
`<dir>/<owner>__<repo>.json` before touching GitHub or a model. A file that validates as a
ThreatModel completes the job at once, marked `replayed: true`; anything else runs
normally. Production ignores the variable and logs one warning.

```
ATTACKCANVAS_REPLAY_DIR=fixtures/replay pnpm dev   # then analyze https://github.com/OWASP/NodeGoat
```

**Model cache** (`ATTACKCANVAS_MODEL_CACHE=1`). `callStructured` hashes the model id,
system text, messages and output schema and serves a repeat from
`.cache/model/<hash>.json`, recording a zero-token ledger entry marked `cached`. A miss
pays once and saves the validated response; a reply that failed validation is never saved.
Delete `.cache/model/` to force fresh calls.

**Stage checkpoints** (`ATTACKCANVAS_CHECKPOINT_DIR`). A run writes
`<dir>/<owner>__<repo>/{load,detect,scanners}.json` after loading, detection and the
scanners. These hold **raw repository content**, so point the variable inside `.cache/`.
`replay-stage.ts` then re-runs only the architecture and threat stages from the scanners
checkpoint, with no GitHub, Docker or Semgrep, and honours the model cache:

```
ATTACKCANVAS_CHECKPOINT_DIR=.cache/checkpoints pnpm try scripts/try-pipeline.ts OWASP/NodeGoat   # paid once, writes checkpoints
ATTACKCANVAS_CHECKPOINT_DIR=.cache/checkpoints ATTACKCANVAS_MODEL_CACHE=1 pnpm try scripts/replay-stage.ts OWASP/NodeGoat --from scanners [--level 0-4]
```

Only `--from scanners` is supported. Without the model cache, or after a prompt change,
the replay makes paid architecture and threat calls; the cost lines say which calls
came from the cache.

## Evaluation runner (`scripts/eval/`)

Measures the pipeline against hand labels. No model ever labels anything. Repos are listed
in `eval/repos.yaml` (fill in the URLs first).

```
pnpm try scripts/eval/run.ts [repo...] [--timeout <ms>]   # PAID. Demo profile, questions skipped -> eval/results/<repo>.json
pnpm try scripts/eval/label.ts [repo...]   # -> eval/labels/<repo>.csv, one row per threat (never overwrites; --force to)
# fill matchesExpected, supported (y/n), evidenceCorrect (e.g. 2/3), notes; write eval/expected/<repo>.yaml
pnpm try scripts/eval/score.ts [repo...]   # -> docs/evaluation.md
```

`--timeout` overrides the pipeline's 10-minute budget (per phase: the analysis, then a fresh
one after answers). It limits time, not spend: a call in flight at the deadline is still
billed. `run.ts` refuses to start if a selected repo already has a result file, before any
network work; to run again, add a new repo name (e.g. `nodegoat-after-fix`). A failed repo
writes nothing and prints the stage it failed during, the pipeline's recorded call count
and cost at the moment of failure, elapsed time and the safe error.

`evidenceCorrect` is correct/total over the entries in `evidenceLocations` (write `0/0` for
none). `matchesExpected` lists expected ids separated by `;`; blank means the threat matches
none. `score.ts` refuses a half-labeled sheet and lists every problem.
