# Reproducibility

Two analyses of the same repository will not be identical, because the model's output is not
deterministic. This page says what is fixed, what still varies, and how to measure how much.

## The short version

- Everything **except the model's own writing** is fixed by the code and the inputs: the
  detectors, the scoring arithmetic, the ordering of the result, and which repository
  snapshot is read.
- **Model sampling is not fixed, and cannot be.** Temperature is not set on any stage, and the
  models AttackCanvas calls reject it (see below). Two runs of the same prompt on the same
  input can produce different components, different threats, different titles and different
  impact and likelihood ratings.
- So expect the **same broad problems** to show up run to run, in different words and with
  some threats appearing or disappearing. Use the consistency command at the end of this page
  to measure how much on your repository, rather than assuming.

## What is fixed

| What | Where it is fixed |
|---|---|
| Prompt text and version | `prompts/architecture.v1.md`, `prompts/threats.v2.md`, `prompts/questions.v1.md`. The versions are constants (`ARCHITECTURE_PROMPT_VERSION`, `THREATS_PROMPT_VERSION`, `QUESTIONS_PROMPT_VERSION`) and every prompt is sent with the same security preamble (`src/server/security/injection.ts`). |
| Model ids | `src/server/ai/models.ts`, per profile. `demo` (what the evaluation runner uses): architecture and STRIDE on `claude-opus-5`, questions on `claude-sonnet-5`. `dev`: `claude-sonnet-5` for all three. The `remediation` and `classify` stages (Sonnet 5 and `claude-haiku-4-5-20251001`) are defined in the profiles, but no code path calls them today. |
| Repository snapshot | A URL of the form `https://github.com/<owner>/<repo>/tree/<ref>` is read at exactly that ref, and the ref is recorded in `threatModel.repo.ref`. The evaluation repos in `eval/repos.yaml` are pinned this way. **A URL with no ref reads the default branch as it is at run time**, which changes as the repository does. |
| Deterministic detection | Control gaps, routes, auth facts, deployment and datastore facts come from `src/server/detect`, which reads declarations and call patterns and never prose. The same files give the same gaps. |
| Scoring | Severity, confidence, basis and priority are pure functions in `src/server/scoring` of the model's impact and likelihood and the evidence. The same threat gives the same score. |
| Semgrep | The rules are this repository's own (`src/server/mcp/semgrepRules.ts`). The Docker image pins Semgrep `1.176.0` and the GitHub MCP server by digest. |
| Order of the result | The assembler sorts components, data flows, evidence and threats by id, byte order, before scoring and return, so the JSON does not depend on the order a stage listed things in. Assumptions and CWE, OWASP and STRIDE lists are sorted too. Threat batches are built from sorted element ids, near-duplicate threats are merged over a canonically sorted list, and threat ids are assigned last from a total order. `tests/assemble.test.ts` ("byte-identical output") assembles the same inputs twice and in shuffled order and requires identical JSON. Trust boundaries and unknowns keep their given order on purpose: the diagram draws a component in the first boundary that lists it, and unknowns are ranked. |

## What still varies

- **Model sampling.** This is the large one. It changes:
  - which components and data flows the architecture step proposes, and what it names them;
  - which threats are written, how many, and how they are titled and described;
  - the impact and likelihood the model assigns, and therefore severity and priority (the
    arithmetic from those numbers is fixed, the numbers are not);
  - which developer questions are asked.
- **Temperature is not set, and cannot be set on these models.** No temperature is sent, so
  every stage runs at the API default. The Claude 5 family (`claude-opus-5`,
  `claude-sonnet-5`) rejects `temperature`, `top_p` and `top_k` with a 400, so adding
  `temperature: 0` would make every paid call fail. `claude-haiku-4-5` does accept it, but no
  stage that runs uses it (`classify` is never called). If a model that accepts sampling controls is ever used for a stage,
  set temperature 0 there and add it to this page; it would reduce variation, not remove it.
- **Model behind the alias.** A model id such as `claude-opus-5` is served by the provider. If
  the provider updates what it serves, results can change with no change here.
- **Live data.** OSV advisories change over time, so the dependency findings for a fixed
  commit can differ between weeks. The GitHub API can also return a different file list for
  a repository with no pinned ref.
- **Timestamps and cost.** `repo.analyzedAt` is the time of the run, and token counts and
  cost differ run to run.

## Measuring run-to-run consistency

This costs money: each run is a full paid analysis. Nothing below is run automatically.

1. Add several entries to `eval/repos.yaml` with the same pinned URL and distinct names. The
   runner refuses to overwrite a result, so each repeat needs its own name:

   ```yaml
   - name: nodegoat-r1
     url: "https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8"
   - name: nodegoat-r2
     url: "https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8"
   - name: nodegoat-r3
     url: "https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8"
   ```

2. Run them, one paid analysis each (questions are answered "skipped" so the result depends
   only on the repository):

   ```bash
   pnpm try scripts/eval/run.ts nodegoat-r1 nodegoat-r2 nodegoat-r3
   ```

3. Compare the saved results. This calls no model:

   ```bash
   scripts/eval/consistency.sh eval/results/nodegoat-r1.json eval/results/nodegoat-r2.json eval/results/nodegoat-r3.json
   ```

   For every pair it prints how many threats (at 25% confidence or higher, as the dashboard
   shows) the two runs share, and the Jaccard similarity: shared threats divided by threats in
   either run, so 1.00 means the runs agree on every threat. Two measures are printed:
   - **strict** matches on title, components and OWASP categories, the same identity the
     dashboard's "Since last run" uses. Model-written titles differ between runs, so this is
     low even when two runs find the same problems.
   - **coarse** matches on components and OWASP categories only. This is the fairer measure of
     "the same problems" and the one to report.

   Report the pairs, not just an average, and say how many runs there were.

The command has been run only on saved results from different code versions, to check that it
works (a result against itself gives 1.00 on both measures). Those are not repeats of one
build, so their low overlap says nothing about run-to-run variation. No repeated-run number
has been measured yet.

## What this page does not claim

It does not claim the model is deterministic, that two runs will agree, or that a low
similarity between runs is a bug. It claims only that everything around the model is fixed and
tested, and gives a way to measure the rest.
