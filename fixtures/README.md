# fixtures

Sample repos, scanner outputs and model responses used in tests.

- `samples/nodegoat-a3118b6.json`: the saved NodeGoat threat model from eval run
  `nodegoat-a3118b6`, validated and kept as an **offline** sample (regenerate with
  `pnpm try scripts/export-nodegoat-sample.ts`). Nothing serves it: the demo switch uses
  `demo-analysis.json`, the synthetic acme/acme-notes model, so a real repository URL never
  returns a canned result.
