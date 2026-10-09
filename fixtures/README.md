# fixtures

Sample repos, scanner outputs and model responses used in tests.

- `samples/nodegoat-a3118b6.json`: the saved NodeGoat threat model from eval run
  `nodegoat-a3118b6`, validated and kept as an **offline** sample (regenerate with
  `pnpm try scripts/export-nodegoat-sample.ts`). Nothing serves it: the demo switch uses
  `demo-analysis.json`, the synthetic acme/acme-notes model, so a real repository URL never
  returns a canned result.
- `replay/OWASP__NodeGoat.json`: a copy of `samples/nodegoat-a3118b6.json` for **replay mode**.
  With `ATTACKCANVAS_REPLAY_DIR=fixtures/replay` (ignored when `NODE_ENV=production`),
  `POST /api/analyze` for `https://github.com/OWASP/NodeGoat` completes at once from this
  file, marked `replayed`, with no GitHub or model call. Any repository without a valid
  `<owner>__<repo>.json` here runs normally.
