# server/ai

Claude API client, prompt assembly and Zod-validated model responses (retry once, then typed error).

| File         | What it holds                                                          |
| ------------ | ---------------------------------------------------------------------- |
| `models.ts`  | Stage → model map (`dev` / `demo`), list prices, `ATTACKCANVAS_MODEL_PROFILE` |
| `prompts.ts` | `loadPrompt(name, version)` → `prompts/<name>.v<N>.md` plus its id      |
| `usage.ts`   | Estimated cost per call and the per-analysis ledger                    |
| `claude.ts`  | `callStructured` — the single entry point every AI stage calls          |

`callStructured` constrains the reply with `output_config.format` (native structured
output, available since @anthropic-ai/sdk 0.126.0), validates it with Zod, retries once
with the validation errors quoted back, then throws `AiError`. Backs off on 429/529/5xx
across three attempts and abandons the call after 120 s.

The cost figure is an estimate from list price, not a billing record. Cache reads are
priced at 0.1× the input rate and cache writes at 1.25×, so the saving caching produces
is visible rather than folded into the input line.

`AiStage` here is the set of model call sites and is deliberately **not** the schema's
`AnalysisStage`, which describes progress shown to the user.

## Environment

| Variable                 | Required | Effect                                                                 |
| ------------------------ | -------- | ---------------------------------------------------------------------- |
| `ANTHROPIC_API_KEY`      | yes      | Read by the SDK                                                        |
| `ATTACKCANVAS_MODEL_PROFILE` | no     | `dev` (default) or `demo`                                              |
| `ANTHROPIC_WORKSPACE_ID` | no       | Sent as the `anthropic-workspace-id` header on every request           |

`ANTHROPIC_WORKSPACE_ID` is for organization-level API keys, which are not scoped to a
workspace and are rejected with an HTTP 400 unless the header names one. Leave it unset
for a workspace-scoped key: nothing is sent and behaviour is unchanged. Put it in the
gitignored `.env.local`, never in a tracked file. The value must be letters, digits, `_`
and `-`; anything else throws, and the error never contains the value.

Smoke test against the real API (needs `ANTHROPIC_API_KEY`, costs a fraction of a cent):

```
pnpm try scripts/try-claude.ts
```
