# prompts

Prompt templates sent to the Claude API.

Named `<name>.v<N>.md` and loaded by `loadPrompt` (`src/server/ai/prompts.ts`), which
returns the id `<name>.v<N>` so a result can record which prompt produced it. Edit a
prompt in place while iterating; bump the version when an old output must stay
reproducible.

`loadPrompt` puts `SECURITY_PREAMBLE` (`src/server/security/injection.ts`) in front of
every file it reads, so no prompt here needs to repeat that repository content is
untrusted, and a prompt added later cannot forget to. The file's own text is
`prompt.body`; what goes on the wire is `prompt.text`. Each prompt still says what to *do*
about an injection attempt in its own stage's vocabulary — the architecture prompt records
an unknown, the threats prompt emits a threat.

| File                  | Used by                                                          |
| --------------------- | ---------------------------------------------------------------- |
| `architecture.v1.md`  | `inferArchitecture` (`src/server/analysis/architecture.ts`)       |
| `threats.v2.md`       | the threat engine, over batches from `src/server/analysis/threatPrompt.ts` |
| `threats.v1.md`       | earlier threat prompt, kept so results recorded as `threats.v1` stay reproducible |
