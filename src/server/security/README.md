# server/security

Untrusted-content handling: redaction, `<repo_file>` wrapping, safe logging.

## `injection.ts`

Indirect prompt-injection defenses. The threat model for all of this is
`docs/security-design.md`.

`SECURITY_PREAMBLE` is the block `loadPrompt` puts in front of every system prompt. It
declares repository content *and* the derived facts untrusted, and says an instruction
found in them is itself reportable. It is prepended at load time rather than pasted into
each prompt file so a prompt added later cannot miss it.

`injectionFindings(content)` → `{ rule, line }[]`. Six phrase rules — `ignore_instructions`,
`role_override`, `output_directive`, `suppress_finding`, `wrapper_forgery`, `tool_address`
— matched over the whole text, because prose wraps and a line-at-a-time scan misses a
sentence split across three lines. Phrases, never single words: "injection" and "ignore"
are ordinary in honest security documentation.

`injectionEvidence(files)` → `Evidence[]` of kind `code`, ids `ev-injection-1…`, one per
matching line, summary the fixed string `"Possible prompt-injection text in repository"`
and **no snippet** — the same discipline as `toEvidence` in `redactor.ts`, for the same
reason: the matched text is untrusted and may itself carry a credential.

`checkModelOutput(...)` → `OutputIssue[]`, never throws. Three codes: `unknown_file` for
evidence citing a file that was never loaded, `injection_echo` for a threat *title*
repeating an injected phrase (any of the six rules, or "ignore previous findings", which is
checked in titles only), and `empty_while_exposed` for an empty threat list while a
proven `authn_missing` gap exists. The echo check reads the title only, on purpose:
`prompts/threats.v1.md` asks the model to describe an injection attempt in
`attackScenario`, so a scenario quoting the phrase is correct behaviour.

### Notes

- **Nothing here removes a finding.** Detection stays deterministic: a control gap is
  produced by `src/server/detect/gaps.ts` from declarations and call patterns, never prose,
  so a README claiming the API gateway handles authentication cannot suppress it.
- **Where the evidence is composed.** `injectionEvidence` is not called by `runDetectors`.
  The caller folds it into `detector.evidence` before `buildRepoFacts`, which is all it
  takes to reach `mergeEvidence` and the assembler. In production that caller is
  `runAnalysis` in `src/server/analysis/pipeline.ts` (the scanning stage), which also runs
  `checkModelOutput` after assembly: `unknown_file` and `empty_while_exposed` fail the run
  with `OUTPUT_REJECTED`, `injection_echo` stays an advisory limitation. The tests and the
  live canary compose it the same way.

## `redactor.ts`

`redact(content, path)` → `{ content, findings: [{ type, line }] }`. Pure and synchronous.
Replaces every credential with `[REDACTED:<type>]`, keeping the variable name and, for connection
strings, the scheme and host: `const JWT_SECRET = "[REDACTED:generic_secret]"`.

Types: `aws_access_key`, `github_token`, `stripe_key`, `anthropic_key`, `openai_key`, `slack_token`,
`google_api_key`, `private_key`, `jwt`, `connection_string`, `generic_secret`, `high_entropy`.

`path` is used only for path-aware exclusions; lockfiles are mostly hashes, not secrets.
Findings never carry the value, only the type and the line (CLAUDE.md rule 8).

`assertNoSecrets(text, path?)` throws `SecretLeakError` if anything still matches. Call it before
every model call and every log line. `redact()` output always passes it.

`toEvidence(path, findings)` → `Evidence[]` of kind `code`, source `detector`, with `filePath` and
`lineStart` and deliberately **no snippet**: the snippet would be the credential.

### Notes

- **Overlaps merge, never drop.** Two matches that overlap become one span covering the union, named
  by the higher-priority rule, so redaction can only ever remove more than one rule asked for.
- **Ordering matters.** `anthropic_key` precedes `openai_key` (`sk-ant-…` also fits the OpenAI shape);
  `private_key` leads so a base64 body inside a key block is never mislabelled.
- **Idempotent.** Matches lying wholly inside an existing `[REDACTED:…]` marker are skipped.
- **Linear in file size.** Every rule is checked against 200 KB of pathological input in the tests.

### Credential keys and values

A value is redacted when a credential key assigns it: `password`, `passwd`, `pwd`, `secret`, `token`,
`api_key`/`apiKey`, `private_key`/`privateKey`, `client_secret`/`clientSecret`, matched case-insensitively
anywhere in the key (so `DB_PASSWORD`, `jwtSecret` and `JWT_SECRET` all count).

Covered forms: `KEY: "v"`, `key = 'v'`, ``key=`v` ``, `"quoted_key": "v"`, `obj.key = "v"`,
`const key: string = "v"` and `process.env.X || "v"` (the reference is kept, the fallback literal is not).

**Length.** A value with no whitespace is redacted at any length: a real password can be six characters, and
an eight-character floor let one through to a model. A value containing whitespace still needs
`MIN_SECRET_LENGTH`, which keeps `{"passwordResetExpiry": "1 hour"}` intact.

**Environment references are kept**: `${VAR}`, `$VAR`, `%VAR%`, `process.env.VAR`, `import.meta.env.VAR`
name where a secret comes from and hold none. `${VAR:-default}` and `prefix${VAR}` carry literals and are
not references.

Prose is untouched: a rule needs a key, an assignment and a quoted value, so "the token expires after an
hour" is left alone.
