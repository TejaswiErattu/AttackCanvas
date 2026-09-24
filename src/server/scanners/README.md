# server/scanners

Semgrep (MCP) and OSV integrations that produce normalized findings as `Evidence`.

## `semgrep.ts`

`normalizeSemgrep(raw: RawSemgrepFinding[])` → evidence of kind `scanner`, source `semgrep`, with `ruleId`,
`filePath`, `lineStart`/`lineEnd`, a one-line summary and a **redacted** snippet (both the snippet and the
message are redacted: Semgrep interpolates matched source into messages). Sorted by file and line, so ids
(`ev-semgrep-N`) are stable, and de-duplicated by `ruleId + path + startLine`.

OWASP 2021 tags are mapped to 2025 by the table in `src/shared/owaspMap.ts` and stored in the schema's typed
`metadata.owasp2025`, so they survive `EvidenceSchema.parse()`. `metadata` is omitted when a rule has no OWASP
tag. The result is plain `Evidence`; the rule's CWE list, its 2021 tags and Semgrep's severity are not carried.

## `osv.ts`

`scanDependencies(files, deps?)` → `{ evidence, limitations }`. Reads `package.json` and, if present,
`package-lock.json` (lockfileVersion 2/3 `packages` map) for exact versions; otherwise takes the minimum of
the semver range and marks `versionExact: false` (the summary says "inferred from range").

Queries `api.osv.dev` (`/v1/querybatch` in chunks of 500, then `/v1/vulns/{id}` five at a time, cached by id).
Evidence is kind `dependency`, source `osv`, capped at 40, highest severity first. **Only package names and
versions leave the machine.** If OSV is down or slow (10 s per request) it returns no evidence and a
limitation message; it never throws.

Supporting modules: `versions.ts` (semver compare and range minimum, since there is no `semver` dependency)
and `cvss.ts` (CVSS v3 base score, used only to order findings; AttackCanvas severity is computed in scoring).

## Evidence metadata

`EvidenceSchema.metadata` is a closed, typed object with two independent groups. Either, both or neither may
be present, and any key not listed is **stripped** by `parse()` (not rejected).

| Group | Fields | Set by |
| --- | --- | --- |
| OWASP | `owasp2025` | Semgrep |
| Dependency (complete) | `package`, `version`, `versionExact`, `dev`, `vulnId`, `cve`, `aliases` | OSV, always |
| Dependency (optional) | `severityScore`, `severityLabel`, `fixedVersion` | OSV, when known |

All ten OSV fields the scanner emits survive `parse()` unchanged. **Coherence:** once any OSV field is present,
all seven required ones must be, so an OSV fragment cannot be stored without saying which dependency and which
advisory it describes. `severityScore` is finite and non-negative, `severityLabel` is `LOW | MEDIUM | HIGH |
CRITICAL`.

`fixedVersion` is the **first applicable fixed version**: the first fix of the affected range that contains
the installed version, not the first fix listed in the record.

## Lockfiles over 200 KB

`package-lock.json` is exempt from the loader's 200 KB per-file limit, up to **1 MiB** (`MAX_LOCKFILE_BYTES`).
That is the GitHub client's own response cap, above which a file cannot be retrieved at all, so 1 MiB is a
hard ceiling, not a tunable one. Every other file, including the other lockfiles, keeps the 200 KB limit, and
the loader's 2 MiB total budget is unchanged.

A lockfile that is over the cap, refused by the client, or dropped for budget is skipped without failing the
analysis, and the scanner falls back to each range's lowest version with `versionExact: false` and a
limitation message saying so.
