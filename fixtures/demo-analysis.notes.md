# demo-analysis.json: scoring notes

`demo-analysis.json` is a fictional analysis of the invented app **acme-notes**. Nothing in it
comes from a real repository. This file shows how `impact x likelihood`, `severity`,
`confidence`, `confidenceLabel`, `basis` and `priority` were computed for each of the 9
threats, using the `CLAUDE.md` scoring rules (rule 2) as the playbook's Prompt O defines them.

`tests/fixtures.test.ts` recomputes all of this independently and fails if the fixture
disagrees, so the numbers below are checked, not just asserted.

## The rules

```
risk       = impact x likelihood
severity   : 20-25 Critical | 12-19 High | 6-11 Medium | 1-5 Low

confidence, in points (sum, clamp to 0..1, round to 2 decimals):
  code             +0.35   once, if any cited item has kind "code"
                           ("config" earns nothing here)
  semgrep          +0.25   once, if any cited item has kind "scanner" from source "semgrep"
  osv              +0.30   once, if any cited item has kind "dependency" from source "osv"
  developer answer +0.30   once, if any cited item has kind "developer_answer"
  second source    +0.10   once, if the cited direct evidence comes from 2+ distinct
                           EvidenceSource values (never applied more than once)
  inference only   +0.20   only if an "inference" item is cited and no "code", "scanner",
                           "dependency" or "developer_answer" item is
  assumption       -0.15   once, if the threat lists one or more assumptions
                           (never once per assumption)
label      : High >= 0.70 | Medium 0.40-0.69 | Low < 0.40      (hide below 0.25)

basis      : evidence_backed       if any cited item is neither "inference" nor "assumption"
             assumption_dependent  if every cited item is inference or assumption, or none is cited
             (listing an assumption does NOT change basis)

Fix Now    : Critical, or High with confidence >= 0.50
Fix Soon   : High with confidence < 0.50, or Medium with confidence >= 0.50
Monitor    : everything else
```

Two readings worth knowing:

- **"Direct" evidence** means any cited item whose kind is not `inference` or `assumption`,
  so `code`, `config`, `scanner`, `dependency` and `developer_answer`. The second-source
  bonus counts the distinct `source` values of direct evidence, so a `config` item from
  `detector` counts as a source even though it earns no code points. `ai`-sourced evidence
  (inference, assumption) never corroborates anything.
- **The inference-only bonus follows the wording exactly.** `config` and `assumption` are not
  on its exclusion list, so inference plus config would still get +0.20. No demo threat
  combines them; a unit test pins the behaviour.

## Arithmetic per threat

Each block lists the cited evidence as `id (kind / source)`.

```
1. admin-routes-missing-authz
   cites        admin-routes-no-role-check (code / detector)
                admin-authz-semgrep        (scanner / semgrep)
                admin-mounted-publicly     (code / detector)
                admin-cors-open            (scanner / semgrep)
   risk         5 x 4 = 20                                   -> Critical
   code         +0.35   (two code items, counted once)
   semgrep      +0.25   (two Semgrep scanner items, counted once)
   osv          0       developer 0       inference-only 0 (direct evidence present)
   second src   +0.10   sources {detector, semgrep}: 2 distinct
   assumptions  none, no penalty
   confidence   0.35 + 0.25 + 0.10 = 0.70                    -> High (exactly on the boundary)
   basis        cites code and scanner evidence              -> evidence_backed
   priority     Critical                                     -> Fix Now
   dashboard    visible

2. jwt-hardcoded-secret
   cites        jwt-hardcoded-fallback-secret (code / detector)
                jwt-hardcoded-secret-semgrep  (scanner / semgrep)
                jsonwebtoken-advisory         (dependency / osv)
   risk         5 x 3 = 15                                   -> High
   code         +0.35
   semgrep      +0.25
   osv          +0.30
   second src   +0.10   sources {detector, semgrep, osv}: 3 distinct, bonus still once
   assumptions  none, no penalty
   confidence   0.35 + 0.25 + 0.30 + 0.10 = 1.00             -> High (no clamp needed)
   basis        cites code, scanner and dependency evidence  -> evidence_backed
   priority     High and 1.00 >= 0.50                        -> Fix Now
   dashboard    visible

3. stripe-webhook-unverified
   cites        stripe-webhook-unverified (code / detector)
   risk         4 x 3 = 12                                   -> High
   code         +0.35
   second src   none    sources {detector}: only 1 distinct
   assumptions  none, no penalty
   confidence   0.35                                         -> Low
   basis        cites code evidence                          -> evidence_backed
   priority     High and 0.35 < 0.50                         -> Fix Soon
   dashboard    visible

4. s3-attachments-public-read
   cites        s3-no-public-access-block (config / detector)
                s3-policy-not-in-repo     (assumption / ai)
   risk         3 x 3 = 9                                    -> Medium
   code         0       the only repository item is "config", which earns no code points
   semgrep 0, osv 0, developer 0
   inference    0       no inference item is cited
   second src   none    direct sources {detector}: only 1 distinct (the assumption item is ai)
   assumptions  1 listed                                     -> -0.15
   confidence   0 - 0.15 = -0.15, clamped to 0.00            -> Low
   basis        the config item is direct evidence           -> evidence_backed
                (it lists an assumption, but that does not change basis)
   priority     Medium and 0.00 < 0.50                       -> Monitor
   dashboard    HIDDEN (0.00 < 0.25)

5. sql-injection-note-search
   cites        search-sql-concatenation (code / detector)
                search-sql-semgrep       (scanner / semgrep)
   risk         4 x 4 = 16                                   -> High
   code         +0.35
   semgrep      +0.25
   second src   +0.10   sources {detector, semgrep}: 2 distinct
   assumptions  none, no penalty
   confidence   0.35 + 0.25 + 0.10 = 0.70                    -> High
   basis        cites code and scanner evidence              -> evidence_backed
   priority     High and 0.70 >= 0.50                        -> Fix Now
   dashboard    visible

6. vulnerable-jsonwebtoken-dependency
   cites        jsonwebtoken-advisory (dependency / osv)
   risk         3 x 2 = 6                                    -> Medium
   osv          +0.30
   second src   none    sources {osv}: only 1 distinct
   assumptions  none, no penalty
   confidence   0.30                                         -> Low
   basis        cites dependency evidence                    -> evidence_backed
   priority     Medium and 0.30 < 0.50                       -> Monitor
   dashboard    visible (0.30 >= 0.25)

7. admin-actions-unaudited
   cites        admin-routes-no-role-check (code / detector)
   risk         2 x 2 = 4                                    -> Low
   code         +0.35
   second src   none    sources {detector}: only 1 distinct
   assumptions  none, no penalty
   confidence   0.35                                         -> Low
   basis        cites code evidence                          -> evidence_backed
   priority     Low                                          -> Monitor
   dashboard    visible

8. admin-panel-exposed             (no CWE)
   cites        admin-same-origin-inference (inference / ai)
   risk         4 x 3 = 12                                   -> High
   code 0, semgrep 0, osv 0, developer 0
   inference    +0.20   inference is cited and no code, scanner, dependency or developer item is
   second src   none    no direct evidence, so no corroborating sources {}
   assumptions  2 listed, penalty applied once               -> -0.15 (not -0.30)
   confidence   0.20 - 0.15 = 0.05                           -> Low
   basis        every cited item is inference                -> assumption_dependent
   priority     High and 0.05 < 0.50                         -> Fix Soon
   dashboard    HIDDEN (0.05 < 0.25)

9. note-search-resource-exhaustion
   cites        search-no-limits-inference (inference / ai)
   risk         3 x 3 = 9                                    -> Medium
   code 0, semgrep 0, osv 0, developer 0
   inference    +0.20   inference is cited and no code, scanner, dependency or developer item is
   second src   none    no direct evidence, so no corroborating sources {}
   assumptions  1 listed                                     -> -0.15
   confidence   0.20 - 0.15 = 0.05                           -> Low
   basis        every cited item is inference                -> assumption_dependent
   priority     Medium and 0.05 < 0.50                       -> Monitor
   dashboard    HIDDEN (0.05 < 0.25)
```

## Result

| # | Threat | Risk | Severity | Confidence | Label | Basis | Priority | Shown |
|---|---|---|---|---|---|---|---|---|
| 1 | admin-routes-missing-authz | 20 | Critical | 0.70 | High | evidence_backed | Fix Now | yes |
| 2 | jwt-hardcoded-secret | 15 | High | 1.00 | High | evidence_backed | Fix Now | yes |
| 3 | stripe-webhook-unverified | 12 | High | 0.35 | Low | evidence_backed | Fix Soon | yes |
| 4 | s3-attachments-public-read | 9 | Medium | 0.00 | Low | evidence_backed | Monitor | **hidden** |
| 5 | sql-injection-note-search | 16 | High | 0.70 | High | evidence_backed | Fix Now | yes |
| 6 | vulnerable-jsonwebtoken-dependency | 6 | Medium | 0.30 | Low | evidence_backed | Monitor | yes |
| 7 | admin-actions-unaudited | 4 | Low | 0.35 | Low | evidence_backed | Monitor | yes |
| 8 | admin-panel-exposed | 12 | High | 0.05 | Low | assumption_dependent | Fix Soon | **hidden** |
| 9 | note-search-resource-exhaustion | 9 | Medium | 0.05 | Low | assumption_dependent | Monitor | **hidden** |

Six threats are shown on the dashboard; three are hidden because their confidence is below
0.25. Hidden threats are still in the stored model. Both developer questions concern hidden
threats on purpose: a developer answer is worth +0.30, so answering the admin question would
lift threat 8 from 0.05 to 0.35 and bring it onto the dashboard.

## What changed from the first version of this fixture

| Threat | Before | After | Why |
|---|---|---|---|
| 4 s3-attachments-public-read | 0.55 Medium, Fix Soon, assumption_dependent | 0.00 Low, Monitor, evidence_backed | `config` earns no code points, so 0.35 + 0.25 + 0.10 - 0.15 became 0 - 0.15, clamped. It cites direct evidence, so it is `evidence_backed` despite its assumption. Its Semgrep item was dropped to keep 14 evidence items. |
| 8 admin-panel-exposed | 0.55 Medium, Fix Now, assumption_dependent | 0.05 Low, Fix Soon, assumption_dependent | It now cites only inference. Its code and CORS items moved to threat 1. A second assumption was added to exercise the once-only penalty. |
| 9 note-search-resource-exhaustion | 0.35 Low, Monitor, evidence_backed | 0.05 Low, Monitor, assumption_dependent | It now cites only a new inference item, and lists the assumption it rests on. |
| 1 admin-routes-missing-authz | 0.70 High | 0.70 High | Score unchanged; it also cites the admin-mount and CORS items. |

## Coverage of the brief

| Requirement | Where |
|---|---|
| All 6 STRIDE letters | S: 2, 3, 6 · T: 5 · R: 7 · I: 4 · D: 9 · E: 1, 2, 8 |
| All 4 severities | Critical: 1 · High: 2, 3, 5, 8 · Medium: 4, 6, 9 · Low: 7 |
| All 3 priorities | Fix Now: 1, 2, 5 · Fix Soon: 3, 8 · Monitor: 4, 6, 7, 9 |
| At least 2 `assumption_dependent` | 8 and 9 |
| Attack scenario over 600 characters | 1 (791 characters) |
| No CWE | 8 |
| Two STRIDE letters and two OWASP codes | 2 (S+E, A04+A07) |

## Things worth knowing

- **Shared evidence.** Threats 1 and 7 both cite `admin-routes-no-role-check`, and 2 and 6
  both cite `jsonwebtoken-advisory`. One finding can support several threats. Every one of
  the 14 evidence items is cited by at least one threat.
- **`valueScore` is not from a rule.** `CLAUDE.md` defines no formula for a question's
  `valueScore`, so 0.85 and 0.60 are illustrative.
- **Identifiers.** The OSV advisory `GHSA-qwph-4952-7xr6` is real and lists jsonwebtoken
  8.5.1 as affected. The Semgrep rule ids are illustrative: the `javascript.*` ones follow
  registry naming but were not looked up, and the `acme.*` one is invented. All file paths and
  line numbers are fictional.
- **Redaction.** The hard-coded secret in the snippet is shown as `[REDACTED]`, as the real
  pipeline would do before anything reaches a model (`CLAUDE.md` rule 3).
- **Layout.** Component positions are on a left-to-right grid with x in steps of 250:
  user 0 · web-frontend, admin-panel and stripe 250 · api-server 500 ·
  postgres-db and s3-attachments 750.
