# What AttackCanvas covers

One row per OWASP Top 10:2025 category. This says which part of the tool can produce
evidence in each category. It does **not** say the tool finds every issue in a category, and
a tick is a claim about a check existing, not about how well it works. For how well the
detectors work, and where they are known to be wrong, read
[gap-adversarial-review.md](gap-adversarial-review.md) and
[known-limitations.md](known-limitations.md).

## The four sources

- **Detector**: deterministic code over the loaded files (`src/server/detect`). It reports a
  *missing control* (a "gap") when it does not find one. There are 13 gap kinds. A gap is a
  prediction from the absence of something, made by regex over JavaScript and TypeScript
  source (`.ts .tsx .js .jsx .mjs .cjs`), `package.json`, and for a few checks HTML and
  deployment files. Each carries a certainty, and low-certainty gaps are reported as
  uncertain, not as findings.
- **Semgrep**: 13 rules of our own (`src/server/mcp/semgrepRules.ts`), JavaScript and
  TypeScript only. They carry OWASP 2021 tags, mapped to 2025 by `src/shared/owaspMap.ts`
  (two 2021 categories land on A01:2025, and nothing maps to A10:2025). Semgrep's
  open-source engine analyses one file at a time.
- **OSV**: known vulnerabilities in the **direct** npm dependencies named in `package.json`,
  at the version in `package-lock.json` when there is one. It attaches no OWASP category to
  its evidence: the model files the resulting threats, and in the saved NodeGoat run it put
  them mostly under A06, some under A03.
- **Model only**: the model can write a threat in any category from what it is shown, with
  no detector, Semgrep or OSV evidence behind it. Those threats rest on assumptions, so they
  are marked assumption-dependent and score lower confidence (`src/shared/confidence.ts`).

## Matrix

| OWASP 2025 | Detector (gap kinds) | Semgrep (rule ids) | OSV | Model only | Not covered |
|---|---|---|---|---|---|
| **A01** Broken Access Control | `authz_missing`, `authn_missing`, `csrf_missing`, `cors_permissive` | `attackcanvas-open-redirect`, `attackcanvas-ssrf-request-url` (2021's SSRF category folds into A01) | none | business-logic access rules, tenant separation, object checks not on an `:id` route | access control enforced outside the loaded code (a gateway, database row-level security) |
| **A02** Security Misconfiguration | `security_headers_missing`, `cors_permissive` | none | none | default credentials, verbose error output, framework hardening | runtime and infrastructure configuration; anything in a file the loader skipped |
| **A03** Software Supply Chain Failures | `supply_chain_integrity` (lockfile and integrity pinning) | none | known advisories in direct npm dependencies | build and CI compromise (deployment files are read as facts, but no gap kind checks them) | transitive dependencies, non-npm ecosystems, private packages |
| **A04** Cryptographic Failures | `transport_insecure`, `password_storage_weak`, `client_secret_storage` | `attackcanvas-weak-hash`, `attackcanvas-jwt-verify-none`, `attackcanvas-plaintext-password-compare` (2021 A02 maps here) | none | key management, encryption at rest | TLS configuration at a load balancer or CDN, certificates, encryption in the database |
| **A05** Injection | `input_validation_missing` (absence of validation, not a data-flow trace) | `attackcanvas-sql-string-concat`, `attackcanvas-eval-user-input`, `attackcanvas-command-injection`, `attackcanvas-reflected-xss`, `attackcanvas-nosql-where-injection` | none | injection kinds with no rule (LDAP, template, header, XML external entities), second-order injection | data that flows across files; any language other than JavaScript and TypeScript |
| **A06** Insecure Design | `input_validation_missing` (also tagged A06) | `attackcanvas-redos-nested-quantifier` (2021 A04 maps here) | advisories are often filed here by the model | most of it: missing threat controls, business-logic abuse, trust boundaries | design problems that are not visible in code |
| **A07** Authentication Failures | `authn_missing`, `rate_limit_missing`, `client_secret_storage` | `attackcanvas-hardcoded-jwt-secret`, `attackcanvas-hardcoded-credentials` | none | session lifecycle, multi-factor, password policy | authentication done by an external identity provider or gateway that is not in the repository |
| **A08** Software or Data Integrity Failures | `supply_chain_integrity` (also tagged A08) | none | none | insecure deserialization, unsigned updates, CI/CD integrity | anything not tied to a lockfile or integrity check. The saved NodeGoat run reported no A08 threat. |
| **A09** Security Logging and Alerting Failures | `logging_missing` (whether logging exists in code) | none | none | what is logged, alerting and monitoring | alerting and monitoring themselves; logs kept by infrastructure |
| **A10** Mishandling of Exceptional Conditions | `error_handling_gap` | none (no rule maps to A10:2025) | none | fail-open logic, resource exhaustion handling | runtime failure behaviour. The saved NodeGoat run reported no A10 threat. |

The gap kinds and their categories are the `META` table in `src/server/detect/gaps.ts`. The
Semgrep tags are in `src/server/mcp/semgrepRules.ts`, and `RULE_IDS` there lists the rules.
`tests/coverageDoc.test.ts` fails if a gap kind or rule id is missing from this page.

## What the tool cannot see

- **Runtime configuration.** It reads source, not a running system. Environment values,
  feature flags, and settings applied at deploy time are invisible. Only environment
  variable *names* are read, never values.
- **Infrastructure outside the repository.** Gateways, load balancers, WAFs, network rules,
  cloud IAM, and database settings. A control that lives there looks absent, so the tool
  reports it as missing (`docs/known-limitations.md` explains why gap certainty is lowered
  for this).
- **Private dependencies.** OSV knows public npm packages. A private package, a git or file
  dependency, or a range with no lower bound is not checked, and the result says how many.
  Only **direct** dependencies are checked, and only from `package.json` and
  `package-lock.json`.
- **Languages the detectors do not parse.** Files in other languages (Python, Go, Java, Ruby,
  PHP and more) are loaded and shown to the model, but no gap detector or Semgrep rule reads
  them. Anything found there is model-only.
- **Secrets in git history.** The repository is read at one ref, through the GitHub API. Past
  commits are never read, so a secret that was committed and later removed is not found. The
  redactor only removes secrets from the current text sent to a model.
- **Files the loader skipped.** The loader reads at most 300 files and 2 MiB in total, skips
  any file over 200 KB (a `package-lock.json` up to 1 MiB is the one exception), and ignores
  dependency and build directories and binary files. Lockfiles other than
  `package-lock.json` are loaded but never read by the dependency check. What it dropped
  is counted, and when a repository is cut short the result says so, but a skipped file is
  never analysed.
- **Anything that only shows when the code runs.** Routes registered at run time, controls
  applied by a framework convention the detectors do not recognise, and behaviour that
  depends on data.

The tool only reads. It never runs the repository's code, and a public repository is readable
by anyone whether or not this tool reads it.
