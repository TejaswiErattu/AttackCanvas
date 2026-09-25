/**
 * The Semgrep ruleset AttackCanvas scans with.
 *
 * Discovery (scripts/list-semgrep-tools.ts) found that no tool on the Semgrep MCP
 * server takes a config or ruleset parameter, so a registry pack such as
 * "p/owasp-top-ten" cannot be selected over MCP. The only tool that accepts file
 * *contents* rather than paths is semgrep_scan_with_custom_rule, and it requires the
 * rule inline. So the rules live here, and repository content never touches disk.
 *
 * A .ts module rather than a .yaml file, so it needs no loader or bundler
 * configuration under tsx, Vitest and Next alike.
 *
 * Every rule carries cwe and owasp in its metadata, because for a custom rule that
 * metadata is the only source of those fields on a finding. The strings are the raw
 * Semgrep convention; mapping them onto Owasp2025Schema belongs to a later stage, not
 * to the MCP client.
 *
 * Rule behaviour is pinned by tests/semgrepRules.test.ts, which runs this pack through a
 * local semgrep binary offline; the targeted rules each have positive and negative cases
 * there. scripts/try-semgrep.ts is a live MCP smoke test over a few samples. Add a
 * positive and a negative test with every new rule.
 */
export const SECURITY_RULESET = `
rules:
  - id: attackcanvas-sql-string-concat
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      SQL is built by concatenating a value into the query string. If any part of that
      value comes from a request, it is SQL injection. Use parameterised queries.
    metadata:
      cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"]
      owasp: ["A03:2021 - Injection"]
      category: security
      confidence: MEDIUM
    pattern-either:
      - pattern: $DB.query("..." + $X, ...)
      - pattern: $DB.execute("..." + $X, ...)
      - patterns:
          - pattern: $DB.query($SQL, ...)
          - pattern-inside: |
              $SQL = "..." + ...;
              ...

  - id: attackcanvas-eval-user-input
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      eval() or new Function() executes a string as code. Reaching it with request
      data is remote code execution.
    metadata:
      cwe: ["CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"]
      owasp: ["A03:2021 - Injection"]
      category: security
      confidence: HIGH
    pattern-either:
      - pattern: eval(...)
      - pattern: new Function(...)

  - id: attackcanvas-hardcoded-jwt-secret
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      A JWT is signed with a secret literal in the source. Anyone who can read the
      repository can mint valid tokens. Load it from configuration instead.
    metadata:
      cwe: ["CWE-798: Use of Hard-coded Credentials"]
      owasp: ["A07:2021 - Identification and Authentication Failures"]
      category: security
      confidence: HIGH
    pattern-either:
      - pattern: $JWT.sign($PAYLOAD, "...", ...)
      - patterns:
          - pattern: $JWT.sign($PAYLOAD, $SECRET, ...)
          - pattern-inside: |
              const $SECRET = "...";
              ...

  - id: attackcanvas-command-injection
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      A shell command is built from a concatenated string. If any part of it comes from
      a request, it is command injection. Use execFile with an argument array.
    metadata:
      cwe: ["CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"]
      owasp: ["A03:2021 - Injection"]
      category: security
      confidence: MEDIUM
    pattern-either:
      - pattern: $CP.exec("..." + $X, ...)
      - pattern: $CP.execSync("..." + $X, ...)

  - id: attackcanvas-reflected-xss
    languages: [javascript, typescript]
    severity: WARNING
    message: >-
      Request data is written straight into a response body or into the DOM without
      escaping, which is reflected cross-site scripting.
    metadata:
      cwe: ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"]
      owasp: ["A03:2021 - Injection"]
      category: security
      confidence: MEDIUM
    pattern-either:
      - pattern: $RES.send($REQ.query.$P)
      - pattern: $RES.send($REQ.body.$P)
      - pattern: $RES.send($REQ.params.$P)
      - pattern: $EL.innerHTML = $REQ.query.$P
      - pattern: $EL.innerHTML = $REQ.body.$P

  - id: attackcanvas-hardcoded-credentials
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      A credential is assigned a string literal in the source. Secrets committed to a
      repository must be treated as disclosed. Load it from the environment.
    metadata:
      cwe: ["CWE-798: Use of Hard-coded Credentials"]
      owasp: ["A07:2021 - Identification and Authentication Failures"]
      category: security
      confidence: LOW
    pattern-either:
      - pattern: password = "..."
      - pattern: apiKey = "..."
      - pattern: api_key = "..."
      - pattern: secretKey = "..."
      - pattern: privateKey = "..."

  - id: attackcanvas-weak-hash
    languages: [javascript, typescript]
    severity: WARNING
    message: >-
      MD5 and SHA-1 are broken for any security purpose. Use SHA-256 for integrity and
      a password hash such as bcrypt, scrypt or argon2 for passwords.
    metadata:
      cwe: ["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"]
      owasp: ["A02:2021 - Cryptographic Failures"]
      category: security
      confidence: HIGH
    pattern-either:
      - pattern: $C.createHash("md5")
      - pattern: $C.createHash("sha1")

  - id: attackcanvas-jwt-verify-none
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      JWT verification accepts the "none" algorithm, or skips verification entirely, so
      an attacker can forge a token by stripping its signature.
    metadata:
      cwe: ["CWE-347: Improper Verification of Cryptographic Signature"]
      owasp: ["A02:2021 - Cryptographic Failures"]
      category: security
      confidence: HIGH
    pattern-either:
      - pattern: '$JWT.verify($TOKEN, $KEY, {..., algorithms: [..., "none", ...], ...})'
      # decode() is only a JWT decode on a JWT library's receiver. A bare $X.decode
      # matched new TextDecoder().decode(...) and Buffer/base64 helpers.
      - patterns:
          - pattern: $JWT.decode($TOKEN, ...)
          - metavariable-regex:
              metavariable: $JWT
              regex: ^(jwt|jsonwebtoken|jsonWebToken|JWT|jose)$
  # --- Targeted rules added after the NodeGoat evaluation (OWASP/NodeGoat@c5cb68a). Each
  # gives a citable finding at the vulnerable line; each has positive and negative cases
  # in tests/semgrepRules.test.ts. They are syntactic, not taint-tracking: a request
  # value that reaches the sink through another function is out of their reach.

  - id: attackcanvas-nosql-where-injection
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      A MongoDB $where clause is built by interpolating a value into JavaScript source.
      If that value comes from a request, it is server-side JavaScript injection into
      the database. Use query operators instead of $where, or coerce the value first.
    metadata:
      cwe: ["CWE-943: Improper Neutralization of Special Elements in Data Query Logic"]
      owasp: ["A03:2021 - Injection"]
      category: security
      confidence: MEDIUM
    patterns:
      - pattern-either:
          - pattern: "{$where: \`...\${$X}...\`}"
          - pattern: '{$where: "..." + $X + ...}'
          - pattern: '{$where: "..." + $X}'
      # A value coerced to a number in the same scope cannot carry code.
      - pattern-not-inside: |
          const $X = parseInt(...);
          ...
      - pattern-not-inside: |
          const $X = Number(...);
          ...
      - pattern-not-inside: |
          $X = parseInt(...);
          ...
      - pattern-not-inside: |
          $X = Number(...);
          ...

  - id: attackcanvas-open-redirect
    languages: [javascript, typescript]
    severity: WARNING
    message: >-
      A redirect target is taken straight from the request, so an attacker can send
      users to any site from a trusted link. Redirect only to an allow-list of paths.
    metadata:
      cwe: ["CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"]
      owasp: ["A01:2021 - Broken Access Control"]
      category: security
      confidence: HIGH
    patterns:
      - pattern-either:
          - pattern: $RES.redirect($REQ.query.$P)
          - pattern: $RES.redirect($REQ.body.$P)
          - pattern: $RES.redirect($REQ.params.$P)
      - pattern-not-inside: |
          if (<... $ALLOWED.includes($REQ.$S.$P) ...>) { ... }
      - pattern-not-inside: |
          if (<... $ALLOWED.has($REQ.$S.$P) ...>) { ... }

  - id: attackcanvas-ssrf-request-url
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      An outbound HTTP request is made to a URL whose beginning comes from the request,
      so an attacker chooses the host: server-side request forgery. Fix the host and
      pass only encoded parameters, or check the URL against an allow-list.
    metadata:
      cwe: ["CWE-918: Server-Side Request Forgery (SSRF)"]
      owasp: ["A10:2021 - Server-Side Request Forgery"]
      category: security
      confidence: MEDIUM
    patterns:
      # Only a URL that STARTS with request data: "https://api.example.com/q?s=" +
      # req.query.s has a fixed host and is not matched.
      - pattern-either:
          - pattern: $C.$M($REQ.$S.$P + $REST, ...)
          - pattern: $C.$M($REQ.$S.$P, ...)
          - patterns:
              - pattern: $C.$M($U, ...)
              - pattern-inside: |
                  const $U = $REQ.$S.$P + $REST;
                  ...
          - patterns:
              - pattern: $C.$M($U, ...)
              - pattern-inside: |
                  const $U = $REQ.$S.$P;
                  ...
      - metavariable-regex:
          metavariable: $S
          regex: ^(query|body|params)$
      - metavariable-regex:
          metavariable: $C
          regex: ^(needle|axios|got|request|superagent|http|https)$
      - metavariable-regex:
          metavariable: $M
          regex: ^(get|post|put|patch|delete|head|request)$

  - id: attackcanvas-redos-nested-quantifier
    languages: [javascript, typescript]
    severity: WARNING
    message: >-
      This regular expression repeats a group that itself contains a quantifier, e.g.
      ([0-9]+)+, which backtracks catastrophically on crafted input and can stall the
      event loop. Remove the outer quantifier.
    metadata:
      cwe: ["CWE-1333: Inefficient Regular Expression Complexity"]
      owasp: ["A04:2021 - Insecure Design"]
      category: security
      confidence: MEDIUM
    # Report the literal once, where it is written, not again at each .test() use.
    options:
      constant_propagation: false
    patterns:
      - pattern: /$R/
      # Only a group that is nothing but one quantified atom, e.g. ([0-9]+)+, (\d+)*,
      # (?:[a-z]+){2,}. A group that starts with a literal separator, such as
      # (?:-[a-z0-9]+)*, cannot backtrack catastrophically and is deliberately not
      # matched; nor are alternation forms like (a|aa)+, which this cannot judge safely.
      - metavariable-regex:
          metavariable: $R
          regex: '.*\\((?:\\?:)?(?:\\[(?:[^\\]\\\\]|\\\\.)*\\]|\\\\.|\\.|\\w)[+*]\\)(?:[+*]|\\{\\d+,\\d*\\})'

  - id: attackcanvas-plaintext-password-compare
    languages: [javascript, typescript]
    severity: ERROR
    message: >-
      A stored password is compared with ===, which means it is stored in plaintext (a
      hash is compared with bcrypt.compare or similar, never ===). Store and compare a
      salted password hash.
    metadata:
      cwe: ["CWE-256: Plaintext Storage of a Password"]
      owasp: ["A02:2021 - Cryptographic Failures"]
      category: security
      confidence: MEDIUM
    pattern-either:
      # A helper named *password* comparing its two arguments with ===, called with a
      # stored record's .password. The call-site check is what separates it from a
      # harmless "passwords match" check on two form fields.
      - patterns:
          - pattern-inside: |
              const $F = ($A, $B) => { ... };
              ...
              <... $F(..., $U.password, ...) ...>;
          - pattern: $A === $B
          - metavariable-regex:
              metavariable: $F
              regex: (?i).*password
          - metavariable-regex:
              metavariable: $U
              regex: (?i)^(user|account|found|record|doc|row|member|customer|existing|dbuser|stored)\\w*$
      # A stored record's .password compared directly. Restricted to record-like names so
      # req.body.password === req.body.verify (a confirm field) is not matched.
      - patterns:
          - pattern-either:
              - pattern: $U.password === $X
              - pattern: $X === $U.password
          - metavariable-regex:
              metavariable: $U
              regex: (?i)^(user|account|found|record|doc|row|member|customer|existing|dbuser|stored)\\w*$
`;

/** Rule ids in the pack, for tests and for anything that needs to enumerate them. */
export const RULE_IDS = [
  "attackcanvas-sql-string-concat",
  "attackcanvas-eval-user-input",
  "attackcanvas-hardcoded-jwt-secret",
  "attackcanvas-command-injection",
  "attackcanvas-reflected-xss",
  "attackcanvas-hardcoded-credentials",
  "attackcanvas-weak-hash",
  "attackcanvas-jwt-verify-none",
  "attackcanvas-nosql-where-injection",
  "attackcanvas-open-redirect",
  "attackcanvas-ssrf-request-url",
  "attackcanvas-redos-nested-quantifier",
  "attackcanvas-plaintext-password-compare",
] as const;

export type RuleId = (typeof RULE_IDS)[number];
