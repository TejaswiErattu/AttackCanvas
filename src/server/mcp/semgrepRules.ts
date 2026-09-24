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
 * Each rule in this pack is verified to fire against the samples in
 * scripts/try-semgrep.ts. Keep it that way when adding one.
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
] as const;

export type RuleId = (typeof RULE_IDS)[number];
