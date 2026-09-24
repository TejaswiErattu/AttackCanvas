/**
 * A saved Semgrep response, for unit-testing the parser without a server.
 *
 * Captured live from the Semgrep MCP server (semgrep 1.176.0, MCP server v1.29.0) by
 * calling semgrep_scan_with_custom_rule with the pack in src/server/mcp/semgrepRules.ts
 * over the three sample files below. This is the verbatim text block that tool
 * returned - semgrep's own --json output, plus the mcp_scan_results and skipped_rules
 * keys the server adds.
 *
 * Note "lines": "requires login". Semgrep withholds the matched source in logged-out
 * OSS mode, which is why parseScanResponse takes its snippet from the content we sent
 * rather than from the response.
 */

/** The files this response was produced from, keyed by the path Semgrep reports. */
export const SAMPLE_FILES: { path: string; content: string }[] = [
  {
    path: "src/db.js",
    content: `const express = require("express");
const mysql = require("mysql2");

const app = express();
const db = mysql.createConnection({ host: "localhost", user: "app" });

app.get("/users", (req, res) => {
  const sql = "SELECT * FROM users WHERE name = '" + req.query.name + "'";
  db.query(sql, (err, rows) => res.json(rows));
});

app.get("/orders", (req, res) => {
  db.query("SELECT * FROM orders WHERE id = " + req.params.id, (err, rows) => {
    res.json(rows);
  });
});

module.exports = app;
`,
  },
  {
    path: "src/eval.js",
    content: `const express = require("express");
const router = express.Router();

router.get("/calc", (req, res) => {
  const result = eval(req.query.expr);
  res.send(String(result));
});

router.post("/run", (req, res) => {
  const fn = new Function("return " + req.body.code);
  res.send(String(fn()));
});

module.exports = router;
`,
  },
  {
    path: "src/auth.js",
    content: `const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const SECRET = "s3cr3t-dev-signing-key";

function issue(user) {
  return jwt.sign({ sub: user.id }, "s3cr3t-dev-signing-key", { expiresIn: "7d" });
}

function issueWithConst(user) {
  return jwt.sign({ sub: user.id }, SECRET);
}

function fingerprint(value) {
  return crypto.createHash("md5").update(value).digest("hex");
}

module.exports = { issue, issueWithConst, fingerprint };
`,
  },
];

/** The MCP text block, verbatim. */
export const SCAN_RESPONSE_TEXT = `{
  "version": "1.176.0",
  "results": [
    {
      "check_id": "attackcanvas-hardcoded-jwt-secret",
      "path": "src/auth.js",
      "start": {
        "line": 7,
        "col": 10,
        "offset": 146
      },
      "end": {
        "line": 7,
        "col": 83,
        "offset": 219
      },
      "extra": {
        "message": "A JWT is signed with a secret literal in the source. Anyone who can read the repository can mint valid tokens. Load it from configuration instead.",
        "metadata": {
          "cwe": [
            "CWE-798: Use of Hard-coded Credentials"
          ],
          "owasp": [
            "A07:2021 - Identification and Authentication Failures"
          ],
          "category": "security",
          "confidence": "HIGH"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "attackcanvas-hardcoded-jwt-secret",
      "path": "src/auth.js",
      "start": {
        "line": 11,
        "col": 10,
        "offset": 265
      },
      "end": {
        "line": 11,
        "col": 44,
        "offset": 299
      },
      "extra": {
        "message": "A JWT is signed with a secret literal in the source. Anyone who can read the repository can mint valid tokens. Load it from configuration instead.",
        "metadata": {
          "cwe": [
            "CWE-798: Use of Hard-coded Credentials"
          ],
          "owasp": [
            "A07:2021 - Identification and Authentication Failures"
          ],
          "category": "security",
          "confidence": "HIGH"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "attackcanvas-weak-hash",
      "path": "src/auth.js",
      "start": {
        "line": 15,
        "col": 10,
        "offset": 343
      },
      "end": {
        "line": 15,
        "col": 34,
        "offset": 367
      },
      "extra": {
        "message": "MD5 and SHA-1 are broken for any security purpose. Use SHA-256 for integrity and a password hash such as bcrypt, scrypt or argon2 for passwords.",
        "metadata": {
          "cwe": [
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
          ],
          "owasp": [
            "A02:2021 - Cryptographic Failures"
          ],
          "category": "security",
          "confidence": "HIGH"
        },
        "severity": "WARNING",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "attackcanvas-sql-string-concat",
      "path": "src/db.js",
      "start": {
        "line": 9,
        "col": 3,
        "offset": 276
      },
      "end": {
        "line": 9,
        "col": 47,
        "offset": 320
      },
      "extra": {
        "message": "SQL is built by concatenating a value into the query string. If any part of that value comes from a request, it is SQL injection. Use parameterised queries.",
        "metadata": {
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A03:2021 - Injection"
          ],
          "category": "security",
          "confidence": "MEDIUM"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "attackcanvas-sql-string-concat",
      "path": "src/db.js",
      "start": {
        "line": 13,
        "col": 3,
        "offset": 364
      },
      "end": {
        "line": 15,
        "col": 5,
        "offset": 466
      },
      "extra": {
        "message": "SQL is built by concatenating a value into the query string. If any part of that value comes from a request, it is SQL injection. Use parameterised queries.",
        "metadata": {
          "cwe": [
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
          ],
          "owasp": [
            "A03:2021 - Injection"
          ],
          "category": "security",
          "confidence": "MEDIUM"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "attackcanvas-eval-user-input",
      "path": "src/eval.js",
      "start": {
        "line": 5,
        "col": 18,
        "offset": 123
      },
      "end": {
        "line": 5,
        "col": 38,
        "offset": 143
      },
      "extra": {
        "message": "eval() or new Function() executes a string as code. Reaching it with request data is remote code execution.",
        "metadata": {
          "cwe": [
            "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"
          ],
          "owasp": [
            "A03:2021 - Injection"
          ],
          "category": "security",
          "confidence": "HIGH"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    },
    {
      "check_id": "attackcanvas-eval-user-input",
      "path": "src/eval.js",
      "start": {
        "line": 10,
        "col": 14,
        "offset": 227
      },
      "end": {
        "line": 10,
        "col": 53,
        "offset": 266
      },
      "extra": {
        "message": "eval() or new Function() executes a string as code. Reaching it with request data is remote code execution.",
        "metadata": {
          "cwe": [
            "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"
          ],
          "owasp": [
            "A03:2021 - Injection"
          ],
          "category": "security",
          "confidence": "HIGH"
        },
        "severity": "ERROR",
        "fingerprint": "requires login",
        "lines": "requires login",
        "validation_state": "NO_VALIDATOR",
        "engine_kind": "OSS"
      }
    }
  ],
  "errors": [],
  "paths": {
    "scanned": [
      "src/auth.js",
      "src/db.js",
      "src/eval.js"
    ]
  },
  "skipped_rules": [],
  "mcp_scan_results": {}
}`;
