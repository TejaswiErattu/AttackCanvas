/**
 * Smoke test: scan three in-memory sample files and print the findings.
 *
 *   pnpm try scripts/try-semgrep.ts
 *
 * The samples carry one planted flaw each - SQL built by string concatenation in an
 * Express handler, eval() on req.query, and jwt.sign() with a hardcoded secret - so
 * the ruleset in src/server/mcp/semgrepRules.ts should report all three. Nothing is
 * written to disk: the content goes to the server in the tool call.
 *
 * Needs the semgrep CLI on PATH ("brew install semgrep"). No token and no account.
 * A run takes about 2 s; the server logs "User doesn't have the Pro Engine installed"
 * to stderr, which is informational and does not stop the OSS scan.
 */
import {
  SemgrepClientConfigError,
  SemgrepMcpError,
  closeSemgrepClient,
  scanFiles,
  type RawSemgrepFinding,
  type RedactedFile,
} from "@/server/mcp/semgrepClient";

try {
  process.loadEnvFile(".env.local");
} catch {
  // No .env.local: fall back to the ambient environment.
}

const SAMPLES: RedactedFile[] = [
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

function print(finding: RawSemgrepFinding): void {
  const span =
    finding.startLine === finding.endLine
      ? `${finding.startLine}`
      : `${finding.startLine}-${finding.endLine}`;

  console.log(`  [${finding.severity}] ${finding.ruleId}  ${finding.path}:${span}`);
  console.log(`      ${finding.message}`);

  const tags = [...finding.cwe, ...finding.owasp];
  if (tags.length > 0) console.log(`      ${tags.join(" | ")}`);

  if (finding.snippet) {
    for (const line of finding.snippet.split("\n")) console.log(`      > ${line}`);
  }
  console.log();
}

async function main(): Promise<void> {
  console.log(`scanning ${SAMPLES.length} in-memory files\n`);

  const started = Date.now();
  const findings = await scanFiles(SAMPLES);
  const seconds = ((Date.now() - started) / 1000).toFixed(1);

  console.log(`${findings.length} findings in ${seconds}s\n`);

  for (const sample of SAMPLES) {
    const forFile = findings.filter((finding) => finding.path === sample.path);
    console.log(`${sample.path} (${forFile.length})`);
    if (forFile.length === 0) console.log("  no findings\n");
    for (const finding of forFile) print(finding);
  }

  const expected = [
    "attackcanvas-sql-string-concat",
    "attackcanvas-eval-user-input",
    "attackcanvas-hardcoded-jwt-secret",
  ];
  const found = new Set(findings.map((finding) => finding.ruleId));
  const missing = expected.filter((ruleId) => !found.has(ruleId));

  if (missing.length > 0) {
    console.error(`expected rules did not fire: ${missing.join(", ")}`);
    process.exitCode = 1;
  }
}

main()
  .catch((error: unknown) => {
    if (error instanceof SemgrepMcpError) {
      console.error(`[${error.code}] ${error.message}`);
    } else if (error instanceof SemgrepClientConfigError) {
      console.error(`[config] ${error.message}`);
    } else {
      console.error(error instanceof Error ? error.message : String(error));
    }
    process.exitCode = 1;
  })
  .finally(() => closeSemgrepClient());
