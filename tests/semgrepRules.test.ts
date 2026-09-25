/**
 * Runs the real rule pack through a local semgrep binary, offline (--metrics=off, a local
 * config, no registry), to pin rule behaviour that string checks on SECURITY_RULESET
 * cannot. Skipped when semgrep is not installed, so CI without it still passes; the skip
 * is reported by Vitest, not hidden.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { SECURITY_RULESET } from "@/server/mcp/semgrepRules";

const available = spawnSync("semgrep", ["--version"], { encoding: "utf8" }).status === 0;
const dir = mkdtempSync(join(tmpdir(), "attackcanvas-semgrep-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** Line numbers where `ruleId` fires on `source`. */
function linesFor(ruleId: string, source: string): number[] {
  const rules = join(dir, "rules.yml");
  const target = join(dir, "sample.js");
  writeFileSync(rules, SECURITY_RULESET);
  writeFileSync(target, source);

  const run = spawnSync(
    "semgrep",
    ["scan", "--config", rules, "--metrics=off", "--disable-version-check", "--json", "--quiet", target],
    { encoding: "utf8", timeout: 120_000 },
  );
  const parsed = JSON.parse(run.stdout) as {
    results: { check_id: string; start: { line: number } }[];
  };
  return parsed.results
    .filter((r) => r.check_id.endsWith(ruleId))
    .map((r) => r.start.line);
}

describe.skipIf(!available)("attackcanvas-jwt-verify-none (real semgrep)", () => {
  it("does not match TextDecoder().decode, the tejaswisummer false positive", () => {
    const source = `function b64urlToJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}
const text = decoder.decode(bytes);
`;
    expect(linesFor("attackcanvas-jwt-verify-none", source)).toEqual([]);
  }, 180_000);

  it("still matches jwt.decode(token) and the algorithms: none form", () => {
    const source = `const jwt = require("jsonwebtoken");
const claims = jwt.decode(token);
jwt.verify(token, key, { algorithms: ["HS256", "none"] });
`;
    expect(linesFor("attackcanvas-jwt-verify-none", source)).toEqual([2, 3]);
  }, 180_000);
});

// ---------------------------------------------------------------------------
// Targeted rules from the NodeGoat evaluation (OWASP/NodeGoat@c5cb68a). Positive cases
// are NodeGoat's own vulnerable lines, trimmed; negatives are the reasonable safe forms
// each rule must not flag.
// ---------------------------------------------------------------------------

describe.skipIf(!available)("attackcanvas-nosql-where-injection (real semgrep)", () => {
  it("flags a request value interpolated into $where, not a parseInt'd one", () => {
    const source = `function byThreshold(userId, threshold) {
  const parsedUserId = parseInt(userId);
  return {
    $where: \`this.userId == \${parsedUserId} && this.stocks > '\${threshold}'\`
  };
}
function safe(threshold) {
  const parsedThreshold = parseInt(threshold, 10);
  return { $where: \`this.stocks > \${parsedThreshold}\` };
}
function constant() {
  return { $where: "this.stocks > 10" };
}
`;
    expect(linesFor("attackcanvas-nosql-where-injection", source)).toEqual([3]);
  }, 180_000);
});

describe.skipIf(!available)("attackcanvas-open-redirect (real semgrep)", () => {
  it("flags res.redirect(req.query.url), not a fixed path or an allow-listed target", () => {
    const source = `app.get("/learn", (req, res) => {
  return res.redirect(req.query.url);
});
app.get("/home", (req, res) => res.redirect("/dashboard"));
app.get("/go", (req, res) => {
  if (ALLOWED.includes(req.query.url)) { res.redirect(req.query.url); }
});
`;
    expect(linesFor("attackcanvas-open-redirect", source)).toEqual([2]);
  }, 180_000);
});

describe.skipIf(!available)("attackcanvas-ssrf-request-url (real semgrep)", () => {
  it("flags a request-chosen URL, not a fixed host with an encoded parameter", () => {
    const source = `function research(req, res) {
  const url = req.query.url + req.query.symbol;
  return needle.get(url, () => {});
}
function direct(req) { return axios.get(req.body.target); }
function fixedHost(req) {
  return axios.get("https://api.example.com/quote?s=" + encodeURIComponent(req.query.symbol));
}
function config() { return needle.get(process.env.QUOTE_URL); }
`;
    expect(linesFor("attackcanvas-ssrf-request-url", source)).toEqual([3, 5]);
  }, 180_000);
});

describe.skipIf(!available)("attackcanvas-redos-nested-quantifier (real semgrep)", () => {
  it("flags a repeated group of one quantified atom, once, and not separator-anchored groups", () => {
    const source = `const regexPattern = /([0-9]+)+\\#/;
const ok = regexPattern.test(bankRouting);
const words = /^([a-z]+)*$/;
const repeated = /(?:\\d+){2,}/;
const slug = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const dotted = /^([A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*)/;
const fixed = /([0-9]+)\\#/;
// const commented = /(a+)+/;
`;
    expect(linesFor("attackcanvas-redos-nested-quantifier", source)).toEqual([1, 3, 4]);
  }, 180_000);
});

describe.skipIf(!available)("attackcanvas-plaintext-password-compare (real semgrep)", () => {
  it("flags a stored password compared with ===, not a confirm-field check or bcrypt", () => {
    const source = `function UserDAO() {
  this.validateLogin = (userName, password, callback) => {
    const comparePassword = (fromDB, fromUser) => {
      return fromDB === fromUser;
    };
    const validateUserDoc = (err, user) => {
      if (comparePassword(password, user.password)) callback(null, user);
    };
  };
}
function signup(req) {
  const passwordsMatch = (a, b) => a === b;
  if (!passwordsMatch(req.body.password, req.body.verify)) return false;
  return req.body.password === req.body.verify;
}
function login(user, attempt) {
  if (user.password === attempt) return true;
  return bcrypt.compareSync(attempt, user.password);
}
`;
    expect(linesFor("attackcanvas-plaintext-password-compare", source)).toEqual([4, 17]);
  }, 180_000);
});
