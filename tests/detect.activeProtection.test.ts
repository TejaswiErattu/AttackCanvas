/**
 * security_headers_missing and csrf_missing count a protection only when live code uses
 * it. A dependency declared in package.json, an import whose name is never used, a
 * comment, a string and a template's `_csrf` field are not protection. The NodeGoat case
 * mirrors OWASP/NodeGoat@c5cb68a, which declares helmet and csurf but calls them only in
 * commented-out code.
 */

import { describe, expect, it } from "vitest";
import { runDetectors } from "@/server/detect";
import type { DetectorInput, GapKind } from "@/server/detect/types";
import { LOCKFILE, file, manifest } from "./gapSamples";

const kindsOf = (files: DetectorInput[]) =>
  new Set(runDetectors(files).gaps.map((gap) => gap.kind));

const DEPS = {
  express: "^4.13.4",
  "express-session": "^1.13.0",
  csurf: "^1.8.3",
  helmet: "^2.0.0",
};

/** An app with a cookie session and one state-changing route, plus `body`. */
function app(body: string, deps: Record<string, string> = DEPS): DetectorInput[] {
  return [
    manifest(deps),
    LOCKFILE,
    file(
      "server.js",
      [
        `const express = require("express");`,
        `const session = require("express-session");`,
        `const app = express();`,
        `app.use(session({ secret: "s", resave: true, saveUninitialized: true }));`,
        body,
        `app.post("/profile", (req, res) => { res.end(); });`,
      ].join("\n"),
    ),
  ];
}

/** The shape of NodeGoat's server.js: both protections declared, every call commented out. */
const NODEGOAT = [
  ...app(
    [
      `// const csrf = require('csurf');`,
      `// const helmet = require("helmet");`,
      `/*`,
      `    // Fix for A5 - Security MisConfig`,
      `    app.disable("x-powered-by");`,
      `    app.use(helmet.frameguard()); //xframe deprecated`,
      `    app.use(helmet.contentSecurityPolicy()); //csp deprecated`,
      `    app.use(helmet.hsts());`,
      `*/`,
      `/*`,
      `    // Fix for A8 - CSRF`,
      `    app.use(csrf());`,
      `    app.use((req, res, next) => {`,
      `        res.locals.csrftoken = req.csrfToken();`,
      `        next();`,
      `    });`,
      `*/`,
      `app.get("/profile", (req, res) => res.render("profile", { hint: "_csrf helmet()" }));`,
    ].join("\n"),
  ),
  file(
    "app/views/profile.html",
    `<form method="post"><input type="hidden" name="_csrf" value="{{csrftoken}}" /></form>`,
  ),
];

const BOTH: GapKind[] = ["security_headers_missing", "csrf_missing"];

describe("declared but inactive protections are gaps", () => {
  it("reports both gaps for NodeGoat's commented-out helmet and csurf calls", () => {
    const kinds = kindsOf(NODEGOAT);
    for (const kind of BOTH) expect(kinds).toContain(kind);
  });

  it.each<[string, string]>([
    ["only declared in package.json", ``],
    ["imported but never used", `const helmet = require("helmet");\nconst csrf = require("csurf");`],
    ["imported with ESM but never used", `import helmet from "helmet";\nimport csurf from "csurf";`],
    ["named only in strings", `const note = "app.use(helmet()); app.use(csrf());";`],
    ["called only in a line comment", `// app.use(helmet()); app.use(csrf());`],
    ["an object key named like a token", `const locals = { csrftoken: "", xsrf: null };`],
  ])("reports both gaps when the middleware is %s", (_why, body) => {
    const kinds = kindsOf(app(body));
    for (const kind of BOTH) expect(kinds).toContain(kind);
  });

  it("does not count a template's _csrf field as protection", () => {
    const repo = [
      ...app(``),
      file("views/form.html", `<input type="hidden" name="_csrf" value="{{csrfToken}}">`),
    ];
    expect(kindsOf(repo)).toContain("csrf_missing");
  });

  it("does not count a declared-only function named for CSRF", () => {
    expect(kindsOf(app(`function verifyCsrf(req) { return true; }`))).toContain("csrf_missing");
  });

  it("does not count req.csrfToken() used only to render a form", () => {
    const body = `app.get("/profile", (req, res) => res.render("profile", { csrftoken: req.csrfToken() }));`;
    expect(kindsOf(app(body))).toContain("csrf_missing");
  });

  it.each<[string, string]>([
    ["a token-producing helper", `app.get("/f", (req, res) => res.json({ t: getCsrfToken(req) }));`],
    ["a token written into a form field", `app.get("/f", (req, res) => res.send(\`<input name="_csrf" value="\${makeCsrfToken()}">\`));`],
    [
      "a CSRF-named middleware whose loaded body only calls next()",
      `const verifyCsrf = (req, res, next) => next();\napp.post("/x", verifyCsrf, (req, res) => res.end());`,
    ],
    [
      "a CSRF-named function whose loaded body checks nothing",
      `function checkCsrf(req, res, next) {\n  console.log("csrf check");\n  next();\n}\napp.use(checkCsrf);`,
    ],
  ])("reports csrf_missing for %s", (_why, body) => {
    expect(kindsOf(app(body))).toContain("csrf_missing");
  });
});

describe("lusca features are checked separately", () => {
  const LUSCA = { ...DEPS, lusca: "^1.7.0" };
  const withoutPackages = { express: "^4.13.4", "express-session": "^1.13.0", lusca: "^1.7.0" };

  it.each<[string, string]>([
    ["lusca.csrf()", `const lusca = require("lusca");\napp.use(lusca.csrf());`],
    ["lusca({ csrf: true })", `const lusca = require("lusca");\napp.use(lusca({ csrf: true }));`],
  ])("%s suppresses csrf_missing but not security_headers_missing", (_why, body) => {
    const kinds = kindsOf(app(body, withoutPackages));
    expect(kinds).not.toContain("csrf_missing");
    expect(kinds).toContain("security_headers_missing");
  });

  it.each<[string, string]>([
    ["lusca.xframe()", `const lusca = require("lusca");\napp.use(lusca.xframe("SAMEORIGIN"));`],
    [
      "lusca({ csp, xframe })",
      `const lusca = require("lusca");\napp.use(lusca({ csp: { policy: {} }, xframe: "DENY" }));`,
    ],
    ["an inline lusca header call", `app.use(require("lusca").hsts({ maxAge: 31536000 }));`],
  ])("%s suppresses security_headers_missing but not csrf_missing", (_why, body) => {
    const kinds = kindsOf(app(body, withoutPackages));
    expect(kinds).not.toContain("security_headers_missing");
    expect(kinds).toContain("csrf_missing");
  });

  it("an imported but unused lusca suppresses neither", () => {
    const kinds = kindsOf(app(`const lusca = require("lusca");`, LUSCA));
    for (const kind of BOTH) expect(kinds).toContain(kind);
  });
});

describe("active protections stay silent", () => {
  it.each<[string, string]>([
    ["helmet() called", `const helmet = require("helmet");\napp.use(helmet());`],
    ["a helmet sub-middleware called", `const helmet = require("helmet");\napp.use(helmet.frameguard());`],
    ["helmet imported with ESM and called", `import helmet from "helmet";\napp.use(helmet());`],
    ["helmet required inline", `app.use(require("helmet")());`],
    ["a renamed helmet binding passed to register", `const secure = require("helmet");\napp.register(secure);`],
    ["a destructured binding used", `const { hsts } = require("helmet");\napp.use(hsts());`],
  ])("no security_headers_missing with %s", (_why, body) => {
    expect(kindsOf(app(body))).not.toContain("security_headers_missing");
  });

  it.each<[string, string, Record<string, string>]>([
    ["csurf called", `const csrf = require("csurf");\napp.use(csrf());`, DEPS],
    [
      "a csurf instance passed to a route",
      `const csurf = require("csurf");\nconst protect = csurf({ cookie: true });\napp.put("/x", protect, (req, res) => res.end());`,
      DEPS,
    ],
    ["csurf imported dynamically", `const csrf = (await import("csurf")).default;\napp.use(csrf());`, DEPS],
    [
      "csrf-csrf's destructured protection",
      `const { doubleCsrf } = require("csrf-csrf");\nconst { doubleCsrfProtection } = doubleCsrf({ getSecret: () => "s" });\napp.use(doubleCsrfProtection);`,
      { ...DEPS, "csrf-csrf": "^3.0.0" },
    ],
    [
      "a loaded CSRF check that compares the request token",
      `function verifyCsrf(req, res, next) {\n  if (req.headers["x-csrf-token"] !== req.session.csrf) return res.status(403).end();\n  next();\n}\napp.use(verifyCsrf);`,
      DEPS,
    ],
    [
      "an arrow CSRF check that verifies the body token",
      `const requireCsrf = (req, res, next) => (tokens.verify(secret, req.body._csrf) ? next() : res.status(403).end());\napp.post("/x", requireCsrf, (req, res) => res.end());`,
      DEPS,
    ],
    [
      "a CSRF middleware imported from a module that is not loaded (behaviour unknown)",
      `const { verifyCsrfToken } = require("./security");\napp.use(verifyCsrfToken);`,
      DEPS,
    ],
  ])("no csrf_missing with %s", (_why, body, deps) => {
    expect(kindsOf(app(body, deps))).not.toContain("csrf_missing");
  });

  it("stays silent on a declared header package when no source was loaded to check", () => {
    const repo = [manifest({ express: "^4.18.0", helmet: "^7.0.0" }), LOCKFILE];
    expect(kindsOf(repo)).not.toContain("security_headers_missing");
  });
});
