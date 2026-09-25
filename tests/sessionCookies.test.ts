/**
 * detectSessionCookies reports the effective session-cookie attributes with library
 * defaults applied, and renderSessionCookies turns them into the threat batch's context
 * block. The HttpOnly default is the fact a model reading commented-out options gets wrong.
 */

import { describe, expect, it } from "vitest";
import { detectSessionCookies } from "@/server/detect/sessionCookies";
import { runDetectors } from "@/server/detect";
import {
  SESSION_COOKIES_HEADER,
  buildThreatBatch,
  renderSessionCookies,
} from "@/server/analysis/threatPrompt";
import { loadPrompt } from "@/server/ai/prompts";
import { THREATS_PROMPT_NAME, THREATS_PROMPT_VERSION } from "@/server/analysis/threatPrompt";
import type { MergedArchitecture } from "@/server/analysis/architecture";

const js = (body: string, path = "server.js") => [{ path, content: body }];
const one = (body: string) => {
  const found = detectSessionCookies(js(body));
  expect(found).toHaveLength(1);
  return found[0];
};

describe("express-session", () => {
  it("applies the defaults when no cookie option is given: HttpOnly yes, Secure no, SameSite unset", () => {
    const c = one(`const session = require("express-session");\napp.use(session({ secret: "s" }));`);
    expect(c).toMatchObject({
      library: "express-session", file: "server.js", line: 2,
      httpOnly: { value: true, source: "default" },
      secure: { value: false, source: "default" },
      sameSite: { value: null, source: "default" },
    });
  });

  it("ignores a commented-out cookie block (the NodeGoat shape) and keeps the defaults", () => {
    const c = one([
      `const session = require("express-session");`,
      `app.use(session({`,
      `  secret: cookieSecret,`,
      `  saveUninitialized: true,`,
      `  /*`,
      `  cookie: {`,
      `    httpOnly: true`,
      `  }`,
      `  */`,
      `}));`,
    ].join("\n"));
    expect(c.httpOnly).toEqual({ value: true, source: "default" });
    expect(c.line).toBe(2);
  });

  it("reads explicit literal attributes, including httpOnly: false", () => {
    const c = one(`import session from "express-session";\napp.use(session({ cookie: { httpOnly: false, secure: true, sameSite: "lax" } }));`);
    expect(c.httpOnly).toEqual({ value: false, source: "explicit" });
    expect(c.secure).toEqual({ value: true, source: "explicit" });
    expect(c.sameSite).toEqual({ value: "lax", source: "explicit" });
  });

  it("reports unknown for non-literal values, a cookie variable, or options passed as a variable", () => {
    expect(one(`const s = require("express-session");\napp.use(s({ cookie: { httpOnly: isProd } }));`).httpOnly)
      .toEqual({ value: "unknown", source: "explicit" });
    expect(one(`const s = require("express-session");\napp.use(s({ secret: "x", cookie: cookieOptions }));`).httpOnly.value)
      .toBe("unknown");
    expect(one(`const s = require("express-session");\napp.use(s(options));`).httpOnly.value).toBe("unknown");
  });

  it("recognises an inline require call", () => {
    expect(one(`app.use(require("express-session")({ secret: "s" }));`).httpOnly.value).toBe(true);
  });
});

describe("cookie-session", () => {
  it("reads flat attributes and defaults the rest", () => {
    const c = one(`const cookieSession = require("cookie-session");\napp.use(cookieSession({ name: "s", httpOnly: false }));`);
    expect(c.library).toBe("cookie-session");
    expect(c.httpOnly).toEqual({ value: false, source: "explicit" });
    expect(c.secure).toEqual({ value: false, source: "default" });
  });
});

describe("no session cookie", () => {
  it("finds nothing when the library is only required in a comment, never imported, or absent", () => {
    expect(detectSessionCookies(js(`// const session = require("express-session");\n// app.use(session({}));`))).toEqual([]);
    expect(detectSessionCookies(js(`app.use(session({ secret: "s" }));`))).toEqual([]);
    expect(detectSessionCookies(js(`res.cookie("sid", id, { httpOnly: false });`))).toEqual([]);
  });

  it("skips non-source files", () => {
    expect(detectSessionCookies(js(`const session = require("express-session"); session({})`, "README.md"))).toEqual([]);
  });

  it("is part of runDetectors' result", () => {
    const r = runDetectors(js(`const session = require("express-session");\napp.use(session({}));`, "src/app.js"));
    expect(r.sessionCookies).toHaveLength(1);
  });
});

describe("the threat batch context block", () => {
  const cookie = one(`const session = require("express-session");\napp.use(session({ secret: "s" }));`);

  it("renders nothing when no cookie was found", () => {
    expect(renderSessionCookies([])).toEqual([]);
  });

  it("renders the effective attributes with their source", () => {
    expect(renderSessionCookies([cookie])).toEqual([
      SESSION_COOKIES_HEADER,
      "- express-session at server.js:2: HttpOnly yes (library default); Secure no (library default); SameSite not set (library default).",
      "",
    ]);
  });

  it("renders unknown attributes as unknown", () => {
    const c = one(`const s = require("express-session");\napp.use(s(opts));`);
    expect(renderSessionCookies([c])[1]).toContain("HttpOnly unknown (not a literal)");
  });

  const architecture: MergedArchitecture = {
    components: [{ id: "web", name: "web", type: "backend", description: "d", technologies: [], files: [], assets: [] }],
    dataFlows: [], trustBoundaries: [], unknowns: [], evidence: [], gapBindings: new Map(),
    componentEvidence: new Map(), dataFlowEvidence: new Map(), limitations: [],
  } as unknown as MergedArchitecture;

  it("appears in the batch before the file excerpts only when cookies were found", () => {
    const withCookie = buildThreatBatch({ architecture, gaps: [], elementIds: ["web"], files: [], sessionCookies: [cookie] });
    const without = buildThreatBatch({ architecture, gaps: [], elementIds: ["web"], files: [] });
    expect(withCookie.text).toContain(SESSION_COOKIES_HEADER);
    expect(withCookie.text.indexOf(SESSION_COOKIES_HEADER)).toBeLessThan(withCookie.text.indexOf("## FILE EXCERPTS"));
    expect(without.text).not.toContain(SESSION_COOKIES_HEADER);
    expect(withCookie.text.replace(renderSessionCookies([cookie]).join("\n") + "\n", "")).toBe(without.text);
  });
});

describe("threats prompt", () => {
  const prompt = loadPrompt(THREATS_PROMPT_NAME, THREATS_PROMPT_VERSION);

  it("describes the block and forbids HttpOnly cookie theft by script, keeping valid impacts", () => {
    expect(prompt.body).toContain("`## SESSION COOKIES`");
    expect(prompt.body).toContain("Do not claim that\n  injected or reflected script reads, steals or exfiltrates that cookie.");
    expect(prompt.body).toContain("send same-origin requests");
    expect(prompt.body).toContain("plaintext network traffic is a\n  different attack and is not affected by HttpOnly");
    expect(prompt.body).toContain("When the attribute is `unknown`,\n  or no block is present, do not assert either way.");
  });
});
