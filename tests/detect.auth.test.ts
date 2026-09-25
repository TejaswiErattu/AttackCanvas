import { describe, expect, it } from "vitest";
import { aliasTarget, authForRoute, detectAuth, handlerBody, isGuardName } from "@/server/detect/auth";
import { detectRoutes } from "@/server/detect/routes";
import type { DetectorInput, Route } from "@/server/detect/types";
import { NEXT_APP_ROUTE, SAMPLE_REPO } from "./detectSamples";

const routes = detectRoutes(SAMPLE_REPO);
const auth = detectAuth(SAMPLE_REPO, routes);

function statusOf(method: string, path: string): string | undefined {
  const route = routes.find((r) => r.method === method && r.path === path);
  return auth.find((a) => a.routeId === route?.id)?.status;
}

function factFor(method: string, path: string) {
  const route = routes.find((r) => r.method === method && r.path === path);
  return auth.find((a) => a.routeId === route?.id);
}

/** Builds a one-file Express app and returns the auth fact for its only route. */
function authOf(body: string, content?: string) {
  const file: DetectorInput = {
    path: "src/a.js",
    content: content ?? `const express = require("express");\n${body}\n`,
  };
  const [route] = detectRoutes([file]);
  return authForRoute(file, route);
}

describe("detectAuth: status", () => {
  it("is authenticated when a known guard call is used", () => {
    expect(statusOf("GET", "/api/v1/:id")).toBe("authenticated");
    expect(factFor("GET", "/api/v1/:id")?.signals).toContain(
      "passport.authenticate",
    );
  });

  it("is authenticated when the middleware name reads as a guard", () => {
    expect(statusOf("GET", "/api/v1")).toBe("authenticated");
    expect(factFor("GET", "/api/v1")?.signals).toContain("requireAuth");
  });

  it("is authenticated when the handler body calls a session guard", () => {
    expect(statusOf("GET", "/api/users")).toBe("authenticated");
    expect(factFor("GET", "/api/users")?.signals).toContain("getServerSession");
  });

  it("is unauthenticated when there is nothing at all", () => {
    expect(statusOf("GET", "/health")).toBe("unauthenticated");
    expect(statusOf("DELETE", "/api/v1/:id")).toBe("unauthenticated");
  });

  it("is unknown when middleware is imported and its name says nothing", () => {
    // auditLog comes from ../middleware/audit and is neither a known guard nor
    // guard-shaped, so the honest answer is that we cannot tell.
    expect(statusOf("POST", "/api/v1")).toBe("unknown");
  });

  it("does not call locally defined middleware unknown", () => {
    const fact = authOf(
      'function logIt(req, res, next) { next(); }\napp.get("/x", logIt, (req, res) => res.end());',
    );
    expect(fact.status).toBe("unauthenticated");
  });

  it.each([
    [
      "passport.authenticate",
      'app.get("/x", passport.authenticate("jwt"), h);',
    ],
    [
      "getSession",
      'app.get("/x", async (req, res) => { await getSession(req); });',
    ],
    [
      "getServerSession",
      'app.get("/x", async (req, res) => { await getServerSession(); });',
    ],
    ["verifyToken", 'app.get("/x", verifyToken, h);'],
    ["requireAuth", 'app.get("/x", requireAuth, h);'],
    ["isAuthenticated", 'app.get("/x", isAuthenticated, h);'],
    ["ensureLoggedIn", 'app.get("/x", ensureLoggedIn(), h);'],
    ["auth()", 'app.get("/x", async (req, res) => { await auth(); });'],
  ])("recognises the guard %s", (_label, body) => {
    expect(authOf(body).status).toBe("authenticated");
  });

  it.each([
    "requireLogin",
    "requireUser",
    "requireRole",
    "isAdmin",
    "verifyToken",
    "verifyJwt",
    "protectRoute",
    "checkAuth",
  ])("treats the guard-shaped name %s as authentication", (name) => {
    expect(authOf(`app.get("/x", ${name}, h);`).status).toBe("authenticated");
  });

  it.each(["authLimiter", "oauthRateLimiter", "authRateLimit"])(
    "does not treat the rate limiter %s as authentication",
    (name) => {
      // It matches the guard-name rule ("auth") but only slows requests down.
      const fact = authOf(`app.post("/x", ${name}, h);`);
      expect(fact.status).toBe("unauthenticated");
      expect(fact.signals).toEqual([]);
    },
  );

  it("calls an imported rate limiter unknown, like any other opaque middleware", () => {
    const fact = authOf(
      'const { authLimiter } = require("./limits");\napp.post("/x", authLimiter, h);',
    );
    expect(fact.status).toBe("unknown");
  });

  it("does not count a guard that only appears in a comment", () => {
    expect(
      authOf('app.post("/x", /* requireAuth, */ (req, res) => res.end());')
        .status,
    ).toBe("unauthenticated");
  });

  it("does not let a comment stretch one route's text over the next route's guard", () => {
    // The apostrophe in the comment used to end the argument scan early, so the body
    // ran to the end of the file and borrowed requireAuth from GET /me.
    const file: DetectorInput = {
      path: "src/a.js",
      content: [
        'app.post("/orders",',
        "  // don't cache this",
        "  async (req, res) => { res.end(); });",
        'app.get("/me", requireAuth, h);',
      ].join("\n"),
    };
    const [orders] = detectRoutes([file]);

    expect(orders.path).toBe("/orders");
    expect(authForRoute(file, orders).status).toBe("unauthenticated");
  });

  it("does not mistake an unrelated word containing auth for a guard", () => {
    // "author" contains "auth", so the name rule fires. That is a deliberate
    // over-match: a false "authenticated" would hide a threat, so it is recorded
    // here as known behaviour rather than silently accepted.
    expect(authOf('app.get("/x", authorFilter, h);').status).toBe(
      "authenticated",
    );
  });
});

describe("detectAuth: App Router exports built from a wrapper", () => {
  /** The auth fact for the only route of a one-file App Router route. */
  function appAuthOf(content: string) {
    const file: DetectorInput = { path: "app/api/items/route.ts", content };
    const [route] = detectRoutes([file]);
    return authForRoute(file, route);
  }

  it.each([
    [
      "withAuth",
      "export const POST = withAuth(async (req) => Response.json({}));",
    ],
    [
      "requireUser",
      "export const POST: Handler = requireUser(async (req) => Response.json({}));",
    ],
    ["auth.protect", "export const POST = auth.protect(handler);"],
  ])("counts the guard-named wrapper %s as authentication", (name, content) => {
    expect(appAuthOf(content)).toMatchObject({
      status: "authenticated",
      signals: [name],
    });
  });

  it.each([
    [
      "a wrapper whose name is not a guard",
      "export const POST = withLogging(handler);",
    ],
    ["a rate-limit wrapper", "export const POST = withAuthRateLimit(handler);"],
    [
      "a plain async arrow",
      "export const POST = async (req) => Response.json({});",
    ],
  ])("leaves %s unauthenticated", (_label, content) => {
    expect(appAuthOf(content).status).toBe("unauthenticated");
  });

  it("judges each export by its own wrapper, not its neighbour's", () => {
    const file: DetectorInput = {
      path: "app/api/items/route.ts",
      content:
        "export const GET = withAuth(list);\nexport const POST = withLogging(create);\n",
    };
    const routes = detectRoutes([file]);
    const status = (method: string) =>
      authForRoute(file, routes.find((r) => r.method === method) as Route)
        .status;

    expect(status("GET")).toBe("authenticated");
    expect(status("POST")).toBe("unauthenticated");
  });
});

describe("detectAuth: roles and admin", () => {
  it("flags a role check separately from authentication", () => {
    const fact = factFor("GET", "/admin/users");

    expect(fact?.status).toBe("authenticated");
    expect(fact?.roleChecks).toContain("requireRole");
    expect(fact?.roleChecks).toContain("role comparison");
  });

  it("flags an admin path even when the route is unauthenticated", () => {
    const fact = factFor("PUT", "/admin/settings");

    expect(fact?.adminPath).toBe(true);
    expect(fact?.status).toBe("unauthenticated");
  });

  it("does not flag an ordinary path as administrative", () => {
    expect(factFor("GET", "/health")?.adminPath).toBe(false);
  });

  it.each([
    ["requireRole", 'app.get("/x", requireRole("a"), h);'],
    ["hasRole", 'app.get("/x", async (req, res) => { hasRole(req, "a"); });'],
    ["isAdmin", 'app.get("/x", async (req, res) => { isAdmin(req); });'],
    [
      "role comparison",
      'app.get("/x", async (req, res) => { if (req.user.role === "a") {} });',
    ],
    [
      "roles.includes",
      'app.get("/x", async (req, res) => { user.roles.includes("a"); });',
    ],
  ])("detects the role check %s", (label, body) => {
    expect(authOf(body).roleChecks).toContain(label);
  });
});

describe("handlerBody", () => {
  it("scopes an App Router handler to its own export", () => {
    const route = routes.find(
      (r) => r.file === NEXT_APP_ROUTE.path && r.method === "POST",
    ) as Route;
    const body = handlerBody(NEXT_APP_ROUTE, route);

    // The GET beside it calls getServerSession; POST must not inherit that.
    expect(body).toContain("POST");
    expect(body).not.toContain("getServerSession");
  });

  it("gives a handler named in an export list the whole file", () => {
    // `export { handler as GET, handler as POST }` shares one offset: GET used to get
    // an empty slice and POST only the export line, so the session check was missed.
    const file: DetectorInput = {
      path: "app/api/items/route.ts",
      content: [
        "async function handler(req: Request) {",
        "  const session = await getServerSession();",
        "  if (!session) return new Response(null, { status: 401 });",
        "}",
        "export { handler as GET, handler as POST };",
      ].join("\n"),
    };
    const found = detectRoutes([file]);

    expect(found.map((r) => r.method)).toEqual(["GET", "POST"]);
    for (const route of found) {
      expect(handlerBody(file, route)).toBe(file.content);
      expect(authForRoute(file, route)).toMatchObject({
        status: "authenticated",
        signals: ["getServerSession"],
      });
    }
  });

  it("gives a Pages API handler the whole file, which is one handler", () => {
    const file: DetectorInput = {
      path: "pages/api/x.ts",
      content:
        'export default function h(req, res) { if (req.method === "GET") {} }',
    };
    const [route] = detectRoutes([file]);

    expect(handlerBody(file, route)).toBe(file.content);
  });

  it("returns something harmless when the route line does not line up", () => {
    const file: DetectorInput = { path: "src/a.js", content: "" };
    const route: Route = {
      id: "route-1",
      method: "GET",
      path: "/x",
      normalizedPath: "/x",
      file: "src/a.js",
      line: 99,
      middleware: [],
      framework: "express",
    };

    expect(() => handlerBody(file, route)).not.toThrow();
  });
});

describe("detectAuth: shape", () => {
  it("returns exactly one fact per route, in route order", () => {
    expect(auth).toHaveLength(routes.length);
    expect(auth.map((a) => a.routeId)).toEqual(routes.map((r) => r.id));
  });

  it("copes with a route whose file is missing", () => {
    const orphan: Route = {
      id: "route-1",
      method: "GET",
      path: "/x",
      normalizedPath: "/x",
      file: "gone.js",
      line: 1,
      middleware: ["requireAuth"],
      framework: "express",
    };
    const [fact] = detectAuth([], [orphan]);

    expect(fact.status).toBe("authenticated");
    expect(fact.routeId).toBe("route-1");
  });

  it("never repeats a signal", () => {
    for (const fact of auth) {
      expect(new Set(fact.signals).size).toBe(fact.signals.length);
    }
  });
});

// ---------------------------------------------------------------------------
// NodeGoat-style middleware (OWASP/NodeGoat app/routes/index.js)
// ---------------------------------------------------------------------------

describe("detectAuth: member-alias middleware", () => {
  const NODEGOAT_INDEX = [
    'const SessionHandler = require("./session");',
    'const ProfileHandler = require("./profile");',
    "const index = (app, db) => {",
    "    const sessionHandler = new SessionHandler(db);",
    "    const profileHandler = new ProfileHandler(db);",
    "    // Middleware to check if a user is logged in",
    "    const isLoggedIn = sessionHandler.isLoggedInMiddleware;",
    "    const check = sessionHandler.isLoggedInMiddleware;",
    "    const opaque = sessionHandler.somethingElse;",
    '    app.post("/login", sessionHandler.handleLoginRequest);',
    '    app.post("/profile", isLoggedIn, profileHandler.handleProfileUpdate);',
    '    app.post("/memos", check, profileHandler.addMemos);',
    '    app.post("/contributions", opaque, profileHandler.update);',
    '    app.post("/open", profileHandler.update);',
    "};",
    "module.exports = index;",
  ].join("\n");
  const file: DetectorInput = { path: "app/routes/index.js", content: NODEGOAT_INDEX };
  const found = detectRoutes([file]);
  const fact = (path: string) => authForRoute(file, found.find((r) => r.path === path)!);

  it("treats isLoggedIn as an authentication guard", () => {
    expect(fact("/profile").status).toBe("authenticated");
    expect(fact("/profile").signals).toContain("isLoggedIn");
  });

  it("judges a neutral alias by the member it points at", () => {
    expect(aliasTarget(NODEGOAT_INDEX, "check")).toBe("sessionHandler.isLoggedInMiddleware");
    expect(fact("/memos").status).toBe("authenticated");
    expect(fact("/memos").signals).toContain("check = sessionHandler.isLoggedInMiddleware");
  });

  it("reports an alias to an unrecognised member as unknown, not unauthenticated", () => {
    expect(fact("/contributions").status).toBe("unknown");
  });

  it("still reports a route with no middleware as unauthenticated", () => {
    expect(fact("/open").status).toBe("unauthenticated");
  });

  it("does not read a login handler or rate limiter as a guard", () => {
    expect(isGuardName("handleLoginRequest")).toBe(false);
    expect(isGuardName("loggedInLimiter")).toBe(false);
    expect(isGuardName("ensureLoggedIn")).toBe(true);
  });

  it("ignores a commented-out alias and non-member right-hand sides", () => {
    expect(aliasTarget("// const g = a.isLoggedInMiddleware;", "g")).toBeUndefined();
    expect(aliasTarget("const g = makeGuard();", "g")).toBeUndefined();
    expect(aliasTarget("const g = a.b;", "a.b")).toBeUndefined();
  });
});
