import { describe, expect, it } from "vitest";
import {
  appRouterPath,
  detectRoutes,
  joinPaths,
  middlewareName,
  mountPrefixes,
  pagesApiPath,
  splitCallArguments,
} from "@/server/detect/routes";
import { normalizeRoutePath } from "@/server/detect/shared";
import {
  EXPRESS_ADMIN_ROUTER,
  EXPRESS_APP,
  EXPRESS_USERS_ROUTER,
  NEXT_APP_DYNAMIC_ROUTE,
  NEXT_APP_ROUTE,
  NEXT_PAGES_API,
  NEXT_PAGES_API_INDEX,
  SAMPLE_REPO,
} from "./detectSamples";

const routes = detectRoutes(SAMPLE_REPO);

function find(method: string, path: string) {
  return routes.find((route) => route.method === method && route.path === path);
}

describe("normalizeRoutePath", () => {
  it.each([
    ["/users/[id]", "/users/:id"],
    ["/a/[b]/c/[d]", "/a/:b/c/:d"],
    ["/api/proxy/[...slug]", "/api/proxy/*"],
    ["/api/[[...all]]", "/api/*"],
    ["/users/:id", "/users/:id"],
    ["/health", "/health"],
    ["/", "/"],
  ])("maps %s to %s", (input, expected) => {
    expect(normalizeRoutePath(input)).toBe(expected);
  });
});

describe("joinPaths", () => {
  it.each([
    ["", "/users", "/users"],
    ["/", "/users", "/users"],
    ["/api", "/users", "/api/users"],
    ["/api/", "/users", "/api/users"],
    ["/api", "/", "/api"],
    ["/api", "", "/api"],
    ["/api", "users", "/api/users"],
  ])("joins %s and %s into %s", (prefix, path, expected) => {
    expect(joinPaths(prefix, path)).toBe(expected);
  });
});

describe("splitCallArguments", () => {
  it("splits on top-level commas only", () => {
    const { args } = splitCallArguments("a, b, c)", 0);
    expect(args).toEqual(["a", "b", "c"]);
  });

  it("ignores commas inside nested calls, arrays and objects", () => {
    const { args } = splitCallArguments(
      "auth({ a: 1, b: 2 }), [x, y], fn(p, q))",
      0,
    );
    expect(args).toEqual(["auth({ a: 1, b: 2 })", "[x, y]", "fn(p, q)"]);
  });

  it("ignores commas and parens inside strings", () => {
    const { args } = splitCallArguments(`"a,b)c", handler)`, 0);
    expect(args).toEqual([`"a,b)c"`, "handler"]);
  });

  it("does not run away on an unbalanced call", () => {
    expect(() => splitCallArguments("a, b(", 0)).not.toThrow();
  });
});

describe("middlewareName", () => {
  it.each([
    ["requireAuth", "requireAuth"],
    ["passport.authenticate('jwt')", "passport.authenticate"],
    ["requireRole(`admin`)", "requireRole"],
    ["a.b.c", "a.b.c"],
  ])("reads %s as %s", (argument, expected) => {
    expect(middlewareName(argument)).toBe(expected);
  });

  it.each([
    "(req, res) => res.json({})",
    "async (req, res) => {}",
    "function (req, res) {}",
    "async function handler() {}",
  ])("treats the inline function %s as unnamed", (argument) => {
    expect(middlewareName(argument)).toBeUndefined();
  });
});

describe("appRouterPath", () => {
  it.each([
    ["app/api/users/route.ts", "/api/users"],
    ["src/app/api/users/route.ts", "/api/users"],
    ["app/route.js", "/"],
    ["src/app/(dashboard)/reports/[id]/route.ts", "/reports/[id]"],
    ["app/(a)/(b)/x/route.ts", "/x"],
    ["app/api/proxy/[...slug]/route.js", "/api/proxy/[...slug]"],
  ])("derives %s as %s", (path, expected) => {
    expect(appRouterPath(path)).toBe(expected);
  });

  it.each([
    "app/api/users/page.tsx",
    "pages/api/users.ts",
    "src/routes/users.ts",
    "app/api/users/route.css",
    // "_" marks a private file or folder Next does not serve. Seen live in
    // shadcn-ui/taxonomy, where _route.ts was being reported as a route.
    "app/api/auth/[...nextauth]/_route.ts",
    "app/_disabled/route.ts",
    "src/app/_lib/route.ts",
  ])("does not treat %s as an App Router route", (path) => {
    expect(appRouterPath(path)).toBeUndefined();
  });
});

describe("pagesApiPath", () => {
  it.each([
    ["pages/api/users.ts", "/api/users"],
    ["src/pages/api/users.ts", "/api/users"],
    ["pages/api/index.ts", "/api"],
    ["pages/api/users/index.js", "/api/users"],
    ["pages/api/webhooks/[id].ts", "/api/webhooks/[id]"],
  ])("derives %s as %s", (path, expected) => {
    expect(pagesApiPath(path)).toBe(expected);
  });

  it.each([
    "pages/index.tsx",
    "pages/about.tsx",
    "app/api/x/route.ts",
    "pages/api/_helpers.ts",
    "pages/api/_lib/db.ts",
  ])("does not treat %s as a Pages API route", (path) => {
    expect(pagesApiPath(path)).toBeUndefined();
  });
});

describe("mountPrefixes", () => {
  it("resolves app.use to the imported router file", () => {
    const prefixes = mountPrefixes([
      EXPRESS_APP,
      EXPRESS_USERS_ROUTER,
      EXPRESS_ADMIN_ROUTER,
    ]);

    expect(prefixes.get("src/routes/users.js")).toBe("/api/v1");
    expect(prefixes.get("src/routes/admin.js")).toBe("/admin");
  });

  it("gives no prefix when the router is not a relative import", () => {
    const app = {
      path: "src/app.js",
      content: 'const r = require("some-pkg");\napp.use("/x", r);\n',
    };
    expect(mountPrefixes([app]).size).toBe(0);
  });

  it("gives no prefix when the same file is mounted twice at different paths", () => {
    const app = {
      path: "src/app.js",
      content:
        'const r = require("./r");\napp.use("/a", r);\napp.use("/b", r);\n',
    };
    const prefixes = mountPrefixes([app, { path: "src/r.js", content: "" }]);

    expect(prefixes.get("src/r.js")).toBe("");
  });
});

describe("detectRoutes: Express", () => {
  it("finds routes declared directly on the app", () => {
    expect(find("GET", "/health")).toMatchObject({
      file: "src/app.js",
      framework: "express",
      middleware: [],
    });
    expect(find("POST", "/login")).toBeDefined();
  });

  it("applies the app.use mount prefix to a router's routes", () => {
    expect(find("GET", "/api/v1/:id")).toMatchObject({
      file: "src/routes/users.js",
      middleware: ["passport.authenticate"],
    });
    expect(find("GET", "/admin/users")).toMatchObject({
      middleware: ["requireRole"],
    });
  });

  it("captures middleware between the path and the handler", () => {
    expect(find("GET", "/api/v1")?.middleware).toEqual(["requireAuth"]);
    expect(find("POST", "/api/v1")?.middleware).toEqual(["auditLog"]);
    expect(find("DELETE", "/api/v1/:id")?.middleware).toEqual([]);
  });

  it("does not mistake the handler for middleware", () => {
    for (const route of routes) {
      expect(route.middleware).not.toContain("res");
      expect(route.middleware.join(" ")).not.toContain("=>");
    }
  });

  it("reports the line the route is declared on", () => {
    const lines = EXPRESS_APP.content.split("\n");
    const expected =
      lines.findIndex((l) => l.includes('app.get("/health"')) + 1;

    expect(find("GET", "/health")?.line).toBe(expected);
  });

  it.each([
    ["an empty file", ""],
    ["an unterminated call", 'app.get("/x", '],
    ["an unterminated string", 'app.get("/x'],
    ["a method-like property that is not a route", "const x = obj.get;"],
  ])("handles %s without throwing", (_label, content) => {
    expect(() => detectRoutes([{ path: "src/a.js", content }])).not.toThrow();
  });

  it.each([
    ["a header read", 'req.get("Referrer");'],
    ["a response header read", 'res.get("ETag");'],
    ["Express's settings getter", 'app.get("view engine");'],
    ["a settings getter with a space", 'app.get("trust proxy");'],
    ["an unrelated receiver", 'cache.get("some-key");'],
    ["a Map read", 'headers.get("content-type");'],
  ])("does not mistake %s for a route", (_label, content) => {
    expect(detectRoutes([{ path: "src/a.js", content }])).toEqual([]);
  });

  it.each([
    ["app", 'app.get("/a", h);'],
    ["router", 'router.get("/a", h);'],
    ["a named router", 'usersRouter.get("/a", h);'],
    ["a named app", 'adminApp.get("/a", h);'],
  ])("still finds a route on %s", (_label, content) => {
    expect(detectRoutes([{ path: "src/a.js", content }])).toHaveLength(1);
  });

  it("accepts a wildcard path", () => {
    expect(
      detectRoutes([{ path: "src/a.js", content: 'app.get("*", h);' }]),
    ).toHaveLength(1);
  });

  it("ignores a path that is not a literal, rather than guessing", () => {
    const found = detectRoutes([
      { path: "src/a.js", content: "app.get(ROUTES.users, handler);" },
    ]);
    expect(found).toEqual([]);
  });

  it("does not invent a route from a commented-out call", () => {
    // Each of these became an unauthenticated route and a 0.9 authn gap.
    const content = [
      '// app.delete("/users/:id", removeUser);',
      "/*",
      ' * app.post("/orders", createOrder);',
      " */",
      'app.get("/live", (req, res) => res.end()); // app.put("/x", h);',
    ].join("\n");
    const found = detectRoutes([{ path: "src/a.js", content }]);

    expect(found.map((r) => [r.method, r.path, r.line])).toEqual([
      ["GET", "/live", 5],
    ]);
  });

  it("keeps the middleware that follows a comment inside the call", () => {
    // The comment used to glue onto `protect`, whose name was then unreadable.
    const content = [
      "router.post(",
      '  "/products",',
      "  // must be logged in, and don't cache",
      "  protect,",
      "  createProduct,",
      ");",
    ].join("\n");
    const [route] = detectRoutes([{ path: "src/a.js", content }]);

    expect(route).toMatchObject({ path: "/products", line: 1 });
    expect(route.middleware).toEqual(["protect"]);
  });

  it("applies no prefix from a commented-out mount", () => {
    const app = {
      path: "src/app.js",
      content:
        'const users = require("./users");\n// app.use("/api", users);\n',
    };
    const users = { path: "src/users.js", content: 'router.get("/", h);' };

    expect(detectRoutes([app, users]).map((r) => r.path)).toEqual(["/"]);
  });
});

describe("detectRoutes: Next.js", () => {
  it("finds each exported method in an App Router file", () => {
    expect(find("GET", "/api/users")).toMatchObject({
      framework: "next_app",
      file: NEXT_APP_ROUTE.path,
    });
    expect(find("POST", "/api/users")).toBeDefined();
  });

  it("reads handlers declared as exported consts", () => {
    expect(find("GET", "/reports/[id]")).toBeDefined();
    expect(find("DELETE", "/reports/[id]")).toBeDefined();
  });

  it("keeps the native path and offers a normalized one", () => {
    expect(find("GET", "/reports/[id]")?.normalizedPath).toBe("/reports/:id");
    expect(find("POST", "/api/proxy/[...slug]")?.normalizedPath).toBe(
      "/api/proxy/*",
    );
  });

  it("drops route groups from the path", () => {
    expect(NEXT_APP_DYNAMIC_ROUTE.path).toContain("(dashboard)");
    expect(find("GET", "/reports/[id]")?.path).not.toContain("dashboard");
  });

  it("narrows a Pages API handler to the methods it checks for", () => {
    const webhooks = routes.filter(
      (route) => route.file === NEXT_PAGES_API.path,
    );

    expect(webhooks.map((route) => route.method).sort()).toEqual([
      "GET",
      "POST",
    ]);
    expect(webhooks.every((route) => route.framework === "next_pages")).toBe(
      true,
    );
  });

  it("falls back to ALL when a Pages API handler checks no method", () => {
    const index = routes.filter(
      (route) => route.file === NEXT_PAGES_API_INDEX.path,
    );

    expect(index).toHaveLength(1);
    expect(index[0]).toMatchObject({ method: "ALL", path: "/api" });
  });

  it("ignores a commented-out App Router export and a commented-out method check", () => {
    const found = detectRoutes([
      {
        path: "app/api/x/route.ts",
        content:
          "// export async function DELETE() {}\nexport async function GET() {}\n",
      },
      {
        path: "pages/api/y.ts",
        content:
          '// if (req.method === "POST") {}\nexport default function h(req, res) {}\n',
      },
    ]);

    expect(found.map((r) => [r.method, r.path])).toEqual([
      ["GET", "/api/x"],
      ["ALL", "/api/y"],
    ]);
  });

  it("does not treat a non-method export as a handler", () => {
    const found = detectRoutes([
      {
        path: "app/api/x/route.ts",
        content:
          "export const revalidate = 60;\nexport async function GET() {}\n",
      },
    ]);
    expect(found.map((route) => route.method)).toEqual(["GET"]);
  });
});

describe("detectRoutes: ids", () => {
  it("gives every route a unique, sequential id", () => {
    expect(routes.map((route) => route.id)).toEqual(
      routes.map((_, index) => `route-${index + 1}`),
    );
  });

  it("assigns the same ids however the input is ordered", () => {
    const shuffled = detectRoutes([...SAMPLE_REPO].reverse());
    expect(shuffled).toEqual(routes);
  });

  it("finds every sample route and no more", () => {
    expect(routes).toHaveLength(16);
  });
});
