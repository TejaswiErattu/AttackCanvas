import {
  byPath,
  lineAt,
  lineStarts,
  maskComments,
  normalizeRoutePath,
  normalizeSeparators,
} from "@/server/detect/shared";
import { workerEntryOffset } from "@/server/detect/web";
import type {
  DetectorInput,
  HttpMethod,
  Route,
} from "@/server/detect/types";

/**
 * HTTP entry points: Express handlers, Next.js App Router route handlers and Next.js
 * Pages API routes.
 *
 * AST NOTE (applies to this whole module): this is regex plus paren balancing, which is
 * the MVP trade. The TypeScript compiler API (ts.createSourceFile + a visitor) would
 * give real syntax and scope, and would fix the cases this cannot see:
 *   - a path built from a variable or template (`app.get(ROUTES.users, …)`);
 *   - middleware spread from an array (`app.get("/x", ...guards, handler)`);
 *   - routers re-exported or wrapped before mounting;
 *   - `app.route("/x").get(…).post(…)` chains;
 *   - a method name shadowed by a local variable.
 * Those show up as missed routes rather than wrong ones, which is the safer failure for
 * a threat model: a missed route is a gap, an invented one is a false finding.
 *
 * Every pattern runs over comment-masked source (see `withoutComments`): a commented-out
 * `app.post(...)` is not a route, and a comment between a route's arguments is not
 * middleware and must not hide the guard after it.
 */

const METHODS: HttpMethod[] = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
  "ALL",
];

/**
 * (app|router).get("/…"  — group 1 is the method, group 2 the opening quote.
 *
 * The receiver has to look like an app or a router, and the path has to start with "/"
 * or be "*". Both guards earn their place against real code:
 *   - `req.get("Referrer")` and `res.get("ETag")` read a header;
 *   - `app.get("view engine")` is Express's settings getter, not a route.
 * Accepting any receiver turned all three into routes when this ran over
 * expressjs/express. A missed route is a gap in the model; an invented one is a false
 * finding, so the guard is deliberately strict.
 */
const EXPRESS_ROUTE = new RegExp(
  "\\b(?:app|router|[A-Za-z_$][\\w$]*(?:Router|App|router|app))" +
    "\\.(get|post|put|patch|delete|all|head|options)\\(\\s*(['\"`])(?=[/*])",
  "g",
);

/** app.use("/prefix", router) — group 2 is the path, group 3 the identifier. */
const EXPRESS_USE =
  /\b([A-Za-z_$][\w$]*)\.use\(\s*(['"`])([^'"`]*)\2\s*,\s*([A-Za-z_$][\w$]*)\s*\)/g;

/** Default and namespace: `import x from "m"`, `import * as x from "m"`, `const x = require("m")`. */
const IMPORT_DEFAULT =
  /(?:import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*)(['"`])([^'"`]+)\3/g;

/** Named: `import { a, b as c } from "m"` and `const { a, b } = require("m")`. */
const IMPORT_NAMED =
  /(?:import\s*\{([^}]*)\}\s*from\s*|(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*)(['"`])([^'"`]+)\3/g;

/** export async function GET / export const GET = / export { GET } */
const NEXT_HANDLER =
  /export\s+(?:async\s+)?function\s+([A-Z]+)\b|export\s+const\s+([A-Z]+)\s*[:=]|export\s*\{([^}]*)\}/g;

/** req.method === "POST" and switch (req.method) { case "POST": */
const REQ_METHOD =
  /\breq(?:uest)?\.method\s*===?\s*(['"`])([A-Za-z]+)\1|case\s+(['"`])([A-Za-z]+)\3/g;

function asMethod(raw: string): HttpMethod | undefined {
  const upper = raw.toUpperCase();
  return (METHODS as string[]).includes(upper)
    ? (upper as HttpMethod)
    : undefined;
}

/**
 * Reads a quoted string starting at `open`, honouring backslash escapes.
 * Returns the contents and the offset just past the closing quote.
 */
function readString(
  content: string,
  open: number,
  quote: string,
): { value: string; end: number } | undefined {
  let value = "";
  for (let index = open + 1; index < content.length; index++) {
    const character = content[index];
    if (character === "\\") {
      value += content[index + 1] ?? "";
      index += 1;
      continue;
    }
    if (character === quote) return { value, end: index + 1 };
    if (character === "\n" && quote !== "`") return undefined;
    value += character;
  }
  return undefined;
}

/**
 * The arguments after the path, split on top-level commas, up to the call's closing
 * paren. Depth-aware over (), [] and {}, and skips over string literals so a comma or
 * bracket inside one does not confuse it.
 */
export function splitCallArguments(
  content: string,
  start: number,
): { args: string[]; end: number } {
  const args: string[] = [];
  let depth = 0;
  let current = "";

  for (let index = start; index < content.length; index++) {
    const character = content[index];

    if (character === '"' || character === "'" || character === "`") {
      const string = readString(content, index, character);
      if (!string) break;
      current += content.slice(index, string.end);
      index = string.end - 1;
      continue;
    }

    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" && depth === 0) {
      args.push(current);
      return {
        args: args.map((arg) => arg.trim()).filter(Boolean),
        end: index + 1,
      };
    } else if (character === ")" || character === "]" || character === "}")
      depth -= 1;

    if (character === "," && depth === 0) {
      args.push(current);
      current = "";
      continue;
    }
    current += character;
  }

  return {
    args: args.map((arg) => arg.trim()).filter(Boolean),
    end: content.length,
  };
}

/**
 * The name a middleware argument refers to: `requireAuth` from `requireAuth`,
 * `passport.authenticate` from `passport.authenticate("jwt")`. An inline function is
 * not a name, so it is dropped rather than guessed at.
 */
export function middlewareName(argument: string): string | undefined {
  const trimmed = argument.trim();
  if (/^(?:async\s*)?(?:\(|function\b)/.test(trimmed)) return undefined;
  if (/=>/.test(trimmed) && !/^[\w$.]+\s*\(/.test(trimmed)) return undefined;

  const match = /^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)/.exec(trimmed);
  return match ? match[1] : undefined;
}

/** Local identifier -> module specifier, for the imports in one file. */
export function importsIn(content: string): Map<string, string> {
  const imports = new Map<string, string>();

  const direct = new RegExp(IMPORT_DEFAULT.source, IMPORT_DEFAULT.flags);
  let match: RegExpExecArray | null;
  while ((match = direct.exec(content)) !== null) {
    const name = match[1] ?? match[2];
    if (name) imports.set(name, match[4]);
  }

  // Destructured forms matter as much as default ones: `const { requireAuth } =
  // require("./auth")` is the common Express shape, and missing it would make every
  // such middleware look locally defined rather than opaque.
  const named = new RegExp(IMPORT_NAMED.source, IMPORT_NAMED.flags);
  while ((match = named.exec(content)) !== null) {
    const specifier = match[4];
    for (const part of (match[1] ?? match[2] ?? "").split(",")) {
      // `a as b` binds b; `a` binds a.
      const local = /(?:^|\bas\s+)([A-Za-z_$][\w$]*)\s*$/.exec(
        part.trim(),
      )?.[1];
      if (local) imports.set(local, specifier);
    }
  }

  return imports;
}

/** Joins a mount prefix and a route path without doubling or dropping a slash. */
export function joinPaths(prefix: string, path: string): string {
  if (!prefix || prefix === "/") return path || "/";
  const left = prefix.replace(/\/+$/, "");
  if (!path || path === "/") return left || "/";
  return `${left}${path.startsWith("/") ? "" : "/"}${path}`;
}

/**
 * Mount prefixes declared with `app.use("/api", usersRouter)`, resolved to the file the
 * router was imported from. Only the simple case: a bare identifier imported by a
 * relative path that matches exactly one loaded file. Anything else gets no prefix,
 * because a wrong prefix is worse than a missing one. detectRoutes passes
 * comment-masked files, so a commented-out mount applies no prefix.
 */
export function mountPrefixes(
  files: readonly DetectorInput[],
): Map<string, string> {
  const byNormalizedPath = new Map<string, string>();
  for (const file of files) {
    byNormalizedPath.set(normalizeSeparators(file.path), file.path);
  }

  const resolve = (fromFile: string, specifier: string): string | undefined => {
    if (!specifier.startsWith(".")) return undefined;

    const fromDir = normalizeSeparators(fromFile).split("/").slice(0, -1);
    const parts = specifier.split("/");
    const stack = [...fromDir];

    for (const part of parts) {
      if (part === "." || part === "") continue;
      else if (part === "..") stack.pop();
      else stack.push(part);
    }
    const base = stack.join("/");

    const candidates = [
      base,
      `${base}.ts`,
      `${base}.js`,
      `${base}.tsx`,
      `${base}.jsx`,
      `${base}/index.ts`,
      `${base}/index.js`,
    ];
    for (const candidate of candidates) {
      const hit = byNormalizedPath.get(candidate);
      if (hit) return hit;
    }
    return undefined;
  };

  const prefixes = new Map<string, string>();

  for (const file of byPath(files)) {
    const imports = importsIn(file.content);
    const pattern = new RegExp(EXPRESS_USE.source, EXPRESS_USE.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(file.content)) !== null) {
      const [, , , mountPath, identifier] = match;
      if (!mountPath.startsWith("/")) continue;

      const specifier = imports.get(identifier);
      if (!specifier) continue;

      const target = resolve(file.path, specifier);
      // A file mounted twice has an ambiguous prefix, so neither is applied.
      if (!target) continue;
      if (prefixes.has(target) && prefixes.get(target) !== mountPath) {
        prefixes.set(target, "");
        continue;
      }
      prefixes.set(target, mountPath);
    }
  }

  return prefixes;
}

function isJavaScript(path: string): boolean {
  return /\.(?:ts|tsx|js|jsx|mjs|cjs)$/.test(normalizeSeparators(path));
}

/** Express handlers in one file, with their middleware. */
function expressRoutes(
  file: DetectorInput,
  prefix: string,
): Omit<Route, "id">[] {
  const routes: Omit<Route, "id">[] = [];
  const starts = lineStarts(file.content);
  const pattern = new RegExp(EXPRESS_ROUTE.source, EXPRESS_ROUTE.flags);
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(file.content)) !== null) {
    const method = asMethod(match[1]);
    if (!method) continue;

    const quoteOffset = match.index + match[0].length - 1;
    const path = readString(file.content, quoteOffset, match[2]);
    if (!path) continue;

    const rest = file.content.slice(path.end).replace(/^\s*,?/, "");
    const offset =
      path.end + (file.content.slice(path.end).length - rest.length);
    const { args } = splitCallArguments(file.content, offset);

    // The last argument is the handler; everything before it is middleware.
    const middleware = args
      .slice(0, Math.max(0, args.length - 1))
      .map(middlewareName)
      .filter((name): name is string => name !== undefined);

    const full = joinPaths(prefix, path.value);
    routes.push({
      method,
      path: full,
      normalizedPath: normalizeRoutePath(full),
      file: file.path,
      line: lineAt(starts, match.index),
      middleware,
      framework: "express",
    });
  }

  return routes;
}

/** Next ignores any file or folder whose name starts with "_". */
function hasPrivateSegment(path: string): boolean {
  return path.split("/").some((segment) => segment.startsWith("_"));
}

/**
 * App Router path from the folder names: drop a leading "src/", the "app/" segment and
 * the trailing "route.ts", and drop route groups like "(marketing)", which organise
 * folders without appearing in the URL.
 */
export function appRouterPath(path: string): string | undefined {
  const normalized = normalizeSeparators(path).replace(/^src\//, "");
  // The slash before "route" is required, not optional: "_route.ts" is a private file
  // Next deliberately does not serve, and an optional slash matched it. Seen live in
  // shadcn-ui/taxonomy, which ships app/api/auth/[...nextauth]/_route.ts.
  if (!/^app\/(?:.*\/)?route\.(?:ts|tsx|js|jsx|mjs)$/.test(normalized))
    return undefined;
  if (hasPrivateSegment(normalized)) return undefined;

  const segments = normalized
    .split("/")
    .slice(1, -1)
    .filter((segment) => !/^\(.*\)$/.test(segment));

  return `/${segments.join("/")}`.replace(/\/{2,}/g, "/");
}

/**
 * Pages API path: "pages/api/users/[id].ts" -> "/api/users/[id]", and an "index" file
 * takes its directory's path.
 */
export function pagesApiPath(path: string): string | undefined {
  const normalized = normalizeSeparators(path).replace(/^src\//, "");
  if (!/^pages\/api\/.+\.(?:ts|tsx|js|jsx|mjs)$/.test(normalized))
    return undefined;
  if (hasPrivateSegment(normalized)) return undefined;

  const withoutExtension = normalized.replace(/\.(?:ts|tsx|js|jsx|mjs)$/, "");
  const segments = withoutExtension.split("/").slice(1); // drop "pages"
  if (segments[segments.length - 1] === "index") segments.pop();

  return `/${segments.join("/")}`.replace(/\/{2,}/g, "/");
}

/**
 * Exported HTTP method handlers in an App Router route file, with their offsets.
 * `listed` marks a name from an export list (`export { handler as GET }`), whose offset
 * is the list, not the handler's own declaration.
 */
export function appRouterMethods(
  content: string,
): { method: HttpMethod; offset: number; listed: boolean }[] {
  const found: { method: HttpMethod; offset: number; listed: boolean }[] = [];
  const pattern = new RegExp(NEXT_HANDLER.source, NEXT_HANDLER.flags);
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(content)) !== null) {
    const names = match[1] ?? match[2] ?? match[3] ?? "";
    for (const raw of names.split(/[,\s]+/)) {
      const method = asMethod(raw.replace(/\bas\b.*$/, "").trim());
      if (method && method !== "ALL")
        found.push({
          method,
          offset: match.index,
          listed: match[3] !== undefined,
        });
    }
  }
  return found;
}

/** Methods a Pages API handler narrows itself to, if it checks req.method at all. */
function pagesApiMethods(content: string): HttpMethod[] {
  const methods = new Set<HttpMethod>();
  const pattern = new RegExp(REQ_METHOD.source, REQ_METHOD.flags);
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(content)) !== null) {
    const method = asMethod(match[2] ?? match[4] ?? "");
    if (method && method !== "ALL") methods.add(method);
  }
  return [...methods];
}

/**
 * A source file with its comments blanked, masked once and shared by every pattern
 * below. Offsets, newlines and string literals are preserved, so paths read from it and
 * the line numbers taken from it are the same as the original's. Other files pass
 * through unchanged.
 */
function withoutComments(file: DetectorInput): DetectorInput {
  return isJavaScript(file.path)
    ? { path: file.path, content: maskComments(file.content) }
    : file;
}

/**
 * Every route in the repository, with stable ids assigned in path then line order.
 */
export function detectRoutes(files: readonly DetectorInput[]): Route[] {
  const sorted = byPath(files).map(withoutComments);
  const prefixes = mountPrefixes(sorted);
  const found: Omit<Route, "id">[] = [];

  for (const file of sorted) {
    if (!isJavaScript(file.path)) continue;

    const appPath = appRouterPath(file.path);
    if (appPath !== undefined) {
      const starts = lineStarts(file.content);
      for (const { method, offset } of appRouterMethods(file.content)) {
        found.push({
          method,
          path: appPath,
          normalizedPath: normalizeRoutePath(appPath),
          file: file.path,
          line: lineAt(starts, offset),
          middleware: [],
          framework: "next_app",
        });
      }
      continue;
    }

    const apiPath = pagesApiPath(file.path);
    if (apiPath !== undefined) {
      const narrowed = pagesApiMethods(file.content);
      // A Pages API handler is one default export serving every method unless it
      // checks req.method, so ALL is the honest answer when it does not.
      const methods: HttpMethod[] = narrowed.length > 0 ? narrowed : ["ALL"];
      for (const method of methods) {
        found.push({
          method,
          path: apiPath,
          normalizedPath: normalizeRoutePath(apiPath),
          file: file.path,
          line: 1,
          middleware: [],
          framework: "next_pages",
        });
      }
      continue;
    }

    // A Worker entry file dispatches inside one fetch handler. Checked on the original
    // content, since the masked copy has already lost the comments it would skip anyway.
    const entry = workerEntryOffset(file.content);
    if (entry !== undefined) {
      found.push(...workerRoutes(file, entry));
      continue;
    }

    found.push(...expressRoutes(file, prefixes.get(file.path) ?? ""));
  }

  return found.map((route, index) => ({ id: `route-${index + 1}`, ...route }));
}

// ---------------------------------------------------------------------------
// Cloudflare Workers
// ---------------------------------------------------------------------------

/** `url.pathname === "/x"`, `pathname == '/x'`, `path === "/x"`: group 2 is the path. */
const WORKER_PATH_EQUALS =
  /\b(?:pathname|path)\s*===?\s*(['"`])(\/[^'"`\n]*)\1/g;

/** `url.pathname.startsWith("/api")`: group 2 is the prefix. */
const WORKER_PATH_PREFIX =
  /\bpathname\s*\.\s*startsWith\s*\(\s*(['"`])(\/[^'"`\n]*)\1/g;

/** `request.method === "POST"` and `request.method !== "POST"`: group 2 is the method. */
const WORKER_METHOD = /\b(?:req|request)\s*\.\s*method\s*[!=]==?\s*(['"`])([A-Za-z]+)\1/g;

/**
 * Routes a Worker's fetch handler dispatches on. A Worker has one entry point and routes
 * by comparing `url.pathname` and `request.method` itself, so the routes are the paths it
 * compares against crossed with the methods it compares against. With no path comparison
 * the entry point serves every path ("*"); with no method comparison, every method (ALL).
 *
 * A `!==` comparison counts as the method it names: `if (request.method !== "POST")
 * return 405` is how a POST-only Worker says so. Capped, because a cross product of a
 * large router is noise rather than a model.
 */
export function workerRoutes(file: DetectorInput, entryOffset: number): Omit<Route, "id">[] {
  const text = file.content;
  const paths = new Set<string>();
  for (const match of text.matchAll(WORKER_PATH_EQUALS)) paths.add(match[2]);
  for (const match of text.matchAll(WORKER_PATH_PREFIX)) {
    paths.add(joinPaths(match[2], "*"));
  }

  const methods = new Set<HttpMethod>();
  for (const match of text.matchAll(WORKER_METHOD)) {
    const method = asMethod(match[2]);
    if (method) methods.add(method);
  }

  const line = lineAt(lineStarts(text), entryOffset);
  const routes: Omit<Route, "id">[] = [];
  for (const path of paths.size > 0 ? [...paths] : ["*"]) {
    for (const method of methods.size > 0 ? [...methods] : (["ALL"] as HttpMethod[])) {
      routes.push({
        method,
        path,
        normalizedPath: normalizeRoutePath(path),
        file: file.path,
        line,
        middleware: [],
        framework: "cloudflare_worker",
      });
    }
  }
  return routes.slice(0, WORKER_ROUTE_CAP);
}

const WORKER_ROUTE_CAP = 20;
