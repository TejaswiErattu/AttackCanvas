import type {
  Evidence,
  EvidenceKind,
  Owasp2025,
  Stride,
} from "@/shared/schema";
import { handlerBody, isGuardName } from "@/server/detect/auth";
import { isCompose, isGithubWorkflow } from "@/server/detect/deployment";
import { isFirestoreRules } from "@/server/detect/datastores";
import {
  cdnLibrary,
  hasCspMeta,
  isServedHtml,
  scriptTags,
} from "@/server/detect/web";
import {
  dependencyNames,
  isManifest,
  manifestScripts,
} from "@/server/detect/frameworks";
import {
  importsIn,
  middlewareName,
  splitCallArguments,
} from "@/server/detect/routes";
import {
  EvidenceBuilder,
  basename,
  byPath,
  lineAt,
  lineOf,
  lineStarts,
  maskCode,
  maskComments,
  normalizeRoutePath,
  normalizeSeparators,
} from "@/server/detect/shared";
import { minVersion, parseVersion } from "@/server/scanners/versions";
import type {
  ControlGap,
  DetectorInput,
  DetectorResult,
  GapKind,
  GapScope,
  Route,
  RouteAuth,
} from "@/server/detect/types";

/**
 * Security controls that should be present and cannot be found: the inverse of the
 * other detectors, which report what is present.
 *
 * Three kinds (cors_permissive, transport_insecure, half of supply_chain_integrity) are
 * really "present but ineffective" rather than "absent"; they are held to a different
 * standard because a positive observation is sound where an absence is not.
 *
 * Certainty answers only "is the control really absent?". It is a property of the
 * detection method, not of the risk: anything that needs an identifier followed to its
 * declaration sits at or below 0.55. Severity and confidence are computed in
 * src/server/scoring (CLAUDE.md rule 2), never here.
 *
 * AST NOTE: this is regex over comment- and string-masked source, like the other
 * detectors. It cannot follow middleware to its definition, so a control applied in a
 * module we did not load looks absent. That limit is why route-scoped kinds carry low
 * certainty and why every absence check is gated on an expectation that the repository
 * actually has the thing the control would protect.
 *
 * Untrusted content (CLAUDE.md rule 3): every summary and expectation is assembled from
 * derived facts only, a route path, a package name or a file path. Never matched text,
 * and never a snippet.
 */

// ---------------------------------------------------------------------------
// Per-kind metadata
// ---------------------------------------------------------------------------

type KindMeta = {
  control: string;
  owasp: Owasp2025[];
  stride: Stride[];
  cwe: string[];
};

const META: Record<GapKind, KindMeta> = {
  authz_missing: {
    control: "ownership or role check",
    owasp: ["A01:2025"],
    stride: ["E", "I"],
    cwe: ["CWE-639"],
  },
  authn_missing: {
    control: "authentication check",
    owasp: ["A01:2025", "A07:2025"],
    stride: ["S", "E"],
    cwe: ["CWE-306"],
  },
  rate_limit_missing: {
    control: "rate limiting",
    owasp: ["A07:2025"],
    stride: ["D", "S"],
    cwe: ["CWE-307"],
  },
  csrf_missing: {
    control: "CSRF protection",
    owasp: ["A01:2025"],
    stride: ["T", "S"],
    cwe: ["CWE-352"],
  },
  security_headers_missing: {
    control: "security response headers",
    owasp: ["A02:2025"],
    stride: ["T", "I"],
    cwe: ["CWE-693"],
  },
  input_validation_missing: {
    control: "input validation",
    owasp: ["A05:2025", "A06:2025"],
    stride: ["T"],
    cwe: ["CWE-20"],
  },
  transport_insecure: {
    control: "transport encryption",
    owasp: ["A04:2025"],
    stride: ["I", "T"],
    cwe: ["CWE-319"],
  },
  password_storage_weak: {
    control: "password hashing",
    owasp: ["A04:2025"],
    stride: ["S", "I"],
    cwe: ["CWE-916"],
  },
  logging_missing: {
    control: "security logging",
    owasp: ["A09:2025"],
    stride: ["R"],
    cwe: ["CWE-778"],
  },
  error_handling_gap: {
    control: "error handling",
    owasp: ["A10:2025"],
    stride: ["I", "D"],
    cwe: ["CWE-755"],
  },
  cors_permissive: {
    control: "restrictive CORS policy",
    owasp: ["A02:2025", "A01:2025"],
    stride: ["I"],
    cwe: ["CWE-942"],
  },
  supply_chain_integrity: {
    control: "dependency integrity",
    owasp: ["A03:2025", "A08:2025"],
    stride: ["T"],
    cwe: ["CWE-1357"],
  },
  client_secret_storage: {
    control: "server-side secret storage",
    owasp: ["A04:2025", "A07:2025"],
    stride: ["I"],
    cwe: ["CWE-922"],
  },
};

// ---------------------------------------------------------------------------
// Context: the derived views every check shares, built once
// ---------------------------------------------------------------------------

type Finding = {
  scope: GapScope;
  expectation: string;
  summary: string;
  file: string;
  line: number;
  routeId?: string;
  basisFacts: string[];
  certainty: number;
  evidenceKind: EvidenceKind;
};

type Ctx = {
  files: readonly DetectorInput[];
  facts: DetectorResult;
  source: readonly DetectorInput[];
  routes: readonly Route[];
  authOf: (route: Route) => RouteAuth | undefined;
  deps: ReadonlySet<string>;
  anchor: { file: string; line: number } | undefined;
  code: (file: DetectorInput) => string;
  uncommented: (file: DetectorInput) => string;
  body: (route: Route) => string;
  /** Every `.use(...)` call in loaded source (useCalls), read once. */
  useCalls: UseCall[];
  appLevelAuth: AppLevelAuth;
};

/**
 * Where a `.use(guard)` applies: to every route (`global`), or only under the mount
 * paths it was given (`prefixes`, e.g. "/admin" from `app.use("/admin", requireAuth)`).
 */
type AppLevelAuth = { global: boolean; prefixes: string[] };

/**
 * Mirrors the ingest classifier's low-priority directories on purpose rather than
 * importing it: detect stays free of any dependency on ingest policy.
 */
export function isScannable(path: string): boolean {
  const normalized = normalizeSeparators(path);
  return (
    /\.(?:ts|tsx|js|jsx|mjs|cjs)$/.test(normalized) &&
    !/(^|\/)(?:tests?|__tests__|__mocks__|mocks?|e2e|examples?|fixtures?|docs?|scripts|stories|bin|tools)\//i.test(
      normalized,
    ) &&
    !/\.(?:test|spec|stories)\.[jt]sx?$/.test(normalized) &&
    !/(^|\/)(?:node_modules|dist|build|\.next|coverage)\//.test(normalized)
  );
}

function memoise<T>(compute: (file: DetectorInput) => T) {
  const cache = new Map<string, T>();
  return (file: DetectorInput): T => {
    let hit = cache.get(file.path);
    if (hit === undefined) {
      hit = compute(file);
      cache.set(file.path, hit);
    }
    return hit;
  };
}

function buildContext(
  files: readonly DetectorInput[],
  facts: DetectorResult,
): Ctx {
  const source = files.filter((file) => isScannable(file.path));
  const scannable = new Set(source.map((file) => file.path));
  const byFile = new Map(files.map((file) => [file.path, file]));
  const authByRoute = new Map(facts.auth.map((fact) => [fact.routeId, fact]));

  const routes = facts.routes.filter((route) => scannable.has(route.file));
  const manifest = files.find((file) => isManifest(file.path));
  const first = manifest ?? source[0] ?? files[0];

  const code = memoise((file) => maskCode(file.content));
  const uncommented = memoise((file) => maskComments(file.content));
  const bodyCache = new Map<string, string>();

  const ctx: Ctx = {
    files,
    facts,
    source,
    routes,
    authOf: (route) => authByRoute.get(route.id),
    deps: dependencyNames(files),
    anchor: first ? { file: first.path, line: 1 } : undefined,
    code,
    uncommented,
    body: (route) => {
      let hit = bodyCache.get(route.id);
      if (hit === undefined) {
        const file = byFile.get(route.file);
        hit = file ? maskCode(handlerBody(file, route)) : "";
        bodyCache.set(route.id, hit);
      }
      return hit;
    },
    useCalls: [],
    appLevelAuth: { global: false, prefixes: [] },
  };
  ctx.useCalls = useCalls(ctx);
  ctx.appLevelAuth = appLevelAuth(ctx);
  return ctx;
}

const hasAny = (deps: ReadonlySet<string>, names: readonly string[]): boolean =>
  names.some((name) => deps.has(name));

const hasPrefix = (
  deps: ReadonlySet<string>,
  prefixes: readonly string[],
): boolean =>
  [...deps].some((name) => prefixes.some((prefix) => name.startsWith(prefix)));

const anySource = (ctx: Ctx, pattern: RegExp): boolean =>
  ctx.source.some((file) => pattern.test(ctx.code(file)));

/** Whether `specifier` names one of `packages` (or a subpath) or starts with a prefix. */
function namesPackage(
  specifier: string,
  packages: readonly string[],
  prefixes: readonly string[],
): boolean {
  return (
    packages.some((name) => specifier === name || specifier.startsWith(`${name}/`)) ||
    prefixes.some((prefix) => specifier.startsWith(prefix))
  );
}

/** Local names bound by an import or require clause: `a`, `{ a, b: c }`, `* as d`. */
function boundNames(clause: string): string[] {
  const names: string[] = [];
  const braces = /\{([^}]*)\}/.exec(clause);
  if (braces) {
    for (const part of braces[1].split(",")) {
      const local = part.trim().split(/\s*(?::|\bas\b)\s*/).at(-1)?.trim();
      if (local && /^[A-Za-z_$][\w$]*$/.test(local)) names.push(local);
    }
  }
  const outside = braces ? clause.replace(braces[0], " ") : clause;
  for (const match of outside.matchAll(/(?:\*\s*as\s+)?([A-Za-z_$][\w$]*)/g)) {
    if (match[1] !== "as") names.push(match[1]);
  }
  return names;
}

const IMPORT_FROM =
  /\bimport\s+([^'"`;]*?)\s+from\s*(['"])([^'"\n]+)\2/g;
const REQUIRE_DECLARATION =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*|\{[^}]*\})\s*=\s*require\s*\(\s*(['"])([^'"\n]+)\2\s*\)/g;
const INLINE_REQUIRE = /\b(?:require|import)\s*\(\s*(['"])([^'"\n]+)\1\s*\)/g;

/** Import and require declarations of any package: names there are bindings, not use. */
function declarationSpans(text: string): [number, number][] {
  return [IMPORT_FROM, REQUIRE_DECLARATION].flatMap((pattern) =>
    [...text.matchAll(pattern)].map(
      (match): [number, number] => [match.index, match.index + match[0].length],
    ),
  );
}

const within = (spans: readonly [number, number][], at: number): boolean =>
  spans.some(([from, to]) => at >= from && at < to);

/**
 * How one file refers to `packages`: the names its import and require clauses bind, the
 * spans of those clauses, and whether it also requires or imports one inline without
 * binding it (`app.use(require("helmet")())`, `await import("csurf")`). Clauses are read
 * from comment-masked text, so a commented-out require binds nothing.
 */
function packageRefs(
  ctx: Ctx,
  file: DetectorInput,
  packages: readonly string[],
  prefixes: readonly string[],
): { names: string[]; spans: [number, number][]; inline: number[] } {
  const text = ctx.uncommented(file);
  const names: string[] = [];
  const spans: [number, number][] = [];
  for (const pattern of [IMPORT_FROM, REQUIRE_DECLARATION]) {
    for (const match of text.matchAll(pattern)) {
      if (!namesPackage(match[3], packages, prefixes)) continue;
      names.push(...boundNames(match[1]));
      spans.push([match.index, match.index + match[0].length]);
    }
  }
  const inline = [...text.matchAll(INLINE_REQUIRE)]
    .filter((match) => namesPackage(match[2], packages, prefixes) && !within(spans, match.index))
    .map((match) => match.index + match[0].length);
  return { names, spans, inline };
}

const escapeName = (name: string): string => name.replace(/\$/g, "\\$");

/**
 * Whether live code actually uses one of `packages`, not merely declares or imports it:
 * a name bound by its import or require is referenced anywhere else in live code (called,
 * passed to `.use()`, read as `helmet.hsts`, ...), or it is required inline. References
 * are read from comment- and string-masked text, which keeps the same offsets as the
 * comment-masked text the clauses come from, so comments, strings and unused imports
 * never count.
 */
function usesPackage(
  ctx: Ctx,
  packages: readonly string[],
  prefixes: readonly string[] = [],
): boolean {
  return ctx.source.some((file) => {
    const { names, spans, inline } = packageRefs(ctx, file, packages, prefixes);
    if (inline.length > 0) return true;
    const code = ctx.code(file);
    return names.some((name) =>
      [...code.matchAll(new RegExp(`(?<![\\w$.])${escapeName(name)}(?![\\w$])`, "g"))].some(
        (match) => !within(spans, match.index),
      ),
    );
  });
}

/**
 * Whether live code enables one of `features` of a multi-purpose package such as lusca:
 * `lusca.csrf()` / `require("lusca").csrf()` or an options key, `lusca({ csrf: true })`.
 * A call for another feature (`lusca.xframe()`) does not count.
 */
function usesPackageFeature(ctx: Ctx, pkg: string, features: readonly string[]): boolean {
  const feature = features.join("|");
  return ctx.source.some((file) => {
    const { names, spans, inline } = packageRefs(ctx, file, [pkg], []);
    const code = ctx.code(file);
    const optionKey = new RegExp(`^\\s*\\(\\s*\\{[^}]*\\b(?:${feature})\\s*:`);
    const member = new RegExp(`^\\s*\\.\\s*(?:${feature})\\s*\\(`);
    const enables = (after: string) => member.test(after) || optionKey.test(after);
    if (inline.some((end) => enables(code.slice(end)))) return true;
    return names.some((name) =>
      [...code.matchAll(new RegExp(`(?<![\\w$.])${escapeName(name)}(?![\\w$])`, "g"))].some(
        (match) =>
          !within(spans, match.index) && enables(code.slice(match.index + match[0].length)),
      ),
    );
  });
}

/** Evidence kind: source files are code, everything else is configuration. */
const kindFor = (path: string): EvidenceKind =>
  isScannable(path) ? "code" : "config";

// ---------------------------------------------------------------------------
// App-level authentication
// ---------------------------------------------------------------------------

/** A router mounted by name, e.g. `authRouter`, is not a guard even though it says "auth". */
const ROUTER_NAME = /router|routes?$/i;

/**
 * The mount path a `.use()` call starts with, e.g. "/admin" from
 * `app.use("/admin", requireAuth)`, with a trailing "/" or "/*" dropped. Undefined when
 * the first argument is not a string literal starting with "/", or when it covers
 * everything ("/", "/*"): the guard is then global.
 */
function mountPathOf(firstArgument: string | undefined): string | undefined {
  const match = /^(['"`])(\/[^'"`]*)\1$/.exec(firstArgument?.trim() ?? "");
  const prefix = match
    ? normalizeRoutePath(match[2]).replace(/\/\*$/, "").replace(/\/+$/, "")
    : "";
  return prefix === "" ? undefined : prefix;
}

/**
 * `app.use(requireAuth)` guards every route below it, and detectRoutes cannot see it: it
 * models `app.use("/prefix", router)` for mounting only. Without this, one global guard
 * turns every route in the app into an authn gap. `app.use("/admin", requireAuth)`
 * guards only what is under /admin, so it is recorded as a prefix, not as global.
 *
 * The arguments are split on the comment-masked text, because the mount path is a
 * string; the `.use(` itself is found on the code-masked text, so a call inside a
 * string does not count.
 *
 * Known limit: a Next.js middleware.ts that mentions auth counts as global even when its
 * `matcher` covers only some paths. Reading the matcher would misfire on the standard
 * catch-all matcher that Clerk and next-auth apps use, turning every route into a
 * confident false gap, so the broad reading is kept on purpose.
 */
/** One `.use(...)` call: the names its arguments refer to and the mount path, if any. */
type UseCall = { file: string; names: string[]; prefix: string | undefined };

/**
 * The name a `.use()` argument refers to. `middlewareName` handles identifiers and
 * member calls; an inline `require("./middleware/requireAuth")` or `import("...")` is
 * judged by the basename of its specifier, since that is the only name it has.
 */
function useArgumentName(argument: string): string | undefined {
  const inline = /^(?:require|import)\s*\(\s*(['"`])([^'"`\n]+)\1\s*\)/.exec(argument.trim());
  if (inline) return basename(inline[2]).replace(/\.[cm]?[jt]sx?$/, "");
  return middlewareName(argument);
}

/**
 * Every `x.use(...)` call in loaded source, read once and shared by the checks that ask
 * "is this control applied at the app or router level?" (auth, authorization, validation,
 * logging). The arguments are split on the comment-masked text, because the mount path is
 * a string; the `.use(` itself is found on the code-masked text, so a call inside a string
 * does not count.
 */
function useCalls(ctx: Ctx): UseCall[] {
  const calls: UseCall[] = [];
  for (const file of ctx.source) {
    const text = ctx.uncommented(file);
    for (const match of ctx.code(file).matchAll(/\b[A-Za-z_$][\w$]*\.use\s*\(/g)) {
      const { args } = splitCallArguments(text, (match.index ?? 0) + match[0].length);
      const names = args
        .map(useArgumentName)
        .filter((name): name is string => name !== undefined);
      calls.push({ file: file.path, names, prefix: mountPathOf(args[0]) });
    }
  }
  return calls;
}

/** The scope `.use()` calls with a matching argument name establish. */
function scopeOfUseCalls(calls: readonly UseCall[], matches: (name: string) => boolean): AppLevelAuth {
  const scope: AppLevelAuth = { global: false, prefixes: [] };
  for (const call of calls) {
    if (!call.names.some(matches)) continue;
    if (call.prefix === undefined) scope.global = true;
    else scope.prefixes.push(call.prefix);
  }
  return scope;
}

/**
 * Next.js request middleware: `middleware.ts` up to Next 15, `proxy.ts` from Next 16. A
 * file of either name that mentions auth is read as a global guard (see appLevelAuth).
 */
const NEXT_MIDDLEWARE_FILE = /(^|\/)(?:middleware|proxy)\.(?:ts|js)$/;

function appLevelAuth(ctx: Ctx): AppLevelAuth {
  const scope = scopeOfUseCalls(
    ctx.useCalls,
    (name) => isGuardName(name) && !ROUTER_NAME.test(name),
  );

  const middleware = ctx.source.some(
    (file) =>
      NEXT_MIDDLEWARE_FILE.test(normalizeSeparators(file.path)) &&
      /auth|clerk|session/i.test(ctx.code(file)),
  );
  if (middleware) scope.global = true;
  return scope;
}

/** True when an app-level guard covers this path: globally, or by a mount prefix. */
function coveredByAppAuth(scope: AppLevelAuth, path: string): boolean {
  return (
    scope.global ||
    scope.prefixes.some(
      (prefix) => path === prefix || path.startsWith(`${prefix}/`),
    )
  );
}

// ---------------------------------------------------------------------------
// 1. authz_missing
// ---------------------------------------------------------------------------

/**
 * A `.use()` argument that decides authorization, not just authentication:
 * `app.use("/admin", requireAdmin)`, `router.use(checkPermission("orders"))`. The route
 * text never sees it, so authzMissing asks here before reporting.
 */
const ROLE_GUARD_NAME = /admin|role|permission|policy|authoriz|ability|acl|rbac/i;
const CAN_GUARD_NAME = /^can[A-Z]/;
const isRoleGuardName = (name: string): boolean =>
  (ROLE_GUARD_NAME.test(name) || CAN_GUARD_NAME.test(name)) && !ROUTER_NAME.test(name);

function authzMissing(ctx: Ctx): Finding[] {
  const found: Finding[] = [];
  const roleScope = scopeOfUseCalls(ctx.useCalls, isRoleGuardName);

  for (const route of ctx.routes) {
    const fact = ctx.authOf(route);
    if (!fact || fact.status !== "authenticated" || fact.roleChecks.length > 0)
      continue;
    if (coveredByAppAuth(roleScope, route.normalizedPath)) continue;

    const hasParam = route.normalizedPath.includes(":");
    if (!hasParam && !fact.adminPath) continue;

    found.push({
      scope: "route",
      expectation:
        "A route that takes a record id or is administrative needs an ownership or role check, not just a logged-in user",
      summary: `${route.method} ${route.normalizedPath} is reachable by any authenticated user with no ownership or role check in the handler or its middleware`,
      file: route.file,
      line: route.line,
      routeId: route.id,
      basisFacts: [
        `${route.id} authenticated`,
        hasParam ? "path takes a parameter" : "administrative path",
      ],
      certainty: fact.adminPath ? 0.85 : 0.7,
      evidenceKind: "code",
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// 2. authn_missing
// ---------------------------------------------------------------------------

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE", "ALL"]);

/** Public by design: a login must be reachable unauthenticated, a webhook signs instead. */
const PUBLIC_SEGMENTS = new Set([
  "health",
  "healthz",
  "livez",
  "readyz",
  "ping",
  "status",
  "metrics",
  "version",
  "login",
  "signin",
  "sign-in",
  "signup",
  "sign-up",
  "register",
  "logout",
  "callback",
  "webhook",
  "webhooks",
  "public",
  "auth",
]);

function isPublicRoute(path: string): boolean {
  return path
    .toLowerCase()
    .split("/")
    .some((segment) => PUBLIC_SEGMENTS.has(segment));
}

function authnMissing(ctx: Ctx): Finding[] {
  const found: Finding[] = [];

  for (const route of ctx.routes) {
    const fact = ctx.authOf(route);
    if (!fact || fact.status === "authenticated") continue;
    if (!MUTATING.has(route.method) && !fact.adminPath) continue;
    if (isPublicRoute(route.normalizedPath)) continue;
    if (coveredByAppAuth(ctx.appLevelAuth, route.normalizedPath)) continue;

    const unknown = fact.status === "unknown";
    found.push({
      scope: "route",
      expectation: unknown
        ? "A state-changing or administrative route needs authentication; its middleware could not be resolved from this file, so this is a detection limit rather than a finding"
        : "A state-changing or administrative route needs an authentication check",
      summary: unknown
        ? `${route.method} ${route.normalizedPath} has middleware whose effect could not be determined, so authentication is unconfirmed`
        : `${route.method} ${route.normalizedPath} changes state with no authentication middleware or session check`,
      file: route.file,
      line: route.line,
      routeId: route.id,
      basisFacts: [`${route.id} ${fact.status}`],
      certainty: unknown ? 0.45 : 0.9,
      evidenceKind: "code",
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// 3. rate_limit_missing
// ---------------------------------------------------------------------------

const AUTH_PATH = /login|signin|register|signup|reset|forgot|token|otp|verify/i;

const RATE_LIMIT_DEPS = [
  "express-rate-limit",
  "express-slow-down",
  "rate-limiter-flexible",
  "@upstash/ratelimit",
  "@fastify/rate-limit",
  "fastify-rate-limit",
  "next-rate-limit",
  "koa-ratelimit",
  "@nestjs/throttler",
  "hono-rate-limiter",
  "limiter",
  "express-brute",
  "rate-limit-redis",
  "koa2-ratelimit",
  "elysia-rate-limit",
];
const RATE_LIMIT_PREFIXES = ["@hono-rate-limiter/"];

/**
 * Server-side OIDC handlers that own the login route and redirect it to a hosted
 * provider. Narrower than delegatesAuth on purpose: a Next app on Clerk can sit beside an
 * Express service with its own /login, and that one still needs a limiter.
 */
const LOGIN_DELEGATED_DEPS = [
  "express-openid-connect",
  "keycloak-connect",
  "passport-auth0",
  "passport-openidconnect",
  "@clerk/express",
  "supertokens-node",
];

/** A limiter named for the mechanism, or for the behaviour it stops (a login lockout). */
const RATE_LIMIT_USAGE =
  /\brate[_-]?limit|\bthrottl(?:e|er|ing)\b|\bslowDown\b|\bbrute[_-]?force|\block(?:out|Account)|\battempts?(?:Remaining|Left|Count)\b/i;

function authRoutes(ctx: Ctx): Route[] {
  return ctx.routes.filter((route) => AUTH_PATH.test(route.normalizedPath));
}

/** Reverse-proxy and platform configuration: the files a gateway-level control lives in. */
const CONFIG_FILE = /\.(?:ya?ml|json|toml|conf)$|(?:^|\/)(?:Caddyfile|nginx\.conf|haproxy\.cfg)$/i;

/**
 * Rate limiting applied at a gateway or platform is written in config, not code: nginx
 * `limit_req`, HAProxy `stick-table`, Caddy `rate_limit`, Kong `rate-limiting`.
 */
const CONFIG_RATE_LIMIT = /throttl|rate[_-]?limit|ratelimit|limit_req|limit_conn|stick-table/i;

function configMentions(ctx: Ctx, pattern: RegExp): boolean {
  return ctx.files.some(
    (file) =>
      CONFIG_FILE.test(file.path) &&
      !isManifest(file.path) &&
      pattern.test(maskComments(file.content)),
  );
}

function rateLimitMissing(ctx: Ctx): Finding[] {
  const [route] = authRoutes(ctx);
  if (!route) return [];
  // The login route is the identity provider's redirect: the brute-force target is theirs.
  if (hasAny(ctx.deps, LOGIN_DELEGATED_DEPS)) return [];
  if (hasAny(ctx.deps, RATE_LIMIT_DEPS) || hasPrefix(ctx.deps, RATE_LIMIT_PREFIXES)) return [];
  if (anySource(ctx, RATE_LIMIT_USAGE)) return [];
  if (configMentions(ctx, CONFIG_RATE_LIMIT)) return [];

  return [
    {
      scope: "repository",
      expectation:
        "Login, registration, reset and token routes are brute-force targets and need rate limiting",
      summary: `${route.method} ${route.normalizedPath} is an authentication route and no rate-limiting package or call was found`,
      file: route.file,
      line: route.line,
      routeId: route.id,
      basisFacts: [
        `${route.id} is an authentication route`,
        "no rate-limit dependency",
      ],
      certainty: 0.85,
      evidenceKind: kindFor(route.file),
    },
  ];
}

// ---------------------------------------------------------------------------
// 4. csrf_missing
// ---------------------------------------------------------------------------

const SESSION_DEPS = [
  "express-session",
  "cookie-session",
  "iron-session",
  "next-auth",
  "@auth/core",
  "cookie-parser",
  "@fastify/cookie",
];
const CSRF_DEPS = [
  "csurf",
  "csrf",
  "csrf-csrf",
  "tiny-csrf",
  "next-csrf",
  "@fastify/csrf-protection",
  "csrf-sync",
  "@dr.pogodin/csurf",
  "koa-csrf",
];

/**
 * An Origin, Referer or Fetch-Metadata check is CSRF protection with no "csrf" in any
 * name (OWASP's "verifying origin with standard headers"): the request's origin is read
 * and compared, or `Sec-Fetch-Site` is consulted.
 */
const ORIGIN_READ =
  /\b(?:headers\s*(?:\.\s*|\[\s*['"`])(?:origin|referer)\b|(?:get|header)\s*\(\s*['"`](?:origin|referer)['"`]\s*\))/i;
const ORIGIN_COMPARED = /===|!==|==|!=|\.(?:includes|startsWith|endsWith|has|test)\s*\(/;
const FETCH_METADATA = /sec-fetch-site/i;

function checksOrigin(ctx: Ctx): boolean {
  return ctx.source.some((file) => {
    const text = ctx.uncommented(file);
    if (FETCH_METADATA.test(text)) return true;
    const read = ORIGIN_READ.exec(text);
    if (!read) return false;
    // The comparison is on the same line or the next one: `if (req.get("origin") !== X)`.
    const nearby = text.slice(read.index, text.indexOf("\n", text.indexOf("\n", read.index) + 1) + 1 || undefined);
    return ORIGIN_COMPARED.test(nearby);
  });
}

/**
 * A body parser that accepts only JSON. A browser cannot send `application/json`
 * cross-site without a CORS preflight, so a JSON-only API is not reachable by the simple
 * form post CSRF relies on; the risk is real only if some route accepts a form body.
 */
const JSON_ONLY_PARSER = /\b(?:express|bodyParser)\s*\.\s*json\s*\(/;
const FORM_PARSER = /\burlencoded\s*\(|\bmulter\b|\bformidable\b|\bbusboy\b|\bmultipart\b|\bformData\s*\(/i;

function jsonOnlyApi(ctx: Ctx): boolean {
  return anySource(ctx, JSON_ONLY_PARSER) && !anySource(ctx, FORM_PARSER);
}
const COOKIE_USAGE =
  /\bres\s*\.\s*cookie\s*\(|\bcookies\s*\(\s*\)|\breq\s*\.\s*session\b/;

/** Names that produce or expose a token rather than validate one: `req.csrfToken()`. */
const CSRF_TOKEN_PRODUCER =
  /^(?:get|generate|create|issue|make|new)?_?(?:csrf|xsrf)_?token$/i;

/** A request token read (body, header or query) and a comparison or verification of it. */
const READS_REQUEST_TOKEN =
  /\breq(?:uest)?\s*\.\s*(?:body|headers|query|get\s*\(|header\s*\()/;
const COMPARES =
  /===|!==|==|!=|\bverify\w*\s*\(|\btimingSafeEqual\s*\(|\bcompare\w*\s*\(/;

/**
 * The body of the function or arrow bound to `name` in loaded source, when one is defined
 * there: `function name(...) {...}`, `const name = (...) => {...}` or
 * `const name = function (...) {...}`. Read from comment-masked text so header names in
 * strings stay visible. Undefined when no definition is loaded.
 */
function definitionBody(ctx: Ctx, name: string): string | undefined {
  const escaped = escapeName(name);
  const head = new RegExp(
    `(?:\\bfunction\\s+${escaped}\\s*\\(|\\b(?:const|let|var)\\s+${escaped}\\s*=\\s*(?:async\\s+)?(?:function\\b|\\(|[A-Za-z_$][\\w$]*\\s*=>))`,
  );
  for (const file of ctx.source) {
    const text = ctx.uncommented(file);
    const found = head.exec(text);
    if (!found) continue;
    const from = found.index + found[0].length;
    // An arrow's body starts after its `=>`; an expression body runs to the line's end.
    const arrow = /^[^{]*?=>\s*/.exec(text.slice(from));
    if (arrow && !/\bfunction\b/.test(found[0])) {
      const start = from + arrow[0].length;
      if (text[start] !== "{") {
        const end = text.indexOf("\n", start);
        return text.slice(start, end === -1 ? undefined : end);
      }
    }
    const open = text.indexOf("{", from);
    if (open === -1) continue;
    let depth = 0;
    for (let at = open; at < text.length; at++) {
      if (text[at] === "{") depth++;
      else if (text[at] === "}" && --depth === 0) return text.slice(open, at + 1);
    }
  }
  return undefined;
}

/**
 * Whether live code runs a CSRF check that is not a known package (those are
 * usesPackage's): a csrf/xsrf-named function that is called (`verifyCsrf(req)`) or passed
 * as middleware (`app.use(verifyCsrf)`, `app.post("/x", verifyCsrf, handler)`).
 *
 * Producing a token is not validating one, so `req.csrfToken()`, `getCsrfToken()`, a
 * template's `_csrf` field and an object key (`{ csrftoken: x }`) never count. When the
 * function is defined in loaded source it counts only if its body reads a token from the
 * request and compares or verifies it. When its definition is not loaded, what it does
 * cannot be established, and it counts: the detector reports absence only when sure.
 */
function checksCsrfToken(ctx: Ctx): boolean {
  return ctx.source.some((file) => {
    const code = ctx.code(file);
    const spans = declarationSpans(ctx.uncommented(file));
    for (const match of code.matchAll(/[\w$]*(?:csrf|xsrf)[\w$]*/gi)) {
      const start = match.index;
      const name = match[0];
      if (start > 0 && /[\w$]/.test(code[start - 1])) continue;
      if (within(spans, start) || CSRF_TOKEN_PRODUCER.test(name)) continue;
      const before = code.slice(0, start).trimEnd();
      const after = code.slice(start + name.length).trimStart();
      const called = after.startsWith("(") && !/\bfunction$/.test(before);
      const argument = /[(,]$/.test(before) && !after.startsWith(":");
      if (!called && !argument) continue;
      // A method on another object (`tokens.verifyCsrf(...)`) has no loaded body to read.
      const body = before.endsWith(".") ? undefined : definitionBody(ctx, name);
      if (body === undefined || (READS_REQUEST_TOKEN.test(body) && COMPARES.test(body))) {
        return true;
      }
    }
    return false;
  });
}

function csrfMissing(ctx: Ctx): Finding[] {
  const usesCookies =
    hasAny(ctx.deps, SESSION_DEPS) || anySource(ctx, COOKIE_USAGE);
  if (!usesCookies) return [];

  const route = ctx.routes.find(
    (candidate) =>
      MUTATING.has(candidate.method) &&
      !candidate.normalizedPath.startsWith("/api"),
  );
  if (!route) return [];

  // A declared or imported CSRF package is not protection until live code uses it.
  if (usesPackage(ctx, CSRF_DEPS, ["@edge-csrf/"])) return [];
  if (usesPackageFeature(ctx, "lusca", ["csrf"])) return [];
  if (checksCsrfToken(ctx)) return [];
  if (checksOrigin(ctx)) return [];

  // The value is inside a string, so this reads the comment-masked text.
  const sameSite = ctx.source.some((file) =>
    /sameSite\s*:\s*['"`]strict['"`]/i.test(ctx.uncommented(file)),
  );
  const jsonOnly = jsonOnlyApi(ctx);

  const expectation = jsonOnly
    ? "Cookie sessions with state-changing routes need CSRF protection; only a JSON body parser was found, which a cross-site form cannot reach, so the exposure depends on whether any route accepts a form body"
    : sameSite
      ? "Cookie sessions with state-changing routes usually need a CSRF token; SameSite strict reduces the risk but is not a token"
      : "Cookie sessions with state-changing routes need CSRF protection";

  return [
    {
      scope: "repository",
      expectation,
      summary: `Cookie-based sessions are used and ${route.method} ${route.normalizedPath} changes state, with no CSRF middleware or token pattern found`,
      file: route.file,
      line: route.line,
      routeId: route.id,
      basisFacts: [
        "cookie session signal",
        `${route.id} changes state`,
        ...(jsonOnly ? ["JSON-only body parser"] : []),
      ],
      certainty: jsonOnly ? 0.45 : sameSite ? 0.5 : 0.8,
      evidenceKind: "code",
    },
  ];
}

// ---------------------------------------------------------------------------
// 5. security_headers_missing
// ---------------------------------------------------------------------------

const HEADER_DEPS = [
  "helmet",
  "koa-helmet",
  "@fastify/helmet",
  "next-secure-headers",
  "nuxt-security",
  "secure-headers",
  "express-secure-headers",
];

/** Header middleware imported by subpath: `import { secureHeaders } from "hono/secure-headers"`. */
const HEADER_SUBPATHS = ["hono/secure-headers"];

/** Server templates and static pages, where a CSP can live in a `<meta http-equiv>`. */
const TEMPLATE_FILE = /\.(?:html?|ejs|pug|jade|hbs|handlebars|njk|liquid|mustache|twig)$/i;

/** Response headers a proxy, host or CDN sets from its own configuration. */
const SECURITY_HEADER_NAMED = /Content-Security-Policy|X-Frame-Options|Strict-Transport-Security/i;

/** lusca's response-header middlewares; its csrf() is csrf_missing's, not this check's. */
const LUSCA_HEADER_FEATURES = [
  "csp",
  "xframe",
  "hsts",
  "nosniff",
  "xssProtection",
  "referrerPolicy",
  "p3p",
];

const isHeaderConfig = (path: string): boolean =>
  /^(?:next\.config\.|vercel\.json$|netlify\.toml$|_headers$|firebase\.json$)/.test(
    basename(path),
  );

/**
 * Whether a header config file sets headers. Each format is read on its own terms:
 * vercel.json's "headers" is a JSON key, which maskCode would blank as a string; a
 * Netlify _headers file is nothing but header rules and usually opens with "/*", which
 * the comment masker would read as a comment running to the end of the file.
 * next.config and netlify.toml keep the code-masked `headers` test.
 */
function declaresHeaders(file: DetectorInput): boolean {
  const name = basename(file.path);
  if (name === "_headers") return file.content.trim() !== "";
  if (name === "vercel.json" || name === "firebase.json") return /"headers"\s*:/.test(file.content);
  return /\bheaders\b/.test(maskCode(file.content));
}

function securityHeadersMissing(ctx: Ctx): Finding[] {
  const web = ctx.facts.frameworks.find(
    (framework) => framework.category === "web" && !framework.dev,
  );
  if (!web) return [];
  // A declared or imported header package is not protection until live code uses it.
  if (usesPackage(ctx, [...HEADER_DEPS, ...HEADER_SUBPATHS])) return [];
  if (usesPackageFeature(ctx, "lusca", LUSCA_HEADER_FEATURES)) return [];
  if (anySource(ctx, /\bhelmet\s*\(|\bsecureHeaders\s*\(/)) return [];
  // Declared, but no source was loaded to show whether it is used: unknown, not missing.
  if (hasAny(ctx.deps, [...HEADER_DEPS, "lusca"]) && ctx.source.length === 0) return [];

  const configs = ctx.files.filter((file) => isHeaderConfig(file.path));
  // Next with no next.config loaded means the headers config is unknown, not missing.
  if (
    ctx.deps.has("next") &&
    !configs.some((f) => basename(f.path).startsWith("next.config"))
  )
    return [];
  if (configs.some(declaresHeaders)) return [];

  const scanned = [...ctx.source, ...configs];
  if (scanned.some((file) => SECURITY_HEADER_NAMED.test(ctx.uncommented(file)))) return [];
  // A proxy or host sets headers from its own config; a template can carry a CSP meta tag.
  // Config comments are `#` to end of line (nginx, Caddy, YAML, TOML), so the YAML masker applies.
  if (
    ctx.files.some(
      (file) =>
        CONFIG_FILE.test(file.path) &&
        !isManifest(file.path) &&
        SECURITY_HEADER_NAMED.test(maskYamlComments(file.content)),
    )
  )
    return [];
  if (ctx.files.some((file) => TEMPLATE_FILE.test(file.path) && hasCspMeta(file.content))) return [];

  return [
    {
      scope: "repository",
      expectation:
        "A web application should set security response headers such as a content security policy",
      summary: `${web.name} is used and no helmet middleware, headers configuration or security header was found`,
      file: web.file,
      line: web.line,
      basisFacts: [`${web.name} web framework`, "no header middleware"],
      certainty: 0.9,
      evidenceKind: "config",
    },
  ];
}

// ---------------------------------------------------------------------------
// 6. input_validation_missing
// ---------------------------------------------------------------------------

const VALIDATION_LIBS = new Set([
  "zod",
  "joi",
  "@hapi/joi",
  "yup",
  "superstruct",
  "valibot",
  "express-validator",
  "class-validator",
  "ajv",
  "@sinclair/typebox",
  "celebrate",
  "express-joi-validation",
  "zod-express-middleware",
  "@hono/zod-validator",
  "arktype",
  "io-ts",
  "runtypes",
  "typia",
  "validator",
  "express-openapi-validator",
  "effect",
]);

/**
 * A validation library re-exported from a local module or a workspace package:
 * `import { z } from "@/lib/validation"`, `import { UserSchema } from "@acme/schemas"`.
 */
const VALIDATION_SPECIFIER = /schema|valid/i;

/**
 * A validation call in the handler itself, whatever module the schema came from.
 * `JSON.parse` is parsing, not validation, and is excluded by the lookbehind.
 */
const VALIDATES_IN_BODY =
  /(?<!\bJSON)\s*\.\s*(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync|validateAsync|assert|check)\s*\(|\b(?:validationResult|matchedData)\s*\(/;

/** Route middleware that validates: by name, or an express-validator chain (`body("email")`). */
const VALIDATING_MIDDLEWARE = /valid|schema|sanitiz|celebrate|^(?:body|check|param|query|header|cookie)\b/i;

const READS_INPUT =
  /\breq(?:uest)?\s*\.\s*(?:body|query)\b|\b(?:req|request)\s*\.\s*json\s*\(|\bsearchParams\b/;

/** The package a specifier names: "zod/v4" -> "zod", "@scope/pkg/sub" -> "@scope/pkg". */
function packageRoot(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function importsValidation(file: DetectorInput): boolean {
  return [...importsIn(file.content).values()].some(
    (specifier) =>
      VALIDATION_LIBS.has(packageRoot(specifier)) || VALIDATION_SPECIFIER.test(specifier),
  );
}

function inputValidationMissing(ctx: Ctx): Finding[] {
  const found: Finding[] = [];
  const seen = new Set<string>();
  const byFile = new Map(ctx.source.map((file) => [file.path, file]));
  // Validation applied with app.use()/router.use() never appears on the route itself.
  const appLevel = scopeOfUseCalls(
    ctx.useCalls,
    (name) => VALIDATING_MIDDLEWARE.test(name) && !ROUTER_NAME.test(name),
  );

  for (const route of ctx.routes) {
    const file = byFile.get(route.file);
    const body = ctx.body(route);
    if (!file || !READS_INPUT.test(body)) continue;
    if (importsValidation(file)) continue;
    if (VALIDATES_IN_BODY.test(body)) continue;
    if (route.middleware.some((name) => VALIDATING_MIDDLEWARE.test(name))) continue;
    if (coveredByAppAuth(appLevel, route.normalizedPath)) continue;

    // A Pages API file is one handler for every method: report it once.
    const key = `${route.file}:${route.line}`;
    if (seen.has(key)) continue;
    seen.add(key);

    found.push({
      scope: "route",
      expectation:
        "A handler that reads request input should validate it. Validation may live in middleware this detector cannot follow, so certainty is deliberately low",
      summary: `${route.method} ${route.normalizedPath} reads request input and its file imports no validation library`,
      file: route.file,
      line: route.line,
      routeId: route.id,
      basisFacts: [`${route.id} reads request input`, "no validation import"],
      certainty: 0.55,
      evidenceKind: "code",
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// 7. transport_insecure
// ---------------------------------------------------------------------------

const DB_PORTS = new Set([5432, 3306, 27017, 6379]);

/** Hosts that appear in `http://` URLs without being a network endpoint. */
const NON_ENDPOINT_HOSTS =
  /^(?:(?:www\.)?w3\.org|json-schema\.org|(?:www\.)?schema\.org|schemas\.[\w.-]+|xmlns\.com|purl\.org|maven\.apache\.org|www\.apache\.org|opensource\.org|unlicense\.org|(?:www\.)?sitemaps\.org|example\.(?:com|org|net)|ogp\.me|ns\.adobe\.com|(?:www\.)?iptc\.org|rdfs\.org|(?:www\.)?dublincore\.org|(?:www\.)?openarchives\.org)$/i;

/** Kubernetes service addressing: `name.namespace.svc`, `name.namespace.svc.cluster.local`. */
const CLUSTER_HOST = /\.svc(?:\.|$)/;

/**
 * Service names declared under `services:` in loaded compose files. Inside the compose
 * network they are hostnames, and one with a dot (`minio.storage`) would otherwise read
 * as an external host.
 */
function composeServiceNames(files: readonly DetectorInput[]): Set<string> {
  const names = new Set<string>();
  for (const file of files) {
    if (!isCompose(file.path)) continue;
    const lines = maskYamlComments(file.content).split("\n");
    const start = lines.findIndex((line) => /^services\s*:/.test(line));
    if (start === -1) continue;
    for (const line of lines.slice(start + 1)) {
      if (/^\S/.test(line)) break; // next top-level key
      const service = /^ {2}([\w.-]+)\s*:/.exec(line);
      if (service) names.add(service[1].toLowerCase());
    }
  }
  return names;
}

function isExternalHost(rawHost: string, internal: ReadonlySet<string> = new Set()): boolean {
  const host = rawHost.toLowerCase();
  if (/^[${%]/.test(host)) return false;
  if (!host.includes(".")) return false;
  if (host.startsWith("[")) return false;
  if (/^(?:127\.|0\.0\.0\.0$|10\.|192\.168\.)/.test(host)) return false;
  if (/^172\.(?:1[6-9]|2\d|3[01])\./.test(host)) return false;
  if (/\.(?:local|localhost|internal|test|invalid|example)$/.test(host))
    return false;
  if (CLUSTER_HOST.test(host) || internal.has(host)) return false;
  return !NON_ENDPOINT_HOSTS.test(host);
}

function firstInsecureUrl(text: string, internal: ReadonlySet<string>): number | undefined {
  for (const match of text.matchAll(
    /\bhttp:\/\/([^\s'"`/:?#)\]]+|\[[^\]]+\])/gi,
  )) {
    if (isExternalHost(match[1], internal)) return match.index;
  }
  return undefined;
}

/** A compose file for development only: its published ports never face the internet. */
const DEV_COMPOSE = /dev|local|test|override/i;

function transportInFile(
  ctx: Ctx,
  file: DetectorInput,
  internal: ReadonlySet<string>,
): Finding | undefined {
  const text = ctx.uncommented(file);
  const tls = /rejectUnauthorized\s*:\s*false/.exec(text);
  const url = firstInsecureUrl(text, internal);
  const offset = tls?.index ?? url;
  if (offset === undefined) return undefined;

  const starts = lineStarts(file.content);
  const disabled = tls !== null && tls.index === offset;
  return {
    scope: "file",
    expectation:
      "Traffic to another host should use TLS and certificate verification",
    summary: disabled
      ? `${file.path} disables TLS certificate verification`
      : `${file.path} makes a plaintext http request to an external host`,
    file: file.path,
    line: lineAt(starts, offset),
    basisFacts: [disabled ? "TLS verification disabled" : "plaintext http URL"],
    certainty: 0.75,
    evidenceKind: "code",
  };
}

/** A compose mapping with no host IP publishes on every interface, 0.0.0.0 included. */
function exposedDatabasePort(file: DetectorInput): Finding | undefined {
  const lines = file.content.split("\n");
  for (const [index, line] of lines.entries()) {
    const match = /^\s*-\s*['"]?(?:([\d.]+):)?(\d+):(\d+)/.exec(line);
    if (!match) continue;

    const [, hostIp, , container] = match;
    const port = Number(container);
    if (!DB_PORTS.has(port)) continue;
    if (hostIp !== undefined && hostIp !== "0.0.0.0") continue;

    return {
      scope: "file",
      expectation:
        "A database port should not be published on every network interface",
      summary: `${file.path} publishes database port ${port} on all interfaces`,
      file: file.path,
      line: index + 1,
      basisFacts: [`database port ${port}`, "no loopback host binding"],
      certainty: 0.75,
      evidenceKind: "config",
    };
  }
  return undefined;
}

function transportInsecure(ctx: Ctx): Finding[] {
  const found: Finding[] = [];
  const internal = composeServiceNames(ctx.files);
  for (const file of ctx.source) {
    const finding = transportInFile(ctx, file, internal);
    if (finding) found.push(finding);
  }
  for (const file of ctx.files) {
    if (!isCompose(file.path) || DEV_COMPOSE.test(basename(file.path))) continue;
    const finding = exposedDatabasePort(file);
    if (finding) found.push(finding);
  }
  return found;
}

// ---------------------------------------------------------------------------
// 8. password_storage_weak
// ---------------------------------------------------------------------------

const KDF_DEPS = [
  "bcrypt",
  "bcryptjs",
  "@node-rs/bcrypt",
  "argon2",
  "@node-rs/argon2",
  "node-argon2",
  "scrypt",
  "scrypt-kdf",
  "better-auth",
  "lucia",
  "passport-local-mongoose",
  "bcrypt-ts",
  "hash-wasm",
  "sodium-native",
  "libsodium-wrappers",
];
/** Passwordless mechanisms: a login route with no password to store. */
const PASSWORDLESS_DEPS = ["otplib", "speakeasy", "passport-magic-link", "@simplewebauthn/server", "passport-webauthn"];
const DELEGATED_EXACT = [
  "express-openid-connect",
  "keycloak-connect",
  "supertokens-node",
  "openid-client",
  "passport-saml",
  "@node-saml/passport-saml",
  "firebase",
  "firebase-admin",
  "auth0",
  "stytch",
  "amazon-cognito-identity-js",
  "@aws-sdk/client-cognito-identity-provider",
];
const DELEGATED_PREFIX = [
  "@clerk/",
  "@supabase/",
  "@auth0/",
  "@workos-inc/",
  "@kinde-oss/",
  "@propelauth/",
  "@descope/",
  "@ory/",
  "@okta/",
];
const PASSWORD_ROUTE = /login|signin|register|signup|password|reset/i;

/** A hosted identity provider means there is no password for this repository to store. */
function delegatesAuth(ctx: Ctx): boolean {
  if (
    hasAny(ctx.deps, DELEGATED_EXACT) ||
    hasPrefix(ctx.deps, DELEGATED_PREFIX)
  )
    return true;
  const nextAuth = ctx.deps.has("next-auth") || ctx.deps.has("@auth/core");
  return nextAuth && !anySource(ctx, /CredentialsProvider|\bCredentials\s*\(/);
}

/** md5 or sha1 within three lines of a password-shaped identifier. */
function weakHashLine(ctx: Ctx): { file: string; line: number } | undefined {
  for (const file of ctx.source) {
    const lines = ctx.uncommented(file).split("\n");
    for (const [index, line] of lines.entries()) {
      if (!/createHash\(\s*['"](?:md5|sha1)['"]/i.test(line)) continue;
      const near = lines.slice(Math.max(0, index - 3), index + 4).join("\n");
      if (/password|passwd|pwd/i.test(near))
        return { file: file.path, line: index + 1 };
    }
  }
  return undefined;
}

function passwordStorageWeak(ctx: Ctx): Finding[] {
  const route = ctx.routes.find((r) => PASSWORD_ROUTE.test(r.normalizedPath));
  if (!route) return [];
  // Browser storage is not an account store: it cannot hold the passwords this is about.
  if (
    !ctx.facts.datastores.some(
      (store) => store.kind !== "redis" && store.kind !== "browser_storage",
    )
  )
    return [];
  if (delegatesAuth(ctx)) return [];
  if (hasAny(ctx.deps, KDF_DEPS)) return [];
  if (anySource(ctx, /\b(?:bcrypt|argon2|scrypt|pbkdf2|crypto_pwhash|sodium)/i)) return [];
  // Passwordless: a magic link, OTP or passkey login stores no password to hash.
  if (hasAny(ctx.deps, PASSWORDLESS_DEPS)) return [];

  const weak = weakHashLine(ctx);
  return [
    {
      scope: "repository",
      expectation:
        "An application that authenticates users itself and stores accounts needs a password hashing function such as bcrypt, argon2 or scrypt",
      summary: weak
        ? `Authentication routes and a datastore exist and ${weak.file} hashes with a fast digest instead of a password hashing function`
        : `${route.method} ${route.normalizedPath} authenticates users against a datastore and no password hashing library was found`,
      file: weak?.file ?? route.file,
      line: weak?.line ?? route.line,
      routeId: weak ? undefined : route.id,
      basisFacts: [
        `${route.id} is an authentication route`,
        "datastore present",
        "no password hashing dependency",
      ],
      certainty: weak ? 0.95 : 0.8,
      evidenceKind: kindFor(weak?.file ?? route.file),
    },
  ];
}

// ---------------------------------------------------------------------------
// 9. logging_missing
// ---------------------------------------------------------------------------

const LOGGING_DEPS = [
  "pino",
  "winston",
  "bunyan",
  "roarr",
  "morgan",
  "loglevel",
  "signale",
  "consola",
  "tslog",
  "npmlog",
  "dd-trace",
  "pino-http",
  "express-winston",
  "koa-logger",
  "koa-pino-logger",
  "log4js",
  "applicationinsights",
  "newrelic",
  "posthog-node",
];
const LOGGING_PREFIX = [
  "@sentry/",
  "@opentelemetry/",
  "@logtail/",
  "@datadog/",
  "@axiomhq/",
  "@google-cloud/logging",
  "@aws-sdk/client-cloudwatch-logs",
  "@newrelic/",
  "@honeycombio/",
];

/** `logger.info(...)`, `this.logger.log(...)` (NestJS), `log.warn(...)`. */
const LOGGER_METHOD_CALL =
  /\b(?:logger|log)\s*\.\s*(?:info|warn|error|debug|fatal|trace|log|verbose)\s*\(/;
/** A logging or audit helper called by name in the sensitive handler: `audit(req, "login")`. */
const LOG_HELPER_CALL =
  /\b(?:log|audit|logEvent|auditLog|logAudit|recordEvent|track|logger)\w*\s*\(/;
/** Logging middleware applied with `.use()`: `app.use(requestLogger)`, `app.use(morgan("combined"))`. */
const LOGGING_MIDDLEWARE = /log|morgan|audit|pino|winston/i;

function loggingMissing(ctx: Ctx): Finding[] {
  const sensitive = ctx.routes.filter((route) => {
    const fact = ctx.authOf(route);
    return AUTH_PATH.test(route.normalizedPath) || fact?.adminPath === true;
  });
  const [route] = sensitive;
  if (!route) return [];

  if (hasAny(ctx.deps, LOGGING_DEPS) || hasPrefix(ctx.deps, LOGGING_PREFIX))
    return [];
  if (anySource(ctx, LOGGER_METHOD_CALL)) return [];
  if (ctx.useCalls.some((call) => call.names.some((name) => LOGGING_MIDDLEWARE.test(name))))
    return [];
  if (
    sensitive.some(
      (r) => /\bconsole\s*\.\s*\w+\s*\(/.test(ctx.body(r)) || LOG_HELPER_CALL.test(ctx.body(r)),
    )
  )
    return [];

  return [
    {
      scope: "repository",
      expectation:
        "Authentication and administrative actions should be logged so misuse can be detected and attributed",
      summary: `${route.method} ${route.normalizedPath} is an authentication or administrative route and no logging library or log call was found`,
      file: route.file,
      line: route.line,
      routeId: route.id,
      basisFacts: [
        `${route.id} is authentication or administrative`,
        "no logging dependency",
      ],
      certainty: 0.7,
      evidenceKind: kindFor(route.file),
    },
  ];
}

// ---------------------------------------------------------------------------
// 10. error_handling_gap
// ---------------------------------------------------------------------------

/** (err, req, res, next), tolerating TypeScript parameter annotations. */
const ERROR_MIDDLEWARE =
  /\(\s*(?:err|error|e)\s*(?::\s*[^,)]+)?,\s*(?:req|request)\s*(?::\s*[^,)]+)?,\s*(?:res|response)\s*(?::\s*[^,)]+)?,\s*(?:next|_next)\b/;
/** `app.use(errorHandler)`, `app.use(errorHandler({ log }))`, `app.use(Sentry.Handlers.errorHandler())`. */
const ERROR_REGISTRATION =
  /\.use\s*\(\s*[\w$.]*(?:error|exception)[\w$]*\s*(?:\([^()]*\))?\s*\)/i;

/** Packages that hand a rejected handler promise to the error handler on Express 4. */
const ASYNC_FORWARDING_DEPS = [
  "express-async-errors",
  "express-async-handler",
  "express-promise-router",
  "@awaitjs/express",
];

/**
 * A handler wrapped in an async-catching helper (`catchAsync(async (req, res) => …)`), or
 * one that attaches `.catch(next)` to the awaited promise, forwards its own rejections.
 */
const ASYNC_WRAPPER =
  /\b(?:asyncHandler|catchAsync|wrapAsync|asyncWrap|tryCatch|catchErrors|wrap|handleAsync|asyncMiddleware)\w*\s*\(\s*(?:async\b|\(|function\b)/;
const CATCHES_PROMISE = /\.\s*catch\s*\(/;

/** The lowest major version a declared range allows, e.g. 5 for "^5.1.0". */
function lowestMajor(range: string): number | undefined {
  const lowest = minVersion(range);
  return lowest === undefined ? undefined : parseVersion(lowest)?.core[0];
}

/**
 * Express 5 passes a rejected handler promise to the error handler itself, and
 * express-async-errors patches Express 4 to do the same, so an await with no try/catch
 * is not a gap there. Every declared express must be 5 or later: a monorepo that still
 * has an Express 4 service keeps the check.
 */
function forwardsRejections(ctx: Ctx): boolean {
  if (hasAny(ctx.deps, ASYNC_FORWARDING_DEPS)) return true;

  const express = ctx.facts.frameworks.filter((f) => f.name === "express");
  return (
    express.length > 0 &&
    express.every((framework) => (lowestMajor(framework.version) ?? 0) >= 5)
  );
}

function errorHandlingGap(ctx: Ctx): Finding[] {
  if (anySource(ctx, ERROR_MIDDLEWARE) || anySource(ctx, ERROR_REGISTRATION))
    return [];
  if (forwardsRejections(ctx)) return [];

  const found: Finding[] = [];
  for (const route of ctx.routes) {
    // Next and Fastify ship default error handling, so absence means nothing there.
    if (route.framework !== "express") continue;
    const body = ctx.body(route);
    if (!/\bawait\b/.test(body) || /\btry\b/.test(body)) continue;
    if (ASYNC_WRAPPER.test(body) || CATCHES_PROMISE.test(body)) continue;

    found.push({
      scope: "route",
      expectation:
        "An async Express handler that can reject needs a try/catch or a registered error handler",
      summary: `${route.method} ${route.normalizedPath} awaits with no try/catch and no error-handling middleware is registered`,
      file: route.file,
      line: route.line,
      routeId: route.id,
      basisFacts: [`${route.id} awaits`, "no error middleware"],
      certainty: 0.5,
      evidenceKind: "code",
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// 11. cors_permissive
// ---------------------------------------------------------------------------

const WILDCARD_ORIGIN =
  /\borigin\s*:\s*(?:(['"`])\*\1|true\b|req(?:uest)?\s*\.\s*headers\s*\.\s*origin\b)/;
const WILDCARD_HEADER = /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/;

/** A reflected origin: any caller's origin is echoed back, which browsers allow with credentials. */
const REFLECTED_ORIGIN = /\borigin\s*:\s*(?:true\b|req(?:uest)?\s*\.\s*headers\s*\.\s*origin\b)/;
/** Credentials allowed alongside: the combination that exposes a user's session cross-origin. */
const CORS_CREDENTIALS = /\bcredentials\s*:\s*true\b|Access-Control-Allow-Credentials/i;

/**
 * A `cors` defined in the file itself (`function cors(options = { origin: ALLOWED })`,
 * `const cors = (opts) => …`) is not the cors package: its defaults are its own and
 * nothing here can read them, so its bare call is not reported. A `cors` bound by
 * import or require, or never declared (mounted from a shared module), still is.
 */
const LOCAL_CORS_DEFINITION =
  /\bfunction\s+cors\s*\(|\b(?:const|let|var)\s+cors\s*=\s*(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)/;

function definesCorsLocally(ctx: Ctx, file: DetectorInput): boolean {
  return LOCAL_CORS_DEFINITION.test(ctx.code(file));
}

function corsInFile(ctx: Ctx, file: DetectorInput): Finding[] {
  const masked = ctx.code(file);
  const starts = lineStarts(file.content);
  const lines = new Map<number, { how: string; reflected: boolean }>();

  if (!definesCorsLocally(ctx, file)) {
    for (const match of masked.matchAll(/\bcors\s*\(/g)) {
      const open = (match.index ?? 0) + match[0].length;
      const { args, end } = splitCallArguments(file.content, open);
      const bare = args.length === 0;
      const call = file.content.slice(open, end);
      const wildcard = WILDCARD_ORIGIN.test(call);
      if (bare || wildcard)
        lines.set(lineAt(starts, match.index ?? 0), {
          how: bare ? "bare cors call" : "wildcard origin",
          reflected: REFLECTED_ORIGIN.test(call),
        });
    }
  }

  const header = WILDCARD_HEADER.exec(ctx.uncommented(file));
  if (header)
    lines.set(lineAt(starts, header.index), { how: "wildcard allow-origin header", reflected: false });

  // A literal `*` cannot carry credentials (browsers refuse the pair), so on its own it
  // exposes public data only; a reflected origin with credentials exposes the session.
  const credentials = CORS_CREDENTIALS.test(ctx.uncommented(file));
  return [...lines].map(([line, { how, reflected }]) => {
    const withSession = reflected || credentials;
    return {
      scope: "file" as const,
      expectation: withSession
        ? "Cross-origin access should be limited to the origins that need it"
        : "Cross-origin access should be limited to the origins that need it; a literal wildcard cannot carry credentials, so this exposes only what the endpoint serves to anyone",
      summary: `${file.path} allows any origin (${how})`,
      file: file.path,
      line,
      basisFacts: [how, ...(withSession ? ["credentials or reflected origin"] : ["no credentials"])],
      certainty: withSession ? 0.9 : 0.5,
      evidenceKind: "code" as const,
    };
  });
}

function corsPermissive(ctx: Ctx): Finding[] {
  return ctx.source.flatMap((file) => corsInFile(ctx, file));
}

// ---------------------------------------------------------------------------
// 12. supply_chain_integrity
// ---------------------------------------------------------------------------

const LOCKFILE =
  /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|deno\.lock)$/i;

/** True when the manifest declares at least one dependency of any kind. */
function declaresDependencies(content: string): boolean {
  try {
    const parsed = JSON.parse(content) as Record<string, unknown> | null;
    if (!parsed || typeof parsed !== "object") return false;
    return ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].some(
      (section) => {
        const value = parsed[section];
        return !!value && typeof value === "object" && Object.keys(value as object).length > 0;
      },
    );
  } catch {
    return false;
  }
}

/**
 * Postinstall commands that are the repository's own tooling, not a third-party hook:
 * the supply-chain vector is a dependency's postinstall, which `ignore-scripts` stops.
 */
const BENIGN_POSTINSTALL =
  /^\s*(?:husky(?:\s+install)?|prisma\s+generate|npx\s+prisma\s+generate|patch-package|next\s+telemetry|electron-builder\s+install-app-deps|ngcc|tsc\b|(?:npm|pnpm|yarn)\s+(?:run\s+)?build|node\s+scripts?\/)/i;

/** The postinstall command a manifest declares, or undefined. */
function postinstallCommand(content: string): string | undefined {
  try {
    const scripts = (JSON.parse(content) as { scripts?: Record<string, unknown> } | null)?.scripts;
    const command = scripts?.postinstall;
    return typeof command === "string" ? command : undefined;
  } catch {
    return undefined;
  }
}

/** `.npmrc` with `ignore-scripts=true`: no dependency's install script runs. */
function ignoresInstallScripts(ctx: Ctx): boolean {
  return ctx.files.some(
    (file) =>
      basename(file.path) === ".npmrc" && /^\s*ignore-scripts\s*=\s*true\s*$/im.test(file.content),
  );
}

function supplyChainIntegrity(ctx: Ctx): Finding[] {
  const manifests = ctx.files.filter((file) => isManifest(file.path));
  if (manifests.length === 0) return [];

  const found: Finding[] = [];
  const noLockfile = !ctx.files.some((file) =>
    LOCKFILE.test(normalizeSeparators(file.path)),
  );
  // A manifest with no dependencies has no tree to pin.
  if (noLockfile && manifests.some((manifest) => declaresDependencies(manifest.content))) {
    found.push({
      scope: "repository",
      expectation:
        "A committed lockfile pins the dependency tree. The loader caps how many and how large the files it fetches are, so a lockfile can be missing from this analysis without being missing from the repository",
      summary: `${manifests[0].path} declares dependencies and no lockfile was among the loaded files`,
      file: manifests[0].path,
      line: 1,
      basisFacts: ["manifest present", "no lockfile loaded"],
      certainty: 0.5,
      evidenceKind: "config",
    });
  }

  if (ignoresInstallScripts(ctx)) return found;
  for (const manifest of manifests) {
    if (!manifestScripts(manifest.content).includes("postinstall")) continue;
    const benign = BENIGN_POSTINSTALL.test(postinstallCommand(manifest.content) ?? "");
    found.push({
      scope: "repository",
      expectation: benign
        ? "A postinstall script runs on every install; this one is the repository's own tooling, so the exposure is the dependencies' install scripts, which ignore-scripts would stop"
        : "A postinstall script runs arbitrary code on every install and is a common supply chain vector",
      summary: `${manifest.path} runs a postinstall script on every install`,
      file: manifest.path,
      line: lineOf(manifest.content, '"postinstall"'),
      basisFacts: ["postinstall script declared", ...(benign ? ["known tooling command"] : [])],
      certainty: benign ? 0.4 : 0.9,
      evidenceKind: "config",
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// 13. security_headers_missing, for pages served without a server framework
// ---------------------------------------------------------------------------

/** GitHub Pages serves files as they are and cannot add response headers. */
const PAGES_DEPLOY = /\bactions\/deploy-pages@/;

/**
 * A served HTML page that runs scripts and sets no Content-Security-Policy, in a
 * repository with no server framework (that case is check 5's). Gated on the page
 * loading at least one script, since a CSP matters most where script runs.
 *
 * Certainty: a CDN or edge in front of the site can add the header without any trace
 * in the repository, so the absence is 0.7. When the site deploys with
 * actions/deploy-pages, GitHub Pages cannot add headers, so a meta tag is the only
 * place a policy could be and its absence is 0.85.
 */
function cspMissingInHtml(ctx: Ctx): Finding[] {
  if (ctx.facts.frameworks.some((f) => f.category === "web" && !f.dev)) return [];

  const page = ctx.files.find(
    (file) =>
      isServedHtml(file.path) &&
      scriptTags(file.content).length > 0 &&
      !hasCspMeta(file.content),
  );
  if (!page) return [];

  const configs = ctx.files.filter((file) => isHeaderConfig(file.path));
  if (configs.some(declaresHeaders)) return [];
  const named = /Content-Security-Policy/i;
  if ([...ctx.source, ...configs].some((file) => named.test(ctx.uncommented(file))))
    return [];

  const githubPages = ctx.files.some(
    (file) => isGithubWorkflow(file.path) && PAGES_DEPLOY.test(maskYamlComments(file.content)),
  );
  return [
    {
      scope: "file",
      expectation: githubPages
        ? "A page that runs scripts should set a content security policy; it deploys to GitHub Pages, which cannot add response headers, so a meta tag is the only place one could be"
        : "A page that runs scripts should set a content security policy, in a meta tag or a response header",
      summary: `${page.path} loads scripts and sets no Content-Security-Policy meta tag, and no header configuration sets one`,
      file: page.path,
      line: 1,
      basisFacts: [
        "served HTML page loads scripts",
        "no CSP meta tag or header configuration",
        ...(githubPages ? ["deployed with actions/deploy-pages"] : []),
      ],
      certainty: githubPages ? 0.85 : 0.7,
      evidenceKind: "code",
    },
  ];
}

/** YAML `#` comments blanked, so a commented-out step does not count. */
function maskYamlComments(content: string): string {
  return content.replace(/(^|\s)#.*$/gm, "$1");
}

// ---------------------------------------------------------------------------
// 14. supply_chain_integrity: CDN scripts without subresource integrity
// ---------------------------------------------------------------------------

/**
 * A `<script src>` from another origin with no `integrity` attribute runs whatever the
 * CDN serves. A positive observation of the tag, so certainty is high; one finding per
 * page, at its first such tag, naming the libraries by the name derived from the URL.
 */
/**
 * Vendors that serve a mutable script and document that SRI must not be used on it:
 * payments, tag managers, analytics, maps, CAPTCHAs, chat widgets. An integrity hash on
 * these would break the page at the vendor's next deploy.
 */
const NO_SRI_HOSTS =
  /^(?:js\.stripe\.com|(?:www\.)?googletagmanager\.com|(?:www\.)?google-analytics\.com|maps\.googleapis\.com|js\.hcaptcha\.com|challenges\.cloudflare\.com|connect\.facebook\.net|widget\.intercom\.io|cdn\.segment\.com|js\.sentry-cdn\.com|browser\.sentry-cdn\.com|static\.hotjar\.com|cdn\.paddle\.com|checkout\.razorpay\.com|www\.paypal\.com|www\.paypalobjects\.com|js\.braintreegateway\.com|cdn\.jsdelivr\.net\/npm\/@?[^/]+@latest)$/i;

function hostOf(src: string): string | undefined {
  try {
    return new URL(src.startsWith("//") ? `https:${src}` : src).host.toLowerCase();
  } catch {
    return undefined;
  }
}

/** Build tools that add integrity hashes to the emitted HTML. */
const SRI_BUILD_DEPS = ["webpack-subresource-integrity", "vite-plugin-sri", "rollup-plugin-sri", "@nuxtjs/security", "nuxt-security"];

function cdnScriptsWithoutIntegrity(ctx: Ctx): Finding[] {
  const found: Finding[] = [];
  if (hasAny(ctx.deps, SRI_BUILD_DEPS)) return found;
  for (const page of ctx.files) {
    if (!isServedHtml(page.path)) continue;

    const bare = scriptTags(page.content).filter((tag) => {
      if (!tag.external || tag.integrity) return false;
      const host = hostOf(tag.src);
      return host === undefined || !NO_SRI_HOSTS.test(host);
    });
    if (bare.length === 0) continue;

    const names = [
      ...new Set(bare.map((tag) => cdnLibrary(tag.src)?.name ?? "unknown")),
    ];
    found.push({
      scope: "file",
      expectation:
        "A script loaded from another origin should carry a subresource integrity hash, so a compromised or changed CDN file is refused",
      summary: `${page.path} loads ${bare.length} script(s) from another origin with no integrity attribute (${names.join(", ")})`,
      file: page.path,
      line: bare[0].line,
      basisFacts: [`${bare.length} external script tag(s)`, "no integrity attribute"],
      certainty: 0.9,
      evidenceKind: "code",
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// 15. client_secret_storage
// ---------------------------------------------------------------------------

/**
 * A secret-named key written to localStorage or sessionStorage (datastores.ts found the
 * write). "Present but ineffective" rather than absent: the write is observed, and what
 * is uncertain is only whether the key's name tells the truth, hence 0.75.
 */
function secretInBrowserStorage(ctx: Ctx): Finding[] {
  const scannable = new Set(ctx.source.map((file) => file.path));
  return ctx.facts.datastores
    .filter((store) => store.kind === "browser_storage" && scannable.has(store.file))
    .map((store) => ({
      scope: "file" as const,
      expectation:
        "A credential in localStorage or sessionStorage is readable by every script on the page, so one injected or compromised script can take it; it belongs on a server or in an HttpOnly cookie",
      summary: `${store.file} writes a secret-named key to ${store.name}`,
      file: store.file,
      line: store.line,
      basisFacts: ["browser storage write", "key names a secret or token"],
      certainty: 0.75,
      evidenceKind: "code" as const,
    }));
}

// ---------------------------------------------------------------------------
// 16. input_validation_missing: Firestore rules
// ---------------------------------------------------------------------------

const RULES_WRITE = /\ballow\b[^;:{}]*\b(?:write|create|update)\b/;

/**
 * Firestore rules that allow a write and never read `request.resource`, the incoming
 * document: any client that passes the auth condition can store any shape and size of
 * data. The rules file is self-contained, but validation could also live in a Cloud
 * Function trigger this repository does not show, so 0.8.
 */
function firestoreRulesUnvalidated(ctx: Ctx): Finding[] {
  const found: Finding[] = [];
  for (const file of ctx.files) {
    if (!isFirestoreRules(file.path)) continue;

    const text = maskComments(file.content);
    const write = RULES_WRITE.exec(text);
    if (!write) continue;
    if (/\brequest\s*\.\s*resource\b/.test(text)) continue;

    found.push({
      scope: "file",
      expectation:
        "Firestore rules that allow client writes should validate the incoming document (request.resource), since the client is the only thing between a user and the database",
      summary: `${file.path} allows writes and never checks request.resource, so written documents are not validated`,
      file: file.path,
      line: lineAt(lineStarts(text), write.index),
      basisFacts: ["Firestore rules allow a write", "no request.resource check"],
      certainty: 0.8,
      evidenceKind: "config",
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// 17. rate_limit_missing: a Worker in front of a paid API
// ---------------------------------------------------------------------------

/** Metered APIs where every forwarded request costs the owner money. */
const PAID_API_HOST =
  /\bhttps:\/\/(api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.cohere\.(?:ai|com)|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.replicate\.com)\b/;

/**
 * A Worker entry file that forwards to a metered API and applies no rate limiting: a
 * caller who gets past its auth, or a stolen token, can run up the bill. Certainty 0.6,
 * because a Cloudflare rate-limiting rule configured in the dashboard leaves no trace in
 * the repository.
 */
function workerProxyWithoutRateLimit(ctx: Ctx): Finding[] {
  const workers = new Set(
    ctx.facts.frameworks
      .filter((f) => f.category === "edge_runtime" && f.origin === "usage")
      .map((f) => f.file),
  );
  if (workers.size === 0) return [];
  if (hasAny(ctx.deps, RATE_LIMIT_DEPS)) return [];
  if (configMentions(ctx, CONFIG_RATE_LIMIT)) return [];

  const found: Finding[] = [];
  for (const file of ctx.source) {
    if (!workers.has(file.path)) continue;

    const host = PAID_API_HOST.exec(ctx.uncommented(file));
    if (!host) continue;
    if (RATE_LIMIT_USAGE.test(ctx.code(file))) continue;
    // Cloudflare's rate limiting binding: `env.MY_LIMITER.limit({ key })`.
    if (/\.\s*limit\s*\(\s*\{/.test(ctx.code(file))) continue;

    found.push({
      scope: "file",
      expectation:
        "A Worker that forwards requests to a metered API should limit how often one caller can use it, or one caller can run up the bill",
      summary: `${file.path} is a Worker that forwards requests to ${host[1]} and no rate limiting was found in its code or configuration`,
      file: file.path,
      line: lineAt(lineStarts(file.content), host.index),
      basisFacts: ["Cloudflare Worker entry point", `forwards to ${host[1]}`, "no rate limiting"],
      certainty: 0.6,
      evidenceKind: "code",
    });
  }
  return found;
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

/** Fixed order: it is also the gap id order, so ids never depend on content. */
const CHECKS: readonly [GapKind, (ctx: Ctx) => Finding[]][] = [
  ["authz_missing", authzMissing],
  ["authn_missing", authnMissing],
  ["rate_limit_missing", rateLimitMissing],
  ["csrf_missing", csrfMissing],
  ["security_headers_missing", securityHeadersMissing],
  ["input_validation_missing", inputValidationMissing],
  ["transport_insecure", transportInsecure],
  ["password_storage_weak", passwordStorageWeak],
  ["logging_missing", loggingMissing],
  ["error_handling_gap", errorHandlingGap],
  ["cors_permissive", corsPermissive],
  ["supply_chain_integrity", supplyChainIntegrity],
  // Appended, never interleaved: ids of the checks above must not shift.
  ["security_headers_missing", cspMissingInHtml],
  ["supply_chain_integrity", cdnScriptsWithoutIntegrity],
  ["client_secret_storage", secretInBrowserStorage],
  ["input_validation_missing", firestoreRulesUnvalidated],
  ["rate_limit_missing", workerProxyWithoutRateLimit],
];

/**
 * Controls that should be present and are not, with the Evidence that backs each.
 *
 * Stable across runs: input is sorted by path, routes arrive in path-then-line order and
 * CHECKS is a fixed array, so the same repository yields the same `gap-3` and `ev-gap-3`
 * whatever order the loader fetched files in. Gap n and evidence n describe the same gap.
 */
export function detectGaps(
  files: readonly DetectorInput[],
  facts: DetectorResult,
): { gaps: ControlGap[]; evidence: Evidence[] } {
  const sorted = byPath(files);
  const ctx = buildContext(sorted, facts);
  const builder = new EvidenceBuilder();
  const gaps: ControlGap[] = [];
  const routePathOf = new Map(ctx.routes.map((route) => [route.id, route.normalizedPath]));

  for (const [kind, check] of CHECKS) {
    const meta = META[kind];
    for (const finding of check(ctx)) {
      gaps.push({
        id: `gap-${gaps.length + 1}`,
        kind,
        scope: finding.scope,
        control: meta.control,
        expectation: finding.expectation,
        file: finding.file,
        line: Math.max(1, Math.floor(finding.line)),
        ...(finding.routeId ? { routeId: finding.routeId } : {}),
        ...(finding.routeId && routePathOf.has(finding.routeId)
          ? { routePath: routePathOf.get(finding.routeId) }
          : {}),
        summary: finding.summary,
        basisFacts: finding.basisFacts,
        certainty: finding.certainty,
        owasp: [...meta.owasp],
        stride: [...meta.stride],
        cwe: [...meta.cwe],
      });
      builder.add(
        "gap",
        finding.evidenceKind,
        finding.summary,
        finding.file,
        finding.line,
        { ruleId: `gap:${kind}`, metadata: { owasp2025: [...meta.owasp] } },
      );
    }
  }

  return { gaps, evidence: builder.all() };
}
