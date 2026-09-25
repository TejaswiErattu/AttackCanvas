import {
  appRouterMethods,
  importsIn,
  splitCallArguments,
} from "@/server/detect/routes";
import {
  isAdminPath,
  lineStarts,
  lineAt,
  maskComments,
} from "@/server/detect/shared";
import type {
  AuthStatus,
  DetectorInput,
  Route,
  RouteAuth,
  TokenCheck,
} from "@/server/detect/types";

/**
 * Whether each route is guarded, and by what.
 *
 * AST NOTE: this matches strings inside the handler's own text and the imports of its
 * file. The TypeScript compiler API would let us follow a middleware identifier to its
 * declaration and see whether it actually calls a guard, instead of judging it by its
 * name. That is exactly the gap the "unknown" status exists to record, and with real
 * scope resolution most "unknown" results would resolve to a definite answer.
 */

/** Calls that are unambiguously an authentication check. */
const GUARD_CALLS = [
  "passport.authenticate",
  "getServerSession",
  "getSession",
  "verifyToken",
  "requireAuth",
  "isAuthenticated",
  "ensureLoggedIn",
];

/** A bare `auth(...)` call, which next-auth v5 uses. Needs the paren to avoid
 * matching the word "auth" inside an unrelated identifier. */
const AUTH_CALL = /\bauth\s*\(/;

/**
 * Names that read as a guard even when we cannot see the implementation. `logged_?in`
 * covers isLoggedIn / ensureLoggedIn / loggedInMiddleware (the Express idiom NodeGoat
 * uses); it never matches a login *handler* such as handleLoginRequest.
 */
export const GUARD_NAME =
  /auth|protect|require(?:User|Login|Role)|isAdmin|verify(?:Token|Jwt)|logged_?in/i;

/** `authLimiter`, `loginRateLimiter`: a rate limiter names what it slows, not a check. */
const LIMITER_NAME = /limit/i;

/**
 * True when a middleware or wrapper name reads as an authentication guard. The one
 * place a name is judged, so a rate limiter is never mistaken for a guard anywhere.
 */
export function isGuardName(name: string): boolean {
  return GUARD_NAME.test(name) && !LIMITER_NAME.test(name);
}

/** `export const POST = withAuth(...)`: group 1 is the wrapper the export is built from. */
const WRAPPED_EXPORT =
  /^export\s+const\s+[A-Z]+\s*(?::[^=]*)?=\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/;

/** Role checks are separate from authentication: being logged in is not being allowed. */
const ROLE_PATTERNS: [string, RegExp][] = [
  ["requireRole", /\brequireRole\b/],
  ["hasRole", /\bhasRole\b/],
  ["isAdmin", /\bisAdmin\b/],
  ["role comparison", /\brole\s*===?\s*['"`]/],
  ["roles.includes", /\broles?\s*\.\s*includes\s*\(/],
  ["scope check", /\bscopes?\s*\.\s*includes\s*\(/],
];

/**
 * The App Router export a route came from: where it starts, where the next export
 * starts, and whether it was named in an export list. Undefined when no export lines up.
 */
function appRouterExport(
  content: string,
  route: Route,
): { start: number; end: number; listed: boolean } | undefined {
  const starts = lineStarts(content);
  const handlers = appRouterMethods(content).sort(
    (a, b) => a.offset - b.offset,
  );
  const index = handlers.findIndex(
    (handler) =>
      handler.method === route.method &&
      lineAt(starts, handler.offset) === route.line,
  );
  if (index === -1) return undefined;

  return {
    start: handlers[index].offset,
    end: handlers[index + 1]?.offset ?? content.length,
    listed: handlers[index].listed,
  };
}

/**
 * The text of the handler a route points at, with comments blanked (offsets kept), so a
 * commented-out guard does not count and a comment cannot stretch the slice.
 *
 * Express: the arguments of the route call. App Router: only that export's own text,
 * from its declaration to the next one — scanning the whole file would mark a POST as
 * authenticated because the GET beside it calls getServerSession, and a false
 * "authenticated" hides a threat. An export list (`export { handler as GET }`) is the
 * exception: the handler is declared elsewhere in the file, so the whole file is its
 * text. Pages API: the whole file, which genuinely is one default export serving every
 * method.
 */
export function handlerBody(file: DetectorInput, route: Route): string {
  const content = maskComments(file.content);
  // A Pages API file and a Worker entry file are both one handler serving every route.
  if (route.framework === "next_pages" || route.framework === "cloudflare_worker")
    return content;

  if (route.framework === "next_app") {
    const found = appRouterExport(content, route);
    if (!found || found.listed) return content;
    return content.slice(found.start, found.end);
  }

  const starts = lineStarts(content);
  const lineStart = starts[route.line - 1] ?? 0;
  const open = content.indexOf("(", lineStart);
  if (open === -1) return "";

  const { args, end } = splitCallArguments(content, open + 1);
  return args.length > 0 ? content.slice(open, end) : "";
}

/**
 * The guard an App Router export is wrapped in, e.g. `withAuth` in
 * `export const POST = withAuth(async (req) => …)`. The wrapper is imported, so its
 * name is all there is to judge, exactly as for Express middleware.
 */
function exportWrapperGuard(
  file: DetectorInput,
  route: Route,
): string | undefined {
  if (route.framework !== "next_app") return undefined;

  const content = maskComments(file.content);
  const found = appRouterExport(content, route);
  if (!found || found.listed) return undefined;

  const callee = WRAPPED_EXPORT.exec(
    content.slice(found.start, found.end),
  )?.[1];
  return callee !== undefined && isGuardName(callee) ? callee : undefined;
}

function guardSignals(text: string): string[] {
  const signals = new Set<string>();

  for (const call of GUARD_CALLS) {
    if (text.includes(call)) signals.add(call);
  }
  if (AUTH_CALL.test(text)) signals.add("auth()");
  const verified = tokenVerification(text);
  if (verified) signals.add(verified.via);

  return [...signals];
}

function roleSignals(text: string): string[] {
  return ROLE_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(
    ([name]) => name,
  );
}

/**
 * Auth status for one route.
 *
 * "authenticated" when a known guard call or a guard-shaped name is involved, as
 * middleware or as the wrapper an App Router export is built from.
 * "unknown" when the route has middleware we cannot judge: it is imported from another
 * file and neither its name nor the handler text says what it does. That is a real
 * finding, not a failure — it tells the questions stage what to ask.
 * "unauthenticated" only when there is genuinely nothing.
 */
export function authForRoute(
  file: DetectorInput | undefined,
  route: Route,
): RouteAuth {
  const body = file ? handlerBody(file, route) : "";
  const middlewareText = route.middleware.join(" ");
  const combined = `${middlewareText}\n${body}`;

  const signals = guardSignals(combined);
  const namedGuards = route.middleware.filter(isGuardName);
  for (const name of namedGuards) signals.push(name);
  // `const check = sessionHandler.isLoggedInMiddleware;` then `app.post("/x", check, h)`:
  // the alias name says nothing, the member it points at does.
  if (file) {
    for (const name of route.middleware) {
      const target = aliasTarget(file.content, name);
      if (target !== undefined && isGuardName(target)) signals.push(`${name} = ${target}`);
    }
  }
  const wrapper = file ? exportWrapperGuard(file, route) : undefined;
  if (wrapper) signals.push(wrapper);

  const roleChecks = roleSignals(combined);
  const adminPath = isAdminPath(route.path);

  let status: AuthStatus;
  if (signals.length > 0) {
    status = "authenticated";
  } else if (file && hasOpaqueMiddleware(file, route)) {
    status = "unknown";
  } else {
    status = "unauthenticated";
  }

  return {
    routeId: route.id,
    status,
    signals: [...new Set(signals)],
    roleChecks,
    adminPath,
  };
}

/**
 * True when the route has middleware that is imported from elsewhere and tells us
 * nothing by its name. Locally defined middleware is not opaque: its body is in the
 * same file, so the text scan above already had its chance.
 */
function hasOpaqueMiddleware(file: DetectorInput, route: Route): boolean {
  if (route.middleware.length === 0) return false;

  const imports = importsIn(file.content);
  return route.middleware.some((name) => {
    if (isGuardName(name)) return false;
    const root = name.split(".")[0];
    // A member alias (`const check = handler.someMiddleware;`) is not locally defined:
    // its body lives wherever `handler` came from, so it is as opaque as an import.
    return imports.has(root) || aliasTarget(file.content, name) !== undefined;
  });
}

/**
 * `sessionHandler.isLoggedInMiddleware` for `const isLoggedIn = sessionHandler.isLoggedInMiddleware;`.
 * Only a plain member-expression alias counts (at least one dot, nothing else on the
 * right-hand side), read from comment-masked text so a commented-out alias is ignored.
 */
export function aliasTarget(content: string, name: string): string | undefined {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
  const pattern = new RegExp(
    `\\b(?:const|let|var)\\s+${name.replace(/\$/g, "\\$")}\\s*=\\s*([A-Za-z_$][\\w$]*(?:\\s*\\.\\s*[A-Za-z_$][\\w$]*)+)\\s*;`,
  );
  const match = pattern.exec(maskComments(content));
  return match ? match[1].replace(/\s+/g, "") : undefined;
}

/** Auth facts for every route, in route order. */
export function detectAuth(
  files: readonly DetectorInput[],
  routes: readonly Route[],
): RouteAuth[] {
  const byPathIndex = new Map(files.map((file) => [file.path, file]));
  return routes.map((route) =>
    authForRoute(byPathIndex.get(route.file), route),
  );
}

// ---------------------------------------------------------------------------
// Token handling
// ---------------------------------------------------------------------------

/**
 * Signature checks, most specific first. `crypto.subtle.verify` checks any signature (a
 * webhook HMAC too), so it only counts when the same text handles a bearer token.
 */
const VERIFY_CALLS: { via: string; pattern: RegExp; needsToken: boolean }[] = [
  { via: "jwt.verify", pattern: /\bjwt\s*\.\s*verify\s*\(/, needsToken: false },
  { via: "jwtVerify", pattern: /\bjwtVerify\s*\(/, needsToken: false },
  {
    via: "crypto.subtle.verify",
    pattern: /\bcrypto\s*\.\s*subtle\s*\.\s*verify\s*\(/,
    needsToken: true,
  },
];

const TOKEN_CONTEXT = /\b(?:id_?token|access_?token|token|jwt|authorization|bearer)\b/i;

/** `header.alg !== "RS256"` or `algorithms: [...]`: the verifier refuses other algorithms. */
const ALG_PINNED = /\balg\s*[!=]==?\s*['"`]|\balgorithms\s*:\s*\[/;

/** `token.split(".")[1]`: the payload segment of a JWT, read by hand. */
const PAYLOAD_SEGMENT = /\.\s*split\s*\(\s*(['"`])\.\1\s*\)\s*\[\s*1\s*\]/;

/** The verification a comment-masked text performs, if any. */
function tokenVerification(
  text: string,
): { via: string; offset: number } | undefined {
  for (const call of VERIFY_CALLS) {
    const match = call.pattern.exec(text);
    if (!match) continue;
    if (call.needsToken && !TOKEN_CONTEXT.test(text)) continue;
    return { via: call.via, offset: match.index };
  }
  return undefined;
}

/**
 * How each source file handles a JWT. A file that verifies a signature is a positive
 * control (`signature_verified`), with `algorithmPinned` recording whether it also
 * refuses unexpected algorithms. A file that reads the payload by hand (atob over
 * `token.split(".")[1]`) and verifies nothing is `decoded_unverified`: fine for showing a
 * name in the UI, never enough to authorise anything.
 *
 * Judged per file, so a browser file that decodes is reported even when a Worker
 * elsewhere verifies; that is the point, since the browser copy is the one a user can
 * edit.
 */
export function detectTokenChecks(files: readonly DetectorInput[]): TokenCheck[] {
  const checks: TokenCheck[] = [];

  for (const file of files) {
    if (!/\.(?:ts|tsx|js|jsx|mjs|cjs)$/.test(file.path)) continue;
    const text = maskComments(file.content);
    const starts = lineStarts(text);
    const algorithmPinned = ALG_PINNED.test(text);

    const verified = tokenVerification(text);
    if (verified) {
      checks.push({
        kind: "signature_verified",
        via: verified.via,
        algorithmPinned,
        file: file.path,
        line: lineAt(starts, verified.offset),
      });
      continue;
    }

    const payload = PAYLOAD_SEGMENT.exec(text);
    if (payload && /\batob\s*\(/.test(text)) {
      checks.push({
        kind: "decoded_unverified",
        via: "atob",
        algorithmPinned: false,
        file: file.path,
        line: lineAt(starts, payload.index),
      });
    }
  }
  return checks;
}

/** Re-exported so callers can report where a guard was seen without re-deriving it. */
export function guardLineIn(content: string, signal: string): number {
  const offset = content.indexOf(signal);
  return offset === -1 ? 1 : lineAt(lineStarts(content), offset);
}
