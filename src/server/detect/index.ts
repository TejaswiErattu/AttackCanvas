import { EvidenceBuilder, byPath } from "@/server/detect/shared";
import { detectFrameworks } from "@/server/detect/frameworks";
import { detectRoutes } from "@/server/detect/routes";
import { detectAuth, detectTokenChecks } from "@/server/detect/auth";
import { detectDatastores } from "@/server/detect/datastores";
import { detectEnvNames } from "@/server/detect/envNames";
import { detectDeployment } from "@/server/detect/deployment";
import { detectGaps } from "@/server/detect/gaps";
import type {
  DetectorInput,
  DetectorResult,
  Framework,
  TokenCheck,
} from "@/server/detect/types";

export * from "@/server/detect/types";
export { categoryOf, detectFrameworks } from "@/server/detect/frameworks";
export {
  appRouterPath,
  detectRoutes,
  joinPaths,
  middlewareName,
  mountPrefixes,
  pagesApiPath,
  splitCallArguments,
} from "@/server/detect/routes";
export {
  authForRoute,
  detectAuth,
  detectTokenChecks,
  handlerBody,
} from "@/server/detect/auth";
export { detectDatastores } from "@/server/detect/datastores";
export { detectEnvNames } from "@/server/detect/envNames";
export { detectDeployment } from "@/server/detect/deployment";
export { detectGaps } from "@/server/detect/gaps";
export { normalizeRoutePath } from "@/server/detect/shared";

/**
 * Runs every detector over the loaded repository and returns the facts plus the
 * Evidence that backs them.
 *
 * Evidence ids are stable: the input is sorted by path first and each detector emits in
 * source order, so the same repository produces the same "ev-route-3" on every run
 * regardless of the order the loader happened to fetch files in. Route ids line up with
 * their evidence, so route-7 is described by ev-route-7 and ev-auth-7.
 *
 * No summary ever contains matched source text. Repository content is untrusted
 * (CLAUDE.md rule 3) and could hold a credential, so summaries are built from derived
 * facts only — a package name, a route path, an env var name — and `snippet` is never
 * set.
 */
export function runDetectors(files: readonly DetectorInput[]): DetectorResult {
  const sorted = byPath(files);
  const evidence = new EvidenceBuilder();

  const frameworks = detectFrameworks(sorted);
  const routes = detectRoutes(sorted);
  const auth = detectAuth(sorted, routes);
  const datastores = detectDatastores(sorted, frameworks);
  const envNames = detectEnvNames(sorted);
  const deployment = detectDeployment(sorted);
  const tokens = detectTokenChecks(sorted);

  for (const framework of frameworks) {
    evidence.add(
      "framework",
      framework.origin === "usage" ? "code" : "config",
      frameworkSummary(framework),
      framework.file,
      framework.line,
    );
  }

  for (const route of routes) {
    evidence.add(
      "route",
      "code",
      `${route.method} ${route.normalizedPath} handled here (${route.framework})`,
      route.file,
      route.line,
    );
  }

  const routeById = new Map(routes.map((route) => [route.id, route]));
  for (const fact of auth) {
    const route = routeById.get(fact.routeId);
    if (!route) continue;

    evidence.add(
      "auth",
      "code",
      authSummary(fact.status, route.method, route.normalizedPath, fact),
      route.file,
      route.line,
    );
  }

  for (const datastore of datastores) {
    const how =
      datastore.origin === "dependency"
        ? `declared as a dependency`
        : datastore.origin === "config"
          ? `security rules declared in ${datastore.name}`
          : datastore.kind === "browser_storage"
            ? `a secret-named key is written to ${datastore.name}`
            : `connection opened with ${datastore.name}`;
    evidence.add(
      "datastore",
      datastore.origin === "usage" ? "code" : "config",
      `Datastore ${datastore.kind}: ${how}`,
      datastore.file,
      datastore.line,
    );
  }

  for (const envName of envNames) {
    const where =
      envName.origin === "env_example"
        ? "documented in .env.example"
        : "read from process.env";
    evidence.add(
      "env",
      envName.origin === "env_example" ? "config" : "code",
      `Environment variable ${envName.name} ${where}`,
      envName.file,
      envName.line,
    );
  }

  for (const item of deployment) {
    const ports =
      item.ports.length > 0 ? `, ports ${item.ports.join(", ")}` : "";
    evidence.add(
      "deploy",
      "config",
      `Deployment (${item.kind}): ${item.name}${ports}`,
      item.file,
      item.line,
    );
  }

  for (const check of tokens) {
    evidence.add("token", "code", tokenSummary(check), check.file, check.line);
  }

  const facts: DetectorResult = {
    frameworks,
    routes,
    auth,
    datastores,
    envNames,
    deployment,
    tokens,
    gaps: [],
    evidence: evidence.all(),
  };

  // Gaps read the facts above, so they run last and their evidence is appended.
  const gapResult = detectGaps(sorted, facts);
  return {
    ...facts,
    gaps: gapResult.gaps,
    evidence: [...facts.evidence, ...gapResult.evidence],
  };
}

function frameworkSummary(framework: Framework): string {
  const version = framework.version ? ` ${framework.version}` : "";
  if (framework.origin === "cdn") {
    return `Loads ${framework.name}${version} (${framework.category}) with a script tag from another origin`;
  }
  if (framework.origin === "usage") {
    return framework.category === "edge_runtime"
      ? `Cloudflare Worker fetch entry point (${framework.name})`
      : `Uses ${framework.name} (${framework.category}) in source`;
  }
  return `Depends on ${framework.name} (${framework.category})${framework.dev ? ", dev only" : ""}`;
}

function tokenSummary(check: TokenCheck): string {
  if (check.kind === "signature_verified") {
    return `Verifies a token signature with ${check.via}${
      check.algorithmPinned ? " and rejects unexpected signing algorithms" : ""
    }`;
  }
  return "Decodes a token payload with atob and verifies no signature in this file";
}

function authSummary(
  status: string,
  method: string,
  path: string,
  fact: { signals: string[]; roleChecks: string[]; adminPath: boolean },
): string {
  const parts: string[] = [];

  if (status === "authenticated") {
    parts.push(`${method} ${path} is guarded by ${fact.signals.join(", ")}`);
  } else if (status === "unknown") {
    parts.push(
      `${method} ${path} has middleware whose effect could not be determined from this file`,
    );
  } else {
    parts.push(`${method} ${path} has no authentication middleware`);
  }

  if (fact.roleChecks.length > 0)
    parts.push(`role checks: ${fact.roleChecks.join(", ")}`);
  if (fact.adminPath) parts.push("administrative path");

  return parts.join("; ");
}

/**
 * Framework names for RepoSummary.frameworks, which the loader currently leaves empty.
 * De-duplicated across manifests and sorted, so the summary is stable.
 */
export function frameworkNames(result: DetectorResult): string[] {
  return [
    ...new Set(result.frameworks.map((framework) => framework.name)),
  ].sort();
}
