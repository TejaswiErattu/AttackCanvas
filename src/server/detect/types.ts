import type { Evidence, Owasp2025, Stride } from "@/shared/schema";

/**
 * Facts the deterministic detectors extract from repository content.
 *
 * None of these live in src/shared/schema: that contract is frozen (CLAUDE.md rule 1)
 * and has no fact types. Only `Evidence` crosses back into the contract, the same way
 * semgrepClient.ts keeps `RawSemgrepFinding` local.
 *
 * Repository content is untrusted (rule 3), so a fact carries a *name* or a *path* and
 * never a value: no connection strings, no env values, no matched source text.
 */

/**
 * What a detector reads. `LoadedFile` from the ingest stage is structurally assignable,
 * so the loader's output can be passed straight in without a conversion.
 */
export type DetectorInput = { path: string; content: string };

export type FrameworkCategory =
  | "web"
  | "auth"
  | "database"
  | "cloud"
  | "payments"
  | "security_middleware"
  | "upload"
  | "templating"
  | "http_client"
  | "edge_runtime"
  | "browser_library";

/**
 * Where a framework fact came from: a package.json dependency, a `<script src>` loaded
 * from a CDN in an HTML page, or a usage pattern in source (a Cloudflare Worker's
 * `export default { fetch }`, a `firebase.initializeApp` call).
 */
export type FrameworkOrigin = "manifest" | "cdn" | "usage";

export type Framework = {
  name: string;
  category: FrameworkCategory;
  /** The declared range, e.g. "^4.18.2", or the version in a CDN URL; "" when unknown. */
  version: string;
  dev: boolean;
  file: string;
  line: number;
  /** Absent means "manifest", so facts built before this field existed still read right. */
  origin?: FrameworkOrigin;
};

export type HttpMethod =
  "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "ALL";

export type RouteFramework =
  "express" | "next_app" | "next_pages" | "cloudflare_worker";

export type Route = {
  /** Stable across runs: "route-7". Auth facts and evidence ids key off it. */
  id: string;
  method: HttpMethod;
  /** Framework-native, e.g. "/users/:id" for Express or "/users/[id]" for Next. */
  path: string;
  /** One vocabulary across frameworks: "[id]" -> ":id", "[...slug]" -> "*". */
  normalizedPath: string;
  file: string;
  line: number;
  middleware: string[];
  framework: RouteFramework;
};

export type AuthStatus = "authenticated" | "unauthenticated" | "unknown";

export type RouteAuth = {
  routeId: string;
  status: AuthStatus;
  /** Which guard names matched, so a reviewer can check the call. */
  signals: string[];
  roleChecks: string[];
  /** True when "admin" appears in the path: authenticated is not enough there. */
  adminPath: boolean;
};

export type DatastoreKind =
  | "postgres"
  | "mysql"
  | "mongodb"
  | "prisma"
  | "redis"
  | "sqlite"
  | "firestore"
  | "browser_storage"
  | "unknown";

export type Datastore = {
  kind: DatastoreKind;
  /** A package name or a constructor name. Never a connection string. */
  name: string;
  /** "config" is a datastore's own configuration file, e.g. firestore.rules. */
  origin: "dependency" | "usage" | "config";
  file: string;
  line: number;
};

export type EnvName = {
  name: string;
  origin: "env_example" | "process_env";
  file: string;
  line: number;
};

export type DeploymentKind =
  | "dockerfile"
  | "compose"
  | "vercel"
  | "serverless"
  | "terraform"
  | "github_actions";

export type Deployment = {
  kind: DeploymentKind;
  /** A service, function or resource name. Never a value. */
  name: string;
  ports: number[];
  file: string;
  line: number;
};

export type GapKind =
  | "authz_missing"
  | "authn_missing"
  | "rate_limit_missing"
  | "csrf_missing"
  | "security_headers_missing"
  | "input_validation_missing"
  | "transport_insecure"
  | "password_storage_weak"
  | "logging_missing"
  | "error_handling_gap"
  | "cors_permissive"
  | "supply_chain_integrity"
  | "client_secret_storage";

export type GapScope = "repository" | "route" | "file";

/**
 * A security control that should be present and cannot be found (or, for a few kinds, is
 * present but ineffective). Like every fact here it carries names and paths, never
 * matched source text (CLAUDE.md rule 3).
 *
 * `certainty` answers only "is the control really absent?" and is a property of the
 * detection method. It is not confidence and not severity; both are computed in
 * src/server/scoring (rule 2), which reads certainty as one input.
 */
export type ControlGap = {
  /** "gap-1", stable across runs. Kebab-case, so the kind cannot be part of it. */
  id: string;
  kind: GapKind;
  scope: GapScope;
  /** "ownership or role check" */
  control: string;
  /** Why this control was expected HERE. */
  expectation: string;
  file: string;
  line: number;
  routeId?: string;
  /**
   * What was found, naming the route or file it is about, e.g. "GET /learn reads request
   * input and its file imports no validation library". The same text as the gap's
   * evidence summary. Optional only so hand-built gaps in tests need not carry one.
   */
  summary?: string;
  /** Detector facts that established the expectation. */
  basisFacts: string[];
  /** 0..1, how sure the control is truly absent. */
  certainty: number;
  owasp: Owasp2025[];
  stride: Stride[];
  cwe: string[];
};

/**
 * How a file handles a bearer token (a JWT). `signature_verified` is a positive control:
 * the signature is checked (crypto.subtle.verify, jwt.verify, jose's jwtVerify) and the
 * algorithm is pinned. `decoded_unverified` is a payload read with atob and no signature
 * check in the same file, which is fine for display and never enough for authorization.
 */
export type TokenCheckKind = "signature_verified" | "decoded_unverified";

export type TokenCheck = {
  kind: TokenCheckKind;
  /** The call that established it, e.g. "crypto.subtle.verify". Never matched text. */
  via: string;
  /** True when an `alg` comparison was seen beside the verification. */
  algorithmPinned: boolean;
  file: string;
  line: number;
};

export type DetectorResult = {
  frameworks: Framework[];
  routes: Route[];
  auth: RouteAuth[];
  datastores: Datastore[];
  envNames: EnvName[];
  deployment: Deployment[];
  tokens: TokenCheck[];
  gaps: ControlGap[];
  evidence: Evidence[];
};
