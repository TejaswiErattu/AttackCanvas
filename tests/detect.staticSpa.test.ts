/**
 * Detector coverage for a static single-page app with a Cloudflare Worker and Firebase,
 * using a trimmed offline copy of TejaswiErattu/tejaswisummer (tests/fixtures/static-spa).
 * That repository produced zero facts of every kind before these detectors existed.
 * No network.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { runDetectors } from "@/server/detect";
import { detectTokenChecks } from "@/server/detect/auth";
import { secretStorageWrites, cdnLibrary, scriptTags, workerEntryOffset } from "@/server/detect/web";
import { assertNoSecrets } from "@/server/security/redactor";
import { EvidenceSchema } from "@/shared/schema";
import type { DetectorInput } from "@/server/detect/types";

const ROOT = join(__dirname, "fixtures", "static-spa");

function load(dir: string): DetectorInput[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return load(full);
    if (entry.name === "README.md") return [];
    return [{ path: relative(ROOT, full), content: readFileSync(full, "utf8") }];
  });
}

const FILES = load(ROOT);
const result = runDetectors(FILES);
const file = (path: string, content: string): DetectorInput => ({ path, content });

describe("static SPA fixture: every fact type is non-empty", () => {
  it("finds frameworks, routes, auth, datastores, deployment, tokens, gaps and evidence", () => {
    expect(result.frameworks.length).toBeGreaterThan(0);
    expect(result.routes.length).toBeGreaterThan(0);
    expect(result.auth.length).toBeGreaterThan(0);
    expect(result.datastores.length).toBeGreaterThan(0);
    expect(result.deployment.length).toBeGreaterThan(0);
    expect(result.tokens.length).toBeGreaterThan(0);
    expect(result.gaps.length).toBeGreaterThan(0);
    expect(result.evidence.length).toBeGreaterThan(0);
  });

  it("emits schema-valid evidence that carries no repository secret", () => {
    for (const e of result.evidence) expect(EvidenceSchema.safeParse(e).success).toBe(true);
    expect(() => assertNoSecrets(JSON.stringify(result))).not.toThrow();
  });
});

describe("frameworks", () => {
  it("reads CDN script tags as one library per name, with its version", () => {
    const cdn = result.frameworks.filter((f) => f.origin === "cdn");
    expect(cdn).toEqual([
      expect.objectContaining({ name: "firebase", category: "cloud", version: "10.12.0", file: "index.html" }),
    ]);
  });

  it("recognises the Worker entry point and Firebase SDK usage", () => {
    expect(result.frameworks).toContainEqual(
      expect.objectContaining({ name: "cloudflare-workers", category: "edge_runtime", file: "proxy/worker.js" }),
    );
    expect(result.frameworks).toContainEqual(
      expect.objectContaining({ name: "firebase", origin: "usage", file: "firebase-sync.js" }),
    );
  });

  it("ignores same-origin scripts and commented-out tags", () => {
    const html = `<!-- <script src="https://cdn.jsdelivr.net/npm/evil@1.0.0/x.js"></script> -->
<script src="app.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>`;
    const tags = scriptTags(html);
    expect(tags.map((t) => t.external)).toEqual([false, true]);
    expect(cdnLibrary(tags[1].src)).toEqual({ name: "chart.js", version: "4.4.0" });
  });

  it("finds both Worker syntaxes and not a plain default export", () => {
    expect(workerEntryOffset("export default { async fetch(req) {} }")).toBe(0);
    expect(workerEntryOffset('addEventListener("fetch", (e) => {})')).toBe(0);
    expect(workerEntryOffset("export default { name: 'x' }")).toBeUndefined();
    expect(workerEntryOffset("// export default { fetch() {} }")).toBeUndefined();
  });
});

describe("routes and auth", () => {
  it("derives Worker routes from its method checks, at the entry point", () => {
    const worker = result.routes.filter((r) => r.framework === "cloudflare_worker");
    expect(worker.map((r) => `${r.method} ${r.normalizedPath}`).sort()).toEqual(["OPTIONS *", "POST *"]);
    expect(new Set(worker.map((r) => r.line)).size).toBe(1);
  });

  it("uses pathname comparisons when the Worker has them", () => {
    const routes = runDetectors([
      file(
        "src/index.js",
        `export default { async fetch(request) {
  const url = new URL(request.url);
  if (url.pathname === "/api/chat") return chat(request);
  if (url.pathname.startsWith("/static")) return asset(request);
} };`,
      ),
    ]).routes;
    expect(routes.map((r) => `${r.method} ${r.normalizedPath}`).sort()).toEqual([
      "ALL /api/chat",
      "ALL /static/*",
    ]);
  });

  it("treats the Worker's POST as authenticated by its signature check", () => {
    const post = result.routes.find((r) => r.framework === "cloudflare_worker" && r.method === "POST")!;
    const auth = result.auth.find((a) => a.routeId === post.id)!;
    expect(auth.status).toBe("authenticated");
    expect(auth.signals).toContain("crypto.subtle.verify");
  });

  it("records verification in the Worker and an unverified decode in the browser", () => {
    expect(result.tokens).toEqual([
      expect.objectContaining({ kind: "decoded_unverified", file: "js/chatbot/auth.js" }),
      expect.objectContaining({ kind: "signature_verified", via: "crypto.subtle.verify", algorithmPinned: true, file: "proxy/worker.js" }),
    ]);
  });

  it("does not count crypto.subtle.verify on a non-token signature, or a decode that is verified", () => {
    expect(
      detectTokenChecks([file("hook.js", "await crypto.subtle.verify('HMAC', key, sig, body);")]),
    ).toEqual([]);
    const verified = detectTokenChecks([
      file("a.js", "const p = atob(t.split('.')[1]); jwt.verify(t, key, { algorithms: ['RS256'] });"),
    ]);
    expect(verified.map((c) => c.kind)).toEqual(["signature_verified"]);
  });
});

describe("datastores", () => {
  it("finds Firestore from its rules and its SDK calls", () => {
    const firestore = result.datastores.filter((d) => d.kind === "firestore");
    expect(firestore).toContainEqual(expect.objectContaining({ origin: "config", file: "firestore.rules" }));
    expect(firestore).toContainEqual(
      expect.objectContaining({ origin: "usage", name: "firebase.firestore", file: "firebase-sync.js" }),
    );
  });

  it("records only secret-named browser storage keys, resolving a constant key", () => {
    const stores = result.datastores.filter((d) => d.kind === "browser_storage");
    expect(stores.map((d) => `${d.file} ${d.name}`)).toEqual([
      "js/chatbot/api.js localStorage chatbot_anthropic_api_key",
    ]);
  });

  it("judges a key by its identifier and its literal", () => {
    const writes = secretStorageWrites(
      file(
        "x.js",
        `localStorage.setItem("theme", "dark");
sessionStorage.setItem("auth_token", t);
localStorage.setItem(ACCESS_TOKEN_KEY, t);
// localStorage.setItem("api_key", k);`,
      ),
    );
    expect(writes.map((w) => `${w.storage} ${w.key}`)).toEqual([
      "sessionStorage auth_token",
      "localStorage ACCESS_TOKEN_KEY",
    ]);
  });
});

describe("deployment", () => {
  it("records GitHub Actions jobs by workflow and job id", () => {
    expect(result.deployment).toEqual([
      expect.objectContaining({ kind: "github_actions", name: "deploy-pages.yml:deploy" }),
    ]);
  });
});

describe("gaps", () => {
  const kinds = result.gaps.map((g) => `${g.kind} ${g.file}`);

  it("finds the five static-site gaps", () => {
    expect(kinds).toEqual([
      "security_headers_missing index.html",
      "supply_chain_integrity index.html",
      "client_secret_storage js/chatbot/api.js",
      "input_validation_missing firestore.rules",
      "rate_limit_missing proxy/worker.js",
    ]);
  });

  it("raises CSP certainty when GitHub Pages cannot add headers", () => {
    const csp = result.gaps.find((g) => g.kind === "security_headers_missing")!;
    expect(csp.certainty).toBe(0.85);
    const withoutPages = runDetectors(FILES.filter((f) => !f.path.startsWith(".github")));
    expect(withoutPages.gaps.find((g) => g.kind === "security_headers_missing")?.certainty).toBe(0.7);
  });

  it("each gap has evidence with its gap: rule id", () => {
    const gapEvidence = result.evidence.filter((e) => e.ruleId?.startsWith("gap:"));
    expect(gapEvidence.map((e) => e.ruleId)).toEqual(result.gaps.map((g) => `gap:${g.kind}`));
  });

  // The negatives: each gap is withdrawn when its control is present.
  it("no CSP gap when the page sets a CSP meta tag", () => {
    const html = FILES.find((f) => f.path === "index.html")!;
    const fixed = FILES.map((f) =>
      f === html
        ? { ...f, content: f.content.replace("<head>", `<head><meta http-equiv="Content-Security-Policy" content="default-src 'self'">`) }
        : f,
    );
    expect(runDetectors(fixed).gaps.some((g) => g.kind === "security_headers_missing")).toBe(false);
  });

  it("no integrity gap when every CDN script has integrity", () => {
    const html = FILES.find((f) => f.path === "index.html")!;
    const fixed = FILES.map((f) =>
      f === html ? { ...f, content: f.content.replace(/<script src="https/g, '<script integrity="sha384-x" src="https') } : f,
    );
    expect(
      runDetectors(fixed).gaps.some((g) => g.kind === "supply_chain_integrity" && g.file === "index.html"),
    ).toBe(false);
  });

  it("no Firestore gap when the rules validate request.resource", () => {
    const fixed = FILES.map((f) =>
      f.path === "firestore.rules"
        ? { ...f, content: f.content.replace("request.auth.uid == userId;", "request.auth.uid == userId && request.resource.data.keys().hasOnly(['state']);") }
        : f,
    );
    expect(runDetectors(fixed).gaps.some((g) => g.kind === "input_validation_missing")).toBe(false);
  });

  it("no Firestore gap when the rules only allow reads", () => {
    const rules = file("firestore.rules", "match /x/{id} { allow read: if true; }");
    expect(runDetectors([rules]).gaps).toEqual([]);
  });

  it("no Worker rate-limit gap with a limiter binding, or without a paid API", () => {
    const worker = FILES.find((f) => f.path === "proxy/worker.js")!;
    const limited = { ...worker, content: worker.content.replace("// --- forward ---", "const { success } = await env.LIMITER.limit({ key: claims.email });") };
    expect(runDetectors([limited]).gaps.some((g) => g.kind === "rate_limit_missing")).toBe(false);
    const free = { ...worker, content: worker.content.replace("https://api.anthropic.com/v1/messages", "https://example.org/echo") };
    expect(runDetectors([free]).gaps.some((g) => g.kind === "rate_limit_missing")).toBe(false);
  });

  it("no CSP gap for a server framework's app: check 5 owns that case", () => {
    const files = [
      file("package.json", JSON.stringify({ dependencies: { express: "^4.18.0", helmet: "^7.0.0" } })),
      file("public/index.html", "<html><script src='app.js'></script></html>"),
    ];
    expect(runDetectors(files).gaps.some((g) => g.kind === "security_headers_missing")).toBe(false);
  });
});
