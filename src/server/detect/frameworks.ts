import {
  basename,
  byPath,
  lineAt,
  lineOf,
  lineStarts,
  maskComments,
} from "@/server/detect/shared";
import {
  cdnLibrary,
  isJavaScriptPath,
  isServedHtml,
  scriptTags,
  workerEntryOffset,
} from "@/server/detect/web";
import type {
  DetectorInput,
  Framework,
  FrameworkCategory,
} from "@/server/detect/types";

/**
 * Frameworks and notable libraries, from every package.json in the repository.
 *
 * A monorepo has several manifests, so all of them are read and their findings merged:
 * "express in services/api" and "express in services/web" are two facts, because a
 * threat model cares which service pulls it in.
 */

/** Exact package names, by category. Scoped prefixes are handled separately. */
const EXACT: Record<string, FrameworkCategory> = {
  express: "web",
  next: "web",
  fastify: "web",
  koa: "web",
  hono: "web",
  "@nestjs/core": "web",
  nestjs: "web",

  passport: "auth",
  "next-auth": "auth",
  jsonwebtoken: "auth",
  jose: "auth",
  "express-session": "auth",
  bcrypt: "auth",
  bcryptjs: "auth",
  argon2: "auth",
  "firebase-admin": "auth",

  pg: "database",
  mysql2: "database",
  mongoose: "database",
  mongodb: "database",
  prisma: "database",
  "@prisma/client": "database",
  sequelize: "database",
  typeorm: "database",
  "drizzle-orm": "database",
  redis: "database",
  ioredis: "database",

  "aws-sdk": "cloud",
  firebase: "cloud",

  stripe: "payments",

  helmet: "security_middleware",
  cors: "security_middleware",
  "express-rate-limit": "security_middleware",
  csurf: "security_middleware",
  "express-validator": "security_middleware",
  zod: "security_middleware",
  joi: "security_middleware",

  multer: "upload",
  formidable: "upload",
  busboy: "upload",

  ejs: "templating",
  pug: "templating",
  handlebars: "templating",

  axios: "http_client",
  "node-fetch": "http_client",
  got: "http_client",
};

/** Scoped families, matched on the "@scope/" prefix. */
const PREFIXES: [string, FrameworkCategory][] = [
  ["@auth/", "auth"],
  ["@clerk/", "auth"],
  ["@supabase/", "auth"],
  ["@aws-sdk/", "cloud"],
  ["@google-cloud/", "cloud"],
  ["@nestjs/", "web"],
];

/** The category for a package name, or undefined when we do not track it. */
export function categoryOf(name: string): FrameworkCategory | undefined {
  const exact = EXACT[name];
  if (exact) return exact;

  for (const [prefix, category] of PREFIXES) {
    if (name.startsWith(prefix)) return category;
  }
  return undefined;
}

/** Package names we class as datastores, shared with datastores.ts. */
export function databasePackages(): string[] {
  return Object.keys(EXACT).filter((name) => EXACT[name] === "database");
}

type Manifest = {
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
};

/**
 * Parses a manifest, returning undefined rather than throwing. A repository is
 * untrusted input (CLAUDE.md rule 3), so a malformed package.json is an expected
 * case, not an error.
 */
function parseManifest(content: string): Manifest | undefined {
  try {
    const parsed: unknown = JSON.parse(content);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return undefined;
    return parsed as Manifest;
  } catch {
    return undefined;
  }
}

function entriesOf(
  section: Record<string, unknown> | undefined,
): [string, string][] {
  if (!section || typeof section !== "object" || Array.isArray(section))
    return [];
  return Object.entries(section).map(([name, version]) => [
    name,
    typeof version === "string" ? version : "",
  ]);
}

export function isManifest(path: string): boolean {
  return basename(path) === "package.json";
}

/**
 * The line of a dependency's key inside its own section. The same name can be a
 * top-level config key first (`"prisma": { "seed": … }`), so the search starts at the
 * section's key; the first occurrence anywhere is the fallback.
 */
function dependencyLine(
  content: string,
  section: string,
  name: string,
): number {
  const key = `"${name}"`;
  const start = content.indexOf(`"${section}"`);
  const offset = start === -1 ? -1 : content.indexOf(key, start);
  return offset === -1
    ? lineOf(content, key)
    : lineAt(lineStarts(content), offset);
}

/**
 * Every tracked dependency across every manifest, in path then declaration order.
 *
 * The line is found by searching the raw text for the package's JSON key within its
 * section, so evidence points at the real line rather than the top of the file. A name
 * appearing in both dependencies and devDependencies is reported once, as a runtime
 * dependency, since that is the stronger claim for a threat model.
 */
export function detectFrameworks(files: readonly DetectorInput[]): Framework[] {
  return [
    ...manifestFrameworks(files),
    ...cdnFrameworks(files),
    ...usageFrameworks(files),
  ];
}

function manifestFrameworks(files: readonly DetectorInput[]): Framework[] {
  const frameworks: Framework[] = [];

  for (const file of byPath(files)) {
    if (!isManifest(file.path)) continue;

    const manifest = parseManifest(file.content);
    if (!manifest) continue;

    const seen = new Set<string>();
    const sections: [string, boolean, [string, string][]][] = [
      ["dependencies", false, entriesOf(manifest.dependencies)],
      ["devDependencies", true, entriesOf(manifest.devDependencies)],
    ];

    for (const [section, dev, entries] of sections) {
      for (const [name, version] of entries) {
        const category = categoryOf(name);
        if (!category || seen.has(name)) continue;
        seen.add(name);

        frameworks.push({
          name,
          category,
          version,
          dev,
          file: file.path,
          line: dependencyLine(file.content, section, name),
        });
      }
    }
  }

  return frameworks;
}

/**
 * Libraries a served HTML page loads from another origin with `<script src>`: a static
 * site's dependency list, since it has no manifest. One fact per library per page, at
 * its first tag, so three Firebase compat scripts are one "firebase" fact.
 *
 * The category comes from the same table as manifests when the name is tracked
 * ("firebase" is cloud), and is browser_library otherwise.
 */
export function cdnFrameworks(files: readonly DetectorInput[]): Framework[] {
  const frameworks: Framework[] = [];

  for (const file of byPath(files)) {
    if (!isServedHtml(file.path)) continue;

    const seen = new Set<string>();
    for (const tag of scriptTags(file.content)) {
      if (!tag.external) continue;
      const library = cdnLibrary(tag.src);
      if (!library || seen.has(library.name)) continue;
      seen.add(library.name);

      frameworks.push({
        name: library.name,
        category: categoryOf(library.name) ?? "browser_library",
        version: library.version,
        dev: false,
        file: file.path,
        line: tag.line,
        origin: "cdn",
      });
    }
  }
  return frameworks;
}

/**
 * Platforms recognised by how source uses them rather than by a declared dependency:
 * a Cloudflare Worker's fetch entry point, and the Firebase SDK initialised from a CDN
 * global (`firebase.initializeApp`) or the modular import. One fact per file.
 */
export function usageFrameworks(files: readonly DetectorInput[]): Framework[] {
  const frameworks: Framework[] = [];

  for (const file of byPath(files)) {
    if (!isJavaScriptPath(file.path)) continue;
    const starts = lineStarts(file.content);

    const worker = workerEntryOffset(file.content);
    if (worker !== undefined) {
      frameworks.push({
        name: "cloudflare-workers",
        category: "edge_runtime",
        version: "",
        dev: false,
        file: file.path,
        line: lineAt(starts, worker),
        origin: "usage",
      });
    }

    const text = maskComments(file.content);
    const firebase =
      /\bfirebase\s*\.\s*initializeApp\s*\(/.exec(text) ??
      /\bfrom\s*['"`]firebase\/app['"`]/.exec(text);
    if (firebase) {
      frameworks.push({
        name: "firebase",
        category: "cloud",
        version: "",
        dev: false,
        file: file.path,
        line: lineAt(starts, firebase.index),
        origin: "usage",
      });
    }
  }
  return frameworks;
}

/**
 * Every dependency name declared in any manifest, tracked or not.
 *
 * detectFrameworks only records a curated allowlist, which is right for placing
 * components on a diagram and wrong for proving a control is absent: `pino`,
 * `rate-limiter-flexible` and `@node-rs/argon2` are not in it, so checking absence
 * there would report a gap when the control is installed.
 */
export function dependencyNames(files: readonly DetectorInput[]): Set<string> {
  const names = new Set<string>();

  for (const file of byPath(files)) {
    if (!isManifest(file.path)) continue;

    const manifest = parseManifest(file.content);
    if (!manifest) continue;

    for (const section of [manifest.dependencies, manifest.devDependencies]) {
      for (const [name] of entriesOf(section)) names.add(name);
    }
  }

  return names;
}

/** Scripts declared in a manifest, by name. Empty when it does not parse. */
export function manifestScripts(content: string): string[] {
  const scripts = (parseManifest(content) as { scripts?: unknown } | undefined)
    ?.scripts;
  if (!scripts || typeof scripts !== "object" || Array.isArray(scripts))
    return [];
  return Object.keys(scripts);
}
