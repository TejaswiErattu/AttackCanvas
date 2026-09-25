/**
 * Extra, bounded source windows for a threat batch: the handler code in an element's own
 * files, one DAO call from each handler, and the application's startup file.
 *
 * Why: a threat batch shows a file that no evidence points into as its first
 * COVERAGE_LINES lines only. In the NodeGoat evaluation that hid the lines that prove
 * three documented flaws even though no batch was near its budget: the `$where` query at
 * allocations-dao.js:78, the plaintext password compare at user-dao.js:61 and the
 * disabled CSRF middleware at server.js:107. These windows reach them without raising
 * the batch budget.
 *
 * Everything is found by reading text, never by executing it (CLAUDE.md rule 3), and is
 * limited three ways: a window count per element, a line count per window, and a
 * character budget per batch that buildThreatBatch enforces on top of its own limit.
 * Resolution is deliberately narrow, the Express/CommonJS shapes below; anything else
 * resolves to nothing rather than to a guess.
 *
 * Pure.
 */

import { dirname, join, normalize } from "node:path";
import type { Range } from "@/server/analysis/context";

/** Handler windows per element (definitions in the element's own files). */
export const MAX_HANDLER_WINDOWS_PER_ELEMENT = 4;
/** DAO windows per element (one call deep from those handlers). */
export const MAX_DAO_WINDOWS_PER_ELEMENT = 4;
/** Lines shown from a handler or DAO method definition onward. */
export const DEFINITION_WINDOW_LINES = 40;
/** Lines shown of the startup file, from its first line. */
export const STARTUP_MAX_LINES = 200;
/**
 * Characters of extra excerpt one batch may add, about 6,000 tokens at the context
 * builder's 3.5 characters per token. Windows are admitted whole, in priority order
 * (handlers, then DAO methods, then the startup file), until this is spent.
 */
export const EXTRA_CONTEXT_CHARS = 21_000;

export type SourceFile = { path: string; content: string };

export type ExtraWindow = {
  path: string;
  range: Range;
  kind: "handler" | "dao" | "startup";
  /** "displayAllocations", "AllocationsDAO.getByUserIdAndThreshold", or the file for startup. */
  label: string;
};

/** Blanks comments (keeping line breaks) so a commented-out definition is not resolved. */
function stripComments(content: string): string {
  return content
    .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, (_m, lead: string) => lead);
}

const HANDLER_DEFINITION = [
  // this.displayAllocations = (req, res, next) => {   /   this.x = function (req, res) {
  /^\s*this\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?\(\s*req\b/,
  // function handleLogin(req, res) {
  /^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(\s*req\b/,
  // const handleLogin = (req, res) => {
  /^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?\(\s*req\b/,
];

const ROUTE_REGISTRATION = /\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(/;

/** True when a file defines request handlers or registers Express routes. */
export function servesHttp(content: string): boolean {
  return handlerDefinitions(content).length > 0 || ROUTE_REGISTRATION.test(stripComments(content));
}

/** Request-handler definitions in a file: functions whose first parameter is `req`. */
export function handlerDefinitions(content: string): { name: string; line: number }[] {
  const out: { name: string; line: number }[] = [];
  stripComments(content)
    .split("\n")
    .forEach((text, index) => {
      for (const pattern of HANDLER_DEFINITION) {
        const match = pattern.exec(text);
        if (match) {
          out.push({ name: match[1], line: index + 1 });
          return;
        }
      }
    });
  return out;
}

/**
 * The file a relative require names, when it was loaded: "../data/allocations-dao" from
 * app/routes/allocations.js is app/data/allocations-dao.js. Package requires and anything
 * outside the loaded set resolve to undefined.
 */
export function resolveRequire(
  fromPath: string,
  specifier: string,
  known: ReadonlySet<string>,
): string | undefined {
  if (!specifier.startsWith(".")) return undefined;
  const base = normalize(join(dirname(fromPath), specifier)).replace(/\\/g, "/");
  for (const candidate of [base, `${base}.js`, `${base}.ts`, `${base}/index.js`, `${base}/index.ts`]) {
    if (known.has(candidate)) return candidate;
  }
  return undefined;
}

/**
 * Instance name -> [class name, file] for `const x = new X(...)` where X came from a
 * relative require in the same file:
 *   const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
 *   const { UserDAO } = require("../data/user-dao");
 *   const allocationsDAO = new AllocationsDAO(db);
 */
export function daoInstances(
  path: string,
  content: string,
  known: ReadonlySet<string>,
): Map<string, { className: string; file: string }> {
  const text = stripComments(content);
  const classFile = new Map<string, string>();
  const single = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*["']([^"']+)["']\s*\)(?:\.[A-Za-z_$][\w$]*)?/g;
  const destructured = /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*["']([^"']+)["']\s*\)/g;
  for (const m of text.matchAll(single)) {
    const file = resolveRequire(path, m[2], known);
    if (file) classFile.set(m[1], file);
  }
  for (const m of text.matchAll(destructured)) {
    const file = resolveRequire(path, m[2], known);
    if (!file) continue;
    for (const part of m[1].split(",")) {
      const name = part.split(":").pop()?.trim();
      if (name) classFile.set(name, file);
    }
  }
  const instances = new Map<string, { className: string; file: string }>();
  for (const m of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+([A-Za-z_$][\w$]*)\s*\(/g)) {
    const file = classFile.get(m[2]);
    if (file) instances.set(m[1], { className: m[2], file });
  }
  return instances;
}

/** The line a method is defined on: `this.m = ...`, `m(...) {` or `m: function`. */
export function methodDefinitionLine(content: string, method: string): number | undefined {
  const name = method.replace(/\$/g, "\\$");
  const patterns = [
    new RegExp(`^\\s*this\\.${name}\\s*=`),
    new RegExp(`^\\s*(?:async\\s+)?${name}\\s*\\([^)]*\\)\\s*\\{`),
    new RegExp(`^\\s*${name}\\s*:\\s*(?:async\\s+)?(?:function\\b|\\()`),
  ];
  const lines = stripComments(content).split("\n");
  const index = lines.findIndex((text) => patterns.some((p) => p.test(text)));
  return index === -1 ? undefined : index + 1;
}

/**
 * The application's startup file: the loaded source file that both creates an Express
 * app and starts listening. Shallowest path wins, then alphabetical, so the result does
 * not depend on load order. Undefined when there is none.
 */
export function startupFile(files: readonly SourceFile[]): string | undefined {
  const candidates = files.filter((f) => {
    if (!/\.(?:js|ts|mjs|cjs)$/.test(f.path)) return false;
    const text = stripComments(f.content);
    return /\bexpress\s*\(\s*\)/.test(text) && /\.listen\s*\(|\bcreateServer\s*\(/.test(text);
  });
  candidates.sort(
    (a, b) => a.path.split("/").length - b.path.split("/").length || a.path.localeCompare(b.path),
  );
  return candidates[0]?.path;
}

function clampWindow(lineCount: number, start: number, lines: number): Range {
  return [start, Math.min(lineCount, start + lines - 1)];
}

/**
 * The extra windows for one batch, in admission priority order. `elementFiles` is each
 * element's own file list; handler windows come only from those files, DAO windows may be
 * in any loaded file, and the startup file is offered once per batch when
 * `options.startup` is set (threatPrompt.ts decides that with servesBrowserRequests).
 */
export function extraWindows(
  elementFiles: readonly (readonly string[])[],
  files: readonly SourceFile[],
  options: { startup: boolean } = { startup: true },
): ExtraWindow[] {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const known = new Set(byPath.keys());
  const handlers: ExtraWindow[] = [];
  const daos: ExtraWindow[] = [];
  const seen = new Set<string>();
  const push = (list: ExtraWindow[], w: ExtraWindow) => {
    const key = `${w.path}:${w.range[0]}`;
    if (seen.has(key)) return false;
    seen.add(key);
    list.push(w);
    return true;
  };

  for (const own of elementFiles) {
    let handlerCount = 0;
    let daoCount = 0;
    for (const path of own) {
      const file = byPath.get(path);
      if (!file) continue;
      const lineCount = file.content.split("\n").length;
      const instances = daoInstances(path, file.content, known);
      const lines = file.content.split("\n");
      for (const handler of handlerDefinitions(file.content)) {
        if (handlerCount >= MAX_HANDLER_WINDOWS_PER_ELEMENT) break;
        const range = clampWindow(lineCount, handler.line, DEFINITION_WINDOW_LINES);
        if (push(handlers, { path, range, kind: "handler", label: handler.name })) handlerCount++;

        // One hop: `instance.method(` inside the handler window, instance from a require.
        const body = lines.slice(range[0] - 1, range[1]).join("\n");
        for (const call of body.matchAll(/\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(/g)) {
          if (daoCount >= MAX_DAO_WINDOWS_PER_ELEMENT) break;
          const target = instances.get(call[1]);
          const dao = target && byPath.get(target.file);
          if (!target || !dao) continue;
          const line = methodDefinitionLine(dao.content, call[2]);
          if (line === undefined) continue;
          const daoRange = clampWindow(dao.content.split("\n").length, line, DEFINITION_WINDOW_LINES);
          if (push(daos, { path: target.file, range: daoRange, kind: "dao", label: `${target.className}.${call[2]}` })) {
            daoCount++;
          }
        }
      }
    }
  }

  const startup = options.startup ? startupFile(files) : undefined;
  const out = [...handlers, ...daos];
  if (startup !== undefined) {
    const file = byPath.get(startup)!;
    out.push({
      path: startup,
      range: clampWindow(file.content.split("\n").length, 1, STARTUP_MAX_LINES),
      kind: "startup",
      label: startup,
    });
  }
  return out;
}
