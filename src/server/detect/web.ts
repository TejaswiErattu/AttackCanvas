import {
  lineAt,
  lineStarts,
  maskCode,
  maskComments,
  normalizeSeparators,
} from "@/server/detect/shared";
import type { DetectorInput } from "@/server/detect/types";

/**
 * Helpers for repositories with no package.json to read: static pages that load their
 * libraries with `<script src>`, browser JavaScript, and Cloudflare Workers. Pure, no I/O.
 *
 * Like every detector, these return names, versions, paths and lines, never matched
 * source text (CLAUDE.md rule 3). A script URL is reduced to a library name and version
 * before it leaves this module.
 */

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

/** A page that would be served: .html/.htm outside test, docs and build output. */
export function isServedHtml(path: string): boolean {
  const normalized = normalizeSeparators(path);
  return (
    /\.html?$/i.test(normalized) &&
    !/(^|\/)(?:tests?|__tests__|e2e|examples?|fixtures?|docs?|node_modules|coverage)\//i.test(
      normalized,
    )
  );
}

/** `<!-- ... -->` blanked with spaces, offsets and newlines kept, so a commented-out tag does not count. */
export function maskHtmlComments(content: string): string {
  return content.replace(/<!--[\s\S]*?(?:-->|$)/g, (comment) =>
    comment.replace(/[^\n]/g, " "),
  );
}

export type ScriptTag = {
  src: string;
  /** Loaded from another origin: an absolute http(s) URL or a protocol-relative one. */
  external: boolean;
  integrity: boolean;
  line: number;
};

/** Every `<script src=...>` in a page, in source order. Inline scripts have no src and are skipped. */
export function scriptTags(content: string): ScriptTag[] {
  const masked = maskHtmlComments(content);
  const starts = lineStarts(masked);
  const tags: ScriptTag[] = [];

  for (const match of masked.matchAll(/<script\b([^>]*)>/gi)) {
    const attributes = match[1];
    const src = /\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attributes);
    const value = src?.[1] ?? src?.[2] ?? src?.[3];
    if (!value) continue;

    tags.push({
      src: value,
      external: /^(?:https?:)?\/\//i.test(value),
      integrity: /\bintegrity\s*=/i.test(attributes),
      line: lineAt(starts, match.index ?? 0),
    });
  }
  return tags;
}

/** True when the page sets a Content-Security-Policy with a meta tag. */
export function hasCspMeta(content: string): boolean {
  return /<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy/i.test(
    maskHtmlComments(content),
  );
}

/**
 * A CDN script URL reduced to a library name and version, or undefined when it does not
 * look like one. Only the shapes the common CDNs use are recognised; an unrecognised URL
 * is named by its host rather than guessed at.
 *
 *   https://www.gstatic.com/firebasejs/10.12.0/firebase-auth-compat.js -> firebase 10.12.0
 *   https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js  -> chart.js 4.4.0
 *   https://unpkg.com/@scope/pkg@1.2.3                                  -> @scope/pkg 1.2.3
 *   https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.js  -> lodash.js 4.17.21
 */
export function cdnLibrary(
  src: string,
): { name: string; version: string } | undefined {
  let url: URL;
  try {
    url = new URL(src.startsWith("//") ? `https:${src}` : src);
  } catch {
    return undefined;
  }
  const path = url.pathname;
  const clean = (value: string) => value.replace(/[^\w@./-]/g, "").slice(0, 80);

  const firebase = /^\/firebasejs\/([\w.-]+)\//.exec(path);
  if (firebase) return { name: "firebase", version: clean(firebase[1]) };

  const npm =
    /^\/(?:npm\/)?((?:@[\w.-]+\/)?[\w.-]+)@([\w.^~-]+)/.exec(path) ??
    undefined;
  if (npm && /(?:^|\.)(?:jsdelivr\.net|unpkg\.com|esm\.sh|skypack\.dev)$/.test(url.hostname)) {
    return { name: clean(npm[1]), version: clean(npm[2]) };
  }

  const cdnjs = /^\/ajax\/libs\/([\w.-]+)\/([\w.-]+)\//.exec(path);
  if (cdnjs) return { name: clean(cdnjs[1]), version: clean(cdnjs[2]) };

  return { name: clean(url.hostname), version: "" };
}

// ---------------------------------------------------------------------------
// Cloudflare Workers
// ---------------------------------------------------------------------------

/**
 * Offset of a Worker's fetch entry point, or undefined when the file has none:
 *   - module syntax: `export default { fetch(...) }` or `{ async fetch(...) }` or `{ fetch: handler }`;
 *   - service-worker syntax: `addEventListener("fetch", ...)`.
 * The module form is read from string-masked code; the listener form needs its event
 * name, which is a string, so it is read from comment-masked text.
 */
export function workerEntryOffset(content: string): number | undefined {
  const code = maskCode(content);
  const moduleEntry = /\bexport\s+default\s*\{\s*(?:async\s+)?fetch\s*[(:,]/.exec(code);
  if (moduleEntry) return moduleEntry.index;

  const listener = /\baddEventListener\s*\(\s*(['"`])fetch\1/.exec(
    maskComments(content),
  );
  return listener?.index;
}

export function isJavaScriptPath(path: string): boolean {
  return /\.(?:ts|tsx|js|jsx|mjs|cjs)$/.test(normalizeSeparators(path));
}

// ---------------------------------------------------------------------------
// Browser storage
// ---------------------------------------------------------------------------

/** A storage key that names a credential rather than ordinary state. */
const SECRET_KEY = /api[_-]?key|secret|token|passw|credential|jwt|bearer|private[_-]?key/i;

export type StorageWrite = {
  storage: "localStorage" | "sessionStorage";
  /** The key as written: a literal's value, or a constant's value when it resolves in the same file. */
  key: string;
  line: number;
};

/**
 * `localStorage.setItem(key, ...)` and `sessionStorage.setItem(key, ...)` whose key looks
 * like a secret or a token. An identifier key is resolved to a `const` string in the same
 * file when one is declared, and judged by its own name either way, so
 * `setItem(API_KEY_STORAGE_KEY, key)` counts. A key that is not a short plain name is
 * reported by its identifier instead of by its value.
 */
export function secretStorageWrites(file: DetectorInput): StorageWrite[] {
  const text = maskComments(file.content);
  const starts = lineStarts(text);
  const writes: StorageWrite[] = [];

  const pattern =
    /\b(localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(?:(['"`])([^'"`\n]*)\2|([A-Za-z_$][\w$.]*))/g;
  for (const match of text.matchAll(pattern)) {
    const storage = match[1] as StorageWrite["storage"];
    const literal = match[3];
    const identifier = match[4];
    const resolved =
      identifier !== undefined ? constantValue(text, identifier) : undefined;
    const candidates = [literal, identifier, resolved].filter(
      (value): value is string => value !== undefined,
    );
    if (!candidates.some((value) => SECRET_KEY.test(value))) continue;

    const plain = [literal, resolved].find(
      (value) => value !== undefined && /^[\w.:-]{1,64}$/.test(value),
    );
    writes.push({
      storage,
      key: plain ?? identifier ?? "unnamed key",
      line: lineAt(starts, match.index ?? 0),
    });
  }
  return writes;
}

/** The string a `const NAME = "..."` declares in this text, if any. */
function constantValue(text: string, name: string): string | undefined {
  const escaped = name.replace(/[$.]/g, "\\$&");
  const match = new RegExp(
    `\\bconst\\s+${escaped}\\s*=\\s*(['"\`])([^'"\`\\n]*)\\1`,
  ).exec(text);
  return match?.[2];
}
