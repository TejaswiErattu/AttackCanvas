/**
 * Effective attributes of the session cookies a repository configures, with each
 * library's defaults applied: a fact the threat engine needs to reason about cookie theft,
 * and one a model reading the source tends to get wrong. `cookie: { httpOnly: true }` left
 * commented out does not make an express-session cookie readable by script, because
 * express-session defaults httpOnly to true.
 *
 * Only live code counts (comments are masked), only express-session and cookie-session are
 * recognised, and only literal option values are read. Anything else (options passed as a
 * variable, a computed value) is "unknown", never guessed. Pure: no I/O.
 */

import { lineAt, lineStarts, maskComments } from "@/server/detect/shared";
import type { DetectorInput } from "@/server/detect/types";

export type CookieAttribute<T> = {
  /** "unknown" when the option is present but not a literal the detector can read. */
  value: T | "unknown";
  /** "default" when the option is absent and the library's default applies. */
  source: "explicit" | "default";
};

export type SessionCookie = {
  library: "express-session" | "cookie-session";
  file: string;
  line: number;
  httpOnly: CookieAttribute<boolean>;
  secure: CookieAttribute<boolean>;
  /** null: no SameSite attribute is sent. */
  sameSite: CookieAttribute<string | null>;
};

/**
 * Library defaults. Both default httpOnly to true, send no Secure flag unless told to and
 * set no SameSite attribute.
 */
const DEFAULTS: Record<SessionCookie["library"], { httpOnly: boolean; secure: boolean; sameSite: null }> = {
  "express-session": { httpOnly: true, secure: false, sameSite: null },
  "cookie-session": { httpOnly: true, secure: false, sameSite: null },
};

const LIBRARIES = Object.keys(DEFAULTS) as SessionCookie["library"][];

const SCANNABLE = /\.(?:ts|tsx|js|jsx|mjs|cjs)$/;

/** Local names bound to a library's default export by require or import. */
function bindingsOf(text: string, library: string): string[] {
  const escaped = library.replace(/[-/]/g, "\\$&");
  const patterns = [
    new RegExp(`\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\s*\\(\\s*['"]${escaped}['"]\\s*\\)`, "g"),
    new RegExp(`\\bimport\\s+([A-Za-z_$][\\w$]*)\\s*(?:,\\s*\\{[^}]*\\})?\\s+from\\s*['"]${escaped}['"]`, "g"),
  ];
  return patterns.flatMap((p) => [...text.matchAll(p)].map((m) => m[1]));
}

/** The text between the parenthesis at `open` and its match, or undefined if unbalanced. */
function balanced(text: string, open: number, pair = "()"): string | undefined {
  let depth = 0;
  for (let at = open; at < text.length; at++) {
    if (text[at] === pair[0]) depth++;
    else if (text[at] === pair[1] && --depth === 0) return text.slice(open + 1, at);
  }
  return undefined;
}

/** The body of `{ ... }` for `key: { ... }` at the top level of `object`, if present. */
function nestedObject(object: string, key: string): string | undefined {
  const match = new RegExp(`(?:^|[,{\\s])${key}\\s*:\\s*\\{`).exec(object);
  if (!match) return undefined;
  return balanced(object, match.index + match[0].length - 1, "{}");
}

function readBoolean(object: string | undefined, key: string, fallback: boolean): CookieAttribute<boolean> {
  if (object === undefined) return { value: fallback, source: "default" };
  const match = new RegExp(`(?:^|[,{\\s])${key}\\s*:\\s*([^,}\\n]+)`).exec(object);
  if (!match) return { value: fallback, source: "default" };
  const raw = match[1].trim();
  if (raw === "true" || raw === "false") return { value: raw === "true", source: "explicit" };
  return { value: "unknown", source: "explicit" };
}

function readSameSite(object: string | undefined, fallback: null): CookieAttribute<string | null> {
  if (object === undefined) return { value: fallback, source: "default" };
  const match = new RegExp(`(?:^|[,{\\s])sameSite\\s*:\\s*([^,}\\n]+)`).exec(object);
  if (!match) return { value: fallback, source: "default" };
  const raw = match[1].trim();
  const literal = /^['"`](strict|lax|none)['"`]$/i.exec(raw);
  if (literal) return { value: literal[1].toLowerCase(), source: "explicit" };
  if (raw === "true") return { value: "strict", source: "explicit" };
  if (raw === "false") return { value: null, source: "explicit" };
  return { value: "unknown", source: "explicit" };
}

const UNKNOWN = { value: "unknown", source: "explicit" } as const;

function cookieFrom(library: SessionCookie["library"], args: string, file: string, line: number): SessionCookie {
  const options = args.trimStart();
  if (!options.startsWith("{")) {
    // Options passed as a variable or call: their values cannot be read here.
    return { library, file, line, httpOnly: UNKNOWN, secure: UNKNOWN, sameSite: UNKNOWN };
  }
  const top = balanced(options, 0, "{}") ?? "";
  // express-session nests cookie attributes under `cookie`; cookie-session takes them flat.
  // A `cookie` value that is not an object literal (a variable) cannot be read.
  if (library === "express-session" && /(?:^|[,{\s])cookie\s*:/.test(top) && nestedObject(top, "cookie") === undefined) {
    return { library, file, line, httpOnly: UNKNOWN, secure: UNKNOWN, sameSite: UNKNOWN };
  }
  const attributes = library === "express-session" ? nestedObject(top, "cookie") : top;
  const defaults = DEFAULTS[library];
  return {
    library,
    file,
    line,
    httpOnly: readBoolean(attributes, "httpOnly", defaults.httpOnly),
    secure: readBoolean(attributes, "secure", defaults.secure),
    sameSite: readSameSite(attributes, defaults.sameSite),
  };
}

/** Every session-cookie configuration in live source, in file then line order. */
export function detectSessionCookies(files: readonly DetectorInput[]): SessionCookie[] {
  const found: SessionCookie[] = [];
  for (const file of files) {
    if (!SCANNABLE.test(file.path)) continue;
    const text = maskComments(file.content);
    const starts = lineStarts(file.content);
    for (const library of LIBRARIES) {
      const calls: number[] = [];
      for (const name of bindingsOf(text, library)) {
        for (const m of text.matchAll(new RegExp(`(?<![\\w$.])${name.replace(/\$/g, "\\$")}\\s*\\(`, "g"))) {
          calls.push(m.index + m[0].length - 1);
        }
      }
      const escaped = library.replace(/[-/]/g, "\\$&");
      for (const m of text.matchAll(new RegExp(`\\brequire\\s*\\(\\s*['"]${escaped}['"]\\s*\\)\\s*\\(`, "g"))) {
        calls.push(m.index + m[0].length - 1);
      }
      for (const open of calls.sort((a, b) => a - b)) {
        const args = balanced(text, open);
        if (args === undefined) continue;
        found.push(cookieFrom(library, args, file.path, lineAt(starts, open)));
      }
    }
  }
  return found.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}
