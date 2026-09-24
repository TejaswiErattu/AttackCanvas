/**
 * The one place src/server writes to stdout/stderr (CLAUDE.md rule 8: never log
 * tokens, API keys, or full prompts outside development mode; Prompt U Part 2).
 *
 * Two independent guards, because they catch different mistakes:
 *
 *   1. `stripAuthorization` removes an `Authorization` header (any case, whether the
 *      field is a `Headers` instance or a plain object, and whether it is passed
 *      directly or nested under a `headers` field) BEFORE serialization. A header
 *      value is a bearer token by construction, so this is a shape-based guard: it
 *      does not need to recognise the credential, only the field it travels in.
 *
 *   2. `assertNoSecrets` (src/server/security/redactor.ts) runs on the message and on
 *      every string inside the fields (recursively, keys included) BEFORE
 *      serialization, and then once more on the fully serialized line, and THROWS
 *      `SecretLeakError` if anything vendor-shaped, keyword-shaped, or
 *      high-entropy-and-quoted survived step 1 -- a caller that tries to log a raw
 *      credential is a bug, and this fails loud rather than emitting it. Checking the
 *      raw strings matters: JSON.stringify escapes `"` as `\"`, so a field holding
 *      `password = "hunter2hunter2"` serializes to text no quoted-value rule matches.
 *      This is safe against false positives on ordinary log output: the high-entropy
 *      rule only matches a source-style `key = "value"` assignment, not a JSON
 *      `"key":"value"` pair (see redactor.ts's own comment on that rule).
 *
 * Full prompts specifically are already handled at the source, not here:
 * src/server/ai/claude.ts only writes a prompt/response dump under `.debug/` when
 * `deps.isDevelopment` is true, and nothing calls this module with prompt text today.
 * `log()` does not need its own prompt-shaped exemption for a field nothing passes it.
 *
 * Nothing here reads environment variables to change its OWN behavior -- it enforces
 * the same two guards in every environment, deliberately: a secret is never safe to
 * log, in development or otherwise, unlike a full prompt (rule 8's dev-only carve-out
 * is for prompts, not credentials).
 */

import { assertNoSecrets } from "@/server/security/redactor";

export type LogLevel = "debug" | "info" | "warn" | "error";

/** Structured fields attached to a log line. Values are serialized with JSON.stringify. */
export type LogFields = Record<string, unknown>;

const AUTHORIZATION_KEY = /^authorization$/i;

/** True for a plain, serializable object -- not an array, a class instance, or null. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * `value` with any `authorization` key removed, case-insensitively. Handles a `Headers`
 * instance (Fetch/Next.js request headers, whose own keys are already lower-cased) and
 * a plain object alike, so a caller can pass either `request.headers` or a manually
 * built record without checking which one it has.
 */
function withoutAuthorization(value: unknown): unknown {
  if (value instanceof Headers) {
    const out: Record<string, string> = {};
    for (const [key, headerValue] of value.entries()) {
      if (AUTHORIZATION_KEY.test(key)) continue;
      out[key] = headerValue;
    }
    return out;
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, fieldValue] of Object.entries(value)) {
      if (AUTHORIZATION_KEY.test(key)) continue;
      out[key] = fieldValue;
    }
    return out;
  }
  return value;
}

/**
 * `fields` with every `authorization` key stripped: a top-level one (a caller that
 * logs headers flattened into the record directly) and one nested under a `headers`
 * field (a caller that logs `{ headers: request.headers }` or similar) alike.
 */
export function stripAuthorization(fields: LogFields): LogFields {
  const cleaned = withoutAuthorization(fields);
  const out = isPlainObject(cleaned) ? { ...cleaned } : {};
  if ("headers" in out) {
    out.headers = withoutAuthorization(out.headers);
  }
  return out;
}

/**
 * Runs assertNoSecrets on every string in `value` -- object keys and values, array items,
 * at any depth -- as the caller passed it, before JSON.stringify escapes any quotes.
 * `seen` stops a cycle (JSON.stringify would throw on one anyway, but only afterwards).
 */
function assertNoSecretStrings(value: unknown, seen: WeakSet<object> = new WeakSet()): void {
  if (typeof value === "string") {
    assertNoSecrets(value);
    return;
  }
  if (typeof value !== "object" || value === null || seen.has(value)) return;
  seen.add(value);
  const entries = Array.isArray(value)
    ? value.map((item) => ["", item] as const)
    : Object.entries(value);
  for (const [key, item] of entries) {
    if (key !== "") assertNoSecrets(key);
    assertNoSecretStrings(item, seen);
  }
}

/**
 * Writes one structured line to stdout (or stderr for "warn"/"error"), after stripping
 * any Authorization header and confirming nothing secret-shaped survived.
 *
 * Throws `SecretLeakError` (never caught here) if `assertNoSecrets` finds one: that is
 * a bug at the call site, not a normal failure, and should stop the request the same
 * way an unredacted secret stops a model call elsewhere in this codebase.
 */
export function log(level: LogLevel, message: string, fields: LogFields = {}): void {
  const safeFields = stripAuthorization(fields);
  assertNoSecrets(message);
  assertNoSecretStrings(safeFields);
  const line = JSON.stringify({
    level,
    message,
    ...safeFields,
    timestamp: new Date().toISOString(),
  });

  assertNoSecrets(line);

  const write = level === "error" || level === "warn" ? console.error : console.log;
  write(line);
}
