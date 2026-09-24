import type { Evidence } from "@/shared/schema";

/**
 * Strips credentials out of repository content before it reaches a model or a log
 * (CLAUDE.md rules 3 and 8).
 *
 * Pure and synchronous: no I/O, no network. `path` is used only for path-aware
 * behaviour: exclusions (lockfiles are full of hashes that are not secrets) and the
 * unquoted config-file rule, which applies only to config files (isConfigFilePath).
 *
 * Three guarantees hold the design together:
 *
 *   1. Overlapping matches are merged, never dropped. A lower-priority match that
 *      extends past a higher-priority one keeps its extra coverage, so redacting can
 *      only ever remove more than one rule asked for, never less.
 *   2. An existing "[REDACTED:type]" marker cannot manufacture a finding, so redact() is
 *      idempotent and assertNoSecrets() passes on anything redact() returns. The marker
 *      is not inert: it is 20+ characters of mixed case, and it contains a colon, so on a
 *      second pass it would match high_entropy and generic_secret, and its colon would
 *      turn `postgres://[REDACTED:aws_access_key]svc@db` into a user:password pair for
 *      connection_string. So every marker is blanked to spaces of the same length before
 *      the rules run (offsets are unchanged), and a match lying wholly inside a marker is
 *      discarded. Text next to a marker is still scanned as usual, and redact() repeats
 *      until a pass finds nothing, so a credential that only becomes visible once its
 *      neighbour is a marker is caught too (see MAX_REDACTION_PASSES).
 *   3. Line numbers survive redaction. A match that spans lines (a PEM private key
 *      block) is replaced by its marker followed by as many newlines as it contained, so
 *      line N of the redacted text is line N of the original. Detectors count lines on
 *      raw content while prompt excerpts are cut from redacted content; the two must
 *      agree.
 */

export type SecretType =
  | "aws_access_key"
  | "github_token"
  | "stripe_key"
  | "anthropic_key"
  | "openai_key"
  | "slack_token"
  | "google_api_key"
  | "private_key"
  | "jwt"
  | "connection_string"
  | "generic_secret"
  | "high_entropy";

/** Where a secret was found. Deliberately carries no value (rule 8). */
export type RedactionFinding = { type: SecretType; line: number };

export type RedactionResult = { content: string; findings: RedactionFinding[] };

/** Shannon entropy above which a long quoted string is treated as a secret. */
export const ENTROPY_THRESHOLD = 4.2;

/** Minimum length for a high-entropy candidate. */
export const MIN_ENTROPY_LENGTH = 20;

/**
 * Values of a secret-looking assignment at or above this length are redacted whatever they
 * contain. Shorter values are redacted too, but only when they hold no whitespace: see the
 * generic_secret rule.
 */
export const MIN_SECRET_LENGTH = 8;

export function redactionPlaceholder(type: SecretType): string {
  return `[REDACTED:${type}]`;
}

/** Markers written by an earlier redact() pass. */
const PLACEHOLDER = /\[REDACTED:[a-z_]+\]/g;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Thrown when content that must be clean still holds a credential. The message names
 * the type and the line and never the value, because this error is itself logged.
 */
export class SecretLeakError extends Error {
  constructor(readonly findings: RedactionFinding[]) {
    const where = findings
      .map((finding) => `${finding.type} at line ${finding.line}`)
      .join(", ");
    super(`refusing to continue: unredacted secret (${where})`);
    this.name = "SecretLeakError";
  }
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

/** Shannon entropy in bits per character. 0 for the empty string. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;

  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

// ---------------------------------------------------------------------------
// High-entropy exclusions
// ---------------------------------------------------------------------------

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX = /^[0-9a-f]{16,}$/i;
const SRI = /^sha(?:1|256|384|512)-/;
const DATA_URI = /^data:[a-z]+\/[a-z0-9.+-]+;base64,/i;
const URL_LIKE = /^[a-z][a-z0-9+.-]*:\/\//i;
const LOCKFILE =
  /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|poetry\.lock|uv\.lock|pipfile\.lock|gemfile\.lock|composer\.lock|cargo\.lock|go\.sum)$/i;

/** Keys whose values are hashes or locations by definition, not credentials. */
const NON_SECRET_KEYS =
  /^(?:integrity|resolved|checksum|digest|sha|hash|etag)$/i;

export function isLockfilePath(path: string): boolean {
  return LOCKFILE.test(path.replace(/\\/g, "/").toLowerCase());
}

/**
 * True when a long, random-looking string is a known kind of non-secret. Hex is
 * excluded explicitly even though hex tops out at 4.0 bits and could never clear the
 * threshold on its own: the rule should not depend on that arithmetic staying true.
 */
export function isKnownNonSecret(
  value: string,
  key: string,
  path: string,
): boolean {
  if (UUID.test(value)) return true;
  if (SRI.test(value)) return true;
  if (DATA_URI.test(value)) return true;
  if (URL_LIKE.test(value)) return true;
  if (isEnvReference(value)) return true;
  if (NON_SECRET_KEYS.test(key)) return true;
  if (HEX.test(value)) return true;
  // Lockfiles are almost entirely hashes and resolved URLs.
  if (isLockfilePath(path) && !/[^A-Za-z0-9+/=_-]/.test(value)) return true;

  return false;
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

type RuleContext = { path: string };

type Rule = {
  type: SecretType;
  /**
   * Global. Either the whole match is the secret, or named groups `pre` (kept) and
   * `secret` (replaced) split it, so the variable name survives.
   */
  pattern: RegExp;
  accept?: (secret: string, key: string, context: RuleContext) => boolean;
  /**
   * Applied only when the path is a config file (isConfigFilePath). Such a rule never
   * runs in assertNoSecrets without a config path, so the prompt guards, which see mixed
   * prompt text and no path, are unaffected by it.
   */
  configOnly?: true;
  /**
   * When `accept` rejects a match, resume the scan one character after the match start
   * instead of after its end. For rules whose pattern matches every assignment and whose
   * `accept` picks the credential ones, so a rejected assignment cannot swallow a
   * credential assignment that overlaps it (`const x: Password = "..."`).
   */
  rescanOnReject?: true;
};

/**
 * Forces a key to start at the beginning of an identifier, so the engine tries each
 * identifier once instead of retrying from every character of it.
 */
const KEY_START = "(?<![\\w$.-])";

/**
 * Case-insensitive fragments that make a key a credential key. They match anywhere inside a
 * key, so jwtSecret, JWT_SECRET, DB_PASSWORD, clientSecret, client_secret, apiKey, api_key,
 * privateKey and private_key are all covered by these.
 *
 * Tested on the key after the pattern has isolated it (isCredentialKey), never nested
 * inside the key pattern. Nested as `[\w$.-]*(?:KEYWORD)[\w$]*`, every keyword occurrence in
 * one long identifier re-scanned the rest of it: "pwd" repeated to 200 KB took ~6 s. And
 * bounding the parts around the keyword to fix that would let a long enough identifier
 * (`"a".repeat(102) + "password"`) carry its value past both redact() and the guards.
 */
const KEYWORD =
  "password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret";

/**
 * True when `key` is a credential key in source: a KEYWORD occurrence reaches into its last
 * segment, i.e. nothing after the keyword but word characters. So `DB_PASSWORD`,
 * `config.apiKey` and `api-key` qualify, while `password.length` and `password-reset` do
 * not. Linear: one global keyword scan and two lastIndexOf calls.
 */
export function isCredentialKey(key: string): boolean {
  const tail = Math.max(key.lastIndexOf("."), key.lastIndexOf("-")) + 1;
  for (const match of key.matchAll(new RegExp(KEYWORD, "gi"))) {
    if (match.index + match[0].length >= tail) return true;
  }
  return false;
}

/** True when a config key names a credential anywhere in it: `password.file`, `DB_PASSWORD_FILE`. */
function isConfigCredentialKey(key: string): boolean {
  return new RegExp(KEYWORD, "i").test(key);
}

/**
 * A TypeScript type annotation between a key and its value: `password: string = "..."`.
 * Bounded and free of spaces so it cannot backtrack badly.
 */
const ANNOTATION = "(?:\\s*:\\s*[A-Za-z_][\\w<>.\\[\\]]{0,40})?";

/**
 * `process.env.X || "literal"` and `x ?? "literal"`: the reference is fine but the fallback
 * literal is a credential in source, so the rule reaches past the reference to it.
 */
const FALLBACK =
  "(?:[\\w$.]+(?:\\([^)\\n]{0,40}\\)|\\[[^\\]\\n]{0,40}\\])?\\s*(?:\\|\\||\\?\\?)\\s*)?";

/**
 * A value that names where a secret comes from and holds none: ${VAR}, $VAR, %VAR%,
 * process.env.VAR, import.meta.env.VAR. It is left alone, since there is no literal to leak
 * and the reference is architecture. Deliberately narrow: `${VAR:-default}` carries a
 * literal default and `prefix${VAR}` a literal prefix, so neither is a pure reference.
 */
const ENV_REFERENCE =
  /^(?:\$\{[A-Za-z_][\w.]*\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|(?:process\.env|import\.meta\.env)\.[A-Za-z_]\w*)$/;

export function isEnvReference(value: string): boolean {
  return ENV_REFERENCE.test(value);
}

/**
 * An unquoted config value that holds no literal: an environment reference, or a whole
 * `{{ ... }}` template expression (Helm, Ansible, Jinja). Values that are not
 * credentials at all -- booleans and null -- are left alone too, so `password: false` or
 * `token: ~` still reads as what it is.
 */
const CONFIG_NON_SECRET = /^(?:\{\{[^{}\n]*\}\}|true|false|yes|no|on|off|null|none|nil|~)$/i;

function isConfigReference(value: string): boolean {
  return isEnvReference(value) || CONFIG_NON_SECRET.test(value);
}

/** Extensions of files that are configuration, not code. */
const CONFIG_EXTENSIONS = new Set([
  "yml",
  "yaml",
  "env",
  "properties",
  "ini",
  "toml",
  "conf",
  "cfg",
]);

/** .env, .env.local, .env.example, .env-prod, .env_test and direnv's .envrc. */
const ENV_FILE_BASE = /^\.env(?:rc|[._-].*)?$/;

/**
 * True for a config file, where values are routinely unquoted (`password: hunter2` in
 * YAML, `DB_PASSWORD=hunter2` in a .env or .properties file) and so need the unquoted
 * rule. Compose files are YAML and covered by the extension. Code is deliberately not a
 * config file: `password: hashedPassword` in a JavaScript object is an identifier, not a
 * credential.
 */
export function isConfigFilePath(path: string): boolean {
  const base = path.replace(/\\/g, "/").split("/").pop()?.toLowerCase() ?? "";
  if (ENV_FILE_BASE.test(base)) return true;
  const dot = base.lastIndexOf(".");
  return dot > 0 && CONFIG_EXTENSIONS.has(base.slice(dot + 1));
}

/**
 * Order is priority: when matches overlap, the earliest rule names the finding.
 *
 * anthropic_key must precede openai_key, because "sk-ant-..." also satisfies the
 * OpenAI shape ("-" is inside its character class). private_key leads so that a base64
 * body inside a key block is never labelled as something else.
 */
const RULES: readonly Rule[] = [
  {
    type: "private_key",
    pattern:
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  { type: "aws_access_key", pattern: /(?:AKIA|ASIA)[0-9A-Z]{16}/g },
  {
    type: "github_token",
    pattern: /gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}/g,
  },
  { type: "stripe_key", pattern: /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { type: "anthropic_key", pattern: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { type: "openai_key", pattern: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { type: "slack_token", pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { type: "google_api_key", pattern: /AIza[0-9A-Za-z_-]{35}/g },
  {
    type: "jwt",
    // Starts only where a token can start. Unanchored, a run of "eyJ" repeated made
    // every occurrence scan the rest of the run for the first ".": quadratic, ~7 s on
    // 200 KB. new RegExp because lookbehind in a literal needs target ES2018.
    pattern: new RegExp(
      "(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
      "g",
    ),
  },
  {
    // scheme://user:password@host - the scheme and host are architecture, not secrets.
    type: "connection_string",
    // The scheme is bounded and cannot start mid-word. Unbounded and unanchored, the
    // case-insensitive [a-z][a-z0-9+.-]* re-scanned a long run of letters from every
    // position hunting for "://": quadratic, ~20 s on one 200 KB line, which the loader
    // will happily hand us from an untrusted repository (CLAUDE.md rule 3).
    // Built with new RegExp, not a literal: named capture groups in a regex *literal*
    // need target ES2018 and this project targets ES2017. Runtime support is fine.
    pattern: new RegExp(
      "(?<![a-z0-9+.-])(?<pre>[a-z][a-z0-9+.-]{0,31}://)" +
        "(?<secret>[^\\s:/@'\"`]+:[^\\s:/@'\"`]+)(?=@[^\\s'\"`]+)",
      "gi",
    ),
  },
  {
    type: "generic_secret",
    // The value is either MIN_SECRET_LENGTH or more characters of anything but a quote or a
    // newline, or 1 to MIN_SECRET_LENGTH-1 characters with no whitespace. The second form is
    // the short password: `PASSWORD: "123456"` is six characters and a real credential, and
    // a floor of eight let it through. Requiring no whitespace keeps `"1 hour"` under a key
    // like passwordResetExpiry from being taken for one.
    pattern: new RegExp(
      `(?<pre>${KEY_START}(?<k>[\\w$.-]+)['"\`]?${ANNOTATION}\\s*[:=]\\s*${FALLBACK}(?<q>['"\`]))` +
        `(?<secret>[^'"\`\\n]{${MIN_SECRET_LENGTH},}|[^'"\`\\s]{1,${MIN_SECRET_LENGTH - 1}})(?=\\k<q>)`,
      "gi",
    ),
    // The pattern matches every quoted assignment; the key decides (see KEYWORD).
    accept: (secret, key) => isCredentialKey(key) && !isEnvReference(secret),
    rescanOnReject: true,
  },
  {
    // The unquoted form, for config files only (configOnly): `password: hunter2` in
    // YAML, `DB_PASSWORD=hunter2` or `export API_TOKEN=...` in a .env file,
    // `- POSTGRES_PASSWORD=...` in a compose list, `db.password = ...` in .properties.
    // Line-anchored, so the key must be the first thing on its line, and the value runs
    // to the end of the line (a trailing comment goes with it: over-redacting a comment
    // is harmless, cutting a value that contains " #" is not). A quoted value is left to
    // generic_secret above, which keeps the quotes.
    type: "generic_secret",
    configOnly: true,
    pattern: new RegExp(
      `(?<pre>^[ \\t]*(?:export[ \\t]+|-[ \\t]*)?['"]?(?<k>[\\w.-]+)['"]?[ \\t]*[:=][ \\t]*)` +
        `(?<secret>[^\\s'"\`][^\\r\\n]*)`,
      "gim",
    ),
    accept: (secret, key) =>
      isConfigCredentialKey(key) && !isConfigReference(secret.trimEnd()),
  },
  {
    type: "high_entropy",
    // Assignment with "=" only, not ":". A quoted value after ":" is usually a JSON or
    // object-literal property, and ordinary prose in one of those can clear the entropy
    // threshold: `{"summary":"GET /api/proxy/* handled here (next_app)"}` scores 4.23
    // against 4.2. The requirement is "assigned to a variable", which is "=". Keyword
    // keys (password, token, ...) are still caught by generic_secret in either form,
    // and vendor-shaped values by their own rules, so nothing known is lost.
    pattern: new RegExp(
      `(?<pre>${KEY_START}(?<k>[A-Za-z_$][\\w$.-]*)['"\`]?\\s*=\\s*(?<q>['"\`]))` +
        `(?<secret>[^'"\`\\n]{${MIN_ENTROPY_LENGTH},})(?=\\k<q>)`,
      "g",
    ),
    accept: (secret, key, context) =>
      shannonEntropy(secret) > ENTROPY_THRESHOLD &&
      !isKnownNonSecret(secret, key, context.path),
  },
];

/** The rule order, exposed so tests can assert the priorities that matter. */
export const RULE_TYPES: readonly SecretType[] = [...new Set(RULES.map((rule) => rule.type))];

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/** A range of `content` to replace, exported so mergeSpans can be tested directly. */
export type Span = { start: number; end: number; type: SecretType };

/** Byte-free line lookup: offsets of the start of each line, for a binary search. */
function lineStarts(content: string): number[] {
  const starts = [0];
  for (let index = 0; index < content.length; index++) {
    if (content[index] === "\n") starts.push(index + 1);
  }
  return starts;
}

function lineAt(starts: readonly number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (starts[mid] <= offset) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

/**
 * Ranges already redacted. A match is only discarded when it lies *wholly* inside one:
 * a match that merely starts in a marker and runs past it still covers unredacted
 * text, so it has to stay.
 */
function placeholderRanges(content: string): { start: number; end: number }[] {
  const ranges: { start: number; end: number }[] = [];
  const pattern = new RegExp(PLACEHOLDER.source, PLACEHOLDER.flags);
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) {
    ranges.push({ start: match.index, end: match.index + match[0].length });
  }
  return ranges;
}

/**
 * `content` with every marker replaced by spaces of the same length (guarantee 2): the
 * marker's own letters and colon can then never form, or complete, a match, while every
 * offset stays exactly where it was.
 */
function blankPlaceholders(
  content: string,
  ranges: readonly { start: number; end: number }[],
): string {
  if (ranges.length === 0) return content;
  const parts: string[] = [];
  let cursor = 0;
  for (const { start, end } of ranges) {
    parts.push(content.slice(cursor, start), " ".repeat(end - start));
    cursor = end;
  }
  parts.push(content.slice(cursor));
  return parts.join("");
}

function collectSpans(original: string, context: RuleContext): Span[] {
  const spans: Span[] = [];
  const redacted = placeholderRanges(original);
  const content = blankPlaceholders(original, redacted);
  const alreadyRedacted = (start: number, end: number): boolean =>
    redacted.some((range) => start >= range.start && end <= range.end);
  const config = isConfigFilePath(context.path);

  for (const rule of RULES) {
    if (rule.configOnly && !config) continue;
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(content)) !== null) {
      // A zero-length match would loop forever; no rule can produce one, but a future
      // one might, so step past it rather than trusting that.
      if (match[0].length === 0) {
        pattern.lastIndex += 1;
        continue;
      }

      const pre = match.groups?.pre ?? "";
      const secret = match.groups?.secret ?? match[0];
      const key = match.groups?.k ?? "";

      if (rule.accept && !rule.accept(secret, key, context)) {
        if (rule.rescanOnReject) pattern.lastIndex = match.index + 1;
        continue;
      }

      const start = match.index + pre.length;
      const end = start + secret.length;
      if (alreadyRedacted(start, end)) continue;

      spans.push({ start, end, type: rule.type });
    }
  }

  return spans;
}

/**
 * Merges overlapping spans into one, keeping the union of their ranges and the
 * highest-priority type among them.
 *
 * Union rather than "highest priority wins" on purpose. If `PASSWORD = "x AKIA…"`
 * matched both generic_secret (the whole value) and aws_access_key (part of it),
 * picking one span would leave the rest of the value in the output.
 */
export function mergeSpans(spans: readonly Span[]): Span[] {
  if (spans.length === 0) return [];

  const priority = new Map(RULE_TYPES.map((type, index) => [type, index]));
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);

  const merged: Span[] = [];
  for (const span of sorted) {
    const last = merged[merged.length - 1];
    if (last && span.start < last.end) {
      last.end = Math.max(last.end, span.end);
      if ((priority.get(span.type) ?? 0) < (priority.get(last.type) ?? 0)) {
        last.type = span.type;
      }
    } else {
      merged.push({ ...span });
    }
  }

  return merged;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** The newlines inside `text`, kept after a marker so line numbers survive (guarantee 3). */
function newlinesIn(text: string): string {
  let count = 0;
  for (let index = text.indexOf("\n"); index !== -1; index = text.indexOf("\n", index + 1)) {
    count += 1;
  }
  return "\n".repeat(count);
}

/** One replacement pass: every span found in `content` becomes its marker. */
function redactOnce(content: string, spans: readonly Span[]): RedactionResult {
  const starts = lineStarts(content);
  const findings: RedactionFinding[] = [];
  const parts: string[] = [];
  let cursor = 0;

  for (const span of spans) {
    parts.push(
      content.slice(cursor, span.start),
      redactionPlaceholder(span.type),
      newlinesIn(content.slice(span.start, span.end)),
    );
    cursor = span.end;
    findings.push({ type: span.type, line: lineAt(starts, span.start) });
  }
  parts.push(content.slice(cursor));

  return { content: parts.join(""), findings };
}

/**
 * Passes redact() may take. A second pass is needed only when a credential sat directly
 * against another one (`AKIA...EXAMPLEeyJhbGci...`): the JWT rule will not start inside a
 * token, so it sees the JWT only once its neighbour has become a marker. Every pass turns
 * at least one character of unredacted text into a marker, so this always terminates;
 * the cap only bounds the work.
 */
const MAX_REDACTION_PASSES = 4;

/**
 * Replaces every credential in `content` with "[REDACTED:type]", keeping the
 * surrounding code intact so the result still reads as source, and keeping the line
 * count: a multi-line match leaves its newlines behind the marker.
 *
 * Repeats until a pass finds nothing (at most MAX_REDACTION_PASSES), so what it returns
 * passes assertNoSecrets for the same path. Line numbers stay those of `content` on every
 * pass, because no pass changes the line count (guarantee 3).
 */
export function redact(content: string, path: string): RedactionResult {
  let current = content;
  const findings: RedactionFinding[] = [];

  for (let pass = 0; pass < MAX_REDACTION_PASSES; pass++) {
    const spans = mergeSpans(collectSpans(current, { path }));
    if (spans.length === 0) break;
    const once = redactOnce(current, spans);
    current = once.content;
    findings.push(...once.findings);
  }

  // Line order across passes. Array sort is stable, so one pass's order is kept.
  return { content: current, findings: findings.sort((a, b) => a.line - b.line) };
}

/**
 * Throws if `text` still holds a credential. Called before every model call and every
 * log line, so it is the last line of defence rather than the first.
 */
export function assertNoSecrets(text: string, path = ""): void {
  const spans = mergeSpans(collectSpans(text, { path }));
  if (spans.length === 0) return;

  const starts = lineStarts(text);
  throw new SecretLeakError(
    spans.map((span) => ({
      type: span.type,
      line: lineAt(starts, span.start),
    })),
  );
}

/**
 * An exact generated wrapper line, as src/server/analysis/context.ts writes it: the whole
 * line, nothing before or after, and an attribute with no raw quote (escapeAttribute
 * turns quotes into &quot;). Content lines can never match -- they always start with a
 * line-number prefix -- so this cannot be used to hide file content.
 */
const PROMPT_WRAPPER_LINE = /^<repo_file path="([^"\n]*)">$/gm;

/**
 * assertNoSecrets for a model prompt built from <repo_file> blocks. The entropy rule
 * reads a wrapper's path="<long path>" as a quoted secret assignment and flags ordinary
 * paths such as .github/workflows/deploy-pages.yml, so each exact wrapper line is
 * replaced by a bare "<repo_file>" (one line for one line: reported line numbers stay
 * accurate) and every extracted path is then checked on its own. A secret-shaped value
 * inside a path still fails closed; nothing else is masked or exempted.
 */
export function assertNoSecretsInPrompt(text: string): void {
  const paths: string[] = [];
  const masked = text.replace(PROMPT_WRAPPER_LINE, (_line, path: string) => {
    paths.push(path);
    return "<repo_file>";
  });
  assertNoSecrets(masked);
  for (const path of paths) assertNoSecrets(path);
}

/** kebab-case, as zId requires: "aws_access_key" -> "aws-access-key". */
function toKebab(type: SecretType): string {
  return type.replace(/_/g, "-");
}

/**
 * Turns findings into Evidence. Never carries a snippet: the snippet would be the
 * credential.
 */
export function toEvidence(
  path: string,
  findings: readonly RedactionFinding[],
): Evidence[] {
  return findings.map((finding, index) => ({
    id: `secret-${toKebab(finding.type)}-${finding.line}-${index + 1}`,
    kind: "code" as const,
    source: "detector" as const,
    summary: `Hardcoded credential of type ${finding.type} committed in source`,
    filePath: path,
    lineStart: finding.line,
  }));
}
