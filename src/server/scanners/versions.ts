/**
 * Just enough semver for dependency scanning: compare two versions, and take the lowest
 * version a package.json range allows. There is no `semver` dependency in the project,
 * and adding one to read a lower bound is not worth the supply-chain surface for a tool
 * that exists to look for supply-chain problems.
 *
 * Not a full range engine. It answers "what is the lowest version this range could
 * resolve to", which is all OSV needs when there is no lockfile.
 */

export type ParsedVersion = {
  core: [number, number, number];
  pre: string[];
};

const VERSION =
  /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Reads "1", "1.2", "1.2.3" or "1.2.3-beta.1". Missing parts are zero. */
export function parseVersion(input: string): ParsedVersion | undefined {
  const match = VERSION.exec(input.trim());
  if (!match) return undefined;

  return {
    core: [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)],
    pre: match[4] ? match[4].split(".") : [],
  };
}

/** True for a complete x.y.z version, which is what OSV needs to be sent. */
export function isFullVersion(input: string): boolean {
  return /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(
    input.trim(),
  );
}

function comparePre(a: string[], b: string[]): number {
  // A version with no prerelease is greater than one with, per semver.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;

  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    const left = a[index];
    const right = b[index];
    if (left === undefined) return -1;
    if (right === undefined) return 1;
    if (left === right) continue;

    const leftNumeric = /^\d+$/.test(left);
    const rightNumeric = /^\d+$/.test(right);
    if (leftNumeric && rightNumeric)
      return Number(left) < Number(right) ? -1 : 1;
    if (leftNumeric) return -1; // numeric identifiers rank below alphanumeric ones
    if (rightNumeric) return 1;
    return left < right ? -1 : 1;
  }
  return 0;
}

/**
 * Semver precedence: negative, zero or positive. An unparseable version sorts below
 * any parseable one, so garbage from an untrusted source can never look "newer".
 */
export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left && !right) return 0;
  if (!left) return -1;
  if (!right) return 1;

  for (let index = 0; index < 3; index++) {
    if (left.core[index] !== right.core[index]) {
      return left.core[index] < right.core[index] ? -1 : 1;
    }
  }
  return comparePre(left.pre, right.pre);
}

/**
 * Specifiers that do not name a registry version, so there is nothing to look up:
 * workspace links, local paths, git and URL dependencies, and aliases.
 */
export function isRegistryRange(spec: string): boolean {
  const trimmed = spec.trim();
  return !/^(?:workspace:|file:|link:|portal:|git[+:]|github:|gitlab:|bitbucket:|https?:|npm:|\.{0,2}\/|~\/)/i.test(
    trimmed,
  );
}

function stripOperator(token: string): { operator: string; version: string } {
  const match = /^(>=|<=|>|<|=|\^|~>|~)?\s*(.*)$/.exec(token);
  return { operator: match?.[1] ?? "", version: (match?.[2] ?? "").trim() };
}

/** "1.x", "1.2.*", "*" -> 1.0.0, 1.2.0, no bound. */
function wildcardFloor(version: string): string | undefined {
  const parts = version.split(".");
  if (/^[xX*]?$/.test(parts[0])) return undefined;

  const cleaned = parts.map((part) => (/^[xX*]$/.test(part) ? "0" : part));
  return cleaned.join(".");
}

function format(parsed: ParsedVersion): string {
  const pre = parsed.pre.length ? `-${parsed.pre.join(".")}` : "";
  return `${parsed.core.join(".")}${pre}`;
}

/**
 * The lowest version strictly above a `>` bound, as semver reads it. A partial bound
 * excludes everything it names, so ">1" (and ">1.x") is 2.0.0 and ">1.2" is 1.3.0; a
 * full one moves to the next patch; a prerelease to its first successor, ">1.2.3-beta"
 * to 1.2.3-beta.0.
 */
function above(bound: string, parsed: ParsedVersion): string {
  if (parsed.pre.length > 0) return `${format(parsed)}.0`;

  const given = bound
    .replace(/^v/, "")
    .split(/[-+]/)[0]
    .split(".")
    .filter((part) => /^\d+$/.test(part)).length;
  const [major, minor, patch] = parsed.core;
  if (given <= 1) return `${major + 1}.0.0`;
  if (given === 2) return `${major}.${minor + 1}.0`;
  return `${major}.${minor}.${patch + 1}`;
}

/** The lowest version one space-separated alternative allows, or undefined. */
function lowerBound(alternative: string): string | undefined {
  // "1.2.3 - 2.0.0": the range starts at the first version.
  const hyphen = /^(\S+)\s+-\s+\S+$/.exec(alternative.trim());
  // "< 2.0.0" and ">= 1.2.3" are legal, so glue an operator to its version before
  // splitting on whitespace; otherwise the version reads as a bare lower bound.
  const glued = alternative.trim().replace(/(>=|<=|>|<|=|\^|~>|~)\s+/g, "$1");
  const tokens = hyphen ? [hyphen[1]] : glued.split(/\s+/).filter(Boolean);

  let best: string | undefined;
  for (const token of tokens) {
    const { operator, version } = stripOperator(token);
    if (operator === "<" || operator === "<=") continue; // an upper bound only

    const floor = wildcardFloor(version);
    if (floor === undefined || !parseVersion(floor)) continue;

    // A partial version is completed with zeros: "1.2" -> "1.2.0". ">" excludes the
    // bound itself, so it starts at the next version instead.
    const parsed = parseVersion(floor) as ParsedVersion;
    const full = operator === ">" ? above(version, parsed) : format(parsed);

    // Several lower bounds in one alternative intersect, so the highest one binds.
    if (best === undefined || compareVersions(full, best) > 0) best = full;
  }
  return best;
}

/**
 * The lowest version a package.json range can resolve to, as a full x.y.z, or
 * undefined when the range has no usable lower bound ("*", "latest", "<2", a dist-tag).
 *
 * For "||" unions the lowest alternative wins. An alternative with no lower bound is
 * ignored rather than treated as 0.0.0, since 0.0.0 would query OSV for a version no
 * project runs.
 */
export function minVersion(range: string): string | undefined {
  if (!isRegistryRange(range)) return undefined;

  let lowest: string | undefined;
  for (const alternative of range.split("||")) {
    const bound = lowerBound(alternative);
    if (bound === undefined) continue;
    if (lowest === undefined || compareVersions(bound, lowest) < 0)
      lowest = bound;
  }
  return lowest;
}
