/**
 * An optional allowlist of repository owners, for a hosted deployment that should analyse
 * only some people's repositories (see "Responsible use" in docs/security-design.md).
 *
 * ATTACKCANVAS_ALLOWED_OWNERS is a comma-separated list of GitHub owners (users or
 * organisations), compared case-insensitively because GitHub names are:
 *
 *   ATTACKCANVAS_ALLOWED_OWNERS=acme,Widgets-Inc
 *
 * Opt-in. Unset, empty, or holding nothing but spaces and commas, the allowlist is OFF and
 * every owner is allowed, exactly as before it existed.
 *
 * A configuration that is set but wrong fails CLOSED, never open. An entry that is not a
 * valid GitHub owner name (a typo, "acme/shop", a stray quote) is dropped, which can only
 * make the list stricter. If nothing valid is left, no owner is allowed: someone who
 * wrote a list meant to restrict, and a broken restriction must not become no restriction.
 * The number of dropped entries is logged once per distinct value, never the entries.
 *
 * Pure apart from that one warning: the environment is passed in.
 */

import { log } from "@/server/log";

export const ALLOWED_OWNERS_ENV = "ATTACKCANVAS_ALLOWED_OWNERS";

/**
 * A GitHub user or organisation name: 1-39 characters, letters, digits and single hyphens,
 * not starting or ending with a hyphen. Anything else cannot be an owner.
 */
const OWNER_NAME = /^(?!.*--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;

export type OwnerAllowlist =
  | { active: false }
  | {
      active: true;
      /** Lower-cased. Empty when every entry was invalid: nothing is allowed. */
      owners: ReadonlySet<string>;
      /** Entries that were not valid owner names and were dropped. */
      dropped: number;
    };

/** Reads the setting. `undefined`, blank, or only separators means the allowlist is off. */
export function parseAllowedOwners(raw: string | undefined): OwnerAllowlist {
  const entries = (raw ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
  if (entries.length === 0) return { active: false };

  const owners = new Set<string>();
  let dropped = 0;
  for (const entry of entries) {
    if (OWNER_NAME.test(entry)) owners.add(entry.toLowerCase());
    else dropped += 1;
  }
  return { active: true, owners, dropped };
}

/** True when `owner` may be analysed under `allowlist`. */
export function isOwnerAllowed(allowlist: OwnerAllowlist, owner: string): boolean {
  return !allowlist.active || allowlist.owners.has(owner.toLowerCase());
}

/** The last setting that was warned about, so a bad value is reported once, not per request. */
let warnedFor: string | undefined;

/** Reads the setting from `env` and checks `owner` against it. */
export function checkOwner(
  owner: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
): boolean {
  const raw = env[ALLOWED_OWNERS_ENV];
  const allowlist = parseAllowedOwners(raw);
  if (allowlist.active && (allowlist.dropped > 0 || allowlist.owners.size === 0) && warnedFor !== raw) {
    warnedFor = raw;
    try {
      log(
        "warn",
        allowlist.owners.size === 0
          ? `${ALLOWED_OWNERS_ENV} has no valid owner, so every owner is refused`
          : `${ALLOWED_OWNERS_ENV} has entries that are not valid owner names and were ignored`,
        { droppedEntries: allowlist.dropped, validEntries: allowlist.owners.size },
      );
    } catch {
      // A log line must never decide a request.
    }
  }
  return isOwnerAllowed(allowlist, owner);
}

/** Test seam: forget which value was already warned about. */
export function resetAllowlistWarning(): void {
  warnedFor = undefined;
}
