/**
 * ATTACKCANVAS_ALLOWED_OWNERS: parsing, matching, and the fail-closed rule for a
 * configuration that is set but wrong. Pure; the log is mocked so what it is asked to write
 * can be inspected.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/server/log", () => ({ log: vi.fn() }));

import { log } from "@/server/log";
import {
  ALLOWED_OWNERS_ENV,
  checkOwner,
  isOwnerAllowed,
  parseAllowedOwners,
  resetAllowlistWarning,
} from "@/server/http/ownerAllowlist";

beforeEach(() => {
  vi.mocked(log).mockReset();
  resetAllowlistWarning();
});

const env = (value: string | undefined) => ({ [ALLOWED_OWNERS_ENV]: value });

describe("unset: the allowlist is off and every owner is allowed", () => {
  it.each([
    ["undefined", undefined],
    ["empty", ""],
    ["spaces", "   "],
    ["only commas", ",,,"],
    ["commas and spaces", " , ,  ,"],
  ])("%s", (_label, raw) => {
    expect(parseAllowedOwners(raw)).toEqual({ active: false });
    expect(checkOwner("anyone", env(raw))).toBe(true);
    expect(checkOwner("someone-else", env(raw))).toBe(true);
  });

  it("logs nothing", () => {
    checkOwner("anyone", env(undefined));
    checkOwner("anyone", env(""));
    expect(log).not.toHaveBeenCalled();
  });
});

describe("allowed", () => {
  it("allows a listed owner and refuses an unlisted one", () => {
    expect(checkOwner("acme", env("acme,widgets"))).toBe(true);
    expect(checkOwner("widgets", env("acme,widgets"))).toBe(true);
    expect(checkOwner("other", env("acme,widgets"))).toBe(false);
  });

  it("ignores case on both sides, since GitHub names do", () => {
    expect(checkOwner("ACME", env("acme"))).toBe(true);
    expect(checkOwner("acme", env("Acme-Corp,ACME"))).toBe(true);
    expect(checkOwner("Acme-Corp", env("acme-corp"))).toBe(true);
  });

  it("trims spaces around entries and skips empty ones", () => {
    const list = parseAllowedOwners(" acme , ,widgets,, ");
    expect(list).toEqual({ active: true, owners: new Set(["acme", "widgets"]), dropped: 0 });
  });

  it("accepts every shape of GitHub owner name", () => {
    for (const name of ["a", "A1", "octo-cat", "a-b-c", "x".repeat(39), "1password"]) {
      expect(parseAllowedOwners(name), name).toMatchObject({ active: true, dropped: 0 });
    }
  });

  it("does not log for a clean configuration", () => {
    checkOwner("acme", env("acme,widgets"));
    expect(log).not.toHaveBeenCalled();
  });
});

describe("blocked", () => {
  it("does not match on a prefix, a suffix or a substring", () => {
    for (const owner of ["acm", "acme2", "my-acme", "acme-corp", "cme"]) {
      expect(checkOwner(owner, env("acme")), owner).toBe(false);
    }
  });

  it("refuses an empty owner name", () => {
    expect(checkOwner("", env("acme"))).toBe(false);
  });
});

describe("malformed: a setting that is set but wrong never becomes 'allow everyone'", () => {
  const INVALID = [
    "acme/shop", // a repo path, not an owner
    "https://github.com/acme",
    "-leading",
    "trailing-",
    "dou--ble",
    "has space",
    "@acme",
    "acme!",
    "x".repeat(40), // one over GitHub's limit
    "ünïcode",
  ];

  it.each(INVALID)("drops the invalid entry %j", (entry) => {
    expect(parseAllowedOwners(`good,${entry}`)).toEqual({
      active: true,
      owners: new Set(["good"]),
      dropped: 1,
    });
  });

  it("with some invalid entries, allows only the valid ones", () => {
    expect(checkOwner("good", env("good,acme/shop"))).toBe(true);
    expect(checkOwner("acme", env("good,acme/shop"))).toBe(false);
    expect(checkOwner("shop", env("good,acme/shop"))).toBe(false);
  });

  it("with no valid entry, refuses every owner", () => {
    for (const raw of ["acme/shop", "@acme,-x", "a b, c d", "https://github.com/acme"]) {
      expect(parseAllowedOwners(raw)).toMatchObject({ active: true, dropped: expect.any(Number) });
      expect(checkOwner("acme", env(raw)), raw).toBe(false);
      expect(checkOwner("anyone", env(raw)), raw).toBe(false);
    }
  });

  it("warns with counts only, once per distinct value, never the entries", () => {
    const raw = "good,acme/shop,secret token";
    checkOwner("good", env(raw));
    checkOwner("good", env(raw));
    checkOwner("other", env(raw));
    expect(log).toHaveBeenCalledTimes(1);
    const [level, message, fields] = vi.mocked(log).mock.calls[0]!;
    expect(level).toBe("warn");
    expect(fields).toEqual({ droppedEntries: 2, validEntries: 1 });
    const serialised = JSON.stringify([message, fields]);
    for (const leaked of ["acme/shop", "secret token", "good"]) {
      expect(serialised).not.toContain(leaked);
    }

    checkOwner("good", env("other-value,bad/one"));
    expect(log).toHaveBeenCalledTimes(2);
  });

  it("warns that everything is refused when nothing valid is left", () => {
    checkOwner("acme", env("acme/shop"));
    expect(vi.mocked(log).mock.calls[0]![1]).toMatch(/no valid owner/);
  });

  it("still decides the request if the log itself throws", () => {
    vi.mocked(log).mockImplementation(() => {
      throw new Error("refused");
    });
    expect(checkOwner("good", env("good,bad/one"))).toBe(true);
    expect(checkOwner("acme", env("bad/one"))).toBe(false);
  });
});

describe("isOwnerAllowed", () => {
  it("allows everything when the allowlist is off", () => {
    expect(isOwnerAllowed({ active: false }, "anyone")).toBe(true);
  });
});
