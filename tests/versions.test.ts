import { describe, expect, it } from "vitest";
import {
  compareVersions,
  isFullVersion,
  isRegistryRange,
  minVersion,
  parseVersion,
} from "@/server/scanners/versions";

describe("parseVersion", () => {
  it.each([
    ["1.2.3", [1, 2, 3], []],
    ["v1.2.3", [1, 2, 3], []],
    ["1.2", [1, 2, 0], []],
    ["1", [1, 0, 0], []],
    ["1.2.3-beta.1", [1, 2, 3], ["beta", "1"]],
    ["1.2.3+build.5", [1, 2, 3], []],
    ["1.2.3-rc.1+build", [1, 2, 3], ["rc", "1"]],
    ["  4.17.15  ", [4, 17, 15], []],
  ])("parses %s", (input, core, pre) => {
    expect(parseVersion(input)).toEqual({ core, pre });
  });

  it.each(["", "abc", "1.2.3.4", "^1.2.3", "1.x", "latest", "1..2", "-1.2.3"])(
    "rejects %s",
    (input) => {
      expect(parseVersion(input)).toBeUndefined();
    },
  );
});

describe("isFullVersion", () => {
  it("accepts x.y.z, with a prerelease or build", () => {
    for (const input of [
      "1.2.3",
      "v1.2.3",
      "1.2.3-beta.1",
      "0.0.0",
      "1.2.3+b",
    ]) {
      expect(isFullVersion(input)).toBe(true);
    }
  });

  it("rejects anything partial or ranged, which OSV cannot be asked about", () => {
    for (const input of [
      "1",
      "1.2",
      "^1.2.3",
      "1.x",
      "",
      "latest",
      "1.2.3.4",
    ]) {
      expect(isFullVersion(input)).toBe(false);
    }
  });
});

describe("compareVersions", () => {
  it.each([
    ["1.0.0", "2.0.0", -1],
    ["2.0.0", "1.0.0", 1],
    ["1.2.3", "1.2.3", 0],
    ["1.2.0", "1.10.0", -1], // numeric, not lexical
    ["1.9.9", "1.10.0", -1],
    ["4.17.15", "4.17.19", -1],
    ["4.17.21", "4.18.0", -1],
    ["v1.2.3", "1.2.3", 0],
    ["1.0.0+a", "1.0.0+b", 0], // build metadata is ignored
  ])("compares %s with %s as %i", (a, b, expected) => {
    expect(Math.sign(compareVersions(a, b))).toBe(expected);
  });

  it("orders prereleases exactly as the semver specification's own example does", () => {
    const ordered = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];

    for (let index = 0; index < ordered.length - 1; index++) {
      expect(compareVersions(ordered[index], ordered[index + 1])).toBeLessThan(
        0,
      );
      expect(
        compareVersions(ordered[index + 1], ordered[index]),
      ).toBeGreaterThan(0);
    }
  });

  it("sorts a prerelease below its release", () => {
    expect(compareVersions("2.0.0-rc.1", "2.0.0")).toBeLessThan(0);
  });

  it("sorts an unparseable version below any real one, never above", () => {
    expect(compareVersions("garbage", "0.0.1")).toBeLessThan(0);
    expect(compareVersions("0.0.1", "garbage")).toBeGreaterThan(0);
    expect(compareVersions("garbage", "also garbage")).toBe(0);
  });

  it("is consistent with sort()", () => {
    const shuffled = ["1.10.0", "1.2.0", "1.9.0", "0.9.9", "1.2.0-beta"];
    expect([...shuffled].sort(compareVersions)).toEqual([
      "0.9.9",
      "1.2.0-beta",
      "1.2.0",
      "1.9.0",
      "1.10.0",
    ]);
  });
});

describe("isRegistryRange", () => {
  it.each([
    "^1.2.3",
    "~1.2.0",
    "1.2.3",
    ">=1.0.0 <2.0.0",
    "*",
    "latest",
    "1.x",
    "",
  ])("treats %j as a registry range", (spec) => {
    expect(isRegistryRange(spec)).toBe(true);
  });

  it.each([
    "workspace:*",
    "workspace:^1.0.0",
    "file:../local",
    "link:../local",
    "portal:../local",
    "git+https://github.com/a/b.git",
    "git://github.com/a/b.git",
    "github:a/b",
    "gitlab:a/b",
    "bitbucket:a/b",
    "https://example.com/pkg.tgz",
    "http://example.com/pkg.tgz",
    "npm:other@^1.0.0",
    "../local",
    "./local",
    "/abs/path",
    "~/home/pkg",
  ])("treats %s as not a registry range", (spec) => {
    expect(isRegistryRange(spec)).toBe(false);
  });
});

describe("minVersion", () => {
  it.each([
    ["4.17.15", "4.17.15"],
    ["=4.17.15", "4.17.15"],
    ["v4.17.15", "4.17.15"],
    ["^4.17.15", "4.17.15"],
    ["~4.17.15", "4.17.15"],
    ["~>4.17.15", "4.17.15"],
    ["^0.0.3", "0.0.3"],
    ["^0.2.0", "0.2.0"],
    [">=1.2.3", "1.2.3"],
    [">1.2.3", "1.2.4"],
    [">=1.2.3 <2.0.0", "1.2.3"],
    [">= 1.2.3 < 2.0.0", "1.2.3"],
    ["1.2.3 - 2.0.0", "1.2.3"],
    ["1.2.3-beta.1", "1.2.3-beta.1"],
    ["^1.2.3-beta.1", "1.2.3-beta.1"],
  ])("takes %s to %s", (range, expected) => {
    expect(minVersion(range)).toBe(expected);
  });

  it.each([
    ["1.2", "1.2.0"],
    ["1", "1.0.0"],
    ["1.x", "1.0.0"],
    ["1.X", "1.0.0"],
    ["1.*", "1.0.0"],
    ["1.2.x", "1.2.0"],
    ["1.2.*", "1.2.0"],
    ["^1", "1.0.0"],
    ["~1.2", "1.2.0"],
  ])("completes the partial or wildcard range %s to %s", (range, expected) => {
    expect(minVersion(range)).toBe(expected);
  });

  it.each([
    [">4.17.20", "4.17.21"],
    ["> 4.17.20", "4.17.21"],
    [">1", "2.0.0"],
    [">1.x", "2.0.0"],
    [">1.2", "1.3.0"],
    [">1.2.x", "1.3.0"],
    [">v1.2.3", "1.2.4"],
    [">1.2.3-beta", "1.2.3-beta.0"],
    [">1.2.3 <2.0.0", "1.2.4"],
    [">=1.5.0 >1.5.0", "1.5.1"],
  ])(
    "treats > as strictly greater, so %s starts at %s, not at the bound",
    (range, expected) => {
      // Querying the bound itself asks OSV about a version the range cannot install:
      // >4.17.20 never resolves to 4.17.20, which CVE-2021-23337 affects.
      expect(minVersion(range)).toBe(expected);
    },
  );

  it("takes the highest lower bound when several intersect", () => {
    expect(minVersion(">=1.0.0 >=1.2.0")).toBe("1.2.0");
    expect(minVersion(">=1.5.0 <2.0.0 >=1.2.0")).toBe("1.5.0");
  });

  it("takes the lowest alternative of a union", () => {
    expect(minVersion("^1.0.0 || ^2.0.0")).toBe("1.0.0");
    expect(minVersion("^2.0.0 || ^1.5.0")).toBe("1.5.0");
    expect(minVersion("^3.0.0 || ^1.0.0 || ^2.0.0")).toBe("1.0.0");
  });

  it("ignores a union alternative with no lower bound, rather than assuming 0.0.0", () => {
    expect(minVersion("* || ^1.2.3")).toBe("1.2.3");
    expect(minVersion("<1.0.0 || ^2.0.0")).toBe("2.0.0");
  });

  it.each([
    ["a wildcard", "*"],
    ["x", "x"],
    ["an empty string", ""],
    ["whitespace", "   "],
    ["latest", "latest"],
    ["a dist-tag", "next"],
    ["only an upper bound", "<2.0.0"],
    ["only an upper bound, spaced", "< 2.0.0"],
    ["<=", "<=1.0.0"],
    ["a union of unbounded ranges", "* || <1.0.0"],
    ["garbage", "not a version"],
  ])("returns undefined for %s", (_label, range) => {
    expect(minVersion(range)).toBeUndefined();
  });

  it.each([
    "workspace:*",
    "file:../x",
    "git+https://github.com/a/b.git",
    "github:a/b",
    "npm:other@^1.0.0",
    "https://example.com/x.tgz",
  ])("returns undefined for the non-registry specifier %s", (spec) => {
    expect(minVersion(spec)).toBeUndefined();
  });

  it("always returns a full version that OSV can be asked about", () => {
    for (const range of ["^1", "~1.2", "1.x", ">=2", "1.2.3", "^0.0.3"]) {
      const version = minVersion(range);
      expect(version).toBeDefined();
      expect(isFullVersion(version as string)).toBe(true);
    }
  });
});
