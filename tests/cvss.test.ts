import { describe, expect, it } from "vitest";
import {
  cvssV3Score,
  labelForScore,
  labelFromText,
  rank,
  roundUp,
  severityOf,
} from "@/server/scanners/cvss";

describe("cvssV3Score", () => {
  /**
   * Base scores published by FIRST for these vectors, plus the four real advisories
   * captured from OSV (each of which GitHub scores as noted).
   */
  it.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10],
    ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2],
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H", 7.4], // lodash CVE-2020-8203
    ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.6], // minimist CVE-2020-7598
    ["CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8],
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4],
    ["CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6],
  ])("scores %s as %d", (vector, expected) => {
    expect(cvssV3Score(vector)).toBe(expected);
  });

  it("scores a vector with no impact as zero", () => {
    expect(cvssV3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
  });

  it("accepts CVSS 3.0 as well as 3.1", () => {
    expect(cvssV3Score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(
      9.8,
    );
  });

  it("uses the scope-changed privilege weights", () => {
    // PR:L is 0.62 unchanged and 0.68 when scope changes, so these must differ.
    const unchanged = cvssV3Score(
      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    ) as number;
    const changed = cvssV3Score(
      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
    ) as number;

    expect(changed).toBeGreaterThan(unchanged);
  });

  it.each([
    ["CVSS 2", "AV:N/AC:L/Au:N/C:P/I:P/A:P"],
    [
      "CVSS 4",
      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    ],
    ["an empty string", ""],
    ["garbage", "not a vector"],
    ["a missing metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"],
    ["an unknown metric value", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["an unknown scope", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Z/C:H/I:H/A:H"],
  ])("returns undefined for %s", (_label, vector) => {
    expect(cvssV3Score(vector)).toBeUndefined();
  });

  it.each([
    ["A:constructor", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:constructor"],
    ["AV:__proto__", "CVSS:3.1/AV:__proto__/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["PR:toString", "CVSS:3.1/AV:N/AC:L/PR:toString/UI:N/S:C/C:H/I:H/A:H"],
    ["UI:valueOf", "CVSS:3.1/AV:N/AC:L/PR:N/UI:valueOf/S:U/C:H/I:H/A:H"],
  ])(
    "treats the inherited property name in %s as an unknown value, not NaN",
    (_label, vector) => {
      expect(cvssV3Score(vector)).toBeUndefined();
    },
  );

  it("never exceeds 10 or drops below 0", () => {
    const worst = cvssV3Score(
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    ) as number;
    expect(worst).toBeLessThanOrEqual(10);
    expect(worst).toBeGreaterThanOrEqual(0);
  });
});

describe("roundUp", () => {
  it.each([
    [4.0, 4.0],
    [4.02, 4.1],
    [4.1, 4.1],
    [4.11, 4.2],
    [0.01, 0.1],
    [9.99, 10],
    [0, 0],
  ])("rounds %d up to %d", (input, expected) => {
    expect(roundUp(input)).toBe(expected);
  });

  it("does not round a value up because of floating-point noise", () => {
    // 4.000000000000001 is 4.0 for scoring purposes; the 3.1 Roundup exists for this.
    expect(roundUp(4.000000000000001)).toBe(4.0);
    expect(roundUp(0.1 + 0.2 + 3.7)).toBe(4.0);
  });
});

describe("labelForScore", () => {
  it.each([
    [10, "CRITICAL"],
    [9.0, "CRITICAL"],
    [8.9, "HIGH"],
    [7.0, "HIGH"],
    [6.9, "MEDIUM"],
    [4.0, "MEDIUM"],
    [3.9, "LOW"],
    [0.1, "LOW"],
  ])("labels %d as %s", (score, label) => {
    expect(labelForScore(score)).toBe(label);
  });

  it("gives no label to a zero score", () => {
    expect(labelForScore(0)).toBeUndefined();
  });
});

describe("labelFromText", () => {
  it.each([
    ["CRITICAL", "CRITICAL"],
    ["High", "HIGH"],
    ["moderate", "MEDIUM"], // GitHub's word for MEDIUM
    ["MEDIUM", "MEDIUM"],
    ["  low ", "LOW"],
  ])("reads %j as %s", (text, label) => {
    expect(labelFromText(text)).toBe(label);
  });

  it.each(["", "severe", "none", "unknown"])("does not read %j", (text) => {
    expect(labelFromText(text)).toBeUndefined();
  });
});

describe("severityOf", () => {
  const CVSS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H";

  it("prefers a computed CVSS score over the advisory's label", () => {
    // The label says LOW; the vector says 7.4 HIGH. The vector is the evidence.
    expect(severityOf([{ type: "CVSS_V3", score: CVSS }], "LOW")).toEqual({
      score: 7.4,
      label: "HIGH",
    });
  });

  it("falls back to the label when there is no usable vector", () => {
    expect(severityOf([], "MODERATE")).toEqual({ label: "MEDIUM" });
    expect(severityOf([{ score: "CVSS:4.0/AV:N" }], "HIGH")).toEqual({
      label: "HIGH",
    });
  });

  it("falls back to the label when a vector names an inherited property", () => {
    // Before, this scored NaN, dropped the HIGH label and ranked as NaN in the sort.
    const hostile = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:constructor";
    const severity = severityOf([{ score: hostile }], "HIGH");

    expect(severity).toEqual({ label: "HIGH" });
    expect(rank(severity)).toBe(8);
  });

  it("uses the first usable vector among several entries", () => {
    const entries = [{ score: "AV:N/AC:L/Au:N/C:P/I:P/A:P" }, { score: CVSS }];
    expect(severityOf(entries, undefined).score).toBe(7.4);
  });

  it("copes with entries that are not shaped as expected", () => {
    expect(severityOf([{ score: 42 }, {}, { type: "x" }], undefined)).toEqual(
      {},
    );
  });

  it("returns an empty severity when there is nothing to go on", () => {
    expect(severityOf([], undefined)).toEqual({});
    expect(severityOf([], 5)).toEqual({});
    expect(severityOf([], "bogus")).toEqual({});
  });
});

describe("rank", () => {
  it("uses the score when there is one", () => {
    expect(rank({ score: 7.4, label: "HIGH" })).toBe(7.4);
  });

  it("stands a label in for a missing score, in severity order", () => {
    const ranks = (["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const).map(
      (label) => rank({ label }),
    );
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
    expect(new Set(ranks).size).toBe(4);
  });

  it("puts an unknown severity last", () => {
    expect(rank({})).toBe(0);
    expect(rank({})).toBeLessThan(rank({ label: "LOW" }));
  });
});
