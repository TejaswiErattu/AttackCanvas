import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ReposFileSchema,
  evalPaths,
  expectedKeyName,
} from "../scripts/eval/lib";

describe("answer-key resolution", () => {
  it("defaults to the run's own name, as for the NodeGoat runs", () => {
    expect(expectedKeyName([{ name: "nodegoat-a3118b6" }], "nodegoat-a3118b6")).toBe("nodegoat-a3118b6");
    expect(expectedKeyName([], "not-listed")).toBe("not-listed");
    expect(evalPaths("/r", "nodegoat").expected).toBe(join("/r", "eval", "expected", "nodegoat.yaml"));
  });

  it("uses a shared key named by `expected`, leaving the run's own files per run", () => {
    const repos = [{ name: "juice-shop-l1-r1", expected: "juice-shop" }];
    const paths = evalPaths("/r", "juice-shop-l1-r1", expectedKeyName(repos, "juice-shop-l1-r1"));
    expect(paths.expected).toBe(join("/r", "eval", "expected", "juice-shop.yaml"));
    expect(paths.result).toBe(join("/r", "eval", "results", "juice-shop-l1-r1.json"));
    expect(paths.labels).toBe(join("/r", "eval", "labels", "juice-shop-l1-r1.csv"));
  });

  it("rejects an `expected` that is not a safe file name", () => {
    const bad = ReposFileSchema.safeParse({ repos: [{ name: "a", url: "", expected: "../secrets" }] });
    expect(bad.success).toBe(false);
  });
});
