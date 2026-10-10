import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ExpectedFileSchema,
  ReposFileSchema,
  evalPaths,
  expectedKeyName,
  parseYamlWith,
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

  it("resolves both Juice Shop runs in eval/repos.yaml to one key that parses", () => {
    const repos = parseYamlWith(readFileSync("eval/repos.yaml", "utf8"), ReposFileSchema, "eval/repos.yaml").repos;
    const keys = ["juice-shop-l1-r1", "juice-shop-l1-r2"].map((name) => expectedKeyName(repos, name));
    expect(keys).toEqual(["juice-shop", "juice-shop"]);
    const key = parseYamlWith(readFileSync(evalPaths(".", "juice-shop-l1-r1", keys[0]).expected, "utf8"), ExpectedFileSchema, "juice-shop.yaml");
    expect(key.mode).toBe("guided");
    expect(key.revision).toBe("0e6d909b7466e76bc8deabf2fdb62bc5c849961f");
  });
});
