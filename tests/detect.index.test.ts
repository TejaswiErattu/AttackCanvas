import { describe, expect, it } from "vitest";
import { frameworkNames, runDetectors } from "@/server/detect";
import { assertNoSecrets } from "@/server/security/redactor";
import { EvidenceSchema, zId } from "@/shared/schema";
import type { LoadedFile } from "@/server/ingest/loader";
import {
  ALL_MARKERS,
  PLANTED_AWS_KEY,
  PLANTED_CONNECTION,
  PLANTED_DB_PASSWORD,
  SAMPLE_REPO,
} from "./detectSamples";

const result = runDetectors(SAMPLE_REPO);

/** Every string value in a structure, so a sweep does not depend on JSON's shape. */
function stringLeaves(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringLeaves);
  if (value && typeof value === "object") {
    return Object.values(value).flatMap(stringLeaves);
  }
  return [];
}

describe("runDetectors", () => {
  it("returns every fact collection", () => {
    expect(result.frameworks.length).toBeGreaterThan(0);
    expect(result.routes.length).toBeGreaterThan(0);
    expect(result.auth).toHaveLength(result.routes.length);
    expect(result.datastores.length).toBeGreaterThan(0);
    expect(result.envNames.length).toBeGreaterThan(0);
    expect(result.deployment.length).toBeGreaterThan(0);
    expect(result.gaps.length).toBeGreaterThan(0);
    expect(result.evidence.length).toBeGreaterThan(0);
  });

  it("accepts the loader's LoadedFile directly", () => {
    // Structural typing is the point: no conversion between the stages.
    const loaded: LoadedFile[] = SAMPLE_REPO.map((file) => ({
      ...file,
      tier: "high" as const,
      reason: "routes/",
    }));

    expect(runDetectors(loaded).routes).toEqual(result.routes);
  });

  it("returns empty collections for no input", () => {
    const empty = runDetectors([]);

    expect(empty.evidence).toEqual([]);
    expect(empty.routes).toEqual([]);
    expect(empty.frameworks).toEqual([]);
    expect(empty.gaps).toEqual([]);
  });

  it("does not throw on files that are nothing but noise", () => {
    expect(() =>
      runDetectors([
        { path: "a.ts", content: "\0\0\0" },
        { path: "package.json", content: "{{{" },
        { path: "Dockerfile", content: "EXPOSE" },
        { path: "docker-compose.yml", content: ":::" },
      ]),
    ).not.toThrow();
  });
});

describe("evidence", () => {
  it("gives every item a schema-valid shape", () => {
    for (const evidence of result.evidence) {
      expect(EvidenceSchema.safeParse(evidence).success).toBe(true);
    }
  });

  it("uses kebab-case ids that satisfy zId", () => {
    for (const evidence of result.evidence) {
      expect(zId.safeParse(evidence.id).success).toBe(true);
    }
  });

  it("numbers ids per category, as ev-route-3", () => {
    const routeIds = result.evidence
      .filter((e) => e.id.startsWith("ev-route-"))
      .map((e) => e.id);

    expect(routeIds[0]).toBe("ev-route-1");
    expect(routeIds[2]).toBe("ev-route-3");
    expect(routeIds).toHaveLength(result.routes.length);
  });

  it("lines a route's evidence up with the route's own id", () => {
    const third = result.routes[2];
    const evidence = result.evidence.find((e) => e.id === "ev-route-3");

    expect(third.id).toBe("route-3");
    expect(evidence?.filePath).toBe(third.file);
    expect(evidence?.lineStart).toBe(third.line);
  });

  it("has a unique id for every item", () => {
    const ids = result.evidence.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("is always from the detector source, with a code or config kind", () => {
    for (const evidence of result.evidence) {
      expect(evidence.source).toBe("detector");
      expect(["code", "config"]).toContain(evidence.kind);
    }
  });

  it("calls package.json and deployment files config, and source files code", () => {
    const framework = result.evidence.find((e) => e.id === "ev-framework-1");
    const route = result.evidence.find((e) => e.id === "ev-route-1");

    expect(framework?.kind).toBe("config");
    expect(route?.kind).toBe("code");
  });

  it("never carries a snippet", () => {
    for (const evidence of result.evidence) {
      expect(evidence.snippet).toBeUndefined();
    }
  });

  it("always points at a file and a line of at least 1", () => {
    for (const evidence of result.evidence) {
      expect(evidence.filePath).toBeTruthy();
      expect(evidence.lineStart).toBeGreaterThanOrEqual(1);
    }
  });

  it("covers each category", () => {
    const prefixes = new Set(
      result.evidence.map((e) => e.id.replace(/^ev-(.*)-\d+$/, "$1")),
    );
    expect(prefixes).toEqual(
      new Set([
        "framework",
        "route",
        "auth",
        "datastore",
        "env",
        "deploy",
        "gap",
      ]),
    );
  });
});

describe("no secret reaches a fact", () => {
  /**
   * The samples deliberately hold a fake AWS key and a postgres:// URL with a
   * password. Repository content is untrusted (CLAUDE.md rule 3), so a detector that
   * copied matched text into a summary would leak it into a prompt or a log.
   */
  const serialised = JSON.stringify(result);

  it.each([
    ["an AWS key", PLANTED_AWS_KEY],
    ["a connection string", PLANTED_CONNECTION],
    ["a password", PLANTED_DB_PASSWORD],
  ])("does not copy %s anywhere into the result", (_label, secret) => {
    expect(serialised).not.toContain(secret);
  });

  it("produces summaries that pass assertNoSecrets", () => {
    for (const evidence of result.evidence) {
      expect(() => assertNoSecrets(evidence.summary)).not.toThrow();
    }
  });

  it("copies no file's content into a fact, for every fact-producing file", () => {
    // One marker per sample file, so this fails whatever file a detector quotes.
    const leaves = stringLeaves(result).join("\n");
    for (const marker of ALL_MARKERS) {
      expect(leaves).not.toContain(marker);
    }
  });

  it("has a marker in every sample that produces a fact", () => {
    // Guards the guard: a marker that is not actually in the samples proves nothing.
    const samples = stringLeaves(SAMPLE_REPO).join("\n");
    for (const marker of ALL_MARKERS) {
      expect(samples).toContain(marker);
    }
  });

  it("produces facts whose every string value passes assertNoSecrets", () => {
    // Asserted on the leaf strings rather than on JSON.stringify(result).
    // assertNoSecrets flags a high-entropy value in an assignment, and JSON is all
    // assignments: `"summary":"GET /api/proxy/* handled here (next_app)"` trips the
    // rule at entropy 4.23 against a 4.2 threshold, with nothing secret in it. The
    // leak-detecting rules that matter here - connection_string, the vendor key
    // patterns - match a bare value and still fire on one string per line.
    expect(() =>
      assertNoSecrets(stringLeaves(result).join("\n")),
    ).not.toThrow();
  });

  it("would notice if a detector did start copying content", () => {
    // Guards the guard: the samples really do hold what the test claims, and the
    // same sweep that passes on the result fails on the raw samples.
    const samples = stringLeaves(SAMPLE_REPO).join("\n");

    expect(samples).toContain(PLANTED_AWS_KEY);
    expect(samples).toContain(PLANTED_CONNECTION);
    expect(() => assertNoSecrets(samples)).toThrow();
  });
});

describe("stability", () => {
  it("produces identical output however the input is ordered", () => {
    const reversed = runDetectors([...SAMPLE_REPO].reverse());
    expect(reversed).toEqual(result);
  });

  it("produces identical output on a shuffled input", () => {
    const shuffled = [...SAMPLE_REPO].sort(
      (a, b) => a.path.length - b.path.length,
    );
    expect(runDetectors(shuffled)).toEqual(result);
  });

  it("is deterministic across repeated runs", () => {
    expect(runDetectors(SAMPLE_REPO)).toEqual(result);
  });
});

describe("frameworkNames", () => {
  it("de-duplicates across manifests and sorts", () => {
    const names = frameworkNames(result);

    expect(names).toEqual([...new Set(names)].sort());
    expect(names.filter((name) => name === "ioredis")).toHaveLength(1);
    expect(names).toContain("express");
    expect(names).toContain("fastify");
  });

  it("is empty when there is no manifest", () => {
    expect(frameworkNames(runDetectors([]))).toEqual([]);
  });
});
