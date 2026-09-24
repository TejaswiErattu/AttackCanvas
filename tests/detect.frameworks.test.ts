import { describe, expect, it } from "vitest";
import {
  categoryOf,
  detectFrameworks,
  isManifest,
} from "@/server/detect/frameworks";
import type { FrameworkCategory } from "@/server/detect/types";
import {
  BROKEN_PACKAGE_JSON,
  PACKAGE_JSON,
  SAMPLE_REPO,
  WORKSPACE_PACKAGE_JSON,
} from "./detectSamples";

describe("categoryOf", () => {
  it.each<[string, FrameworkCategory]>([
    ["express", "web"],
    ["next", "web"],
    ["fastify", "web"],
    ["koa", "web"],
    ["hono", "web"],
    ["@nestjs/core", "web"],
    ["passport", "auth"],
    ["next-auth", "auth"],
    ["jsonwebtoken", "auth"],
    ["jose", "auth"],
    ["express-session", "auth"],
    ["bcrypt", "auth"],
    ["argon2", "auth"],
    ["firebase-admin", "auth"],
    ["pg", "database"],
    ["mysql2", "database"],
    ["mongoose", "database"],
    ["mongodb", "database"],
    ["prisma", "database"],
    ["@prisma/client", "database"],
    ["sequelize", "database"],
    ["typeorm", "database"],
    ["drizzle-orm", "database"],
    ["redis", "database"],
    ["ioredis", "database"],
    ["aws-sdk", "cloud"],
    ["firebase", "cloud"],
    ["stripe", "payments"],
    ["helmet", "security_middleware"],
    ["cors", "security_middleware"],
    ["express-rate-limit", "security_middleware"],
    ["csurf", "security_middleware"],
    ["express-validator", "security_middleware"],
    ["zod", "security_middleware"],
    ["joi", "security_middleware"],
    ["multer", "upload"],
    ["formidable", "upload"],
    ["busboy", "upload"],
    ["ejs", "templating"],
    ["pug", "templating"],
    ["handlebars", "templating"],
    ["axios", "http_client"],
    ["node-fetch", "http_client"],
    ["got", "http_client"],
  ])("maps %s to %s", (name, category) => {
    expect(categoryOf(name)).toBe(category);
  });

  it.each<[string, FrameworkCategory]>([
    ["@auth/core", "auth"],
    ["@auth/prisma-adapter", "auth"],
    ["@clerk/nextjs", "auth"],
    ["@supabase/supabase-js", "auth"],
    ["@aws-sdk/client-s3", "cloud"],
    ["@google-cloud/storage", "cloud"],
  ])("maps the scoped family %s to %s", (name, category) => {
    expect(categoryOf(name)).toBe(category);
  });

  it.each([
    "lodash",
    "typescript",
    "react",
    "@types/node",
    "authentic-widgets",
  ])("does not classify %s", (name) => {
    expect(categoryOf(name)).toBeUndefined();
  });

  it("does not treat a lookalike scope as a tracked family", () => {
    expect(categoryOf("@authorized/thing")).toBeUndefined();
    expect(categoryOf("@clerkx/thing")).toBeUndefined();
  });
});

describe("isManifest", () => {
  it.each(["package.json", "services/api/package.json", "./package.json"])(
    "accepts %s",
    (path) => {
      expect(isManifest(path)).toBe(true);
    },
  );

  it.each(["package-lock.json", "src/package.json.ts", "mypackage.json"])(
    "rejects %s",
    (path) => {
      expect(isManifest(path)).toBe(false);
    },
  );
});

describe("detectFrameworks", () => {
  const frameworks = detectFrameworks(SAMPLE_REPO);
  const names = frameworks.map((framework) => framework.name);

  it("finds the tracked dependencies and ignores the rest", () => {
    expect(names).toContain("express");
    expect(names).toContain("@clerk/nextjs");
    expect(names).toContain("stripe");
    expect(names).not.toContain("lodash");
    expect(names).not.toContain("typescript");
  });

  it("records the declared version and the manifest it came from", () => {
    const express = frameworks.find(
      (framework) => framework.name === "express",
    );

    expect(express).toMatchObject({
      name: "express",
      category: "web",
      version: "^4.18.2",
      dev: false,
      file: "package.json",
    });
  });

  it("points at the line the package is declared on", () => {
    const stripe = frameworks.find((framework) => framework.name === "stripe");
    const line = PACKAGE_JSON.content
      .split("\n")
      .findIndex((l) => l.includes('"stripe"'));

    expect(stripe?.line).toBe(line + 1);
  });

  it("points into the dependency's own section, not at a config key of the same name", () => {
    // "prisma" is a top-level config key (line 3) and a devDependency (line 8); a
    // script named after a package is the same trap.
    const content = [
      "{",
      '  "scripts": { "express": "node server.js" },',
      '  "prisma": { "seed": "node seed.js" },',
      '  "dependencies": {',
      '    "express": "^4.18.2"',
      "  },",
      '  "devDependencies": {',
      '    "prisma": "^5.0.0"',
      "  }",
      "}",
    ].join("\n");
    const found = detectFrameworks([{ path: "package.json", content }]);

    expect(found.map((f) => [f.name, f.line])).toEqual([
      ["express", 5],
      ["prisma", 8],
    ]);
  });

  it("marks devDependencies as dev", () => {
    expect(frameworks.find((f) => f.name === "joi")?.dev).toBe(true);
    expect(frameworks.find((f) => f.name === "zod")?.dev).toBe(false);
  });

  it("merges every manifest in a monorepo", () => {
    const fastify = frameworks.find(
      (framework) => framework.name === "fastify",
    );
    expect(fastify?.file).toBe("services/worker/package.json");

    // ioredis is declared in both manifests: two facts, because which service pulls
    // in a datastore is the thing a threat model cares about.
    const ioredis = frameworks.filter(
      (framework) => framework.name === "ioredis",
    );
    expect(ioredis.map((f) => f.file)).toEqual([
      "package.json",
      "services/worker/package.json",
    ]);
  });

  it("survives a malformed manifest without throwing", () => {
    expect(() => detectFrameworks([BROKEN_PACKAGE_JSON])).not.toThrow();
    expect(detectFrameworks([BROKEN_PACKAGE_JSON])).toEqual([]);
  });

  it.each([
    ["not JSON at all", "nope"],
    ["a JSON array", "[1,2,3]"],
    ["null", "null"],
    ["an empty file", ""],
    ["a manifest with no dependencies", '{"name":"x"}'],
    ["dependencies of the wrong type", '{"dependencies": "express"}'],
  ])("returns nothing for %s", (_label, content) => {
    expect(detectFrameworks([{ path: "package.json", content }])).toEqual([]);
  });

  it("does not read dependencies from a non-manifest", () => {
    expect(
      detectFrameworks([{ path: "src/a.ts", content: PACKAGE_JSON.content }]),
    ).toEqual([]);
  });

  it("reports a package listed in both sections once, as a runtime dependency", () => {
    const both = {
      path: "package.json",
      content: '{"dependencies":{"zod":"^3"},"devDependencies":{"zod":"^3"}}',
    };
    const found = detectFrameworks([both]);

    expect(found).toHaveLength(1);
    expect(found[0].dev).toBe(false);
  });

  it("is ordered by path, whatever order the files arrive in", () => {
    const shuffled = detectFrameworks([WORKSPACE_PACKAGE_JSON, PACKAGE_JSON]);
    expect(shuffled.map((f) => f.file)).toEqual(
      [...shuffled.map((f) => f.file)].sort(),
    );
  });
});
