import { describe, expect, it } from "vitest";
import {
  LOCKFILE_REASON,
  MAX_FILE_BYTES,
  MAX_LOCKFILE_BYTES,
  maxBytesFor,
  classifyPath,
  isSourceFile,
  type Tier,
} from "@/server/ingest/classifier";

function tierOf(path: string, size?: number): Tier {
  return classifyPath(path, size).tier;
}

describe("classifyPath: ignore", () => {
  it.each([
    "node_modules/left-pad/index.js",
    "dist/bundle.js",
    "build/out.js",
    ".next/cache/x.js",
    "out/index.html",
    "coverage/lcov.info",
    "vendor/lib.php",
    ".git/config",
    "src/__pycache__/a.py",
    ".venv/lib/site.py",
    "public/index.html",
    "packages/web/node_modules/x/index.js",
  ])("ignores %s", (path) => {
    expect(tierOf(path)).toBe("ignore");
  });

  it.each([
    "logo.png",
    "a.jpg",
    "a.jpeg",
    "a.gif",
    "a.svg",
    "favicon.ico",
    "doc.pdf",
    "a.zip",
    "demo.mp4",
    "f.woff",
    "f.woff2",
    "f.ttf",
    "bun.lockb",
  ])("ignores binary or media %s", (path) => {
    expect(tierOf(`src/${path}`)).toBe("ignore");
  });

  it("ignores minified files", () => {
    expect(tierOf("src/vendor.min.js")).toBe("ignore");
    expect(tierOf("src/site.min.css")).toBe("ignore");
  });

  it("ignores files over 200 KB but not files at exactly 200 KB", () => {
    expect(tierOf("src/big.ts", MAX_FILE_BYTES + 1)).toBe("ignore");
    expect(tierOf("src/big.ts", MAX_FILE_BYTES)).toBe("medium");
  });

  it("does not ignore a file whose size is unknown", () => {
    expect(tierOf("src/a.ts", undefined)).toBe("medium");
  });

  it.each([
    ".env",
    ".env.local",
    ".env.production",
    "apps/api/.env",
    "apps/api/.env.test",
  ])("never fetches %s", (path) => {
    expect(tierOf(path)).toBe("ignore");
  });

  it("keeps .env.example, and ignores lookalikes", () => {
    expect(classifyPath(".env.example")).toMatchObject({ tier: "high" });
    expect(tierOf("src/environment.ts")).toBe("medium");
  });

  it.each([
    ".envrc",
    "apps/api/.envrc",
    ".env-prod",
    ".env_test",
    "web.env",
    "config/production.env",
    "docker/db.ENV",
  ])("never fetches the environment file %s either", (path) => {
    expect(classifyPath(path)).toEqual({ tier: "ignore", reason: "environment file (never fetched)" });
  });

  it("does not mistake names that merely contain env for environment files", () => {
    expect(tierOf("src/env.ts")).toBe("medium");
    expect(tierOf("src/envelope.ts")).toBe("medium");
    expect(tierOf("docs/env.md")).toBe("low");
    expect(tierOf("config/environment.yml")).toBe("medium");
  });

  it("matches directories by whole segment only", () => {
    expect(tierOf("src/building/plan.ts")).toBe("medium");
    expect(tierOf("src/outline/a.ts")).toBe("medium");
  });
});

describe("classifyPath: high", () => {
  it.each([
    "package.json",
    "services/api/package.json",
    "src/routes/users.ts",
    "routes/index.js",
    "src/controllers/orders.ts",
    "src/middleware/cors.ts",
    "src/models/user.ts",
    "src/auth.ts",
    "src/lib/session-store.ts",
    "src/login.tsx",
    "src/admin.ts",
    "prisma/schema.prisma",
    "prisma/migrations/001/migration.sql",
    "schema.prisma",
    "app/api/users/route.ts",
    "src/app/route.js",
    "pages/api/hello.ts",
    "server.ts",
    "src/server.js",
    "app.js",
    "index.ts",
    "src/index.js",
    "Dockerfile",
    "docker/Dockerfile.prod",
    "docker-compose.yml",
    "docker-compose.prod.yaml",
    "infra/main.tf",
    "serverless.yml",
    "vercel.json",
    "next.config.mjs",
    "firebase.json",
    "firestore.rules",
    "storage.rules",
    ".env.example",
    "src/schema.graphql",
  ])("ranks %s high", (path) => {
    expect(tierOf(path)).toBe("high");
  });

  it.each([
    "src/admin/panel.ts",
    "src/auth/helpers.ts",
    "lib/session/store.ts",
    "packages/web/src/login/form.tsx",
    "src/api/v1/admin/users.ts",
    "src/Auth/Helpers.ts",
  ])("matches sensitive names anywhere in the path: %s", (path) => {
    expect(tierOf(path)).toBe("high");
  });

  it("only treats index.(ts|js) as high at the root or src root", () => {
    expect(tierOf("src/components/index.ts")).toBe("medium");
    expect(tierOf("lib/index.js")).toBe("medium");
  });

  it("gives a reason", () => {
    expect(classifyPath("src/routes/users.ts").reason).toBe("routes/");
    expect(classifyPath("package.json").reason).toBe("package manifest");
  });
});

describe("classifyPath: medium", () => {
  it.each([
    "src/services/email.ts",
    "lib/db.ts",
    "server/util.js",
    "api/health.js",
    "config/default.json",
    "config/nested/x.yaml",
    "packages/web/src/thing.tsx",
  ])("ranks %s medium", (path) => {
    expect(tierOf(path)).toBe("medium");
  });

  it.each([
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Gemfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "apps/web/pnpm-lock.yaml",
  ])("ranks lockfile %s medium, for dependencies", (path) => {
    expect(classifyPath(path)).toEqual({
      tier: "medium",
      reason: LOCKFILE_REASON,
    });
  });

  it("keeps the 200 KB limit for every lockfile the dependency scanner does not read", () => {
    for (const path of [
      "yarn.lock",
      "pnpm-lock.yaml",
      "poetry.lock",
      "Cargo.lock",
      "go.sum",
      "npm-shrinkwrap.json",
    ]) {
      expect(tierOf(path, MAX_FILE_BYTES)).toBe("medium");
      expect(tierOf(path, MAX_FILE_BYTES + 1)).toBe("ignore");
      expect(tierOf(path, 900 * 1024)).toBe("ignore");
    }
  });

  it("lets package-lock.json, which the scanner reads, exceed 200 KB up to 1 MiB", () => {
    expect(tierOf("package-lock.json", MAX_FILE_BYTES + 1)).toBe("medium");
    expect(tierOf("package-lock.json", 900 * 1024)).toBe("medium");
    expect(tierOf("package-lock.json", MAX_LOCKFILE_BYTES)).toBe("medium");
    expect(classifyPath("package-lock.json", 900 * 1024)).toEqual({
      tier: "medium",
      reason: LOCKFILE_REASON,
    });
  });

  it("still refuses a package-lock.json over 1 MiB, which cannot be fetched, and says why", () => {
    expect(classifyPath("package-lock.json", MAX_LOCKFILE_BYTES + 1)).toEqual({
      tier: "ignore",
      reason: "lockfile over 1 MiB (too large to fetch)",
    });
  });

  it("applies the exemption at any depth and in any case, but only to that exact name", () => {
    expect(tierOf("apps/web/package-lock.json", 500 * 1024)).toBe("medium");
    expect(tierOf("src/auth/package-lock.json", 500 * 1024)).toBe("medium");
    expect(tierOf("PACKAGE-LOCK.JSON", 500 * 1024)).toBe("medium");
    expect(tierOf("package-lock.json.bak", 500 * 1024)).toBe("ignore");
    expect(tierOf("my-package-lock.json", 500 * 1024)).toBe("ignore");
    expect(tierOf("package.json", 500 * 1024)).toBe("ignore");
  });

  it("does not let the exemption reach anywhere ignore rules already apply", () => {
    expect(tierOf("node_modules/x/package-lock.json", 500 * 1024)).toBe(
      "ignore",
    );
    expect(tierOf("dist/package-lock.json", 500 * 1024)).toBe("ignore");
  });

  it("leaves every other file at the 200 KB limit", () => {
    expect(tierOf("src/big.ts", 500 * 1024)).toBe("ignore");
    expect(tierOf("README.md", 500 * 1024)).toBe("ignore");
    expect(tierOf("package.json", MAX_FILE_BYTES + 1)).toBe("ignore");
  });

  it("maxBytesFor reports the limit each path is held to", () => {
    expect(maxBytesFor("package-lock.json")).toBe(MAX_LOCKFILE_BYTES);
    expect(maxBytesFor("a/b/package-lock.json")).toBe(MAX_LOCKFILE_BYTES);
    expect(maxBytesFor("yarn.lock")).toBe(MAX_FILE_BYTES);
    expect(maxBytesFor("src/a.ts")).toBe(MAX_FILE_BYTES);
    expect(MAX_LOCKFILE_BYTES).toBeGreaterThan(MAX_FILE_BYTES);
  });
});

describe("classifyPath: low", () => {
  it.each([
    "tests/users.test.ts",
    "src/__tests__/a.ts",
    "test/helpers.js",
    "src/users.test.ts",
    "src/users.spec.tsx",
    "pkg/thing_test.go",
    "app/test_thing.py",
    "docs/guide.md",
    "README.md",
    "examples/basic.ts",
    "scripts/seed.ts",
    "e2e/login.ts",
  ])("ranks %s low", (path) => {
    expect(tierOf(path)).toBe("low");
  });

  it("does not promote a test or doc for having a sensitive name", () => {
    expect(tierOf("src/auth.test.ts")).toBe("low");
    expect(tierOf("tests/login.ts")).toBe("low");
    expect(tierOf("docs/admin.md")).toBe("low");
    expect(tierOf("src/routes/__tests__/users.ts")).toBe("low");
  });

  it("falls back to low, not ignore, for an unremarkable first-party file", () => {
    expect(classifyPath("Makefile")).toEqual({ tier: "low", reason: "other" });
    expect(tierOf("styles/site.css")).toBe("low");
  });
});

describe("classifyPath: input handling", () => {
  it("is case-insensitive and tolerates a leading ./", () => {
    expect(tierOf("./SRC/Routes/Users.TS")).toBe("high");
    expect(tierOf("Node_Modules/x/index.js")).toBe("ignore");
  });

  it("tolerates backslash separators", () => {
    expect(tierOf("src\\routes\\users.ts")).toBe("high");
  });
});

describe("isSourceFile", () => {
  it("counts code, not lockfiles, manifests or docs", () => {
    expect(isSourceFile("src/a.ts")).toBe(true);
    expect(isSourceFile("main.py")).toBe(true);
    expect(isSourceFile("package.json")).toBe(false);
    expect(isSourceFile("pnpm-lock.yaml")).toBe(false);
    expect(isSourceFile("go.sum")).toBe(false);
    expect(isSourceFile("README.md")).toBe(false);
  });
});

describe("assets/ directory", () => {
  it.each([
    "assets/app.js",
    "src/assets/a.ts",
    "packages/web/assets/x.ts",
    "public/assets/x.ts",
    "ASSETS/x.ts",
  ])("ignores %s, at any path boundary", (path) => {
    expect(tierOf(path)).toBe("ignore");
  });

  it.each([
    "src/assets.ts",
    "src/assets-loader.ts",
    "src/myassets/x.ts",
    "src/assetsManager/x.ts",
    "src/lib/preassets.ts",
  ])(
    "does not ignore %s: a name containing the word is not the directory",
    (path) => {
      expect(tierOf(path)).not.toBe("ignore");
    },
  );
});

describe("precedence", () => {
  it.each([
    // 1. ignore beats everything
    ["node_modules/x/auth.js", "ignore"],
    ["src/auth/logo.png", "ignore"],
    ["src/auth/.env", "ignore"],
    ["assets/admin/panel.ts", "ignore"],
    ["src/admin/panel.min.js", "ignore"],
    ["dist/pnpm-lock.yaml", "ignore"],
    // 2. lockfiles are medium/dependencies wherever they sit
    ["package-lock.json", "medium"],
    ["src/auth/package-lock.json", "medium"],
    ["tests/pnpm-lock.yaml", "medium"],
    ["examples/app/yarn.lock", "medium"],
    ["src/routes/poetry.lock", "medium"],
    // 3. tests, docs, examples, scripts stay low
    ["tests/auth.test.ts", "low"],
    ["src/admin/panel.test.ts", "low"],
    ["docs/auth/setup.ts", "low"],
    ["examples/admin/app.ts", "low"],
    ["scripts/login.ts", "low"],
    ["src/routes/__tests__/users.ts", "low"],
    // 4. sensitive application paths are high
    ["src/admin/panel.ts", "high"],
    ["src/auth/helpers.ts", "high"],
    ["src/routes/users.ts", "high"],
    ["package.json", "high"],
    // 5. other source in src, lib, server, api, config is medium
    ["src/services/email.ts", "medium"],
    ["lib/db.ts", "medium"],
    ["server/util.js", "medium"],
    ["api/health.js", "medium"],
    ["config/default.yaml", "medium"],
    // 6. everything else is low
    ["Makefile", "low"],
  ] as const)("%s is %s", (path, tier) => {
    expect(tierOf(path)).toBe(tier);
  });

  it("gives every lockfile the reason dependencies, wherever it sits", () => {
    for (const path of [
      "package-lock.json",
      "src/auth/yarn.lock",
      "tests/go.sum",
      "docs/Cargo.lock",
    ]) {
      expect(classifyPath(path)).toEqual({
        tier: "medium",
        reason: LOCKFILE_REASON,
      });
    }
  });

  it("never treats a lockfile as source", () => {
    for (const path of [
      "package-lock.json",
      "yarn.lock",
      "pnpm-lock.yaml",
      "poetry.lock",
      "go.sum",
      "Cargo.lock",
      "Gemfile.lock",
      "composer.lock",
      "src/auth/uv.lock",
    ]) {
      expect(isSourceFile(path)).toBe(false);
    }
  });
});
