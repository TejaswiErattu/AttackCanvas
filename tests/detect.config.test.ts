import { describe, expect, it } from "vitest";
import { detectDatastores } from "@/server/detect/datastores";
import { detectEnvNames, isEnvExample } from "@/server/detect/envNames";
import {
  detectDeployment,
  isCompose,
  isDockerfile,
  isServerless,
  isTerraform,
} from "@/server/detect/deployment";
import { detectFrameworks } from "@/server/detect/frameworks";
import {
  COMPOSE,
  DOCKERFILE,
  ENV_EXAMPLE,
  PLANTED_CONNECTION,
  PLANTED_DB_PASSWORD,
  SAMPLE_REPO,
  SERVERLESS_YML,
  TERRAFORM,
} from "./detectSamples";

// ---------------------------------------------------------------------------
// datastores
// ---------------------------------------------------------------------------

describe("detectDatastores", () => {
  const datastores = detectDatastores(
    SAMPLE_REPO,
    detectFrameworks(SAMPLE_REPO),
  );

  it.each([
    ["pg", "postgres"],
    ["mongoose", "mongodb"],
    ["@prisma/client", "prisma"],
    ["ioredis", "redis"],
  ])("maps the dependency %s to %s", (name, kind) => {
    const found = datastores.find(
      (d) => d.name === name && d.origin === "dependency",
    );
    expect(found?.kind).toBe(kind);
  });

  it.each([
    ["new Pool", "postgres"],
    ["mongoose.connect", "mongodb"],
    ["new PrismaClient", "prisma"],
  ])("finds the connection call %s as %s", (name, kind) => {
    const found = datastores.find(
      (d) => d.name === name && d.origin === "usage",
    );

    expect(found?.kind).toBe(kind);
    expect(found?.file).toBe("src/db.js");
  });

  it("records both origins for the same datastore", () => {
    const origins = datastores
      .filter((d) => d.kind === "postgres")
      .map((d) => d.origin);

    expect(origins).toContain("dependency");
    expect(origins).toContain("usage");
  });

  it("never captures a connection string", () => {
    for (const datastore of datastores) {
      expect(JSON.stringify(datastore)).not.toContain(PLANTED_CONNECTION);
      expect(JSON.stringify(datastore)).not.toContain(PLANTED_DB_PASSWORD);
      expect(datastore.name).not.toContain("://");
    }
  });

  it("narrows an ambiguous createClient using the file's imports", () => {
    const redis = detectDatastores(
      [
        {
          path: "src/r.ts",
          content: 'import { createClient } from "redis";\ncreateClient();',
        },
      ],
      [],
    );
    expect(redis[0]).toMatchObject({ kind: "redis", name: "createClient" });

    const unknown = detectDatastores(
      [{ path: "src/r.ts", content: "createClient();" }],
      [],
    );
    expect(unknown[0].kind).toBe("unknown");
  });

  it("ignores connection-shaped text in a non-source file", () => {
    expect(
      detectDatastores([{ path: "README.md", content: "new Pool()" }], []),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// env names
// ---------------------------------------------------------------------------

describe("detectEnvNames", () => {
  const envNames = detectEnvNames(SAMPLE_REPO);
  const names = envNames.map((entry) => entry.name);

  it("reads keys from .env.example", () => {
    const fromExample = envNames.filter((e) => e.origin === "env_example");
    expect(fromExample.map((e) => e.name)).toEqual([
      "DATABASE_URL",
      "SESSION_SECRET",
      "JWT_SECRET",
      "STRIPE_SECRET_KEY",
    ]);
  });

  it("reads process.env in all its forms", () => {
    const fromCode = envNames
      .filter((e) => e.origin === "process_env")
      .map((e) => e.name);

    expect(fromCode).toContain("DATABASE_URL"); // process.env.X
    expect(fromCode).toContain("STRIPE_SECRET_KEY"); // process.env["X"]
    expect(fromCode).toContain("NODE_ENV"); // const { X } = process.env
    expect(fromCode).toContain("PORT");
    expect(fromCode).toContain("MONGO_URL");
  });

  it("never records a value, only a name", () => {
    const serialised = JSON.stringify(envNames);

    expect(serialised).not.toContain("replace-me");
    expect(serialised).not.toContain("sk_test_replace_me");
    expect(serialised).not.toContain("postgres://");
    for (const name of names) expect(name).not.toContain("=");
  });

  it("skips comments and blank lines", () => {
    expect(names).not.toContain("Database");
    expect(names).not.toContain("Auth");
  });

  it("handles an exported key", () => {
    expect(names).toContain("JWT_SECRET");
  });

  it("reports each name once per origin, at its first occurrence", () => {
    const keys = envNames.map((e) => `${e.origin}:${e.name}`);
    expect(new Set(keys).size).toBe(keys.length);

    const fromExample = envNames.find(
      (e) => e.name === "DATABASE_URL" && e.origin === "env_example",
    );
    expect(fromExample?.line).toBe(2);
  });

  it("never reads a .env file, only the example", () => {
    expect(isEnvExample(".env.example")).toBe(true);
    expect(isEnvExample(".env")).toBe(false);
    expect(isEnvExample(".env.local")).toBe(false);

    expect(detectEnvNames([{ path: ".env", content: "SECRET=real" }])).toEqual(
      [],
    );
  });

  it("returns nothing for an empty or comment-only example", () => {
    expect(
      detectEnvNames([{ path: ".env.example", content: "# nothing\n\n" }]),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// deployment
// ---------------------------------------------------------------------------

describe("deployment file matching", () => {
  it.each(["Dockerfile", "docker/Dockerfile.prod", "dockerfile"])(
    "treats %s as a Dockerfile",
    (path) => {
      expect(isDockerfile(path)).toBe(true);
    },
  );

  it.each(["docker-compose.yml", "docker-compose.prod.yaml"])(
    "treats %s as compose",
    (path) => {
      expect(isCompose(path)).toBe(true);
    },
  );

  it("matches serverless and terraform", () => {
    expect(isServerless("serverless.yml")).toBe(true);
    expect(isTerraform("infra/main.tf")).toBe(true);
    expect(isTerraform("src/a.ts")).toBe(false);
  });
});

describe("detectDeployment", () => {
  const deployment = detectDeployment(SAMPLE_REPO);

  it("reads EXPOSE ports from a Dockerfile", () => {
    const docker = deployment.filter((d) => d.kind === "dockerfile");
    expect(docker.flatMap((d) => d.ports).sort((a, b) => a - b)).toEqual([
      3000, 9229,
    ]);
  });

  it("reads compose service names and their container ports", () => {
    const compose = deployment.filter((d) => d.kind === "compose");

    expect(compose.map((d) => d.name)).toEqual(["api", "db", "cache"]);
    expect(compose.find((d) => d.name === "api")?.ports).toEqual([3000, 9229]);
    expect(compose.find((d) => d.name === "db")?.ports).toEqual([5432]);
    expect(compose.find((d) => d.name === "cache")?.ports).toEqual([]);
  });

  it("reads serverless function names", () => {
    const serverless = deployment.filter((d) => d.kind === "serverless");
    expect(serverless.map((d) => d.name)).toEqual([
      "generateReport",
      "purgeOldReports",
    ]);
  });

  it("reads terraform resource names", () => {
    const terraform = deployment.filter((d) => d.kind === "terraform");
    expect(terraform.map((d) => d.name)).toEqual([
      "aws_s3_bucket.uploads",
      "aws_db_instance.primary",
    ]);
  });

  it("records vercel.json", () => {
    expect(deployment.find((d) => d.kind === "vercel")?.name).toBe(
      "vercel.json",
    );
  });

  it("never records a value from any of these files", () => {
    const serialised = JSON.stringify(deployment);

    expect(serialised).not.toContain(PLANTED_CONNECTION);
    expect(serialised).not.toContain(PLANTED_DB_PASSWORD);
    expect(serialised).not.toContain("us-east-1");
    expect(serialised).not.toContain("sample-app-uploads");
  });

  it("does not treat the provider block as a serverless function", () => {
    const names = detectDeployment([SERVERLESS_YML]).map((d) => d.name);
    expect(names).not.toContain("provider");
    expect(names).not.toContain("name");
  });

  it("does not treat a top-level key as a compose service", () => {
    const names = detectDeployment([COMPOSE]).map((d) => d.name);
    expect(names).not.toContain("volumes");
    expect(names).not.toContain("version");
  });

  it("ignores a port outside the valid range", () => {
    const found = detectDeployment([
      { path: "Dockerfile", content: "EXPOSE 99999\nEXPOSE 0\nEXPOSE 8080\n" },
    ]);
    expect(found.flatMap((d) => d.ports)).toEqual([8080]);
  });

  it.each([
    ["an empty Dockerfile", { path: "Dockerfile", content: "" }],
    [
      "compose with no services",
      { path: "docker-compose.yml", content: "version: '3'\n" },
    ],
    [
      "serverless with no functions",
      { path: "serverless.yml", content: "service: x\n" },
    ],
    [
      "terraform with no resources",
      { path: "infra/a.tf", content: "# nothing\n" },
    ],
  ])("handles %s without throwing", (_label, file) => {
    expect(() => detectDeployment([file])).not.toThrow();
    expect(detectDeployment([file])).toEqual([]);
  });

  it("reports the line each fact came from", () => {
    const expose = DOCKERFILE.content
      .split("\n")
      .findIndex((l) => l.startsWith("EXPOSE"));
    expect(detectDeployment([DOCKERFILE])[0].line).toBe(expose + 1);

    const resource = TERRAFORM.content
      .split("\n")
      .findIndex((l) => l.includes("aws_s3_bucket"));
    expect(detectDeployment([TERRAFORM])[0].line).toBe(resource + 1);
  });

  it("ignores files it does not own", () => {
    expect(detectDeployment([ENV_EXAMPLE])).toEqual([]);
  });
});
