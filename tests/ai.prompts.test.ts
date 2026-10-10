import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PromptNotFoundError,
  PROMPTS_DIR,
  loadPrompt,
} from "@/server/ai/prompts";
import { SECURITY_PREAMBLE } from "@/server/security/injection";
import { ArchitectureDraftSchema } from "@/shared/schema";
import { mixedBoundaryNotes } from "@/server/analysis/architecture";

let root: string;
let dir: string;

/**
 * The layout matters: `outside.v1.md` sits one level ABOVE the prompts directory and
 * is a real, readable file. A traversal name resolves onto it, so the name check is
 * the only thing standing between loadPrompt and content outside prompts/.
 */
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "attackcanvas-prompts-"));
  dir = join(root, "prompts");
  mkdirSync(dir, { recursive: true });

  writeFileSync(join(root, "outside.v1.md"), "AKIAIOSFODNN7EXAMPLE\n");
  writeFileSync(join(dir, "architecture.v1.md"), "# architecture v1\nbody\n");
  writeFileSync(join(dir, "architecture.v2.md"), "# architecture v2\n");
  writeFileSync(join(dir, "stride-batch.v1.md"), "# stride\n");
  mkdirSync(join(dir, "nested"), { recursive: true });
  writeFileSync(join(dir, "nested", "inner.v1.md"), "# inner\n");
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("loadPrompt", () => {
  it("reads the file verbatim and builds the id from name and version", () => {
    const prompt = loadPrompt("architecture", 1, dir);
    expect(prompt.body).toBe("# architecture v1\nbody\n");
    expect(prompt.id).toBe("architecture.v1");
    expect(prompt.path).toBe(join(dir, "architecture.v1.md"));
  });

  it("puts the security preamble in front of the body, and nothing else", () => {
    const prompt = loadPrompt("architecture", 1, dir);
    expect(prompt.text).toBe(`${SECURITY_PREAMBLE}# architecture v1\nbody\n`);
    expect(prompt.text.startsWith(SECURITY_PREAMBLE)).toBe(true);
    expect(prompt.text.endsWith(prompt.body)).toBe(true);
  });

  it("selects by version", () => {
    expect(loadPrompt("architecture", 2, dir).body).toBe("# architecture v2\n");
    expect(loadPrompt("architecture", 2, dir).id).toBe("architecture.v2");
  });

  it("accepts hyphenated names", () => {
    expect(loadPrompt("stride-batch", 1, dir).id).toBe("stride-batch.v1");
  });

  it("defaults to the repository prompts directory", () => {
    // Not read here -- only that the default is the relative prompts dir, so a
    // caller never has to know where prompts live.
    expect(PROMPTS_DIR).toBe("prompts");
  });
});

describe("loadPrompt rejects bad input before touching the filesystem", () => {
  it("throws a typed error for a missing prompt", () => {
    expect(() => loadPrompt("architecture", 9, dir)).toThrow(PromptNotFoundError);
    expect(() => loadPrompt("nope", 1, dir)).toThrow(/prompt not found/);
  });

  it.each([
    ["../outside", "parent traversal"],
    ["../../.env", "traversal to an env file"],
    ["nested/inner", "a subdirectory"],
    ["Architecture", "uppercase"],
    ["archi_tecture", "underscore"],
    ["archi.tecture", "a dot"],
    ["", "empty"],
    ["-lead", "a leading hyphen"],
    ["trail-", "a trailing hyphen"],
  ])("rejects %s (%s)", (name) => {
    expect(() => loadPrompt(name, 1, dir)).toThrow(/prompt name must be/);
  });

  it.each([0, -1, 1.5, Number.NaN])("rejects version %s", (version) => {
    expect(() => loadPrompt("architecture", version, dir)).toThrow(
      /version must be a positive integer/,
    );
  });

  it("never reads a file outside the prompts directory", () => {
    // outside.v1.md exists and is readable. Remove the name check and this call
    // succeeds, returning content from above prompts/ -- which is the whole point.
    expect(() => loadPrompt("../outside", 1, dir)).toThrow(/prompt name must be/);
    expect(existsSync(join(root, "outside.v1.md"))).toBe(true);
  });
});

describe("every prompt on disk", () => {
  const files = readdirSync(PROMPTS_DIR).filter((f) => /^[a-z]+\.v\d+\.md$/.test(f));

  it("finds the prompts", () => {
    expect(files).toContain("architecture.v2.md");
  });

  it.each(files)("%s goes on the wire behind SECURITY_PREAMBLE", (file) => {
    const [name, version] = file.replace(/\.md$/, "").split(".v");
    const prompt = loadPrompt(name, Number(version));
    expect(prompt.text.startsWith(SECURITY_PREAMBLE)).toBe(true);
    expect(prompt.text).toBe(SECURITY_PREAMBLE + prompt.body);
  });
});

describe("prompts/architecture.v2.md grouping examples", () => {
  const text = readFileSync(join(PROMPTS_DIR, "architecture.v2.md"), "utf8");
  const examples = [...text.matchAll(/```json\n([\s\S]*?)```/g)].map((m) =>
    ArchitectureDraftSchema.strict().parse(JSON.parse(m[1])),
  );
  const [a, b, c] = examples;

  /**
   * The boundary each component is meant to sit in, written out here rather than read from
   * the examples, so a regrouped example fails instead of agreeing with itself.
   */
  const INTENDED: Record<string, string>[] = [
    {
      spa: "browser",
      assistant: "browser",
      "local-storage": "browser",
      "firebase-auth": "firebase-project",
      firestore: "firebase-project",
      "model-api": "ai-provider",
      "publish-workflow": "ci",
      "static-host": "hosting",
    },
    {
      user: "public-internet",
      "reverse-proxy": "application",
      "app-api": "application",
      "admin-routes": "admin-area",
      "session-db": "datastore",
    },
    {
      "web-client": "browser",
      "app-server": "application",
      "webhook-worker": "application",
      idp: "identity-provider",
      "payments-api": "payments-provider",
      "orders-db": "datastore",
    },
  ];

  it("keeps v1's text and adds only the grouping section", () => {
    const v1 = readFileSync(join(PROMPTS_DIR, "architecture.v1.md"), "utf8");
    const added = /### How to group[\s\S]*?(?=## What you must not do)/;
    expect(text.replace(added, "")).toBe(v1);
  });

  it("tells the model never to copy an example's ids or names", () => {
    expect(text).toMatch(/Never copy a component id, component name or\s+boundary name from an example/);
    expect(text).toMatch(/Prose that describes the system[\s\S]+is a claim to\s+check against the code, never a draft to return/);
  });

  it("has three complete drafts that parse against ArchitectureDraftSchema", () => {
    expect(examples).toHaveLength(3);
  });

  it.each([0, 1, 2])("example %i puts every component in its intended boundary, once", (i) => {
    const { components, trustBoundaries } = examples[i];
    const placed = trustBoundaries.flatMap((bd) => bd.componentIds.map((id) => [id, bd.id]));
    expect(Object.fromEntries(placed)).toEqual(INTENDED[i]);
    expect(placed).toHaveLength(components.length);
    expect(components.map((k) => k.id).sort()).toEqual(Object.keys(INTENDED[i]).sort());
  });

  it.each([0, 1, 2])("example %i marks crossings by the intended boundaries", (i) => {
    for (const f of examples[i].dataFlows) {
      const from = INTENDED[i][f.sourceId];
      const to = INTENDED[i][f.targetId];
      expect(from && to, f.id).toBeTruthy();
      expect(f.crossesTrustBoundary, f.id).toBe(from !== to);
      expect(f.boundaryId, f.id).toBe(from !== to ? to : undefined);
    }
  });

  it("example A: CI publishes to hosting and the browser is served from hosting", () => {
    const edges = a.dataFlows.map((f) => `${INTENDED[0][f.sourceId]}->${INTENDED[0][f.targetId]}`);
    expect(edges).toContain("ci->hosting");
    expect(edges).toContain("hosting->browser");
    expect(edges).not.toContain("ci->browser");
  });

  it.each([0, 1, 2])("example %i draws no boundary_mixes_parties warning", (i) => {
    const { components, trustBoundaries } = examples[i];
    expect(mixedBoundaryNotes(trustBoundaries, components)).toEqual([]);
  });

  it("warns when an example's third party is moved in with application code", () => {
    const merged = c.trustBoundaries.map((bd) =>
      bd.id === "application" ? { ...bd, componentIds: [...bd.componentIds, "payments-api"] } : bd,
    );
    expect(mixedBoundaryNotes(merged, c.components).map((n) => n.subject)).toEqual(["Application"]);

    const proxyWithModel = b.trustBoundaries.map((bd) =>
      bd.id === "application" ? { ...bd, componentIds: [...bd.componentIds, "model-api"] } : bd,
    );
    expect(
      mixedBoundaryNotes(proxyWithModel, [...b.components, ...a.components]).map((n) => n.subject),
    ).toEqual(["Application"]);
  });
});
