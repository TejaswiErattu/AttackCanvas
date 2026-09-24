import {
  existsSync,
  mkdirSync,
  mkdtempSync,
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
