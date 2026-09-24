/**
 * Loads a versioned prompt from prompts/.
 *
 * Prompts are files rather than string literals so a prompt can be edited and diffed
 * without touching code, and versioned in the filename so a ThreatModel can record
 * WHICH prompt produced it. The returned id ("architecture.v1") is what gets stored.
 *
 * `name` and `version` are validated before they reach the filesystem. Nothing in the
 * pipeline should ever pass a repository-derived name here, but the check is cheap and
 * a path traversal into an .env file is not the failure to discover later.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { withSecurityPreamble } from "@/server/security/injection";

/** Lowercase letters, digits and hyphens. No dots, no slashes, no "..". */
const NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export const PROMPTS_DIR = "prompts";

export type LoadedPrompt = {
  /**
   * What is actually sent as the system prompt: SECURITY_PREAMBLE followed by the file's
   * contents. Never the file alone -- see the note on loadPrompt.
   */
  text: string;
  /** The file's contents, verbatim, with no preamble. */
  body: string;
  /** "<name>.v<version>", recorded alongside whatever the prompt produced. */
  id: string;
  /** Repository-relative path, for an error message or a debug dump. */
  path: string;
};

export class PromptNotFoundError extends Error {
  constructor(
    readonly promptPath: string,
    options?: { cause?: unknown },
  ) {
    super(`prompt not found: ${promptPath}`, options);
    this.name = "PromptNotFoundError";
  }
}

/**
 * Reads prompts/<name>.v<version>.md and returns it with SECURITY_PREAMBLE in front.
 *
 * The preamble is prepended here, rather than pasted into each prompt file, so that
 * "every system prompt states that repository content is untrusted" is a property of the
 * loader instead of a thing an author has to remember (Prompt U, Part 1). A prompt added
 * later for questions or remediation inherits it by existing. It also keeps the preamble
 * a constant prefix of the cacheable system block in src/server/ai/claude.ts.
 *
 * The prompt files stay verbatim in `body`, and `id` still identifies the file, since the
 * preamble is the same for every prompt and every version.
 *
 * `baseDir` exists for tests and defaults to the prompts directory under the process's
 * working directory, which is the repository root under both `next` and `tsx`.
 */
export function loadPrompt(
  name: string,
  version: number,
  baseDir: string = PROMPTS_DIR,
): LoadedPrompt {
  if (!NAME.test(name)) {
    throw new Error(
      `prompt name must be lowercase letters, digits and hyphens, got "${name}"`,
    );
  }
  if (!Number.isInteger(version) || version < 1) {
    throw new Error(`prompt version must be a positive integer, got ${version}`);
  }

  const file = `${name}.v${version}.md`;
  const path = join(baseDir, file);
  let body: string;
  try {
    body = readFileSync(path, "utf8");
  } catch (cause) {
    throw new PromptNotFoundError(path, { cause });
  }

  return {
    text: withSecurityPreamble(body),
    body,
    id: `${name}.v${version}`,
    path,
  };
}
