/**
 * A local cache of validated model responses, for working without paying.
 *
 * When ATTACKCANVAS_MODEL_CACHE=1 and NODE_ENV is not "production", callStructured hashes
 * what decides the reply (model id, system text, messages, output schema) and looks for
 * .cache/model/<hash>.json. A hit returns the saved parsed response; a miss makes the call
 * and saves the parsed response with its usage. Only a response that passed validation is
 * ever saved.
 *
 * The file holds the parsed response and token counts, never the prompt, so repository
 * text reaches the cache only as far as the model's own answer quotes it. Every body is
 * checked with assertNoSecrets before it is written and is skipped if that fails. .cache/
 * is gitignored.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CallUsage } from "@/server/ai/usage";
import { assertNoSecrets } from "@/server/security/redactor";

export const MODEL_CACHE_ENV = "ATTACKCANVAS_MODEL_CACHE";
export const MODEL_CACHE_DIR = join(".cache", "model");

export type CachedResponse = {
  version: 1;
  model: string;
  /** The parsed, validated response. */
  value: unknown;
  /** What the original call cost, one entry per provider response. */
  usage: CallUsage[];
};

export type ModelCache = {
  read(hash: string): CachedResponse | undefined;
  write(hash: string, entry: CachedResponse): void;
};

/** True when the cache is on: the variable is "1" and this is not production. */
export function modelCacheEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env[MODEL_CACHE_ENV] === "1" && env.NODE_ENV !== "production";
}

/** sha256 over everything that decides the reply. Key order is fixed by construction. */
export function cacheKey(input: {
  model: string;
  system: string;
  messages: readonly { role: string; content: unknown }[];
  jsonSchema: Record<string, unknown>;
}): string {
  return createHash("sha256")
    .update(
      JSON.stringify([
        input.model,
        input.system,
        input.messages.map((m) => [m.role, m.content]),
        input.jsonSchema,
      ]),
    )
    .digest("hex");
}

/** A file-backed cache under `dir`. Never throws: a broken cache is a miss. */
export function fileModelCache(dir: string = MODEL_CACHE_DIR): ModelCache {
  return {
    read(hash) {
      try {
        const entry = JSON.parse(readFileSync(join(dir, `${hash}.json`), "utf8")) as CachedResponse;
        return entry?.version === 1 && Array.isArray(entry.usage) ? entry : undefined;
      } catch {
        return undefined;
      }
    },
    write(hash, entry) {
      try {
        const body = JSON.stringify(entry, null, 2);
        assertNoSecrets(body);
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, `${hash}.json`), body, "utf8");
      } catch {
        // A secret-shaped response or a filesystem error: not cached, nothing else lost.
      }
    },
  };
}
