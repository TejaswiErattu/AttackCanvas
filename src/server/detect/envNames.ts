import { basename, byPath, lineAt, lineStarts } from "@/server/detect/shared";
import type { DetectorInput, EnvName } from "@/server/detect/types";

/**
 * Environment variable NAMES. Never values.
 *
 * A name tells the threat model what the system depends on ("this service holds a
 * Stripe key"); the value is the credential itself. Only `.env.example` is read, and
 * only its keys — `.env` never reaches here, because the ingest classifier refuses to
 * fetch it (CLAUDE.md rule 3).
 */

/** KEY=…, optionally exported, with the value deliberately uncaptured. */
const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;

/** process.env.NAME, process.env["NAME"] and destructured reads. */
const PROCESS_ENV =
  /process\s*\.\s*env\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*(['"`])([A-Za-z_][A-Za-z0-9_]*)\2\s*\])/g;

/** const { A, B } = process.env */
const DESTRUCTURED =
  /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*process\s*\.\s*env\b/g;

export function isEnvExample(path: string): boolean {
  return basename(path) === ".env.example";
}

/**
 * Keys from a .env.example. The part after "=" is never read, so a file that ships a
 * real value by mistake still cannot leak it through a detector.
 */
export function envExampleNames(file: DetectorInput): EnvName[] {
  const names: EnvName[] = [];

  file.content.split("\n").forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) return;

    const match = ENV_LINE.exec(line);
    if (!match) return;

    names.push({
      name: match[1],
      origin: "env_example",
      file: file.path,
      line: index + 1,
    });
  });

  return names;
}

/** process.env reads in source. */
export function processEnvNames(file: DetectorInput): EnvName[] {
  const names: EnvName[] = [];
  const starts = lineStarts(file.content);

  const direct = new RegExp(PROCESS_ENV.source, PROCESS_ENV.flags);
  let match: RegExpExecArray | null;
  while ((match = direct.exec(file.content)) !== null) {
    const name = match[1] ?? match[3];
    if (name) {
      names.push({
        name,
        origin: "process_env",
        file: file.path,
        line: lineAt(starts, match.index),
      });
    }
  }

  const destructured = new RegExp(DESTRUCTURED.source, DESTRUCTURED.flags);
  while ((match = destructured.exec(file.content)) !== null) {
    const line = lineAt(starts, match.index);
    for (const part of match[1].split(",")) {
      // Handles `A` and `A: alias`; the name is what is read from the environment.
      const name = /^\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(part)?.[1];
      if (name)
        names.push({ name, origin: "process_env", file: file.path, line });
    }
  }

  return names;
}

/**
 * Every env name, de-duplicated per name and origin so a variable read in ten places
 * is one fact pointing at the first read rather than ten.
 */
export function detectEnvNames(files: readonly DetectorInput[]): EnvName[] {
  const found: EnvName[] = [];
  const seen = new Set<string>();

  for (const file of byPath(files)) {
    const fromFile = isEnvExample(file.path)
      ? envExampleNames(file)
      : /\.(?:ts|tsx|js|jsx|mjs|cjs)$/.test(file.path)
        ? processEnvNames(file)
        : [];

    for (const entry of fromFile) {
      const key = `${entry.origin}:${entry.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      found.push(entry);
    }
  }

  return found;
}
