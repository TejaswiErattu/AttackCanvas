import { basename, byPath, normalizeSeparators } from "@/server/detect/shared";
import type { Deployment, DetectorInput } from "@/server/detect/types";

/**
 * Where the system runs and what it exposes: Docker, Compose, Vercel, Serverless and
 * Terraform. Names and ports only, never values — a Compose environment block and a
 * Terraform variable are full of credentials (CLAUDE.md rule 3).
 *
 * AST NOTE: Compose and Serverless are read with indentation-aware line matching, which
 * is the weakest parsing in the detectors. It handles ordinary two-space YAML and will
 * miss flow mappings (`ports: ["80:80"]` inline at depth), anchors and multi-document
 * files. A real YAML parser is the fix, and the same goes for HCL in the .tf case.
 */

const PORT_RANGE = { min: 1, max: 65_535 };

function validPort(value: string): number | undefined {
  const port = Number(value);
  return Number.isInteger(port) &&
    port >= PORT_RANGE.min &&
    port <= PORT_RANGE.max
    ? port
    : undefined;
}

export function isDockerfile(path: string): boolean {
  const name = basename(path).toLowerCase();
  return name === "dockerfile" || name.startsWith("dockerfile.");
}

export function isCompose(path: string): boolean {
  return /^docker-compose[\w.-]*\.ya?ml$/i.test(basename(path));
}

export function isServerless(path: string): boolean {
  return /^serverless\.ya?ml$/i.test(basename(path));
}

export function isTerraform(path: string): boolean {
  return /\.tf$/i.test(basename(path));
}

export function isVercel(path: string): boolean {
  return basename(path) === "vercel.json";
}

/** EXPOSE 8080 / EXPOSE 8080/tcp 9090 */
export function dockerfilePorts(file: DetectorInput): Deployment[] {
  const found: Deployment[] = [];

  file.content.split("\n").forEach((line, index) => {
    const match = /^\s*EXPOSE\s+(.+?)\s*$/i.exec(line);
    if (!match) return;

    const ports = match[1]
      .split(/\s+/)
      .map((token) => validPort(token.split("/")[0]))
      .filter((port): port is number => port !== undefined);

    if (ports.length > 0) {
      found.push({
        kind: "dockerfile",
        name: basename(file.path),
        ports,
        file: file.path,
        line: index + 1,
      });
    }
  });

  return found;
}

/**
 * Compose service names and their published ports. A service is a key at the first
 * indent level under `services:`; its ports are the "HOST:CONTAINER" entries in its
 * own `ports:` list, of which we keep the container port.
 */
export function composeServices(file: DetectorInput): Deployment[] {
  const lines = file.content.split("\n");
  const found: Deployment[] = [];

  let inServices = false;
  let servicesIndent = 0;
  let current: Deployment | undefined;
  let inPorts = false;

  const indentOf = (line: string): number =>
    line.length - line.trimStart().length;

  for (const [index, line] of lines.entries()) {
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const indent = indentOf(line);

    if (/^services\s*:/.test(line.trim()) && indent === 0) {
      inServices = true;
      servicesIndent = indent;
      current = undefined;
      continue;
    }

    if (
      inServices &&
      indent <= servicesIndent &&
      !/^services\s*:/.test(line.trim())
    ) {
      inServices = false;
      current = undefined;
      continue;
    }
    if (!inServices) continue;

    const serviceMatch = /^([A-Za-z0-9._-]+)\s*:\s*$/.exec(line.trim());
    if (serviceMatch && current === undefined) {
      current = {
        kind: "compose",
        name: serviceMatch[1],
        ports: [],
        file: file.path,
        line: index + 1,
      };
      found.push(current);
      inPorts = false;
      continue;
    }

    if (
      current &&
      serviceMatch &&
      indent === indentOf(lines[current.line - 1])
    ) {
      current = {
        kind: "compose",
        name: serviceMatch[1],
        ports: [],
        file: file.path,
        line: index + 1,
      };
      found.push(current);
      inPorts = false;
      continue;
    }

    if (!current) continue;

    if (/^ports\s*:/.test(line.trim())) {
      inPorts = true;
      const inline = /\[(.+)\]/.exec(line);
      if (inline) {
        for (const entry of inline[1].split(",")) {
          const port = validPort(
            entry
              .replace(/['"\s]/g, "")
              .split(":")
              .pop() ?? "",
          );
          if (port !== undefined) current.ports.push(port);
        }
        inPorts = false;
      }
      continue;
    }

    if (inPorts) {
      const entry = /^-\s*['"]?([0-9.:]+)['"]?/.exec(line.trim());
      if (entry) {
        const port = validPort(entry[1].split(":").pop() ?? "");
        if (port !== undefined) current.ports.push(port);
        continue;
      }
      inPorts = false;
    }
  }

  return found;
}

/** Serverless function names under `functions:`. */
export function serverlessFunctions(file: DetectorInput): Deployment[] {
  const lines = file.content.split("\n");
  const found: Deployment[] = [];

  let inFunctions = false;
  let depth = 0;

  for (const [index, line] of lines.entries()) {
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;

    if (/^functions\s*:/.test(line.trim()) && indent === 0) {
      inFunctions = true;
      depth = indent;
      continue;
    }
    if (inFunctions && indent <= depth) {
      inFunctions = false;
      continue;
    }
    if (!inFunctions) continue;

    const match = /^([A-Za-z0-9._-]+)\s*:\s*$/.exec(line.trim());
    if (match && indent === depth + 2) {
      found.push({
        kind: "serverless",
        name: match[1],
        ports: [],
        file: file.path,
        line: index + 1,
      });
    }
  }

  return found;
}

/** resource "aws_s3_bucket" "uploads" -> name "aws_s3_bucket.uploads". */
export function terraformResources(file: DetectorInput): Deployment[] {
  const found: Deployment[] = [];

  file.content.split("\n").forEach((line, index) => {
    const match = /^\s*resource\s+"([^"]+)"\s+"([^"]+)"/.exec(line);
    if (!match) return;

    found.push({
      kind: "terraform",
      name: `${match[1]}.${match[2]}`,
      ports: [],
      file: file.path,
      line: index + 1,
    });
  });

  return found;
}

/** vercel.json: recorded as present, since its existence is the deployment fact. */
export function vercelConfig(file: DetectorInput): Deployment[] {
  return [
    {
      kind: "vercel",
      name: "vercel.json",
      ports: [],
      file: file.path,
      line: 1,
    },
  ];
}

/** .github/workflows/*.yml, at any depth so a monorepo package's workflows count too. */
export function isGithubWorkflow(path: string): boolean {
  return /(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(normalizeSeparators(path));
}

/**
 * One fact per job under `jobs:`, named "<workflow file>:<job id>". A job id is a key the
 * repository chose, like a Compose service name; nothing else in the file is read, since
 * `env:` and `with:` blocks are where a workflow keeps its values.
 * A workflow whose jobs cannot be read is still recorded once, at line 1.
 */
export function workflowJobs(file: DetectorInput): Deployment[] {
  const lines = file.content.split("\n");
  const name = basename(file.path);
  const found: Deployment[] = [];

  let inJobs = false;
  let jobIndent: number | undefined;
  for (const [index, line] of lines.entries()) {
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;

    if (indent === 0) {
      inJobs = /^jobs\s*:\s*$/.test(line.trim());
      jobIndent = undefined;
      continue;
    }
    if (!inJobs) continue;

    jobIndent ??= indent;
    if (indent !== jobIndent) continue;
    const job = /^([A-Za-z0-9_-]+)\s*:\s*$/.exec(line.trim());
    if (job) {
      found.push({
        kind: "github_actions",
        name: `${name}:${job[1]}`,
        ports: [],
        file: file.path,
        line: index + 1,
      });
    }
  }

  return found.length > 0
    ? found
    : [{ kind: "github_actions", name, ports: [], file: file.path, line: 1 }];
}

export function detectDeployment(
  files: readonly DetectorInput[],
): Deployment[] {
  const found: Deployment[] = [];

  for (const file of byPath(files)) {
    const path = normalizeSeparators(file.path);

    if (isDockerfile(path)) found.push(...dockerfilePorts(file));
    else if (isCompose(path)) found.push(...composeServices(file));
    else if (isServerless(path)) found.push(...serverlessFunctions(file));
    else if (isTerraform(path)) found.push(...terraformResources(file));
    else if (isVercel(path)) found.push(...vercelConfig(file));
    else if (isGithubWorkflow(path)) found.push(...workflowJobs(file));
  }

  return found;
}
