import { basename, byPath, lineAt, lineStarts } from "@/server/detect/shared";
import { isJavaScriptPath, secretStorageWrites } from "@/server/detect/web";
import { detectFrameworks } from "@/server/detect/frameworks";
import type {
  Datastore,
  DatastoreKind,
  DetectorInput,
  Framework,
} from "@/server/detect/types";

/**
 * Datastores, from declared dependencies and from connection calls in code.
 *
 * A connection string is never captured. The call name and its line are enough to place
 * the datastore on the diagram, and the string itself would be a credential
 * (CLAUDE.md rules 3 and 8).
 */

const KIND_BY_PACKAGE: Record<string, DatastoreKind> = {
  pg: "postgres",
  postgres: "postgres",
  mysql2: "mysql",
  mongoose: "mongodb",
  mongodb: "mongodb",
  prisma: "prisma",
  "@prisma/client": "prisma",
  sequelize: "unknown",
  typeorm: "unknown",
  "drizzle-orm": "unknown",
  redis: "redis",
  ioredis: "redis",
  "better-sqlite3": "sqlite",
  sqlite3: "sqlite",
};

/**
 * Connection calls. `createClient` is deliberately "unknown": redis, supabase and
 * several SDKs all use that name, so the kind is settled by the file's imports when
 * they say, and left unknown when they do not.
 */
const USAGE: { pattern: RegExp; name: string; kind: DatastoreKind }[] = [
  { pattern: /\bnew\s+Pool\s*\(/, name: "new Pool", kind: "postgres" },
  { pattern: /\bnew\s+Client\s*\(/, name: "new Client", kind: "unknown" },
  { pattern: /\bcreatePool\s*\(/, name: "createPool", kind: "mysql" },
  {
    pattern: /\bmongoose\s*\.\s*connect\s*\(/,
    name: "mongoose.connect",
    kind: "mongodb",
  },
  {
    pattern: /\bnew\s+MongoClient\s*\(/,
    name: "new MongoClient",
    kind: "mongodb",
  },
  {
    pattern: /\bnew\s+PrismaClient\s*\(/,
    name: "new PrismaClient",
    kind: "prisma",
  },
  { pattern: /\bcreateClient\s*\(/, name: "createClient", kind: "unknown" },
  {
    pattern: /\bfirebase\s*\.\s*firestore\s*\(\s*\)/,
    name: "firebase.firestore",
    kind: "firestore",
  },
  { pattern: /\bgetFirestore\s*\(/, name: "getFirestore", kind: "firestore" },
  { pattern: /\bsetDoc\s*\(/, name: "setDoc", kind: "firestore" },
];

/** Narrows an ambiguous call using what the file imports. */
function refineKind(kind: DatastoreKind, content: string): DatastoreKind {
  if (kind !== "unknown") return kind;

  if (
    /from\s*['"`](?:redis|ioredis)['"`]|require\(\s*['"`](?:redis|ioredis)['"`]/.test(
      content,
    )
  ) {
    return "redis";
  }
  if (/from\s*['"`]pg['"`]|require\(\s*['"`]pg['"`]/.test(content))
    return "postgres";
  if (/from\s*['"`]mysql2?/.test(content)) return "mysql";
  if (/from\s*['"`]mongodb['"`]/.test(content)) return "mongodb";

  return "unknown";
}

/** Datastore packages declared in any manifest. */
export function datastoresFromDependencies(
  frameworks: readonly Framework[],
): Datastore[] {
  return frameworks
    .filter((framework) => framework.category === "database")
    .map((framework) => ({
      kind: KIND_BY_PACKAGE[framework.name] ?? "unknown",
      name: framework.name,
      origin: "dependency" as const,
      file: framework.file,
      line: framework.line,
    }));
}

/** Connection calls found in source. */
export function datastoresFromUsage(
  files: readonly DetectorInput[],
): Datastore[] {
  const found: Datastore[] = [];

  for (const file of byPath(files)) {
    if (!/\.(?:ts|tsx|js|jsx|mjs|cjs)$/.test(file.path)) continue;

    const starts = lineStarts(file.content);
    for (const usage of USAGE) {
      const pattern = new RegExp(usage.pattern.source, "g");
      let match: RegExpExecArray | null;

      while ((match = pattern.exec(file.content)) !== null) {
        found.push({
          kind: refineKind(usage.kind, file.content),
          name: usage.name,
          origin: "usage",
          file: file.path,
          line: lineAt(starts, match.index),
        });
      }
    }
  }

  return found;
}

/** `firestore.rules`: the file's existence is the fact, like vercel.json for deployment. */
export function isFirestoreRules(path: string): boolean {
  return basename(path) === "firestore.rules";
}

/** Firestore security rules files, as config-origin datastores. */
export function datastoresFromConfig(
  files: readonly DetectorInput[],
): Datastore[] {
  return byPath(files)
    .filter((file) => isFirestoreRules(file.path))
    .map((file) => ({
      kind: "firestore" as const,
      name: "firestore.rules",
      origin: "config" as const,
      file: file.path,
      line: 1,
    }));
}

/**
 * Browser storage written under a key that names a secret or a token. The browser is a
 * datastore an attacker with script execution can read, so a credential kept there
 * belongs on the diagram. The key name is recorded; the value never is.
 */
export function datastoresFromBrowserStorage(
  files: readonly DetectorInput[],
): Datastore[] {
  const found: Datastore[] = [];
  for (const file of byPath(files)) {
    if (!isJavaScriptPath(file.path)) continue;
    for (const write of secretStorageWrites(file)) {
      found.push({
        kind: "browser_storage",
        name: `${write.storage} ${write.key}`,
        origin: "usage",
        file: file.path,
        line: write.line,
      });
    }
  }
  return found;
}

/**
 * Both origins, dependencies first. The same datastore legitimately appears twice — as
 * a declared package and as a connection call — because they are different evidence.
 */
export function detectDatastores(
  files: readonly DetectorInput[],
  frameworks: readonly Framework[] = detectFrameworks(files),
): Datastore[] {
  return [
    ...datastoresFromDependencies(frameworks),
    ...datastoresFromUsage(files),
    ...datastoresFromConfig(files),
    ...datastoresFromBrowserStorage(files),
  ];
}
