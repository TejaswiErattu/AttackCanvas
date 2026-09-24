import type { DetectorInput } from "@/server/detect/types";

/**
 * Small generated repositories for the gap tests.
 *
 * Every gap kind needs a case where the control is absent and a twin where it is
 * present, so these are built from factories rather than written out as 24 fixtures.
 * A gap that fires when the control exists is worse than no detector, and only the
 * twin catches that.
 */

/** Present in the sources that should trigger a gap, to prove no gap quotes a file. */
export const GAP_MARKER = "AKIAZZGAPSZZ000000001";

export function file(path: string, content: string): DetectorInput {
  return { path, content };
}

/** A package.json with the given dependencies and, optionally, scripts. */
export function manifest(
  deps: Record<string, string> = {},
  scripts: Record<string, string> = {},
): DetectorInput {
  return file(
    "package.json",
    JSON.stringify({ name: "app", dependencies: deps, scripts }, null, 2),
  );
}

export const LOCKFILE = file("package-lock.json", "{}");

/** An Express app file: `body` is the routes and middleware under test. */
export function expressApp(body: string, path = "src/app.js"): DetectorInput {
  return file(
    path,
    `const express = require("express");\nconst app = express();\n${body}\n`,
  );
}

/** The dependencies every Express case shares. */
export const EXPRESS_DEPS = { express: "^4.18.2" };

/**
 * A repository with a manifest, a lockfile and one Express file, so kinds that are not
 * under test stay quiet for the right reasons.
 */
export function expressRepo(
  body: string,
  deps: Record<string, string> = {},
): DetectorInput[] {
  return [manifest({ ...EXPRESS_DEPS, ...deps }), LOCKFILE, expressApp(body)];
}

/** A repository that trips many kinds at once, each source carrying GAP_MARKER. */
export const MARKED_REPO: DetectorInput[] = [
  manifest(
    { ...EXPRESS_DEPS, pg: "^8.0.0", "express-session": "^1.17.0" },
    {
      postinstall: "node setup.js",
    },
  ),
  file(
    "src/app.js",
    `const express = require("express");
const cors = require("cors");
const app = express();
const KEY = "${GAP_MARKER}";
app.use(cors());
app.post("/login", async (req, res) => {
  const body = req.body;
  await save(body);
  res.json({ ok: true });
});
app.get("/admin/users", async (req, res) => { await list(); });
app.put("/orders/:id", requireAuth, async (req, res) => { await update(req.query); });
`,
  ),
  file(
    "src/client.js",
    `const KEY = "${GAP_MARKER}";\nfetch("http://api.acme-corp.com/v1");\nconst agent = { rejectUnauthorized: false };\n`,
  ),
  file(
    "docker-compose.yml",
    `services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n    environment:\n      NOTE: ${GAP_MARKER}\n`,
  ),
];
