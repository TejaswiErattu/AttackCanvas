import type { DetectorInput } from "@/server/detect/types";

/**
 * Sample repository content for the detector tests.
 *
 * Two of these files deliberately contain a credential — a fake AWS key and a
 * postgres:// URL with a password. Repository content is untrusted (CLAUDE.md rule 3),
 * so the suite uses them to prove that no detector copies a matched value into a fact
 * or an Evidence summary.
 */

export const PLANTED_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

/**
 * A distinct AWS-shaped marker in every file that produces a fact.
 *
 * Without one per file, a detector could copy raw content into a summary and the
 * suite would miss it whenever the copied file happened to hold no secret — which is
 * exactly what a mutation showed: route summaries were free to quote src/app.js.
 */
export const MARKERS = {
  app: "AKIAZZAPPZZ000000001",
  users: "AKIAZZUSERSZZ0000001",
  nextApp: "AKIAZZNEXTAPPZZ00001",
  pages: "AKIAZZPAGESZZ0000001",
  config: "AKIAZZCONFIGZZ000001",
  manifest: "AKIAZZMANIFESTZZ0001",
  dockerfile: "AKIAZZDOCKERZZ000001",
  serverless: "AKIAZZSERVERLESSZZ01",
} as const;

export const ALL_MARKERS: string[] = Object.values(MARKERS);
export const PLANTED_DB_PASSWORD = "hunter2pass";
export const PLANTED_CONNECTION = `postgres://admin:${PLANTED_DB_PASSWORD}@db.internal:5432/app`;

export const PACKAGE_JSON: DetectorInput = {
  path: "package.json",
  content: `{
  "name": "sample-app",
  "version": "1.0.0",
  "description": "${MARKERS.manifest}",
  "dependencies": {
    "express": "^4.18.2",
    "next": "15.0.0",
    "passport": "^0.7.0",
    "jsonwebtoken": "^9.0.2",
    "@clerk/nextjs": "^5.0.0",
    "pg": "^8.11.3",
    "mongoose": "^8.0.0",
    "@prisma/client": "^5.7.0",
    "ioredis": "^5.3.2",
    "@aws-sdk/client-s3": "^3.470.0",
    "@google-cloud/storage": "^7.7.0",
    "stripe": "^14.10.0",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "zod": "^3.22.4",
    "multer": "^1.4.5",
    "ejs": "^3.1.9",
    "axios": "^1.6.2",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "typescript": "^5.3.3",
    "joi": "^17.11.0"
  }
}
`,
};

/** A second manifest, so the monorepo merge is exercised. */
export const WORKSPACE_PACKAGE_JSON: DetectorInput = {
  path: "services/worker/package.json",
  content: `{
  "name": "worker",
  "dependencies": {
    "fastify": "^4.25.0",
    "ioredis": "^5.3.2"
  }
}
`,
};

export const BROKEN_PACKAGE_JSON: DetectorInput = {
  path: "services/broken/package.json",
  content: `{ "dependencies": { "express": `,
};

export const EXPRESS_APP: DetectorInput = {
  path: "src/app.js",
  content: `const express = require("express");
const helmet = require("helmet");
const usersRouter = require("./routes/users");
const adminRouter = require("./routes/admin");

const LEGACY_DEPLOY_KEY = "${MARKERS.app}";

const app = express();
app.use(helmet());
app.use("/api/v1", usersRouter);
app.use("/admin", adminRouter);

app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/login", async (req, res) => {
  res.json({ token: "issued" });
});

module.exports = app;
`,
};

export const EXPRESS_USERS_ROUTER: DetectorInput = {
  path: "src/routes/users.js",
  content: `const express = require("express");
const passport = require("passport");
const { requireAuth } = require("../middleware/auth");
const { auditLog } = require("../middleware/audit");

const LEGACY_DEPLOY_KEY = "${MARKERS.users}";

const router = express.Router();

router.get("/", requireAuth, async (req, res) => {
  res.json(await listUsers());
});

router.get("/:id", passport.authenticate("jwt"), async (req, res) => {
  res.json(await getUser(req.params.id));
});

router.post("/", auditLog, async (req, res) => {
  res.status(201).json(await createUser(req.body));
});

router.delete("/:id", async (req, res) => {
  res.status(204).end();
});

module.exports = router;
`,
};

export const EXPRESS_ADMIN_ROUTER: DetectorInput = {
  path: "src/routes/admin.js",
  content: `const express = require("express");
const { requireRole } = require("../middleware/roles");

const router = express.Router();

router.get("/users", requireRole("admin"), async (req, res) => {
  if (req.user.role === "superuser") {
    return res.json(await listAll());
  }
  res.json([]);
});

router.put("/settings", async (req, res) => {
  res.json({ saved: true });
});

module.exports = router;
`,
};

export const NEXT_APP_ROUTE: DetectorInput = {
  path: "src/app/api/users/route.ts",
  content: `import { getServerSession } from "next-auth";

const LEGACY_DEPLOY_KEY = "${MARKERS.nextApp}";

export async function GET() {
  const session = await getServerSession();
  return Response.json({ users: [], session });
}

export async function POST(request: Request) {
  return Response.json({ created: true });
}
`,
};

export const NEXT_APP_DYNAMIC_ROUTE: DetectorInput = {
  path: "src/app/(dashboard)/reports/[id]/route.ts",
  content: `export const GET = async () => Response.json({ report: null });
export const DELETE = async () => new Response(null, { status: 204 });
`,
};

export const NEXT_APP_CATCH_ALL: DetectorInput = {
  path: "app/api/proxy/[...slug]/route.js",
  content: `export async function POST(request) {
  return Response.json({ proxied: true });
}
`,
};

export const NEXT_PAGES_API: DetectorInput = {
  path: "pages/api/webhooks/[id].ts",
  content: `const LEGACY_DEPLOY_KEY = "${MARKERS.pages}";

export default async function handler(req, res) {
  if (req.method === "POST") {
    return res.status(200).json({ received: true });
  }
  if (req.method === "GET") {
    return res.status(200).json({ status: "ok" });
  }
  res.status(405).end();
}
`,
};

export const NEXT_PAGES_API_INDEX: DetectorInput = {
  path: "pages/api/index.ts",
  content: `export default function handler(req, res) {
  res.json({ ok: true });
}
`,
};

/** Holds a real-looking connection string: nothing here may reach a fact. */
export const DB_MODULE: DetectorInput = {
  path: "src/db.js",
  content: `const { Pool } = require("pg");
const mongoose = require("mongoose");
const { PrismaClient } = require("@prisma/client");

const pool = new Pool({ connectionString: "${PLANTED_CONNECTION}" });
const prisma = new PrismaClient();

mongoose.connect(process.env.MONGO_URL);

const AWS_KEY = "${PLANTED_AWS_KEY}";

module.exports = { pool, prisma, AWS_KEY };
`,
};

export const CONFIG_MODULE: DetectorInput = {
  path: "src/config.ts",
  content: `const LEGACY_DEPLOY_KEY = "${MARKERS.config}";

const { NODE_ENV, PORT } = process.env;

export const config = {
  env: NODE_ENV,
  port: PORT,
  databaseUrl: process.env.DATABASE_URL,
  stripeKey: process.env["STRIPE_SECRET_KEY"],
  sessionSecret: process.env.SESSION_SECRET,
};
`,
};

export const ENV_EXAMPLE: DetectorInput = {
  path: ".env.example",
  content: `# Database
DATABASE_URL=postgres://user:password@localhost:5432/app

# Auth
SESSION_SECRET=replace-me
export JWT_SECRET=replace-me

STRIPE_SECRET_KEY=sk_test_replace_me
`,
};

export const DOCKERFILE: DetectorInput = {
  path: "Dockerfile",
  content: `FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci
ENV LEGACY_DEPLOY_KEY=${MARKERS.dockerfile}
EXPOSE 3000
EXPOSE 9229/tcp
CMD ["node", "src/index.js"]
`,
};

export const COMPOSE: DetectorInput = {
  path: "docker-compose.yml",
  content: `version: "3.9"
services:
  api:
    build: .
    ports:
      - "8080:3000"
      - "9229:9229"
    environment:
      DATABASE_URL: ${PLANTED_CONNECTION}
  db:
    image: postgres:16
    ports:
      - "5432:5432"
  cache:
    image: redis:7
volumes:
  pgdata:
`,
};

export const VERCEL_JSON: DetectorInput = {
  path: "vercel.json",
  content: `{ "framework": "nextjs", "regions": ["iad1"] }
`,
};

export const SERVERLESS_YML: DetectorInput = {
  path: "serverless.yml",
  content: `service: reports
provider:
  name: aws
  runtime: nodejs20.x
  environment:
    LEGACY_DEPLOY_KEY: ${MARKERS.serverless}
functions:
  generateReport:
    handler: src/handlers.generate
  purgeOldReports:
    handler: src/handlers.purge
`,
};

export const TERRAFORM: DetectorInput = {
  path: "infra/main.tf",
  content: `provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "uploads" {
  bucket = "sample-app-uploads"
}

resource "aws_db_instance" "primary" {
  password = "${PLANTED_DB_PASSWORD}"
}
`,
};

/** Everything, in a deliberately unsorted order. */
export const SAMPLE_REPO: DetectorInput[] = [
  TERRAFORM,
  NEXT_PAGES_API,
  EXPRESS_ADMIN_ROUTER,
  ENV_EXAMPLE,
  PACKAGE_JSON,
  COMPOSE,
  NEXT_APP_ROUTE,
  DB_MODULE,
  EXPRESS_APP,
  SERVERLESS_YML,
  NEXT_APP_DYNAMIC_ROUTE,
  CONFIG_MODULE,
  WORKSPACE_PACKAGE_JSON,
  DOCKERFILE,
  EXPRESS_USERS_ROUTER,
  VERCEL_JSON,
  NEXT_APP_CATCH_ALL,
  NEXT_PAGES_API_INDEX,
];
