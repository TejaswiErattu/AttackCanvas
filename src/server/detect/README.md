# server/detect

Deterministic detectors for languages, frameworks, entry points and trust boundaries.

`runDetectors(files)` → `DetectorResult` with typed facts plus the `Evidence` that backs them.
Input is `{ path, content }[]`, so the ingest stage's `LoadedFile[]` can be passed straight in.

| Module | Facts |
| --- | --- |
| `frameworks.ts` | `Framework` — package → category, from every `package.json`; CDN `<script src>` libraries; Cloudflare Worker entry and Firebase SDK usage |
| `routes.ts` | `Route` — Express, Next App Router, Next Pages API and Cloudflare Worker fetch dispatch |
| `auth.ts` | `RouteAuth` — authenticated / unauthenticated / unknown, role checks, admin paths; `TokenCheck` — JWT signature verified, or decoded without verification |
| `datastores.ts` | `Datastore` — from dependencies, connection calls, `firestore.rules`, and secret-named browser storage keys |
| `envNames.ts` | `EnvName` — names only, from `.env.example` and `process.env` |
| `deployment.ts` | `Deployment` — Dockerfile, Compose, Vercel, Serverless, Terraform, GitHub Actions jobs |
| `web.ts` | Shared helpers for static sites and Workers: script tags, CDN URLs, Worker entry, storage writes |

## Rules these obey

- **Never emit a value.** Repository content is untrusted (CLAUDE.md rule 3), so a fact carries a
  name, a path or a port and never matched source text. `Evidence.snippet` is never set. The tests
  plant a marker in every sample file and assert none reaches the output.
- **Stable ids.** Input is sorted by path and each detector emits in source order, so `ev-route-3`
  means the same thing on every run. Route ids line up with their evidence: `route-7` →
  `ev-route-7`, and its auth fact → `ev-auth-7`.
- **A missed fact beats an invented one.** A path built from a variable is skipped rather than
  guessed at; an ambiguous mount prefix is dropped rather than applied.

## Accuracy limits (MVP)

Regex and light parsing. Each module carries an `AST NOTE` comment naming what the TypeScript
compiler API would fix. Known gaps: middleware spread from an array, `app.route().get().post()`
chains, routers wrapped before mounting, and guards recognised only by name — a locally defined
`restrict` middleware reads as unauthenticated because it matches no known guard pattern.
