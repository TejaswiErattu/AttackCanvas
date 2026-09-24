# AttackCanvas

Paste a public GitHub repo URL and get an interactive threat model (STRIDE, mapped to OWASP Top 10:2025 and CWE). See `CLAUDE.md` for the product description and engineering rules.

## Setup

```bash
pnpm install
cp .env.example .env.local   # fill in keys
pnpm dev
```

Scripts: `dev`, `build`, `lint`, `typecheck`, `test`, `try`.
