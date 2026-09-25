# Production image for hosts without Docker-in-Docker (e.g. Render).
# The GitHub MCP server binary is copied from the same pinned image the app uses
# locally (src/server/mcp/githubClient.ts IMAGE), so the tool surface is identical.
FROM ghcr.io/github/github-mcp-server:v1.12.2@sha256:508a0857ec762b1ab1cece29193345b501fab1dd9d1228a7b617062954cecac6 AS github-mcp

FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM node:22-bookworm-slim
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates \
  && pip3 install --no-cache-dir --break-system-packages semgrep==1.176.0 \
  && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN corepack enable
COPY --from=github-mcp /server/github-mcp-server /usr/local/bin/github-mcp-server
COPY --from=build /app ./
ENV NODE_ENV=production \
  GITHUB_MCP_BINARY=/usr/local/bin/github-mcp-server \
  HOSTNAME=0.0.0.0
EXPOSE 3000
CMD ["sh", "-c", "pnpm start -p ${PORT:-3000}"]
