// Child process for tests/mcpShutdownSignal.test.ts. Opens a real stdio connection to a
// fake server, prints "ready", then waits for a signal from the parent.
//   argv: <serverMarkerFile> <otherHandlerFile | "-">
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { createStdioConnection } from "@/server/mcp/base";

const [serverMarker, otherFile] = process.argv.slice(2);
const server = join(__dirname, "server.mjs");

if (otherFile && otherFile !== "-") {
  // Another module's handler: must survive, run once, and here it decides to exit.
  process.on("SIGTERM", () => {
    appendFileSync(otherFile, "x");
    setTimeout(() => process.exit(0), 500);
  });
}

const connection = createStdioConnection({
  command: process.execPath,
  args: [server, serverMarker],
  clientName: "shutdown-test",
  clientVersion: "0",
  errors: {
    tool: (code, message) => Object.assign(new Error(message), { code }),
    config: (message) => new Error(message),
    unclassified: "AI_FAILURE",
  },
  isTyped: () => false,
  isConfigError: () => false,
  startFailureContext: "shutdown-test",
});

void connection.getClient().then(() => {
  process.stdout.write("ready\n");
  setInterval(() => {}, 1000);
});
