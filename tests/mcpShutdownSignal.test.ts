import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

/**
 * SIGTERM shutdown in a real child process. Signals cannot be tested in-process without
 * signalling the test runner, so the child runs the real createStdioConnection against a
 * fake stdio MCP server and this file only reads what it left behind.
 */

const CHILD = join(process.cwd(), "tests/fixtures/mcpShutdown/child.ts");

let dir: string;
afterEach(() => rmSync(dir, { recursive: true, force: true }));

type Outcome = { code: number | null; signal: NodeJS.Signals | null; closed: boolean };

async function runChild(withOtherHandler: boolean): Promise<{ outcome: Outcome; other: string }> {
  dir = mkdtempSync(join(tmpdir(), "mcp-shutdown-"));
  const serverMarker = join(dir, "server-closed");
  const otherFile = join(dir, "other-handler");

  const child = spawn(process.execPath, ["--import", "tsx", CHILD, serverMarker, withOtherHandler ? otherFile : "-"], {
    cwd: process.cwd(),
    stdio: ["ignore", "pipe", "inherit"],
  });

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("child never became ready")), 20_000);
    child.stdout.on("data", (chunk: Buffer) => {
      if (chunk.toString().includes("ready")) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.once("exit", () => reject(new Error("child exited before ready")));
  });

  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
    child.once("exit", (code, signal) => resolve({ code, signal })),
  );
  const guard = setTimeout(() => child.kill("SIGKILL"), 10_000);
  child.kill("SIGTERM");
  const { code, signal } = await exited;
  clearTimeout(guard);

  return {
    outcome: { code, signal, closed: existsSync(serverMarker) },
    other: existsSync(otherFile) ? readFileSync(otherFile, "utf8") : "",
  };
}

describe("SIGTERM shutdown of an open connection", () => {
  it("closes the connection and terminates by the signal when nothing else listens", async () => {
    const { outcome } = await runChild(false);

    expect(outcome.closed).toBe(true);
    // Terminated by SIGTERM itself: the re-raise restored the default action, and it was
    // not swallowed (which would be SIGKILL from the guard) or handled in a loop.
    expect(outcome.signal).toBe("SIGTERM");
  }, 40_000);

  it("leaves another SIGTERM handler in place and does not invoke it twice", async () => {
    const { outcome, other } = await runChild(true);

    expect(outcome.closed).toBe(true);
    expect(other).toBe("x"); // ran, and exactly once
    expect(outcome).toMatchObject({ code: 0, signal: null }); // its own exit, not a kill
  }, 40_000);
});
