/**
 * Prompt U, Part 2: src/server/log.ts.
 *
 * Offline: console is spied, never actually printed to the test runner's own stdout.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { log, stripAuthorization } from "@/server/log";
import { SecretLeakError } from "@/server/security/redactor";

let logSpy: ReturnType<typeof vi.spyOn>;
let errorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  logSpy.mockRestore();
  errorSpy.mockRestore();
});

// ---------------------------------------------------------------------------
// stripAuthorization
// ---------------------------------------------------------------------------

describe("stripAuthorization", () => {
  it("removes a top-level authorization key, case-insensitively", () => {
    expect(stripAuthorization({ Authorization: "Bearer x", other: "keep" })).toEqual({
      other: "keep",
    });
    expect(stripAuthorization({ AUTHORIZATION: "Bearer x" })).toEqual({});
    expect(stripAuthorization({ authorization: "Bearer x" })).toEqual({});
  });

  it("removes authorization nested under a headers object", () => {
    const result = stripAuthorization({
      headers: { authorization: "Bearer x", "content-type": "application/json" },
    });
    expect(result).toEqual({ headers: { "content-type": "application/json" } });
  });

  it("removes authorization from a Headers instance passed directly", () => {
    const headers = new Headers({
      Authorization: "Bearer x",
      "X-Forwarded-For": "1.2.3.4",
    });
    const result = stripAuthorization({ headers });
    expect(result).toEqual({ headers: { "x-forwarded-for": "1.2.3.4" } });
  });

  it("leaves fields with no authorization untouched", () => {
    const fields = { analysisId: "abc-123", stage: "loading_repo" };
    expect(stripAuthorization(fields)).toEqual(fields);
  });

  it("does not mutate the input object", () => {
    const fields = { authorization: "Bearer x", keep: "yes" };
    const result = stripAuthorization(fields);
    expect(fields).toEqual({ authorization: "Bearer x", keep: "yes" }); // unchanged
    expect(result).toEqual({ keep: "yes" });
  });
});

// ---------------------------------------------------------------------------
// log
// ---------------------------------------------------------------------------

describe("log", () => {
  it("writes info/debug to console.log and warn/error to console.error", () => {
    log("info", "hello");
    log("debug", "hello");
    expect(logSpy).toHaveBeenCalledTimes(2);
    expect(errorSpy).not.toHaveBeenCalled();

    log("warn", "careful");
    log("error", "broken");
    expect(errorSpy).toHaveBeenCalledTimes(2);
  });

  it("writes one JSON line containing the level, message, fields and a timestamp", () => {
    log("info", "analysis started", { analysisId: "job-1", stage: "queued" });

    expect(logSpy).toHaveBeenCalledTimes(1);
    const line = logSpy.mock.calls[0][0] as string;
    const parsed = JSON.parse(line);
    expect(parsed).toMatchObject({
      level: "info",
      message: "analysis started",
      analysisId: "job-1",
      stage: "queued",
    });
    expect(typeof parsed.timestamp).toBe("string");
    expect(new Date(parsed.timestamp).toString()).not.toBe("Invalid Date");
  });

  it("strips an Authorization header before the line is ever built", () => {
    log("info", "request received", {
      headers: { authorization: "Bearer super-secret-token-value", "x-request-id": "r1" },
    });

    const line = logSpy.mock.calls[0][0] as string;
    expect(line).not.toContain("super-secret-token-value");
    expect(line).not.toMatch(/authorization/i);
    expect(JSON.parse(line).headers).toEqual({ "x-request-id": "r1" });
  });

  it("throws SecretLeakError and writes nothing when a field is secret-shaped", () => {
    expect(() =>
      log("info", "config loaded", { note: 'apiKey = "sk-ant-abcdefghijklmnopqrstuvwx"' }),
    ).toThrow(SecretLeakError);
    expect(logSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("does not false-positive on ordinary JSON-shaped fields (ids, paths, messages)", () => {
    // Guards the guard: if this ever throws, the whole helper is unusable for routine
    // logging, since analysis ids, file paths and human messages are exactly what a
    // real caller logs. Relies on assertNoSecrets' high_entropy rule requiring a
    // source-style `key = "value"` assignment, which log()'s JSON.stringify output
    // (`"key":"value"`) never produces (see redactor.ts's own comment on that rule).
    expect(() =>
      log("info", "loaded repository", {
        analysisId: "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        repoPath: "src/server/analysis/pipeline.ts",
        commitSha: "8d16ba17fbb6141d3c9c583521b569f2ca83541e",
      }),
    ).not.toThrow();
    expect(logSpy).toHaveBeenCalledTimes(1);
  });

  it("redacts authorization even when a secret ALSO appears elsewhere, still throwing for the secret", () => {
    // The two guards are independent: stripping headers does not exempt the line from
    // assertNoSecrets, and a thrown secret does not mean the header strip was skipped.
    // Uses a vendor-shaped pattern (github_token) rather than a keyword-plus-quote
    // assignment: JSON.stringify escapes the quotes around a `key = "value"` secret,
    // which changes the exact character sequence generic_secret/high_entropy match on
    // (proven directly against assertNoSecrets while writing this test) -- a
    // vendor-prefix pattern like `ghp_...` has no such quote dependency.
    expect(() =>
      log("info", "double trouble", {
        headers: { authorization: "Bearer x" },
        note: "found token ghp_abcdefghijklmnopqrstuvwxyz0123456789 in a comment",
      }),
    ).toThrow(SecretLeakError);

    // Nothing reached either stream: the throw happens before the write, so a partially
    // cleaned line is never emitted "just because most of it was safe".
    expect(logSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it.each(["debug", "info", "warn", "error"] as const)(
    "writes nothing on ANY level when the line is secret-bearing: %s",
    (level) => {
      // warn/error take the console.error branch, so the "assert before write" ordering
      // has to hold on both write paths, not just the stdout one.
      expect(() =>
        log(level, "leaky", { note: "ghp_abcdefghijklmnopqrstuvwxyz0123456789" }),
      ).toThrow(SecretLeakError);
      expect(logSpy).not.toHaveBeenCalled();
      expect(errorSpy).not.toHaveBeenCalled();
    },
  );

  it("strips Authorization from a Headers instance at error level too, and still writes", () => {
    const headers = new Headers({ Authorization: "Bearer another-secret-value" });
    log("error", "upstream rejected us", { headers, status: 401 });

    expect(errorSpy).toHaveBeenCalledTimes(1);
    const line = errorSpy.mock.calls[0][0] as string;
    expect(line).not.toContain("another-secret-value");
    expect(line).not.toMatch(/authorization/i);
    expect(JSON.parse(line)).toMatchObject({ level: "error", status: 401 });
  });

  it("strips Authorization passed at the top level AND nested under headers in one call", () => {
    log("info", "both shapes", {
      Authorization: "Bearer top-level-secret",
      headers: { AUTHORIZATION: "Bearer nested-secret" },
      keep: "visible",
    });

    const line = logSpy.mock.calls[0][0] as string;
    expect(line).not.toContain("top-level-secret");
    expect(line).not.toContain("nested-secret");
    expect(line).not.toMatch(/authorization/i);
    expect(JSON.parse(line).keep).toBe("visible");
  });
});

// ---------------------------------------------------------------------------
// Strings are checked as the caller passed them, before JSON escapes their quotes
// ---------------------------------------------------------------------------

describe("log: secrets that JSON escaping used to hide", () => {
  it.each([
    ["a top-level field", { causeMessage: 'bad config: password = "hunter2hunter2"' }],
    ["a nested field", { diagnostic: { cause: { message: 'db_password: "hunter2hunter2"' } } }],
    ["an array item", { issues: ["ok", 'const token = "hunter2hunter2";'] }],
    ["an object key", { ['password = "hunter2hunter2"']: 1 }],
  ])("throws on a double-quoted keyword secret in %s, and writes nothing", (_label, fields) => {
    expect(() => log("error", "analysis failed", fields)).toThrow(SecretLeakError);
    expect(logSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("throws on a double-quoted keyword secret in the message itself", () => {
    expect(() => log("error", 'failed: secret = "hunter2hunter2"')).toThrow(SecretLeakError);
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("still writes ordinary nested diagnostics, and survives a cycle", () => {
    const cyclic: Record<string, unknown> = { stage: "scanning" };
    cyclic.self = cyclic;
    expect(() =>
      log("info", "stage", { detail: { stage: "scanning", files: ["src/a.ts", "src/b.ts"] } }),
    ).not.toThrow();
    expect(logSpy).toHaveBeenCalledTimes(1);
    // The walk terminates on a cycle; JSON.stringify then rejects it as before.
    expect(() => log("info", "cyclic", { cyclic })).toThrow(TypeError);
  });
});
