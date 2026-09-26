/**
 * categorizeProviderError: a safe allowlisted category for a rejected provider request.
 * The provider's message is matched against and never returned.
 */

import { describe, expect, it } from "vitest";
import {
  PROVIDER_ERROR_CATEGORIES,
  categorizeProviderError,
} from "@/server/ai/providerError";

describe("categorizeProviderError", () => {
  it.each([
    ["Your credit balance is too low to access the Anthropic API.", "credit_balance_low"],
    ["You have reached your specified workspace API usage limits.", "usage_limit_reached"],
    ["prompt is too long: 250000 tokens > 200000 maximum", "prompt_too_long"],
    ["max_tokens: 40000 > 32000, which is the maximum allowed", "max_tokens_invalid"],
    ["The request body is not valid JSON: no low surrogate in string", "invalid_json_body"],
    ["messages.0.content.0.text: text content blocks must be non-empty", "empty_content"],
    ["output_config.format.schema: schema is too complex", "schema_rejected"],
    ["model: claude-nope does not exist", "model_unavailable"],
  ] as const)("400 %s -> %s", (message, category) => {
    expect(categorizeProviderError(400, message)).toBe(category);
  });

  it("matches case-insensitively", () => {
    expect(categorizeProviderError(400, "CREDIT BALANCE IS TOO LOW")).toBe("credit_balance_low");
  });

  it("labels a 400 it does not recognise, or cannot read, unknown", () => {
    expect(categorizeProviderError(400, "something entirely new happened")).toBe("unknown");
    expect(categorizeProviderError(400, "")).toBe("unknown");
    expect(categorizeProviderError(400, undefined)).toBe("unknown");
    expect(categorizeProviderError(400, { message: "credit balance is too low" })).toBe("unknown");
  });

  it("uses the status alone for the status-only causes, whatever the message", () => {
    expect(categorizeProviderError(401, "x")).toBe("authentication");
    expect(categorizeProviderError(403, "x")).toBe("permission");
    expect(categorizeProviderError(404, "x")).toBe("not_found");
    expect(categorizeProviderError(413, "x")).toBe("request_too_large");
  });

  it("does not read the message of a non-400 status", () => {
    expect(categorizeProviderError(422, "credit balance is too low")).toBe("unknown");
  });

  it("categorises only 4xx", () => {
    expect(categorizeProviderError(500, "credit balance is too low")).toBe("unknown");
    expect(categorizeProviderError(undefined, "credit balance is too low")).toBe("unknown");
  });

  it("only ever returns a value from the allowlist, never any of the message", () => {
    const hostile = `${"a".repeat(5000)} credit balance is too low sk-ant-api03-SECRET <repo_file path="x">`;
    for (const status of [400, 401, 403, 404, 413, 418]) {
      const result = categorizeProviderError(status, hostile);
      expect(PROVIDER_ERROR_CATEGORIES).toContain(result);
      expect(result).not.toContain("SECRET");
    }
  });

  it("scans only the start of a very long message", () => {
    expect(categorizeProviderError(400, `${"x".repeat(3000)} credit balance is too low`)).toBe("unknown");
  });

  it("has unknown in the allowlist", () => {
    expect(PROVIDER_ERROR_CATEGORIES).toContain("unknown");
  });
});
