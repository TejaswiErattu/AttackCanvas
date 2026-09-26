/**
 * A safe category for a provider request the API rejected with a 4xx.
 *
 * The provider's error message can quote the request (prompt, repository text, workspace
 * id), so it is never logged or stored. But without it a 400 is undiagnosable: a request
 * that is malformed and one refused for account reasons look the same. This module reads the
 * message only to match it against a fixed allowlist of known causes and returns one of the
 * ProviderErrorCategory values, which are constants. Whatever does not match is "unknown".
 * The message itself never leaves this function (CLAUDE.md rules 3 and 8).
 *
 * The patterns are the wording the API is documented and observed to use, so a rewording
 * degrades to "unknown", never to a wrong or leaky answer. Status-only causes (401, 403,
 * 404, 413) need no message at all.
 */

export const PROVIDER_ERROR_CATEGORIES = [
  "credit_balance_low",
  "usage_limit_reached",
  "prompt_too_long",
  "max_tokens_invalid",
  "invalid_json_body",
  "empty_content",
  "schema_rejected",
  "model_unavailable",
  "authentication",
  "permission",
  "not_found",
  "request_too_large",
  "unknown",
] as const;

export type ProviderErrorCategory = (typeof PROVIDER_ERROR_CATEGORIES)[number];

/** Only the start of a message is scanned, so a hostile or huge one costs nothing. */
const SCAN_CHARS = 2_000;

/** In priority order: the first pattern that matches decides. */
const MESSAGE_PATTERNS: readonly (readonly [RegExp, ProviderErrorCategory])[] = [
  [/credit balance is too low/i, "credit_balance_low"],
  [/usage limits?|spend(ing)? limit|reached your (specified )?(workspace )?(api )?(usage )?limit/i, "usage_limit_reached"],
  [/prompt is too long|exceeds? the (maximum|context)|context (window|length)/i, "prompt_too_long"],
  [/max_tokens/i, "max_tokens_invalid"],
  [/not valid json|no low surrogate|invalid json|could not parse the json/i, "invalid_json_body"],
  [/non-empty|must not be empty|cannot be empty/i, "empty_content"],
  [/output_config|json_schema|output format|schema/i, "schema_rejected"],
  [/model[^.]{0,80}(not found|does not exist|not available)|invalid model|unknown model/i, "model_unavailable"],
];

const STATUS_CATEGORIES: Readonly<Record<number, ProviderErrorCategory>> = {
  401: "authentication",
  403: "permission",
  404: "not_found",
  413: "request_too_large",
};

/**
 * @param status  the HTTP status; only 4xx are categorised, anything else is "unknown"
 * @param message the provider's message, read for matching only and never returned
 */
export function categorizeProviderError(
  status: number | undefined,
  message: unknown,
): ProviderErrorCategory {
  if (status === undefined || status < 400 || status > 499) return "unknown";
  if (status !== 400) return STATUS_CATEGORIES[status] ?? "unknown";
  if (typeof message !== "string") return "unknown";
  const scanned = message.slice(0, SCAN_CHARS);
  for (const [pattern, category] of MESSAGE_PATTERNS) {
    if (pattern.test(scanned)) return category;
  }
  return "unknown";
}
