import { z } from "zod";
import {
  EvidenceKindSchema,
  EvidenceSourceSchema,
  Owasp2025Schema,
  zId,
} from "./enums";

/** The pattern the OSV scanner filters aliases with, so a stored CVE id is always this shape. */
const CVE_ID = /^CVE-\d{4}-\d+$/;

/**
 * The fields the OSV scanner always emits for a dependency finding. Complete OSV metadata
 * has all of them; see the coherence rule below.
 */
const OSV_REQUIRED = [
  "package",
  "version",
  "versionExact",
  "dev",
  "vulnId",
  "cve",
  "aliases",
] as const;

/** OSV fields that are legitimately absent: no score or label on the advisory, or no fix listed. */
const OSV_OPTIONAL = [
  "severityScore",
  "severityLabel",
  "fixedVersion",
] as const;

/**
 * Structured facts a scanner attaches to a piece of evidence, for the analysis prompt
 * to use. Deliberately a closed, typed object rather than a free-form record: a field
 * that is not listed here is stripped by parse(), and adding one is a contract change
 * that should be made on purpose.
 *
 * Two independent groups, either or both of which may be present:
 *   - OWASP, from Semgrep: `owasp2025`;
 *   - dependency, from OSV: ten fields, seven always present and three optional. Once
 *     any of them appears, all seven required ones must, so an OSV fragment cannot be
 *     stored without saying which dependency and which advisory it describes.
 */
export const EvidenceMetadataSchema = z
  .object({
    /**
     * OWASP Top 10:2025 categories this evidence maps to. Scanners tag rules with 2021
     * codes, which src/shared/owaspMap.ts converts, so only 2025 codes are stored here.
     * Display names are in OWASP_LABELS.
     */
    owasp2025: z.array(Owasp2025Schema).optional(),

    /** npm package name a dependency finding is about. */
    package: z.string().min(1).optional(),
    /** The version that was checked: exact from a lockfile, else a range's minimum. */
    version: z.string().min(1).optional(),
    /** False when `version` was inferred from a semver range rather than a lockfile. */
    versionExact: z.boolean().optional(),
    /** True when the dependency is declared under devDependencies. */
    dev: z.boolean().optional(),
    /** The OSV advisory id, e.g. "GHSA-p6mc-m468-83gw". */
    vulnId: z.string().min(1).optional(),
    /** CVE aliases of the advisory. May be empty when it has none. */
    cve: z.array(z.string().regex(CVE_ID)).optional(),
    /** Every alias of the advisory (CVE, GHSA, ...). May be empty. */
    aliases: z.array(z.string().min(1)).optional(),
    /**
     * The scanner's own base score, used only to order findings. Finite and
     * non-negative; zod rejects NaN and Infinity for z.number(). AttackCanvas severity is
     * computed in scoring and never taken from here (CLAUDE.md rule 2).
     */
    severityScore: z.number().min(0).optional(),
    severityLabel: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
    /** The first applicable fixed version. Absent when no fix is listed. */
    fixedVersion: z.string().min(1).optional(),
  })
  .superRefine((metadata, ctx) => {
    const anyOsv = [...OSV_REQUIRED, ...OSV_OPTIONAL].some(
      (key) => metadata[key] !== undefined,
    );
    if (!anyOsv) return;

    for (const key of OSV_REQUIRED) {
      if (metadata[key] === undefined) {
        ctx.addIssue({
          code: "custom",
          message: `${key} is required whenever any OSV dependency field is present`,
          path: [key],
        });
      }
    }
  });
export type EvidenceMetadata = z.infer<typeof EvidenceMetadataSchema>;

/**
 * A single citation backing a component, flow or threat. Snippets are repository
 * content and therefore untrusted data (CLAUDE.md rule 3).
 */
export const EvidenceSchema = z.object({
  id: zId,
  kind: EvidenceKindSchema,
  source: EvidenceSourceSchema,
  summary: z.string().min(1),
  filePath: z.string().min(1).optional(),
  lineStart: z.number().int().min(1).optional(),
  lineEnd: z.number().int().min(1).optional(),
  snippet: z.string().optional(),
  /** Scanner rule that produced this, e.g. a Semgrep rule id or an OSV id. */
  ruleId: z.string().min(1).optional(),
  url: z.url().optional(),
  metadata: EvidenceMetadataSchema.optional(),
});
export type Evidence = z.infer<typeof EvidenceSchema>;
