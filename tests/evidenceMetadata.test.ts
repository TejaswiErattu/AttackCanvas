import { describe, expect, it } from "vitest";
import { z } from "zod";
import { normalizeSemgrep } from "@/server/scanners/semgrep";
import {
  scanDependencies,
  type OsvEvidenceMetadata,
} from "@/server/scanners/osv";
import type { RawSemgrepFinding } from "@/server/mcp/semgrepClient";
import {
  EvidenceMetadataSchema,
  EvidenceSchema,
  type EvidenceMetadata,
  OWASP_LABELS,
  Owasp2025Schema,
  ThreatModelSchema,
  validateThreatModel,
  type Evidence,
} from "@/shared/schema";
import demoJson from "../fixtures/demo-analysis.json";
import { BATCH_RESPONSE, VULNS } from "./osvResponses";

const BASE: Evidence = {
  id: "ev-semgrep-1",
  kind: "scanner",
  source: "semgrep",
  summary: "SQL is built by concatenating a value into the query string.",
  filePath: "src/db.js",
  lineStart: 9,
  lineEnd: 9,
  ruleId: "attackcanvas-sql-string-concat",
};

const ALL_CODES = Owasp2025Schema.options;

function finding(owasp: string[]): RawSemgrepFinding {
  return {
    ruleId: "rule.one",
    path: "src/a.js",
    startLine: 3,
    endLine: 3,
    message: "Something is wrong here.",
    severity: "error",
    cwe: [],
    owasp,
  };
}

describe("EvidenceSchema: metadata.owasp2025 is preserved by parse()", () => {
  it("keeps the mapped codes, which used to be stripped", () => {
    const input = { ...BASE, metadata: { owasp2025: ["A05:2025"] } };
    const parsed = EvidenceSchema.parse(input);

    expect(parsed).toEqual(input);
    expect(parsed.metadata?.owasp2025).toEqual(["A05:2025"]);
  });

  it.each(ALL_CODES)("accepts and keeps %s", (code) => {
    const parsed = EvidenceSchema.parse({
      ...BASE,
      metadata: { owasp2025: [code] },
    });
    expect(parsed.metadata?.owasp2025).toEqual([code]);
  });

  it("keeps several codes in the order given", () => {
    const parsed = EvidenceSchema.parse({
      ...BASE,
      metadata: { owasp2025: ["A01:2025", "A05:2025", "A07:2025"] },
    });
    expect(parsed.metadata?.owasp2025).toEqual([
      "A01:2025",
      "A05:2025",
      "A07:2025",
    ]);
  });

  it("accepts metadata with no codes, and an empty list", () => {
    expect(EvidenceSchema.parse({ ...BASE, metadata: {} }).metadata).toEqual(
      {},
    );
    expect(
      EvidenceSchema.parse({ ...BASE, metadata: { owasp2025: [] } }).metadata,
    ).toEqual({
      owasp2025: [],
    });
  });

  it("survives inside a whole ThreatModel, not only on its own", () => {
    const model = structuredClone(demoJson) as unknown as {
      evidence: Record<string, unknown>[];
    };
    model.evidence[0].metadata = { owasp2025: ["A01:2025", "A06:2025"] };

    const result = validateThreatModel(model);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.evidence[0].metadata?.owasp2025).toEqual([
        "A01:2025",
        "A06:2025",
      ]);
    }
  });

  it("is what normalizeSemgrep returns, unchanged by parsing", () => {
    const [evidence] = normalizeSemgrep([finding(["A03:2021 - Injection"])]);
    const parsed = EvidenceSchema.parse(evidence);

    expect(parsed).toEqual(evidence);
    expect(parsed.metadata).toEqual({ owasp2025: ["A05:2025"] });
  });
});

describe("EvidenceSchema: evidence without metadata is unchanged", () => {
  it("parses to exactly the same object, with no metadata key added", () => {
    const parsed = EvidenceSchema.parse(BASE);

    expect(parsed).toEqual(BASE);
    expect("metadata" in parsed).toBe(false);
  });

  it("still accepts the smallest valid evidence", () => {
    const minimal = {
      id: "ev-1",
      kind: "code",
      source: "detector",
      summary: "x",
    };
    expect(EvidenceSchema.parse(minimal)).toEqual(minimal);
  });

  it("parses every evidence item in the demo fixture unchanged", () => {
    const items = (demoJson as unknown as { evidence: unknown[] }).evidence;

    expect(items.length).toBeGreaterThan(0);
    for (const item of items) {
      const parsed = EvidenceSchema.parse(item);
      expect(parsed).toEqual(item);
      expect("metadata" in parsed).toBe(false);
    }
  });

  it("still validates the whole demo fixture as a ThreatModel", () => {
    expect(ThreatModelSchema.safeParse(demoJson).success).toBe(true);
    expect(validateThreatModel(demoJson).ok).toBe(true);
  });

  it("does not turn the model's output shape into something new", () => {
    const result = validateThreatModel(demoJson);
    expect(result.ok && JSON.stringify(result.data.evidence)).toBe(
      JSON.stringify((demoJson as unknown as { evidence: unknown[] }).evidence),
    );
  });
});

describe("EvidenceSchema: invalid OWASP codes are rejected", () => {
  const reject = (owasp2025: unknown) =>
    EvidenceSchema.safeParse({ ...BASE, metadata: { owasp2025 } });

  it.each([
    ["a code past A10", "A11:2025"],
    ["A00", "A00:2025"],
    ["a 2021 code", "A03:2021"],
    ["a 2017 code", "A03:2017"],
    ["a lowercase code", "a05:2025"],
    ["an unpadded code", "A5:2025"],
    ["a code with trailing text", "A05:2025 - Injection"],
    ["a code with a leading space", " A05:2025"],
    ["a category name", "Injection"],
    ["an empty string", ""],
  ])("rejects %s", (_label, code) => {
    expect(reject([code]).success).toBe(false);
  });

  it.each([
    ["a number", [5]],
    ["null", [null]],
    ["an object", [{ code: "A05:2025" }]],
  ])("rejects a list containing %s", (_label, list) => {
    expect(reject(list).success).toBe(false);
  });

  it("rejects one bad code among good ones, rather than dropping it", () => {
    expect(reject(["A05:2025", "A99:2025", "A07:2025"]).success).toBe(false);
  });

  it("rejects a bare string in place of a list", () => {
    expect(reject("A05:2025").success).toBe(false);
  });

  it.each([
    ["a string", "A05:2025"],
    ["a number", 5],
    ["null", null],
    ["an array", ["A05:2025"]],
  ])("rejects metadata that is %s", (_label, metadata) => {
    expect(EvidenceSchema.safeParse({ ...BASE, metadata }).success).toBe(false);
  });

  it("points at the offending field", () => {
    const result = reject(["A05:2025", "A99:2025"]);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0].path).toEqual(["metadata", "owasp2025", 1]);
    }
  });

  it("rejects an invalid code inside a whole ThreatModel", () => {
    const model = structuredClone(demoJson) as unknown as {
      evidence: Record<string, unknown>[];
    };
    model.evidence[0].metadata = { owasp2025: ["A03:2021"] };

    expect(validateThreatModel(model).ok).toBe(false);
  });
});

describe("EvidenceMetadataSchema is closed and strongly typed", () => {
  it("has exactly the eleven fields of the two supported groups", () => {
    expect(Object.keys(EvidenceMetadataSchema.shape)).toEqual([
      "owasp2025",
      "package",
      "version",
      "versionExact",
      "dev",
      "vulnId",
      "cve",
      "aliases",
      "severityScore",
      "severityLabel",
      "fixedVersion",
    ]);
  });
  it("does not carry a field it does not define", () => {
    const parsed = EvidenceSchema.parse({
      ...BASE,
      metadata: {
        owasp2025: ["A05:2025"],
        cwe: ["CWE-89"],
        anything: { at: "all" },
      },
    });

    expect(parsed.metadata).toEqual({ owasp2025: ["A05:2025"] });
  });

  it("is an enum in the generated JSON Schema, not an open string or any", () => {
    const json = z.toJSONSchema(EvidenceSchema) as unknown as {
      properties: {
        metadata: { properties: { owasp2025: { items: { enum?: string[] } } } };
      };
    };
    const allowed = json.properties.metadata.properties.owasp2025.items.enum;

    expect(allowed).toBeDefined();
    expect([...(allowed ?? [])].sort()).toEqual(
      Object.keys(OWASP_LABELS).sort(),
    );
  });

  it("accepts exactly the codes OWASP_LABELS has a name for", () => {
    expect([...ALL_CODES].sort()).toEqual(Object.keys(OWASP_LABELS).sort());
    for (const code of ALL_CODES) expect(OWASP_LABELS[code]).toBeTruthy();
  });
});

describe("every 2021 -> 2025 mapping, end to end through the schema", () => {
  // Written out here on purpose, independent of src/shared/owaspMap.ts, so a transposed
  // row in the table is caught even if a test built from the table would agree with it.
  it.each([
    ["A01:2021 - Broken Access Control", "A01:2025", "Broken Access Control"],
    ["A02:2021 - Cryptographic Failures", "A04:2025", "Cryptographic Failures"],
    ["A03:2021 - Injection", "A05:2025", "Injection"],
    ["A04:2021 - Insecure Design", "A06:2025", "Insecure Design"],
    [
      "A05:2021 - Security Misconfiguration",
      "A02:2025",
      "Security Misconfiguration",
    ],
    [
      "A06:2021 - Vulnerable and Outdated Components",
      "A03:2025",
      "Software Supply Chain Failures",
    ],
    [
      "A07:2021 - Identification and Authentication Failures",
      "A07:2025",
      "Authentication Failures",
    ],
    [
      "A08:2021 - Software and Data Integrity Failures",
      "A08:2025",
      "Software or Data Integrity Failures",
    ],
    [
      "A09:2021 - Security Logging and Monitoring Failures",
      "A09:2025",
      "Security Logging and Alerting Failures",
    ],
    [
      "A10:2021 - Server-Side Request Forgery (SSRF)",
      "A01:2025",
      "Broken Access Control",
    ],
  ])("%s becomes %s (%s)", (tag, expected, label) => {
    const [evidence] = normalizeSemgrep([finding([tag])]);
    const parsed = EvidenceSchema.parse(evidence);

    expect(parsed.metadata?.owasp2025).toEqual([expected]);
    expect(OWASP_LABELS[expected as keyof typeof OWASP_LABELS]).toBe(label);
  });

  it("never maps anything onto A10:2025, which has no 2021 counterpart", () => {
    const codes = [
      "A01:2021",
      "A02:2021",
      "A03:2021",
      "A04:2021",
      "A05:2021",
      "A06:2021",
      "A07:2021",
      "A08:2021",
      "A09:2021",
      "A10:2021",
    ].flatMap((code) => {
      const [evidence] = normalizeSemgrep([finding([code])]);
      return EvidenceSchema.parse(evidence).metadata?.owasp2025 ?? [];
    });

    expect(codes).not.toContain("A10:2025");
    expect(codes).toHaveLength(10);
  });
});

// ---------------------------------------------------------------------------
// OSV dependency metadata: all ten emitted fields
// ---------------------------------------------------------------------------

/** Serves the saved, real OSV responses. Nothing here touches the network. */
const savedOsv = (async (input: RequestInfo | URL) => {
  const url = String(input);
  if (url.endsWith("/v1/querybatch"))
    return new Response(JSON.stringify(BATCH_RESPONSE));
  const id = decodeURIComponent(url.split("/v1/vulns/")[1] ?? "");
  return new Response(JSON.stringify(VULNS[id] ?? {}), {
    status: VULNS[id] ? 200 : 404,
  });
}) as unknown as typeof fetch;

const MANIFEST = {
  path: "package.json",
  content: JSON.stringify({
    dependencies: { lodash: "^4.17.15", "left-pad": "1.3.0" },
    devDependencies: { minimist: "~1.2.0" },
  }),
};
const LOCKFILE = {
  path: "package-lock.json",
  content: JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "node_modules/lodash": { version: "4.17.15" },
      "node_modules/left-pad": { version: "1.3.0" },
      "node_modules/minimist": { version: "1.2.0" },
    },
  }),
};

async function osvEvidence(withLockfile: boolean) {
  const { evidence } = await scanDependencies(
    withLockfile ? [MANIFEST, LOCKFILE] : [MANIFEST],
    {
      fetch: savedOsv,
      cache: new Map(),
    },
  );
  return evidence;
}

/** A hand-made advisory (SYNTHETIC) for the optional-field cases the real data lacks. */
function synth(id: string, options: { label?: string; fixed?: string } = {}) {
  return {
    id,
    summary: "Problem in a",
    aliases: [],
    ...(options.label
      ? { database_specific: { severity: options.label } }
      : {}),
    affected: [
      {
        package: { name: "a", ecosystem: "npm" },
        ranges: [
          {
            type: "SEMVER",
            events: [
              { introduced: "0" },
              options.fixed
                ? { fixed: options.fixed }
                : { last_affected: "99.0.0" },
            ],
          },
        ],
      },
    ],
  };
}

/** Runs the scanner on one synthetic advisory and returns the one evidence item. */
async function scanSynthetic(vuln: ReturnType<typeof synth>) {
  const fetchFn = (async (input: RequestInfo | URL) =>
    String(input).endsWith("/v1/querybatch")
      ? new Response(
          JSON.stringify({ results: [{ vulns: [{ id: vuln.id }] }] }),
        )
      : new Response(JSON.stringify(vuln))) as unknown as typeof fetch;
  const manifest = {
    path: "package.json",
    content: JSON.stringify({ dependencies: { a: "1.0.0" } }),
  };
  const { evidence } = await scanDependencies([manifest], {
    fetch: fetchFn,
    cache: new Map(),
  });
  return evidence[0];
}

const ALL_TEN = [
  "package",
  "version",
  "versionExact",
  "dev",
  "vulnId",
  "cve",
  "aliases",
  "severityScore",
  "severityLabel",
  "fixedVersion",
] as const;

/** One complete OSV metadata object, as the scanner emits it for the lodash prototype-pollution advisory. */
const COMPLETE = {
  package: "lodash",
  version: "4.17.15",
  versionExact: true,
  dev: false,
  vulnId: "GHSA-p6mc-m468-83gw",
  cve: ["CVE-2020-8203"],
  aliases: ["CVE-2020-8203"],
  severityScore: 7.4,
  severityLabel: "HIGH",
  fixedVersion: "4.17.19",
} as const;

/** Only what is always present: no severity on the advisory and no fix listed. */
const MINIMAL = {
  package: "a",
  version: "1.0.0",
  versionExact: false,
  dev: true,
  vulnId: "X-1",
  cve: [],
  aliases: [],
} as const;

const REQUIRED = [
  "package",
  "version",
  "versionExact",
  "dev",
  "vulnId",
  "cve",
  "aliases",
] as const;
const OPTIONAL = ["severityScore", "severityLabel", "fixedVersion"] as const;

const metadataOf = (metadata: unknown) =>
  EvidenceSchema.safeParse({ ...BASE, metadata });
const without = <T extends object>(obj: T, key: string) =>
  Object.fromEntries(Object.entries(obj).filter(([k]) => k !== key));

describe("all ten emitted OSV metadata fields survive EvidenceSchema.parse() exactly", () => {
  it("returns every emitted field, with the same value, for every finding", async () => {
    const evidence = await osvEvidence(true);
    expect(evidence.length).toBeGreaterThan(0);

    for (const item of evidence) {
      const parsed = EvidenceSchema.parse(item);

      expect(parsed.metadata).toEqual(item.metadata);
      expect(Object.keys(parsed.metadata ?? {}).sort()).toEqual(
        Object.keys(item.metadata).sort(),
      );
    }
  });

  it("keeps each of the ten fields individually, by strict equality", async () => {
    const [item] = await osvEvidence(true);
    const parsed = EvidenceSchema.parse(item).metadata as Record<
      string,
      unknown
    >;
    const emitted = item.metadata as unknown as Record<string, unknown>;

    for (const field of ALL_TEN) {
      expect(parsed[field], field).toEqual(emitted[field]);
    }
  });

  it("emits all ten for a real finding, so the previous test is not vacuous", async () => {
    const proto = (await osvEvidence(true)).find(
      (e) => e.ruleId === "GHSA-p6mc-m468-83gw",
    );

    expect(Object.keys(proto?.metadata ?? {}).sort()).toEqual(
      [...ALL_TEN].sort(),
    );
    expect(proto?.metadata).toEqual(COMPLETE);
  });

  it("keeps the exact values for a known finding", async () => {
    const proto = (await osvEvidence(true)).find(
      (e) => e.ruleId === "GHSA-p6mc-m468-83gw",
    );
    expect(EvidenceSchema.parse(proto).metadata).toEqual(COMPLETE);
  });

  it("keeps dev true for a devDependency and false for a runtime one", async () => {
    const parsed = (await osvEvidence(true)).map(
      (e) => EvidenceSchema.parse(e).metadata,
    );

    expect(
      parsed
        .filter((m) => m?.package === "minimist")
        .every((m) => m?.dev === true),
    ).toBe(true);
    expect(
      parsed
        .filter((m) => m?.package === "lodash")
        .every((m) => m?.dev === false),
    ).toBe(true);
    expect(parsed.some((m) => m?.dev === true)).toBe(true);
    expect(parsed.some((m) => m?.dev === false)).toBe(true);
  });

  it("keeps vulnId, aliases, severityScore and severityLabel, which parse() used to strip", async () => {
    const proto = (await osvEvidence(true)).find(
      (e) => e.ruleId === "GHSA-p6mc-m468-83gw",
    );
    const kept = EvidenceSchema.parse(proto).metadata;

    expect(kept?.vulnId).toBe("GHSA-p6mc-m468-83gw");
    expect(kept?.aliases).toEqual(["CVE-2020-8203"]);
    expect(kept?.severityScore).toBe(7.4);
    expect(kept?.severityLabel).toBe("HIGH");
  });

  it("keeps aliases and cve in the advisory's own order, for a finding with several aliases", async () => {
    // GHSA-r5fr lists three aliases (two CVEs and another GHSA), so order is observable.
    const item = (await osvEvidence(true)).find(
      (e) => e.metadata.aliases.length > 1,
    );
    expect(item).toBeDefined();

    const record = VULNS[item?.ruleId ?? ""] as { aliases: string[] };
    const parsed = EvidenceSchema.parse(item).metadata;

    expect(item?.metadata.aliases).toEqual(record.aliases); // emitted in the record's order
    expect(parsed?.aliases).toEqual(record.aliases); // and kept in that order
    expect(parsed?.cve).toEqual(
      record.aliases.filter((a) => /^CVE-\d{4}-\d+$/.test(a)),
    );
    expect((parsed?.aliases ?? []).length).toBeGreaterThan(1);
  });

  it("keeps versionExact true for a lockfile version and false for one inferred from a range", async () => {
    for (const item of await osvEvidence(true)) {
      expect(EvidenceSchema.parse(item).metadata?.versionExact).toBe(true);
    }
    for (const item of await osvEvidence(false)) {
      expect(EvidenceSchema.parse(item).metadata?.versionExact).toBe(false);
    }
  });

  it("is schema-valid straight from the scanner, for every item", async () => {
    for (const item of await osvEvidence(true)) {
      expect(EvidenceSchema.safeParse(item).success).toBe(true);
    }
  });

  it("agrees with the scanner's own type: all ten fields are assignable to the schema's", () => {
    // Compile-time check, enforced by tsc: a mismatch in name or type fails typecheck.
    const asSchema = (metadata: OsvEvidenceMetadata): EvidenceMetadata =>
      metadata;

    expect(asSchema({ ...MINIMAL, cve: [], aliases: [] })).toEqual(MINIMAL);
    expect(
      asSchema({
        ...COMPLETE,
        cve: [...COMPLETE.cve],
        aliases: [...COMPLETE.aliases],
      }),
    ).toBeDefined();
  });
});

describe("optional OSV fields: severityScore, severityLabel and fixedVersion", () => {
  it("parses with none of them present, and does not add any", () => {
    const parsed = EvidenceSchema.parse({ ...BASE, metadata: MINIMAL });

    expect(parsed.metadata).toEqual(MINIMAL);
    for (const field of OPTIONAL)
      expect(field in (parsed.metadata ?? {})).toBe(false);
  });

  it.each(OPTIONAL)("parses with only %s missing", (missing) => {
    const parsed = EvidenceSchema.parse({
      ...BASE,
      metadata: without(COMPLETE, missing),
    });

    expect(missing in (parsed.metadata ?? {})).toBe(false);
    expect(parsed.metadata).toEqual(without(COMPLETE, missing));
  });

  it.each(OPTIONAL)("parses with only %s present", (present) => {
    const metadata = { ...MINIMAL, [present]: COMPLETE[present] };
    expect(EvidenceSchema.parse({ ...BASE, metadata }).metadata).toEqual(
      metadata,
    );
  });

  it("matches what the scanner emits for an advisory with no severity and no fix", async () => {
    const item = await scanSynthetic(synth("NO-1")); // last_affected only, no severity of any kind

    expect(item.metadata).not.toHaveProperty("severityScore");
    expect(item.metadata).not.toHaveProperty("severityLabel");
    expect(item.metadata).not.toHaveProperty("fixedVersion");
    expect(EvidenceSchema.parse(item).metadata).toEqual(item.metadata);
  });

  it("matches what the scanner emits for a label with no score", async () => {
    const item = await scanSynthetic(
      synth("LB-1", { label: "MODERATE", fixed: "2.0.0" }),
    );

    expect(item.metadata).toMatchObject({
      severityLabel: "MEDIUM",
      fixedVersion: "2.0.0",
    });
    expect(item.metadata).not.toHaveProperty("severityScore");
    expect(EvidenceSchema.parse(item).metadata).toEqual(item.metadata);
  });

  it("accepts a zero score and every valid label", () => {
    expect(metadataOf({ ...MINIMAL, severityScore: 0 }).success).toBe(true);
    for (const label of ["LOW", "MEDIUM", "HIGH", "CRITICAL"]) {
      expect(metadataOf({ ...MINIMAL, severityLabel: label }).success).toBe(
        true,
      );
    }
  });
});

describe("invalid severity and OSV field values are rejected", () => {
  it.each([
    ["a lowercase label", "high"],
    ["MODERATE (GitHub's word; the scanner maps it to MEDIUM)", "MODERATE"],
    ["INFO", "INFO"],
    ["NONE", "NONE"],
    ["an empty label", ""],
    ["a label with a space", "HIGH "],
    ["a number", 3],
    ["null", null],
  ])("rejects a severityLabel of %s", (_label, value) => {
    expect(metadataOf({ ...COMPLETE, severityLabel: value }).success).toBe(
      false,
    );
  });

  it.each([
    ["negative", -0.1],
    ["minus one", -1],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["a numeric string", "7.4"],
    ["null", null],
    ["an object", {}],
  ])("rejects a severityScore that is %s", (_label, value) => {
    expect(metadataOf({ ...COMPLETE, severityScore: value }).success).toBe(
      false,
    );
  });

  it("accepts a finite non-negative score, and does not cap it at 10 (as specified)", () => {
    for (const score of [0, 0.1, 5.3, 7.4, 10, 100]) {
      expect(metadataOf({ ...COMPLETE, severityScore: score }).success).toBe(
        true,
      );
    }
  });

  it.each([
    ["a string dev", { dev: "false" }],
    ["a numeric dev", { dev: 0 }],
    ["a null dev", { dev: null }],
    ["an empty vulnId", { vulnId: "" }],
    ["a numeric vulnId", { vulnId: 7 }],
    ["aliases that is not an array", { aliases: "CVE-2020-8203" }],
    ["an empty alias", { aliases: ["CVE-2020-8203", ""] }],
    ["a non-string alias", { aliases: [5] }],
    ["an empty package", { package: "" }],
    ["an empty version", { version: "" }],
    ["a string versionExact", { versionExact: "true" }],
    ["a malformed cve id", { cve: ["not-a-cve"] }],
    ["a GHSA id in cve", { cve: ["GHSA-p6mc-m468-83gw"] }],
    ["an empty fixedVersion", { fixedVersion: "" }],
  ])("rejects %s", (_label, change) => {
    expect(metadataOf({ ...COMPLETE, ...change }).success).toBe(false);
  });

  it("accepts the complete form, so the rejections above are about the field, not the shape", () => {
    expect(metadataOf(COMPLETE).success).toBe(true);
  });

  it("accepts aliases beyond CVE ids, since aliases is every alias and cve is only the CVEs", () => {
    const metadata = {
      ...COMPLETE,
      aliases: ["CVE-2021-23337", "GHSA-r5fr-rjxr-66jc"],
      cve: ["CVE-2021-23337"],
    };
    expect(EvidenceSchema.parse({ ...BASE, metadata }).metadata).toEqual(
      metadata,
    );
  });
});

describe("incomplete OSV metadata is rejected", () => {
  it.each(REQUIRED)(
    "rejects complete metadata with %s removed, and points at it",
    (missing) => {
      const result = metadataOf(without(COMPLETE, missing));

      expect(result.success).toBe(false);
      if (!result.success) {
        const paths = result.error.issues.map((i) => i.path.join("."));
        expect(paths).toContain(`metadata.${missing}`);
        expect(
          result.error.issues.find(
            (i) => i.path.join(".") === `metadata.${missing}`,
          )?.message,
        ).toContain("required whenever any OSV dependency field is present");
      }
    },
  );

  it.each([...REQUIRED, ...OPTIONAL])(
    "rejects %s on its own, as an OSV fragment",
    (field) => {
      const result = metadataOf({ [field]: COMPLETE[field] });

      expect(result.success).toBe(false);
      if (!result.success) {
        // every required field other than the one given is reported
        const reported = result.error.issues.map((i) => i.path[1]);
        for (const required of REQUIRED.filter((f) => f !== field))
          expect(reported).toContain(required);
      }
    },
  );

  it("rejects the optional fields on their own, without the identity fields", () => {
    expect(
      metadataOf({ severityScore: 7.4, severityLabel: "HIGH" }).success,
    ).toBe(false);
    expect(metadataOf({ fixedVersion: "4.17.19" }).success).toBe(false);
    expect(
      metadataOf({ cve: ["CVE-2020-8203"], fixedVersion: "4.17.19" }).success,
    ).toBe(false);
  });

  it("rejects the old five-field form, which lacks dev and vulnId", () => {
    expect(
      metadataOf({
        package: "a",
        version: "1.0.0",
        versionExact: true,
        cve: [],
        fixedVersion: "2.0.0",
      }).success,
    ).toBe(false);
  });

  it("rejects an OSV fragment even when a valid OWASP group is present beside it", () => {
    expect(
      metadataOf({ owasp2025: ["A05:2025"], package: "lodash" }).success,
    ).toBe(false);
  });

  it("reports every missing required field, not just the first", () => {
    const result = metadataOf({ package: "a" });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.map((i) => i.path[1]).sort()).toEqual(
        ["aliases", "cve", "dev", "vulnId", "version", "versionExact"].sort(),
      );
    }
  });

  it("accepts each optional field being absent from otherwise complete metadata", () => {
    for (const field of OPTIONAL)
      expect(metadataOf(without(COMPLETE, field)).success).toBe(true);
  });

  it("is not triggered by an empty object, by OWASP alone, or by unknown keys alone", () => {
    expect(metadataOf({}).success).toBe(true);
    expect(metadataOf({ owasp2025: ["A05:2025"] }).success).toBe(true);
    expect(metadataOf({ bogus: 1 }).success).toBe(true);
  });

  it("also rejects incomplete OSV metadata inside a whole ThreatModel", () => {
    const model = structuredClone(demoJson) as unknown as {
      evidence: Record<string, unknown>[];
    };
    model.evidence[0].metadata = { package: "lodash", version: "4.17.15" };

    expect(validateThreatModel(model).ok).toBe(false);
  });
});

describe("Semgrep and OSV metadata together and apart", () => {
  const BOTH = { owasp2025: ["A03:2025", "A06:2025"], ...COMPLETE };

  it("parses evidence carrying both a Semgrep group and complete OSV metadata", () => {
    const result = metadataOf(BOTH);

    expect(result.success).toBe(true);
    if (result.success) expect(result.data.metadata).toEqual(BOTH);
  });

  it("still works with Semgrep metadata alone", () => {
    const parsed = EvidenceSchema.parse({
      ...BASE,
      metadata: { owasp2025: ["A05:2025"] },
    });
    expect(parsed.metadata).toEqual({ owasp2025: ["A05:2025"] });
  });

  it("still works with complete OSV metadata alone", () => {
    expect(
      EvidenceSchema.parse({ ...BASE, metadata: COMPLETE }).metadata,
    ).toEqual(COMPLETE);
  });

  it("survives inside a whole ThreatModel, in each of the three forms", () => {
    const model = structuredClone(demoJson) as unknown as {
      evidence: Record<string, unknown>[];
    };
    model.evidence[0].metadata = BOTH;
    model.evidence[1].metadata = { owasp2025: ["A05:2025"] };
    model.evidence[2].metadata = COMPLETE;

    const result = validateThreatModel(model);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.evidence[0].metadata).toEqual(BOTH);
      expect(result.data.evidence[1].metadata).toEqual({
        owasp2025: ["A05:2025"],
      });
      expect(result.data.evidence[2].metadata).toEqual(COMPLETE);
    }
  });

  it("rejects the combination when either group is invalid", () => {
    expect(metadataOf({ ...BOTH, owasp2025: ["A03:2021"] }).success).toBe(
      false,
    );
    expect(metadataOf({ ...BOTH, severityLabel: "SEVERE" }).success).toBe(
      false,
    );
    expect(metadataOf({ ...BOTH, vulnId: "" }).success).toBe(false);
  });
});

describe("unknown metadata keys are STRIPPED, not rejected", () => {
  it("drops an unknown key and keeps the known ones", () => {
    const result = metadataOf({
      owasp2025: ["A05:2025"],
      bogus: 1,
      nested: { a: 1 },
    });

    expect(result.success).toBe(true);
    if (result.success)
      expect(result.data.metadata).toEqual({ owasp2025: ["A05:2025"] });
  });

  it("keeps all ten OSV fields and drops an unknown one beside them", () => {
    const result = metadataOf({
      ...COMPLETE,
      cwe: ["CWE-89"],
      extra: { at: "all" },
    });

    expect(result.success).toBe(true);
    if (result.success) expect(result.data.metadata).toEqual(COMPLETE);
  });

  it("reduces metadata holding only unknown keys to an empty object", () => {
    expect(
      EvidenceSchema.parse({ ...BASE, metadata: { unknown: true } }).metadata,
    ).toEqual({});
  });

  it("does not pass an unknown key through, whatever its type", () => {
    for (const extra of [1, "x", null, [1], { a: 1 }, true]) {
      const parsed = EvidenceSchema.parse({
        ...BASE,
        metadata: { owasp2025: [], extra },
      });
      expect("extra" in (parsed.metadata ?? {})).toBe(false);
    }
  });

  it("does not let an unknown key stand in for a missing required OSV field", () => {
    expect(
      metadataOf({ ...without(COMPLETE, "vulnId"), vulnid: "GHSA-x" }).success,
    ).toBe(false);
  });
});
