import { describe, expect, it } from "vitest";
import {
  ENTROPY_THRESHOLD,
  RULE_TYPES,
  isEnvReference,
  SecretLeakError,
  assertNoSecrets,
  assertNoSecretsInPrompt,
  isConfigFilePath,
  isKnownNonSecret,
  isLockfilePath,
  mergeSpans,
  redact,
  redactionPlaceholder,
  shannonEntropy,
  toEvidence,
  type SecretType,
  type Span,
} from "@/server/security/redactor";
import { EvidenceSchema } from "@/shared/schema";

/**
 * Every credential below is fabricated. AKIAIOSFODNN7EXAMPLE and the JWT are the
 * vendors' own published examples, which is why they are safe to commit.
 */
const SAMPLES: { type: SecretType; code: string; secret: string }[] = [
  {
    type: "aws_access_key",
    code: 'const id = "AKIAIOSFODNN7EXAMPLE";',
    secret: "AKIAIOSFODNN7EXAMPLE",
  },
  {
    type: "aws_access_key",
    code: 'const id = "ASIAIOSFODNN7EXAMPLE";',
    secret: "ASIAIOSFODNN7EXAMPLE",
  },
  {
    type: "github_token",
    code: 'const t = "ghp_0123456789abcdefghijABCDEFGHIJ012345";',
    secret: "ghp_0123456789abcdefghijABCDEFGHIJ012345",
  },
  {
    type: "github_token",
    code: 'const t = "ghs_0123456789abcdefghijABCDEFGHIJ012345";',
    secret: "ghs_0123456789abcdefghijABCDEFGHIJ012345",
  },
  {
    type: "github_token",
    code: `const t = "github_pat_${"0123456789".repeat(5)}abcde";`,
    secret: `github_pat_${"0123456789".repeat(5)}abcde`,
  },
  {
    type: "stripe_key",
    code: 'const k = "sk_live_0123456789abcdefghij";',
    secret: "sk_live_0123456789abcdefghij",
  },
  {
    type: "stripe_key",
    code: 'const k = "rk_test_0123456789abcdefghij";',
    secret: "rk_test_0123456789abcdefghij",
  },
  {
    type: "anthropic_key",
    code: 'const k = "sk-ant-api03-0123456789abcdefghijklmn";',
    secret: "sk-ant-api03-0123456789abcdefghijklmn",
  },
  {
    type: "openai_key",
    code: 'const k = "sk-0123456789abcdefghijklmn";',
    secret: "sk-0123456789abcdefghijklmn",
  },
  {
    type: "openai_key",
    code: 'const k = "sk-proj-0123456789abcdefghijklmn";',
    secret: "sk-proj-0123456789abcdefghijklmn",
  },
  {
    type: "slack_token",
    code: 'const t = "xoxb-0123456789-abcdefghij";',
    secret: "xoxb-0123456789-abcdefghij",
  },
  {
    type: "google_api_key",
    code: `const k = "AIza${"0123456789".repeat(3)}abcde";`,
    secret: `AIza${"0123456789".repeat(3)}abcde`,
  },
  {
    type: "jwt",
    code:
      'const t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.' +
      'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";',
    secret:
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  },
  {
    type: "connection_string",
    code: 'const url = "postgres://admin:hunter2pass@db.example.com:5432/app";',
    secret: "admin:hunter2pass",
  },
  {
    type: "generic_secret",
    code: 'const JWT_SECRET = "supersecret123";',
    secret: "supersecret123",
  },
  {
    type: "high_entropy",
    code: 'const seed = "Gx7pQ2vZ9mK4wR6tY8jL3nB5";',
    secret: "Gx7pQ2vZ9mK4wR6tY8jL3nB5",
  },
];

const PRIVATE_KEY = [
  "-----BEGIN RSA PRIVATE KEY-----",
  "MIIEowIBAAKCAQEAx7Qm9vK2pLn4TzR8bW1cVfHgY6sD0eJkQpAoZtXuNrMlIyBc",
  "3FhGdEwSvUaPqOiJkLmNbVcXzZaQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpA",
  "-----END RSA PRIVATE KEY-----",
].join("\n");

describe("redact: every pattern", () => {
  it.each(SAMPLES)("redacts $type", ({ type, code, secret }) => {
    const { content, findings } = redact(code, "src/config.ts");

    expect(content).not.toContain(secret);
    expect(content).toContain(redactionPlaceholder(type));
    expect(findings).toEqual([{ type, line: 1 }]);
  });

  it("covers every rule", () => {
    expect(new Set(SAMPLES.map((s) => s.type))).toEqual(
      new Set(RULE_TYPES.filter((t) => t !== "private_key")),
    );
  });

  it("redacts a whole private key block", () => {
    const code = `const KEY = \`\n${PRIVATE_KEY}\n\`;\n`;
    const { content, findings } = redact(code, "src/keys.ts");

    expect(content).not.toContain("MIIEowIBAAKCAQEA");
    expect(content).not.toContain("BEGIN RSA PRIVATE KEY");
    expect(content).toContain(redactionPlaceholder("private_key"));
    expect(findings).toEqual([{ type: "private_key", line: 2 }]);
  });

  it.each(["RSA", "EC", "OPENSSH", "PGP", ""])(
    "redacts a %s private key block",
    (kind) => {
      const label = kind ? `${kind} PRIVATE KEY` : "PRIVATE KEY";
      const block = `-----BEGIN ${label}-----\nMIIEowIBAAKC\n-----END ${label}-----`;
      const { findings } = redact(block, "k.pem");

      expect(findings).toEqual([{ type: "private_key", line: 1 }]);
    },
  );
});

describe("redact: replacement keeps the code readable", () => {
  it("keeps the variable name", () => {
    const { content } = redact('const JWT_SECRET = "supersecret123";', "a.ts");
    expect(content).toBe('const JWT_SECRET = "[REDACTED:generic_secret]";');
  });

  it("keeps the scheme and host of a connection string", () => {
    const { content } = redact(
      'const url = "postgres://admin:hunter2pass@db.example.com:5432/app";',
      "a.ts",
    );
    expect(content).toBe(
      'const url = "postgres://[REDACTED:connection_string]@db.example.com:5432/app";',
    );
  });

  it("leaves a URL with no credentials alone", () => {
    const code = 'const url = "https://api.example.com/v1/users";';
    expect(redact(code, "a.ts").content).toBe(code);
  });

  it("leaves content with no secrets untouched", () => {
    const code =
      "export function add(a: number, b: number) {\n  return a + b;\n}\n";
    expect(redact(code, "a.ts")).toEqual({ content: code, findings: [] });
  });

  it("redacts several secrets in one file, reporting each line", () => {
    const code = [
      'const a = "AKIAIOSFODNN7EXAMPLE";',
      "const ok = 1;",
      'const PASSWORD = "hunter2pass";',
      'const c = "xoxb-0123456789-abcdefghij";',
    ].join("\n");
    const { content, findings } = redact(code, "a.ts");

    expect(findings).toEqual([
      { type: "aws_access_key", line: 1 },
      { type: "generic_secret", line: 3 },
      { type: "slack_token", line: 4 },
    ]);
    expect(content).toContain("const ok = 1;");
  });

  it("is idempotent", () => {
    const code = SAMPLES.map((s) => s.code).join("\n");
    const once = redact(code, "a.ts");
    const twice = redact(once.content, "a.ts");

    expect(twice.content).toBe(once.content);
    expect(twice.findings).toEqual([]);
  });
});

describe("redact: overlapping rules", () => {
  it("labels an Anthropic key as anthropic_key, not openai_key", () => {
    const { findings } = redact(
      'const k = "sk-ant-api03-0123456789abcdefghijklmn";',
      "a.ts",
    );
    expect(findings).toEqual([{ type: "anthropic_key", line: 1 }]);
  });

  it("prefers the specific type when a vendor key sits in a secret assignment", () => {
    const { content, findings } = redact(
      'const API_KEY = "AKIAIOSFODNN7EXAMPLE";',
      "a.ts",
    );

    expect(findings).toEqual([{ type: "aws_access_key", line: 1 }]);
    expect(content).toBe('const API_KEY = "[REDACTED:aws_access_key]";');
  });

  it("keeps the wider coverage when a specific match covers only part of a value", () => {
    // The AWS key is precise but partial; the rest of the value is still a secret.
    const { content } = redact(
      'const PASSWORD = "hunter2pass AKIAIOSFODNN7EXAMPLE";',
      "a.ts",
    );

    expect(content).not.toContain("hunter2pass");
    expect(content).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(content).toBe('const PASSWORD = "[REDACTED:aws_access_key]";');
  });

  it("does not label a base64 body inside a key block as something else", () => {
    const { findings } = redact(PRIVATE_KEY, "k.pem");
    expect(findings.map((f) => f.type)).toEqual(["private_key"]);
  });
});

describe("redact: what must not be redacted", () => {
  it("leaves a UUID alone", () => {
    const code = 'const requestId = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";';
    expect(redact(code, "src/a.ts")).toEqual({ content: code, findings: [] });
  });

  it("leaves a sha256 hex digest alone", () => {
    const code =
      'const checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";';
    expect(redact(code, "src/a.ts")).toEqual({ content: code, findings: [] });
  });

  it("leaves package-lock integrity strings alone", () => {
    const code = [
      "{",
      '  "node_modules/express": {',
      '    "version": "4.18.2",',
      '    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",',
      '    "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ=="',
      "  }",
      "}",
    ].join("\n");

    expect(redact(code, "package-lock.json")).toEqual({
      content: code,
      findings: [],
    });
  });

  it("leaves base64 image data alone", () => {
    const code =
      'const logo = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";';
    expect(redact(code, "src/a.ts")).toEqual({ content: code, findings: [] });
  });

  it.each([
    // Deliberately not hex, so this rests on the entropy threshold and not on the
    // hex exclusion. "aaaa..." would be excluded as hex before entropy is consulted.
    'const label = "xxxxxxxxxx-yyyyyyyyyy-zzz";',
    'const banner = "welcome welcome welcome welcome";',
    'const sep = "----------------------------";',
  ])("leaves the long low-entropy string in %s alone", (code) => {
    expect(redact(code, "src/a.ts")).toEqual({ content: code, findings: [] });
  });

  it("redacts a high-entropy value just over the threshold but not one under it", () => {
    const low = 'const a = "xxxxxxxxxx-yyyyyyyyyy-zzz";';
    const high = 'const a = "Gx7pQ2vZ9mK4wR6tY8jL3nB5";';

    expect(redact(low, "a.ts").findings).toEqual([]);
    expect(redact(high, "a.ts").findings).toEqual([
      { type: "high_entropy", line: 1 },
    ]);
  });

  it("leaves an env-var reference alone: there is no literal to leak", () => {
    const code = "const JWT_SECRET = process.env.JWT_SECRET;";
    expect(redact(code, "src/a.ts")).toEqual({ content: code, findings: [] });
  });

  it("redacts a short value under a credential key, since a real password can be short", () => {
    const { content, findings } = redact('const password = "abc";', "src/a.ts");
    expect(content).toBe('const password = "[REDACTED:generic_secret]";');
    expect(findings).toEqual([{ type: "generic_secret", line: 1 }]);
  });

  it("leaves an equality check alone", () => {
    const code = 'if (token === "abcdefghijkl") return;';
    expect(redact(code, "src/a.ts")).toEqual({ content: code, findings: [] });
  });

  it("leaves lockfile hashes alone", () => {
    const code = [
      "express@4.18.2:",
      '  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#3fabe08296e930c796c19e3c516979386ba9fd59"',
      "  integrity sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ==",
    ].join("\n");

    expect(redact(code, "yarn.lock").findings).toEqual([]);
  });
});

describe("shannonEntropy", () => {
  it("is 0 for an empty string and for one repeated character", () => {
    expect(shannonEntropy("")).toBe(0);
    expect(shannonEntropy("aaaaaaaa")).toBe(0);
  });

  it("is 1 bit for two equally frequent characters", () => {
    expect(shannonEntropy("abab")).toBeCloseTo(1, 10);
  });

  it("is log2(n) for n distinct characters", () => {
    expect(shannonEntropy("abcd")).toBeCloseTo(2, 10);
  });

  it("puts hex below the threshold and mixed-case base64 above it", () => {
    const hex =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(shannonEntropy(hex)).toBeLessThan(ENTROPY_THRESHOLD);
    expect(shannonEntropy("Gx7pQ2vZ9mK4wR6tY8jL3nB5")).toBeGreaterThan(
      ENTROPY_THRESHOLD,
    );
  });
});

describe("isKnownNonSecret and isLockfilePath", () => {
  it.each([
    ["3f2504e0-4f89-11d3-9a0c-0305e82c3301", "id"],
    ["sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJf", "x"],
    ["data:image/png;base64,iVBORw0KGgoAAA", "logo"],
    ["https://registry.npmjs.org/express/-/express-4.18.2.tgz", "url"],
    ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4", "x"],
  ])("excludes %s", (value, key) => {
    expect(isKnownNonSecret(value, key, "src/a.ts")).toBe(true);
  });

  it.each(["integrity", "resolved", "checksum", "digest", "hash", "etag"])(
    "excludes anything under the key %s",
    (key) => {
      expect(
        isKnownNonSecret("Gx7pQ2vZ9mK4wR6tY8jL3nB5", key, "src/a.ts"),
      ).toBe(true);
    },
  );

  it("does not exclude a plain high-entropy value", () => {
    expect(
      isKnownNonSecret("Gx7pQ2vZ9mK4wR6tY8jL3nB5", "seed", "src/a.ts"),
    ).toBe(false);
  });

  it.each([
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "apps/web/package-lock.json",
  ])("treats %s as a lockfile", (path) => {
    expect(isLockfilePath(path)).toBe(true);
  });

  it("does not treat ordinary source as a lockfile", () => {
    expect(isLockfilePath("src/lock.ts")).toBe(false);
  });
});

describe("assertNoSecrets", () => {
  it("throws on a planted key", () => {
    const text = 'Here is the config:\nconst id = "AKIAIOSFODNN7EXAMPLE";';
    expect(() => assertNoSecrets(text)).toThrow(SecretLeakError);
  });

  it.each(SAMPLES)("throws on a planted $type", ({ code }) => {
    expect(() => assertNoSecrets(code)).toThrow(SecretLeakError);
  });

  it("reports the type and line, and never the secret", () => {
    const text = 'line one\nconst id = "AKIAIOSFODNN7EXAMPLE";';

    try {
      assertNoSecrets(text);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(SecretLeakError);
      const leak = error as SecretLeakError;

      expect(leak.findings).toEqual([{ type: "aws_access_key", line: 2 }]);
      expect(leak.message).toContain("aws_access_key");
      expect(leak.message).toContain("line 2");
      expect(leak.message).not.toContain("AKIAIOSFODNN7EXAMPLE");
    }
  });

  it("passes on clean text", () => {
    expect(() =>
      assertNoSecrets("const total = price * quantity;"),
    ).not.toThrow();
  });

  it("passes on anything redact() returns", () => {
    const code = [...SAMPLES.map((s) => s.code), PRIVATE_KEY].join("\n");
    const { content } = redact(code, "src/config.ts");

    expect(() => assertNoSecrets(content)).not.toThrow();
  });
});

describe("toEvidence", () => {
  const findings = [
    { type: "aws_access_key" as const, line: 12 },
    { type: "generic_secret" as const, line: 40 },
  ];

  it("builds code/detector evidence with the file and line, and no snippet", () => {
    const [first] = toEvidence("src/config.ts", findings);

    expect(first).toEqual({
      id: "secret-aws-access-key-12-1",
      kind: "code",
      source: "detector",
      summary:
        "Hardcoded credential of type aws_access_key committed in source",
      filePath: "src/config.ts",
      lineStart: 12,
    });
    expect(first).not.toHaveProperty("snippet");
  });

  it("never carries a snippet, for any finding", () => {
    for (const evidence of toEvidence("a.ts", findings)) {
      expect(evidence.snippet).toBeUndefined();
    }
  });

  it("satisfies the Evidence contract, including the kebab-case id", () => {
    const all = toEvidence(
      "src/config.ts",
      RULE_TYPES.map((type, index) => ({ type, line: index + 1 })),
    );

    for (const evidence of all) {
      expect(EvidenceSchema.safeParse(evidence).success).toBe(true);
    }
  });

  it("gives each finding a unique id, even on the same line", () => {
    const all = toEvidence("a.ts", [
      { type: "aws_access_key", line: 3 },
      { type: "aws_access_key", line: 3 },
    ]);

    expect(new Set(all.map((e) => e.id)).size).toBe(2);
  });

  it("returns nothing for no findings", () => {
    expect(toEvidence("a.ts", [])).toEqual([]);
  });

  it("round-trips from redact", () => {
    const { findings: found } = redact(
      'const JWT_SECRET = "supersecret123";',
      "a.ts",
    );
    const [evidence] = toEvidence("src/a.ts", found);

    expect(evidence.summary).toBe(
      "Hardcoded credential of type generic_secret committed in source",
    );
    expect(evidence.lineStart).toBe(1);
  });
});

describe("mergeSpans", () => {
  const span = (start: number, end: number, type: SecretType): Span => ({
    start,
    end,
    type,
  });

  it("returns nothing for no spans", () => {
    expect(mergeSpans([])).toEqual([]);
  });

  it("leaves disjoint spans alone, in order", () => {
    expect(
      mergeSpans([span(10, 20, "jwt"), span(0, 5, "aws_access_key")]),
    ).toEqual([span(0, 5, "aws_access_key"), span(10, 20, "jwt")]);
  });

  it("widens to the union when spans overlap only partly", () => {
    // The lower-priority span ends later: its extra coverage must survive, or the
    // tail of it would be left unredacted.
    expect(
      mergeSpans([
        span(0, 10, "aws_access_key"),
        span(5, 30, "generic_secret"),
      ]),
    ).toEqual([span(0, 30, "aws_access_key")]);
  });

  it("keeps the union when the wider span comes first", () => {
    expect(
      mergeSpans([
        span(0, 30, "generic_secret"),
        span(5, 10, "aws_access_key"),
      ]),
    ).toEqual([span(0, 30, "aws_access_key")]);
  });

  it("takes the highest-priority type across a whole merged run", () => {
    const merged = mergeSpans([
      span(0, 10, "high_entropy"),
      span(8, 20, "aws_access_key"),
      span(18, 30, "generic_secret"),
    ]);

    expect(merged).toEqual([span(0, 30, "aws_access_key")]);
  });

  it("does not merge spans that only touch at the edge", () => {
    expect(mergeSpans([span(0, 10, "jwt"), span(10, 20, "jwt")])).toHaveLength(
      2,
    );
  });
});

describe("pathological input", () => {
  /**
   * The loader hands over files of up to 200 KB of untrusted repository content
   * (CLAUDE.md rule 3), so every rule has to stay linear in the size of the file.
   * connection_string was once quadratic and took ~20 s on the first case here.
   * The budget is deliberately loose: it is there to catch quadratic blow-up, not to
   * measure milliseconds on a shared CI box.
   */
  const BUDGET_MS = 2_000;
  const SIZE = 200_000;

  it.each([
    ["one long run of letters", 'const token = "' + "A".repeat(SIZE) + '";'],
    ["repeated scheme separators", "a://".repeat(SIZE / 4)],
    ["repeated colons", "a:b".repeat(SIZE / 3)],
    ["one long quoted value", 'const x = "' + "Ab3-".repeat(SIZE / 4) + '";'],
    ["many short assignments", 'const a = "value-here";\n'.repeat(SIZE / 23)],
    [
      "an unterminated key block",
      "-----BEGIN RSA PRIVATE KEY-----\n" + "A".repeat(SIZE),
    ],
  ])("redacts %s well inside the budget", (_label, text) => {
    const started = performance.now();
    redact(text, "src/big.ts");

    expect(performance.now() - started).toBeLessThan(BUDGET_MS);
  });

  it("still finds a credential buried at the end of a large file", () => {
    const text =
      "const ok = 1;\n".repeat(10_000) + 'const id = "AKIAIOSFODNN7EXAMPLE";';
    const { findings } = redact(text, "src/big.ts");

    expect(findings).toEqual([{ type: "aws_access_key", line: 10_001 }]);
  });
});

describe("connection_string edge cases", () => {
  it.each([
    ["postgres://u:p@h", "postgres"],
    ["mongodb+srv://u:p@h", "mongodb+srv"],
    ["redis://u:p@h", "redis"],
    ["amqp://u:p@h", "amqp"],
  ])("handles the scheme in %s", (url, scheme) => {
    const { content, findings } = redact(`const u = "${url}";`, "a.ts");

    expect(findings).toEqual([{ type: "connection_string", line: 1 }]);
    expect(content).toContain(`${scheme}://[REDACTED:connection_string]@h`);
  });

  it("does not match a scheme that starts mid-word", () => {
    const code = 'const note = "see xhttps://example.com for docs";';
    expect(redact(code, "a.ts").findings).toEqual([]);
  });

  it("leaves a user with no password alone", () => {
    const code = 'const u = "ssh://git@github.com/owner/repo.git";';
    expect(redact(code, "a.ts")).toEqual({ content: code, findings: [] });
  });
});

describe("high_entropy: assignment with = only", () => {
  /**
   * Found by the detector tests: JSON.stringify wraps every string as "key":"value",
   * and the rule used to accept ":" as an assignment operator, so ordinary English in
   * a JSON property tripped it. This summary has entropy 4.23 against the 4.2
   * threshold, which is deliberately not raised.
   */
  const PROSE = "GET /api/proxy/* handled here (next_app)";

  it("sits above the threshold, so only the assignment shape keeps it safe", () => {
    expect(shannonEntropy(PROSE)).toBeGreaterThan(ENTROPY_THRESHOLD);
    expect(ENTROPY_THRESHOLD).toBe(4.2);
  });

  it("does not throw on a JSON property holding ordinary prose", () => {
    expect(() =>
      assertNoSecrets(JSON.stringify({ summary: PROSE })),
    ).not.toThrow();
  });

  it("does not throw on a whole evidence-shaped payload", () => {
    const payload = JSON.stringify({
      evidence: [
        {
          id: "ev-route-1",
          summary: PROSE,
          filePath: "app/api/proxy/route.js",
        },
        {
          id: "ev-auth-1",
          summary: "POST /api/users has no authentication middleware",
        },
        { id: "ev-deploy-1", summary: "Deployment (compose): api, ports 3000" },
      ],
    });

    expect(() => assertNoSecrets(payload)).not.toThrow();
    expect(redact(payload, "payload.json")).toEqual({
      content: payload,
      findings: [],
    });
  });

  it("does not flag a high-entropy value in a JSON property, by design", () => {
    // The trade this change makes, stated rather than hidden: a random-looking string
    // that is not a known key shape and has no secret-ish name is no longer caught in
    // a ":" position. Vendor patterns and generic_secret still cover the real cases.
    const json = JSON.stringify({ seed: "Gx7pQ2vZ9mK4wR6tY8jL3nB5" });
    expect(redact(json, "a.json").findings).toEqual([]);
  });

  it.each([
    ["const", 'const seed = "Gx7pQ2vZ9mK4wR6tY8jL3nB5";'],
    ["a bare assignment", 'seed = "Gx7pQ2vZ9mK4wR6tY8jL3nB5"'],
    ["export const", 'export const seed = "Gx7pQ2vZ9mK4wR6tY8jL3nB5";'],
    ["let", "let seed = 'Gx7pQ2vZ9mK4wR6tY8jL3nB5';"],
    ["a template literal", "const seed = `Gx7pQ2vZ9mK4wR6tY8jL3nB5`;"],
    ["a property assignment", 'config.seed = "Gx7pQ2vZ9mK4wR6tY8jL3nB5";'],
    ["no spaces around =", 'seed="Gx7pQ2vZ9mK4wR6tY8jL3nB5"'],
    ["a Python assignment", 'SEED = "Gx7pQ2vZ9mK4wR6tY8jL3nB5"'],
  ])(
    "still detects a genuine high-entropy value assigned with = (%s)",
    (_l, code) => {
      const { content, findings } = redact(code, "src/a.ts");

      expect(findings).toEqual([{ type: "high_entropy", line: 1 }]);
      expect(content).not.toContain("Gx7pQ2vZ9mK4wR6tY8jL3nB5");
      expect(() => assertNoSecrets(code)).toThrow(SecretLeakError);
    },
  );

  it("does not treat ==, === or => as an assignment", () => {
    for (const code of [
      'if (seed == "Gx7pQ2vZ9mK4wR6tY8jL3nB5") {}',
      'if (seed === "Gx7pQ2vZ9mK4wR6tY8jL3nB5") {}',
      'if (seed !== "Gx7pQ2vZ9mK4wR6tY8jL3nB5") {}',
      'const f = seed => "Gx7pQ2vZ9mK4wR6tY8jL3nB5";',
    ]) {
      expect(redact(code, "a.ts").findings).toEqual([]);
    }
  });

  it("still flags prose assigned with =, a known limitation the threshold keeps", () => {
    // Not fixed by this change, and stated so nobody assumes otherwise. The
    // requirement is a quoted string assigned to a variable with entropy over 4.2,
    // and this sentence clears 4.2 (4.23). Only the ":" case was a false positive
    // against the requirement; this one matches it.
    const { content, findings } = redact(`const summary = "${PROSE}";`, "a.ts");

    expect(findings).toEqual([{ type: "high_entropy", line: 1 }]);
    expect(content).toBe('const summary = "[REDACTED:high_entropy]";');
  });
});

describe("secrets inside JSON are still found", () => {
  const VENDOR: [string, string][] = [
    ["aws_access_key", "AKIAIOSFODNN7EXAMPLE"],
    ["github_token", "ghp_0123456789abcdefghijABCDEFGHIJ012345"],
    ["stripe_key", "sk_live_0123456789abcdefghij"],
    ["anthropic_key", "sk-ant-api03-0123456789abcdefghijklmn"],
    ["openai_key", "sk-proj-0123456789abcdefghijklmn"],
    ["slack_token", "xoxb-0123456789-abcdefghij"],
    ["google_api_key", `AIza${"0123456789".repeat(3)}abcde`],
    [
      "jwt",
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    ],
  ];

  it.each(VENDOR)("finds %s in a JSON property", (type, secret) => {
    const json = JSON.stringify({ value: secret });
    const { content, findings } = redact(json, "config.json");

    expect(findings.map((f) => f.type)).toEqual([type]);
    expect(content).not.toContain(secret);
    expect(() => assertNoSecrets(json)).toThrow(SecretLeakError);
  });

  it("finds a connection string in a JSON property", () => {
    const json = JSON.stringify({
      url: "postgres://admin:hunter2pass@db.internal:5432/app",
    });
    const { content, findings } = redact(json, "config.json");

    expect(findings.map((f) => f.type)).toEqual(["connection_string"]);
    expect(content).not.toContain("hunter2pass");
    expect(content).toContain("@db.internal:5432/app");
  });

  it("finds a private key block in a JSON property", () => {
    const json = JSON.stringify({ key: PRIVATE_KEY });
    const { content, findings } = redact(json, "config.json");

    expect(findings.map((f) => f.type)).toEqual(["private_key"]);
    expect(content).not.toContain("MIIEowIBAAKCAQEA");
  });

  it.each([
    ["password", "supersecret123"],
    ["secret", "supersecret123"],
    ["token", "abcd1234efgh5678"],
    ["api_key", "abcd1234efgh5678"],
    ["apiKey", "abcd1234efgh5678"],
    ["client_secret", "abcd1234efgh5678"],
    ["private_key", "abcd1234efgh5678"],
    ["dbPassword", "supersecret123"],
  ])("finds generic_secret under the JSON key %s", (key, value) => {
    const json = JSON.stringify({ [key]: value });
    const { content, findings } = redact(json, "config.json");

    expect(findings).toEqual([{ type: "generic_secret", line: 1 }]);
    expect(content).not.toContain(value);
    expect(content).toContain(`"${key}"`);
    expect(() => assertNoSecrets(json)).toThrow(SecretLeakError);
  });

  it("finds generic_secret in pretty-printed JSON, with the right line", () => {
    const json = JSON.stringify(
      { name: "app", db: { password: "supersecret123" } },
      null,
      2,
    );
    const { findings } = redact(json, "config.json");

    expect(findings).toEqual([{ type: "generic_secret", line: 4 }]);
  });

  it("finds a secret sitting beside harmless prose in the same JSON", () => {
    const json = JSON.stringify({
      summary: "GET /api/proxy/* handled here (next_app)",
      password: "supersecret123",
    });
    const { content, findings } = redact(json, "config.json");

    expect(findings.map((f) => f.type)).toEqual(["generic_secret"]);
    expect(content).toContain("handled here (next_app)");
    expect(content).not.toContain("supersecret123");
  });

  it("redacts a short value under a credential key in JSON too", () => {
    const json = JSON.stringify({ password: "abc" });
    expect(redact(json, "config.json").findings).toEqual([{ type: "generic_secret", line: 1 }]);
  });
});

// ---------------------------------------------------------------------------
// Credential keys: any length, any common syntax
// ---------------------------------------------------------------------------

/** Made-up values. Not credentials: they exist only so a test can look for them. */
const SHORT = "Zq7Kp1"; // 6 characters: the length the sample password had
const LONG = "sentinel-signing-key-0042"; // 25 characters
const MARKER = redactionPlaceholder("generic_secret");

/** Every key the redactor must treat as a credential key, in the casings a codebase uses. */
const KEYS = [
  "password", "PASSWORD", "Password", "DB_PASSWORD", "dbPassword",
  "passwd", "PASSWD",
  "pwd", "PWD",
  "secret", "SECRET", "Secret",
  "token", "TOKEN", "accessToken",
  "apiKey", "APIKEY", "api_key", "API_KEY", "api-key",
  "clientSecret", "client_secret", "CLIENT_SECRET",
  "privateKey", "private_key", "PRIVATE_KEY",
  "jwtSecret", "jwt_secret", "JWT_SECRET",
];

describe("credential keys", () => {
  it.each(KEYS)("redacts a short and a long value under %s", (key) => {
    for (const value of [SHORT, LONG]) {
      const { content, findings } = redact(`const cfg = { ${key}: "${value}" };`, "src/a.js");
      expect(content).toBe(`const cfg = { ${key}: "${MARKER}" };`);
      expect(findings).toEqual([{ type: "generic_secret", line: 1 }]);
    }
  });

  it("covers the value lengths on both sides of the eight-character floor", () => {
    for (const length of [1, 2, 6, 7, 8, 9, 20]) {
      const value = "Zq7Kp1Xw".repeat(4).slice(0, length);
      const { content } = redact(`password = "${value}";`, "src/a.js");
      expect(content, `length ${length}`).toBe(`password = "${MARKER}";`);
    }
  });
});

describe("credential syntax", () => {
  const FORMS: [string, string][] = [
    ['PASSWORD: "V"', `PASSWORD: "${MARKER}"`],
    ['password = "V"', `password = "${MARKER}"`],
    ["secret: 'V'", `secret: '${MARKER}'`],
    ["apiKey=`V`", `apiKey=\`${MARKER}\``],
    ['"client_secret": "V"', `"client_secret": "${MARKER}"`],
    ["'private_key': 'V'", `'private_key': '${MARKER}'`],
    ['"jwtSecret" : "V"', `"jwtSecret" : "${MARKER}"`],
    ['const token = `V`;', `const token = \`${MARKER}\`;`],
    ['this.pwd = "V";', `this.pwd = "${MARKER}";`],
    ['config.db.password = "V"', `config.db.password = "${MARKER}"`],
    ['let JWT_SECRET: string = "V";', `let JWT_SECRET: string = "${MARKER}";`],
    ['const apiKey: string = "V";', `const apiKey: string = "${MARKER}";`],
  ];

  it.each(FORMS)("redacts the value and keeps the syntax: %s", (code, expected) => {
    for (const value of [SHORT, LONG]) {
      const { content, findings } = redact(code.replaceAll("V", value), "src/a.ts");
      expect(content).toBe(expected);
      expect(content).not.toContain(value);
      expect(findings.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("redacts the fallback literal after an environment reference, and keeps the reference", () => {
    for (const op of ["||", "??"]) {
      const code = `const jwtSecret = process.env.JWT_SECRET ${op} "${SHORT}";`;
      const { content } = redact(code, "src/a.js");
      expect(content).toBe(`const jwtSecret = process.env.JWT_SECRET ${op} "${MARKER}";`);
    }
    expect(redact(`const password = cfg.get("x") || '${SHORT}';`, "a.js").content).not.toContain(SHORT);
    expect(redact(`secret: config["k"] ?? "${SHORT}"`, "a.js").content).not.toContain(SHORT);
  });

  it("redacts the exact structural shape of the sample database config", () => {
    const code = [
      "module.exports = {",
      '  HOST: "localhost",',
      '  USER: "root",',
      `  PASSWORD: "${SHORT}",`,
      '  DB: "testdb",',
      '  dialect: "mysql",',
      "  pool: {",
      "    max: 5,",
      "    idle: 10000",
      "  }",
      "};",
    ].join("\n");
    const { content, findings } = redact(code, "app/config/db.config.js");
    expect(findings).toEqual([{ type: "generic_secret", line: 4 }]);
    expect(content).toBe(code.replace(`"${SHORT}"`, `"${MARKER}"`));
    // Everything that is architecture survives.
    for (const kept of ['HOST: "localhost"', 'USER: "root"', 'DB: "testdb"', 'dialect: "mysql"', "max: 5"]) {
      expect(content).toContain(kept);
    }
  });

  it("redacts the exact structural shape of the sample auth config", () => {
    const code = `module.exports = {\n  secret: "${LONG}"\n};`;
    const { content, findings } = redact(code, "app/config/auth.config.js");
    expect(findings).toEqual([{ type: "generic_secret", line: 2 }]);
    expect(content).toBe(`module.exports = {\n  secret: "${MARKER}"\n};`);
  });

  it("finds credentials in nested objects, each on its own line", () => {
    const code = JSON.stringify(
      { db: { password: SHORT, host: "localhost" }, auth: { jwt_secret: LONG } },
      null,
      2,
    );
    const { content, findings } = redact(code, "config.json");
    expect(content).not.toContain(SHORT);
    expect(content).not.toContain(LONG);
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.type === "generic_secret")).toBe(true);
    expect(content).toContain('"host": "localhost"');
  });

  it("handles a value in a JSON string with quotes around the property name", () => {
    const { content } = redact(`{"client_secret":"${SHORT}","other":"fine-value-here"}`, "a.json");
    expect(content).toBe(`{"client_secret":"${MARKER}","other":"fine-value-here"}`);
  });
});

describe("environment references and prose are left alone", () => {
  const REFERENCES = [
    "const password = process.env.DB_PASSWORD;",
    'const password = process.env["DB_PASSWORD"];',
    'const password = "${process.env.DB_PASSWORD}";',
    "const password = `${process.env.DB_PASSWORD}`;",
    'password: "$DB_PASSWORD"',
    'password: "${DB_PASSWORD}"',
    'password: "%DB_PASSWORD%"',
    'const token = "import.meta.env.VITE_API_TOKEN";',
    'secret: "process.env.JWT_SECRET"',
    "const jwtSecret = import.meta.env.VITE_JWT_SECRET;",
  ];

  it.each(REFERENCES)("preserves the reference: %s", (code) => {
    expect(redact(code, "src/a.ts")).toEqual({ content: code, findings: [] });
    expect(() => assertNoSecrets(code)).not.toThrow();
  });

  it("does not treat a value that merely contains a reference as one", () => {
    expect(redact(`password: "\${DB_PASSWORD:-${SHORT}}"`, "a.js").content).not.toContain(SHORT);
    expect(redact(`password: "prefix-\${DB_PASSWORD}"`, "a.js").findings).toHaveLength(1);
    expect(redact(`password: "\${a b}"`, "a.js").content).toBe(`password: "\${a b}"`);
  });

  it("recognises exactly the pure references", () => {
    for (const ok of ["${VAR}", "${a.b.c}", "$VAR", "%VAR%", "process.env.X", "import.meta.env.X"]) {
      expect(isEnvReference(ok), ok).toBe(true);
    }
    for (const no of ["${VAR:-x}", "prefix${VAR}", "$", "plain", "process.env", "process.env.", "process.env.X.Y", "${}", ""]) {
      expect(isEnvReference(no), no).toBe(false);
    }
  });

  const PROSE = [
    "The token is checked on every request and the password is hashed with bcrypt.",
    "Note: the token expires after an hour.",
    "secret handling is documented in the README",
    "Reset your password: follow the link in the email.",
    'const label = "Enter your password";',
    '{"description": "Signs a token with the secret key at login"}',
    '{"passwordResetExpiry": "1 hour"}',
    '{"tokenLifetime": "1 day"}',
    'const password = "";',
    'if (password === "abc") return;',
    'if (token == "abcdefghijkl") return;',
    "const password = prompt();",
    "function checkToken(token) { return token.length > 0; }",
    "password: string;",
  ];

  it.each(PROSE)("leaves ordinary text unchanged: %s", (text) => {
    expect(redact(text, "README.md")).toEqual({ content: text, findings: [] });
  });
});

describe("the redaction error and the guard never expose a value", () => {
  it("names only a type and a line in the error", () => {
    let thrown: unknown;
    try {
      assertNoSecrets(`const a = 1;\nPASSWORD: "${SHORT}"\n`);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(SecretLeakError);
    const error = thrown as SecretLeakError;
    expect(error.message).toBe("refusing to continue: unredacted secret (generic_secret at line 2)");
    expect(error.message).not.toContain(SHORT);
    expect(JSON.stringify(error.findings)).not.toContain(SHORT);
  });

  it("makes redact() output pass the guard for every form, and is idempotent", () => {
    const codes = [
      `PASSWORD: "${SHORT}"`,
      `apiKey=\`${SHORT}\``,
      `const s: string = "${LONG}";`,
      `const j = process.env.JWT_SECRET || "${SHORT}";`,
      `{"client_secret": "${LONG}"}`,
    ];
    for (const code of codes) {
      const once = redact(code, "a.ts");
      expect(() => assertNoSecrets(once.content)).not.toThrow();
      expect(redact(once.content, "a.ts").content).toBe(once.content);
    }
  });

  it("keeps the newer forms linear in the size of hostile input", () => {
    const SIZE = 200_000;
    // Shapes aimed at what the newer rules added: the annotation, the fallback and the short
    // value. (A run of "password" repeated is quadratic in the older key match too, which
    // this change did not alter.)
    const hostile = [
      `password: ${"a".repeat(SIZE)}`,
      `password: ${"a ".repeat(SIZE / 2)}`,
      `password: ${"a".repeat(SIZE)}"`,
      `secret: cfg.get(${"(".repeat(SIZE)}`,
      `secret: ${"process.env.X || ".repeat(SIZE / 17)}`,
      `token: string${" ".repeat(SIZE)}= "`,
      `"pwd"${"[".repeat(SIZE)}`,
    ];
    for (const input of hostile) {
      const started = performance.now();
      redact(input, "a.js");
      expect(performance.now() - started, input.slice(0, 20)).toBeLessThan(1500);
    }
  });
});

// ---------------------------------------------------------------------------
// assertNoSecretsInPrompt: the <repo_file> wrapper-aware prompt guard
// ---------------------------------------------------------------------------

describe("assertNoSecretsInPrompt", () => {
  const DEPLOY = '<repo_file path=".github/workflows/deploy-pages.yml">';
  const block = (wrapper: string, ...lines: string[]) =>
    [wrapper, ...lines.map((line, i) => `${i + 1}| ${line}`), "</repo_file>"].join("\n");

  const findingsOf = (fn: () => void) => {
    try {
      fn();
    } catch (error) {
      if (error instanceof SecretLeakError) return error.findings;
      throw error;
    }
    return [];
  };

  it("is needed: plain assertNoSecrets flags the deploy-pages wrapper line as high_entropy", () => {
    expect(findingsOf(() => assertNoSecrets(DEPLOY))).toEqual([{ type: "high_entropy", line: 1 }]);
  });

  it("passes a prompt whose only suspicious line is the .github/workflows/deploy-pages.yml wrapper", () => {
    expect(() =>
      assertNoSecretsInPrompt(block(DEPLOY, "name: Deploy", "on: push")),
    ).not.toThrow();
  });

  it("still fails on a real secret in a content line, at the right line number", () => {
    const text = [
      "Repository facts",
      block(DEPLOY, "name: Deploy", 'const id = "AKIAIOSFODNN7EXAMPLE";'),
    ].join("\n");

    expect(findingsOf(() => assertNoSecretsInPrompt(text))).toEqual([
      { type: "aws_access_key", line: 4 },
    ]);
  });

  it("keeps line numbers exact after a masked wrapper (one line replaced by one line)", () => {
    const text = [block(DEPLOY, "ok"), block(DEPLOY, "a", 'const id = "AKIAIOSFODNN7EXAMPLE";')].join("\n");

    expect(findingsOf(() => assertNoSecretsInPrompt(text))).toEqual([
      { type: "aws_access_key", line: 6 },
    ]);
  });

  it("fails closed on a secret-shaped value inside a wrapper's path", () => {
    const text = block('<repo_file path="keys/AKIAIOSFODNN7EXAMPLE.txt">', "hello");

    expect(findingsOf(() => assertNoSecretsInPrompt(text))).toEqual([
      { type: "aws_access_key", line: 1 },
    ]);
  });

  it.each([
    ["leading text", 'x <repo_file path=".github/workflows/deploy-pages.yml">'],
    ["trailing text", '<repo_file path=".github/workflows/deploy-pages.yml"> x'],
    ["a raw quote inside the attribute", '<repo_file path=".github/workflows/deploy-pages.yml" x=".github/workflows/deploy-pages.yml">'],
    ["a different attribute name", '<repo_file name=".github/workflows/deploy-pages.yml">'],
    ["a missing closing bracket", '<repo_file path=".github/workflows/deploy-pages.yml"'],
    ["a content-line number prefix", '12| <repo_file path=".github/workflows/deploy-pages.yml">'],
  ])("does not mask a non-exact wrapper line (%s)", (_label, line) => {
    const findings = findingsOf(() => assertNoSecretsInPrompt(line));
    expect(findings.length).toBeGreaterThan(0);
    // Unmasked means: exactly what the plain guard says about the same line.
    expect(findings).toEqual(findingsOf(() => assertNoSecrets(line)));
  });

  it("cannot be used to smuggle a content-line secret behind an exact wrapper", () => {
    const text = `${DEPLOY}\n1| token = "AKIAIOSFODNN7EXAMPLE"`;

    expect(() => assertNoSecretsInPrompt(text)).toThrow(SecretLeakError);
  });
});

// ---------------------------------------------------------------------------
// Review fixes: unquoted config secrets, linear rules, markers, line count
// ---------------------------------------------------------------------------

describe("unquoted secrets in config files (CLAUDE.md rule 3)", () => {
  const PW = "Tr0ub4dor-horse-staple";

  it.each([
    ["docker-compose.yml", `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${PW}\n`],
    ["docker-compose.yml", `    environment:\n      - MYSQL_ROOT_PASSWORD=${PW}\n`],
    ["config/database.yml", `production:\n  password: ${PW}\n`],
    ["config/production.env", `DB_PASSWORD=${PW}\n`],
    [".env.example", `JWT_SECRET=${PW}\n`],
    [".envrc", `export API_TOKEN=${PW}\n`],
    ["application.properties", `spring.datasource.password=${PW}\n`],
    ["settings.ini", `[db]\npassword = ${PW}\n`],
    ["app.toml", `api_key = ${PW}\n`],
    ["nginx.conf", `  secret: ${PW}  # rotate yearly\n`],
    ["config.yaml", `${"a".repeat(120)}_password: ${PW}\n`],
  ])("redacts an unquoted value in %s", (path, content) => {
    const { content: out, findings } = redact(content, path);

    expect(out).not.toContain(PW);
    expect(out).toContain(redactionPlaceholder("generic_secret"));
    expect(findings.map((f) => f.type)).toEqual(["generic_secret"]);
    // The key survives; only the value is replaced.
    expect(out.split("\n").length).toBe(content.split("\n").length);
  });

  it("keeps the key and reports the value's line", () => {
    const { content, findings } = redact(`name: app\npassword: ${PW}\n`, "config.yml");

    expect(content).toBe("name: app\npassword: [REDACTED:generic_secret]\n");
    expect(findings).toEqual([{ type: "generic_secret", line: 2 }]);
  });

  it.each([
    "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
    "- POSTGRES_PASSWORD=$POSTGRES_PASSWORD",
    "password: %DB_PASSWORD%",
    "password: {{ .Values.db.password }}",
    "password: false",
    "token: ~",
    "password:",
    'password: "Tr0ub4dor-horse-staple"',
  ])("leaves a reference, a non-credential or a quoted value to other rules: %s", (line) => {
    const { content } = redact(line, "docker-compose.yml");
    // Quoted values are generic_secret's job (with the quotes kept), not this rule's.
    if (line.includes('"')) expect(content).toBe('password: "[REDACTED:generic_secret]"');
    else expect(content).toBe(line);
  });

  it("does not apply to code: an identifier after a key is not a credential", () => {
    const code = "const user = { email, password: hashedPassword, token: session.token };";
    expect(redact(code, "src/users.js").content).toBe(code);
  });

  it("stays out of the prompt guards, which see mixed text and no path", () => {
    const js = [
      '<repo_file path="src/users.js">',
      "1| const user = {",
      "2|   password: hashedPassword,",
      "3|   apiKey: config.apiKey,",
      "4| };",
      "</repo_file>",
    ].join("\n");

    expect(() => assertNoSecrets(js)).not.toThrow();
    expect(() => assertNoSecretsInPrompt(js)).not.toThrow();
    expect(() => assertNoSecrets("password: hashedPassword")).not.toThrow();
  });

  it.each([
    ["docker-compose.yml", true],
    ["deploy/compose.yaml", true],
    ["config/app.properties", true],
    ["setup.cfg", true],
    ["pyproject.toml", true],
    [".env", true],
    [".env.example", true],
    [".env-prod", true],
    ["apps/api/.envrc", true],
    ["web.env", true],
    ["src/config.ts", false],
    ["src/env.js", false],
    ["README.md", false],
    ["environment.ts", false],
  ])("isConfigFilePath(%s) is %s", (path, expected) => {
    expect(isConfigFilePath(path)).toBe(expected);
  });
});

describe("linear rules with no length-based bypass", () => {
  const SIZE = 200_000;
  const BUDGET_MS = 1_000;
  const timed = (fn: () => void): number => {
    const started = performance.now();
    fn();
    return performance.now() - started;
  };

  it("jwt: a run of eyJ stays linear, and a real JWT is still found", () => {
    expect(timed(() => redact("eyJ".repeat(SIZE / 3), "a.ts"))).toBeLessThan(BUDGET_MS);
    const jwt = SAMPLES.find((s) => s.type === "jwt")!;
    expect(redact(jwt.code, "a.ts").findings).toEqual([{ type: "jwt", line: 1 }]);
  });

  it("generic_secret: a keyword repeated through one identifier stays linear", () => {
    expect(timed(() => redact("pwd".repeat(SIZE / 3), "a.ts"))).toBeLessThan(BUDGET_MS);
    expect(timed(() => redact(`${"pwd".repeat(SIZE / 3)} = "hunter22"`, "a.ts"))).toBeLessThan(
      BUDGET_MS,
    );
    expect(
      timed(() => redact(`${"password".repeat(SIZE / 8)}\n`.repeat(2), "config.yml")),
    ).toBeLessThan(BUDGET_MS);
    expect(redact(`${"pwd".repeat(SIZE / 3)} = "hunter22"`, "a.ts").findings).toEqual([
      { type: "generic_secret", line: 1 },
    ]);
  });

  it.each([
    ["a 102-character prefix", `${"a".repeat(102)}password: "Zq7 Kp1Xw2"`],
    ["a 150-character suffix", `password${"a".repeat(150)} = "hunter22"`],
    ["a 1,000-character dotted prefix", `${"cfg.".repeat(250)}apiKey = "hunter22"`],
  ])("still redacts under a key with %s, and so does the guard", (_label, line) => {
    expect(redact(line, "a.ts").content).toContain(redactionPlaceholder("generic_secret"));
    expect(() => assertNoSecrets(line)).toThrow(SecretLeakError);
  });

  it("does not let an annotation hide a credential key: const pw: Password = ...", () => {
    expect(redact('const pw: Password = "hunter22";', "a.ts").content).toBe(
      'const pw: Password = "[REDACTED:generic_secret]";',
    );
  });

  it.each([
    ["password.length", 'password.length = "abcdefgh"'],
    ["password-reset", 'password-reset = "abcdefgh"'],
  ])("keeps the old key shape: %s is not a credential key", (_label, line) => {
    expect(redact(line, "a.ts").content).toBe(line);
  });
});

describe("markers never manufacture a finding", () => {
  it.each([
    ["an AWS key used as a connection-string user", 'const url = "postgres://AKIAIOSFODNN7EXAMPLEsvc@db.internal/app";'],
    ["a GitHub token used as a URL user", 'remote = "https://ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8.bot@github.com/o/r.git"'],
  ])("redact() output passes the guard: %s", (_label, line) => {
    const once = redact(line, "src/db.ts");

    expect(once.findings.length).toBeGreaterThan(0);
    expect(() => assertNoSecrets(once.content)).not.toThrow();
    expect(() => assertNoSecretsInPrompt(once.content)).not.toThrow();
    expect(redact(once.content, "src/db.ts").content).toBe(once.content);
  });

  it("does not flag a match that starts inside a marker", () => {
    expect(() => assertNoSecrets("postgres://[REDACTED:aws_access_key]svc@db.internal/app")).not.toThrow();
  });

  it("still redacts a credential that sits directly against another one", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl";
    const { content, findings } = redact(`k: AKIAIOSFODNN7EXAMPLE${jwt}`, "a.ts");

    expect(content).toBe("k: [REDACTED:aws_access_key][REDACTED:jwt]");
    expect(findings.map((f) => f.type)).toEqual(["aws_access_key", "jwt"]);
    expect(() => assertNoSecrets(content)).not.toThrow();
  });

  it("keeps redacting text that follows a planted marker in the same value", () => {
    expect(() => assertNoSecrets('password = "[REDACTED:jwt]hunter2hunter2"')).toThrow(
      SecretLeakError,
    );
  });
});

describe("redaction keeps the line count", () => {
  const pemBody = Array.from({ length: 50 }, (_, i) => `MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoIC${i}`).join("\n");
  const pem = `-----BEGIN PRIVATE KEY-----\n${pemBody}\n-----END PRIVATE KEY-----`;
  const code = [
    'const express = require("express");',
    `const KEY = \`${pem}\`;`,
    'router.post("/login", handler); // line 54',
    'const id = "AKIAIOSFODNN7EXAMPLE"; // line 55',
  ].join("\n");

  it("leaves as many lines as the original, with every later line where it was", () => {
    const { content, findings } = redact(code, "src/routes/auth.js");
    const before = code.split("\n");
    const after = content.split("\n");

    expect(after.length).toBe(before.length);
    expect(after[1]).toBe("const KEY = `[REDACTED:private_key]");
    expect(after[53]).toBe(before[53]);
    expect(after[54]).toBe('const id = "[REDACTED:aws_access_key]"; // line 55');
    expect(findings).toEqual([
      { type: "private_key", line: 2 },
      { type: "aws_access_key", line: 55 },
    ]);
  });

  it("stays idempotent and guard-clean with the kept newlines", () => {
    const once = redact(code, "src/routes/auth.js").content;

    expect(redact(once, "src/routes/auth.js").content).toBe(once);
    expect(() => assertNoSecrets(once)).not.toThrow();
  });
});
