import { describe, expect, it } from "vitest";
import { parseGitHubUrl } from "@/server/ingest/urlParser";

describe("parseGitHubUrl", () => {
  describe("valid URLs", () => {
    it("parses https://github.com/owner/repo", () => {
      const result = parseGitHubUrl("https://github.com/vercel/next.js");
      expect(result).toEqual({ ok: true, owner: "vercel", repo: "next.js" });
    });

    it("parses https://github.com/owner/repo/ with trailing slash", () => {
      const result = parseGitHubUrl("https://github.com/facebook/react/");
      expect(result).toEqual({ ok: true, owner: "facebook", repo: "react" });
    });

    it("parses https://github.com/owner/repo.git", () => {
      const result = parseGitHubUrl("https://github.com/golang/go.git");
      expect(result).toEqual({ ok: true, owner: "golang", repo: "go" });
    });

    it("normalizes http:// to https://", () => {
      const result = parseGitHubUrl("http://github.com/owner/repo");
      expect(result).toEqual({ ok: true, owner: "owner", repo: "repo" });
    });

    it("parses github.com/owner/repo without scheme", () => {
      const result = parseGitHubUrl("github.com/owner/repo");
      expect(result).toEqual({ ok: true, owner: "owner", repo: "repo" });
    });

    it("normalizes www.github.com", () => {
      const result = parseGitHubUrl("https://www.github.com/owner/repo");
      expect(result).toEqual({ ok: true, owner: "owner", repo: "repo" });
    });

    it("extracts ref from /tree/branch-name", () => {
      const result = parseGitHubUrl("https://github.com/owner/repo/tree/main");
      expect(result).toEqual({
        ok: true,
        owner: "owner",
        repo: "repo",
        ref: "main",
      });
    });

    it.each([
      ["a non-ASCII branch", "https://github.com/o/r/tree/caf%C3%A9", "café"],
      ["a non-ASCII branch typed raw", "https://github.com/o/r/tree/café", "café"],
      ["an encoded slash inside one segment", "https://github.com/o/r/tree/feat%2Fx", "feat/x"],
      ["a branch with a percent sign kept encoded once", "https://github.com/o/r/tree/100%2525", "100%25"],
    ])("decodes the ref exactly once: %s", (_label, url, ref) => {
      expect(parseGitHubUrl(url)).toEqual({ ok: true, owner: "o", repo: "r", ref });
    });

    it.each([
      ["malformed percent-encoding", "https://github.com/o/r/tree/bad%E0%A4"],
      ["a lone percent sign", "https://github.com/o/r/tree/100%"],
      ["an encoded newline", "https://github.com/o/r/tree/main%0Aevil"],
      ["an encoded NUL", "https://github.com/o/r/tree/main%00"],
    ])("rejects a ref with %s", (_label, url) => {
      const result = parseGitHubUrl(url);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe("INVALID_URL");
    });

    it("handles ref with slashes (release/v1.0)", () => {
      const result = parseGitHubUrl("https://github.com/owner/repo/tree/release/v1.0");
      expect(result).toEqual({
        ok: true,
        owner: "owner",
        repo: "repo",
        ref: "release/v1.0",
      });
    });

    it("parses owner/repo shorthand", () => {
      const result = parseGitHubUrl("vercel/next.js");
      expect(result).toEqual({ ok: true, owner: "vercel", repo: "next.js" });
    });

    it("strips leading and trailing whitespace", () => {
      const result = parseGitHubUrl("  vercel/next.js  ");
      expect(result).toEqual({ ok: true, owner: "vercel", repo: "next.js" });
    });

    it("strips query strings", () => {
      const result = parseGitHubUrl("https://github.com/owner/repo?tab=readme");
      expect(result).toEqual({ ok: true, owner: "owner", repo: "repo" });
    });

    it("strips fragments", () => {
      const result = parseGitHubUrl("https://github.com/owner/repo#section");
      expect(result).toEqual({ ok: true, owner: "owner", repo: "repo" });
    });

    it("parses repos with hyphens, dots, underscores anywhere", () => {
      const result = parseGitHubUrl("A1/repo-name_2.3-test");
      expect(result).toEqual({
        ok: true,
        owner: "A1",
        repo: "repo-name_2.3-test",
      });
    });

    it("accepts repo starting with hyphen", () => {
      const result = parseGitHubUrl("owner/-repo");
      expect(result).toEqual({ ok: true, owner: "owner", repo: "-repo" });
    });

    it("accepts repo starting with dot", () => {
      const result = parseGitHubUrl("owner/.gitignore");
      expect(result).toEqual({ ok: true, owner: "owner", repo: ".gitignore" });
    });

    it("accepts owner at 39 character limit", () => {
      const owner39 = "a".repeat(38) + "B";
      const result = parseGitHubUrl(`${owner39}/repo`);
      expect(result).toEqual({ ok: true, owner: owner39, repo: "repo" });
    });

    it("accepts repo at 100 character limit", () => {
      const repo100 = "a".repeat(100);
      const result = parseGitHubUrl(`owner/${repo100}`);
      expect(result).toEqual({ ok: true, owner: "owner", repo: repo100 });
    });

    it("handles query string and fragment together", () => {
      const result = parseGitHubUrl("https://github.com/owner/repo?foo=bar#anchor");
      expect(result).toEqual({ ok: true, owner: "owner", repo: "repo" });
    });

    it("accepts numeric-only repo names", () => {
      const result = parseGitHubUrl("owner/123");
      expect(result).toEqual({ ok: true, owner: "owner", repo: "123" });
    });
  });

  describe("invalid URLs", () => {
    it("rejects empty string", () => {
      const result = parseGitHubUrl("");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects whitespace-only string", () => {
      const result = parseGitHubUrl("   ");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects input exceeding 500 characters", () => {
      const long = "vercel/" + "a".repeat(500);
      const result = parseGitHubUrl(long);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects github.com.evil.com (domain hijack)", () => {
      const result = parseGitHubUrl("https://github.com.evil.com/owner/repo");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects gist.github.com", () => {
      const result = parseGitHubUrl("https://gist.github.com/user/abc123");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects credentials in URL", () => {
      const result = parseGitHubUrl("https://user:pass@github.com/owner/repo");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects owner starting with hyphen", () => {
      const result = parseGitHubUrl("-owner/repo");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects owner exceeding 39 characters", () => {
      const owner40 = "a".repeat(40);
      const result = parseGitHubUrl(`${owner40}/repo`);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });


    it("rejects repo exceeding 100 characters", () => {
      const repo101 = "a".repeat(101);
      const result = parseGitHubUrl(`owner/${repo101}`);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it('rejects repo = "."', () => {
      const result = parseGitHubUrl("owner/.");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it('rejects repo = ".."', () => {
      const result = parseGitHubUrl("owner/..");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects %2e (lowercase encoded dot)", () => {
      const result = parseGitHubUrl("https://github.com/owner%2e/repo");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects %2E (uppercase encoded dot)", () => {
      const result = parseGitHubUrl("https://github.com/owner%2E/repo");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it.each([
      ["a whole %2e%2e segment", "https://github.com/evil/%2e%2e/vercel/next.js"],
      ["a mixed-case %2E%2e segment", "https://github.com/evil/%2E%2e/vercel/next.js"],
      ["a single %2e segment", "https://github.com/%2e/vercel/next.js"],
      ["an encoded dot in the ref", "https://github.com/o/r/tree/%2e%2e/x"],
      ["no scheme", "github.com/evil/%2e%2e/vercel/next.js"],
    ])("rejects an encoded dot segment before the URL class can resolve it: %s", (_label, url) => {
      expect(parseGitHubUrl(url)).toEqual({
        ok: false,
        code: "INVALID_URL",
        message: "Encoded characters are not allowed",
      });
    });

    it("rejects .. (path traversal)", () => {
      const result = parseGitHubUrl("https://github.com/owner/../admin/repo");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects repo with invalid characters (@)", () => {
      const result = parseGitHubUrl("owner/repo@name");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects owner starting with non-alphanumeric", () => {
      const result = parseGitHubUrl("_owner/repo");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects repo with invalid characters (space)", () => {
      const result = parseGitHubUrl("owner/repo name");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects URL without owner and repo", () => {
      const result = parseGitHubUrl("https://github.com");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects URL with only owner", () => {
      const result = parseGitHubUrl("https://github.com/owner");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });

    it("rejects other hosts (example.com)", () => {
      const result = parseGitHubUrl("https://example.com/owner/repo");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("INVALID_URL");
      }
    });
  });
});
