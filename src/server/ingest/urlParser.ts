/** True when `text` holds an ASCII control character (0x00-0x1F or 0x7F). */
function hasControlCharacter(text: string): boolean {
  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

export function parseGitHubUrl(
  input: string,
): { ok: true; owner: string; repo: string; ref?: string } | { ok: false; code: "INVALID_URL"; message: string } {
  if (!input || typeof input !== "string") {
    return { ok: false, code: "INVALID_URL", message: "Input is empty" };
  }

  const trimmed = input.trim();

  if (trimmed.length === 0) {
    return { ok: false, code: "INVALID_URL", message: "Input is empty" };
  }

  if (trimmed.length > 500) {
    return { ok: false, code: "INVALID_URL", message: "Input exceeds 500 characters" };
  }

  if (trimmed.includes("@")) {
    return { ok: false, code: "INVALID_URL", message: "Credentials are not allowed" };
  }

  // Try shorthand owner/repo format first, before URL parsing.
  const shorthandMatch = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/.exec(trimmed);
  if (shorthandMatch) {
    const [, owner, repo] = shorthandMatch;
    if (repo === "." || repo === "..") {
      return { ok: false, code: "INVALID_URL", message: "Invalid repo name" };
    }
    return { ok: true, owner, repo };
  }

  let urlString = trimmed;

  // Remove fragment and query before parsing.
  const hashIdx = urlString.indexOf("#");
  if (hashIdx !== -1) {
    urlString = urlString.slice(0, hashIdx);
  }
  const queryIdx = urlString.indexOf("?");
  if (queryIdx !== -1) {
    urlString = urlString.slice(0, queryIdx);
  }

  // Check for path traversal in the original string (URL class normalizes pathnames).
  if (urlString.includes("..")) {
    return { ok: false, code: "INVALID_URL", message: "Path traversal is not allowed" };
  }

  // Encoded dots (%2e, any case), also in the raw string: the URL class resolves a
  // "%2e%2e" segment as ".." while parsing, so after parsing there is nothing left to
  // see -- "github.com/evil/%2e%2e/vercel/next.js" came out as vercel/next.js.
  if (/%2e/i.test(urlString)) {
    return { ok: false, code: "INVALID_URL", message: "Encoded characters are not allowed" };
  }

  // Add scheme if missing.
  if (!urlString.includes("://")) {
    urlString = "https://" + urlString;
  }

  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    return { ok: false, code: "INVALID_URL", message: "Invalid URL format" };
  }

  // Normalize www.github.com to github.com.
  let hostname = url.hostname;
  if (hostname === "www.github.com") {
    hostname = "github.com";
  }

  if (hostname !== "github.com") {
    return { ok: false, code: "INVALID_URL", message: "Only github.com is supported" };
  }

  let pathname = url.pathname;

  // Remove trailing slash.
  if (pathname.endsWith("/")) {
    pathname = pathname.slice(0, -1);
  }

  // Remove .git suffix.
  if (pathname.endsWith(".git")) {
    pathname = pathname.slice(0, -4);
  }

  // Parse pathname.
  const parts = pathname.split("/").filter((p) => p.length > 0);

  if (parts.length < 2) {
    return { ok: false, code: "INVALID_URL", message: "Missing owner or repo" };
  }

  const owner = parts[0];
  const repo = parts[1];
  let ref: string | undefined;

  // Extract ref from /tree/branch-name. url.pathname is percent-encoded ("café" arrives
  // as "caf%C3%A9"), and the ref goes to GitHub as a value that its client encodes
  // itself, so each segment is decoded here exactly once. Malformed encoding, or a
  // decoded control character (git refs cannot hold one), is rejected.
  if (parts.length > 2 && parts[2] === "tree" && parts.length > 3) {
    const segments: string[] = [];
    for (const segment of parts.slice(3)) {
      let decoded: string;
      try {
        decoded = decodeURIComponent(segment);
      } catch {
        return { ok: false, code: "INVALID_URL", message: "Invalid ref encoding" };
      }
      if (hasControlCharacter(decoded)) {
        return { ok: false, code: "INVALID_URL", message: "Invalid ref" };
      }
      segments.push(decoded);
    }
    ref = segments.join("/");
  }

  // Validate owner: start with alphanumeric, followed by 0-38 chars of alphanumeric or hyphen.
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)) {
    return { ok: false, code: "INVALID_URL", message: "Invalid owner name" };
  }

  // Validate repo: 1-100 chars of alphanumeric, dot, underscore, or hyphen.
  if (!/^[A-Za-z0-9._-]{1,100}$/.test(repo)) {
    return { ok: false, code: "INVALID_URL", message: "Invalid repo name" };
  }

  if (repo === "." || repo === "..") {
    return { ok: false, code: "INVALID_URL", message: "Invalid repo name" };
  }

  return { ok: true, owner, repo, ...(ref && { ref }) };
}
