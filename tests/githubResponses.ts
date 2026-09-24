/**
 * Responses captured from the live GitHub MCP server (ghcr.io/github/github-mcp-server
 * v1.12.2) with scripts/inspect-github-file.ts, for octocat/Hello-World.
 *
 * Tests use these instead of invented shapes: an earlier mocked test suite passed while
 * the real server put the file body in a `resource` block that the client ignored.
 */

export const README_STATUS_MESSAGE =
  "successfully downloaded text file (SHA: 980a0d5f19a64b4b30a87d4206aade58726b60e3)";

export const README_BODY = "Hello World!\n";

/** get_file_contents for octocat/Hello-World, path "README". */
export const REAL_GET_FILE_CONTENTS_RESULT = {
  content: [
    { type: "text", text: README_STATUS_MESSAGE },
    {
      type: "resource",
      resource: {
        uri: "repo://octocat/Hello-World/sha/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d/contents/README",
        mimeType: "text/plain; charset=utf-8",
        text: README_BODY,
      },
    },
  ],
};

/** The same call if a server returned only the status block. */
export const STATUS_ONLY_RESULT = {
  content: [{ type: "text", text: README_STATUS_MESSAGE }],
};

/** REST Contents API response for the same file (GitHub wraps base64 at 60 columns). */
export const REST_README_RESPONSE = {
  type: "file",
  encoding: "base64",
  size: 13,
  name: "README",
  path: "README",
  sha: "980a0d5f19a64b4b30a87d4206aade58726b60e3",
  content: "SGVsbG8gV29ybGQhCg==\n",
};
