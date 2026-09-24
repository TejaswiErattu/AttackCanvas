// @vitest-environment jsdom

/**
 * The landing page: submission is real, every analysis level 0-4 is selectable, the
 * server's own error copy is shown, and the hero graphic is labelled as an illustration.
 *
 * `fetch` is stubbed and next/navigation's router is mocked, so nothing leaves the test.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

const { default: HomePage } = await import("@/app/page");

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  push.mockReset();
});

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function stubFetch(response: Response) {
  const calls: { url: string; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), body: JSON.parse(String(init?.body)) });
      return response;
    }),
  );
  return calls;
}

function typeUrl(value: string) {
  fireEvent.change(screen.getByLabelText("Public GitHub repository URL"), {
    target: { value },
  });
}

describe("HomePage", () => {
  it("offers all five analysis levels, with Standard selected by default", () => {
    render(<HomePage />);
    const labels = ["Snapshot", "Basic", "Standard", "Deep", "Exhaustive"];
    labels.forEach((label) => {
      expect((screen.getByLabelText(new RegExp(label)) as HTMLInputElement).type).toBe("radio");
    });
    expect((screen.getByLabelText(/Standard/) as HTMLInputElement).checked).toBe(true);
  });

  it("posts the typed URL and the chosen level, then routes to the analysis", async () => {
    const calls = stubFetch(json({ analysisId: "abc-123", status: "queued" }, 202));
    render(<HomePage />);

    typeUrl("https://github.com/acme/acme-notes");
    fireEvent.click(screen.getByLabelText(/Exhaustive/));
    fireEvent.click(screen.getByRole("button", { name: "Analyze repository" }));

    await waitFor(() => expect(push).toHaveBeenCalledWith("/analyze/abc-123"));
    expect(calls).toEqual([
      {
        url: "/api/analyze",
        body: { repoUrl: "https://github.com/acme/acme-notes", analysisLevel: 4 },
      },
    ]);
  });

  it("can submit level 0", async () => {
    const calls = stubFetch(json({ analysisId: "zero", status: "queued" }, 202));
    render(<HomePage />);

    typeUrl("https://github.com/acme/acme-notes");
    fireEvent.click(screen.getByLabelText(/Snapshot/));
    fireEvent.click(screen.getByRole("button", { name: "Analyze repository" }));

    await waitFor(() => expect(push).toHaveBeenCalled());
    expect(calls[0].body).toMatchObject({ analysisLevel: 0 });
  });

  it("shows the server's validation error and does not navigate", async () => {
    stubFetch(
      json(
        {
          error: {
            code: "INVALID_URL",
            title: "That URL won't work",
            message: "repoUrl must be a full https://github.com/<owner>/<repo> URL.",
            canRetry: false,
          },
        },
        400,
      ),
    );
    render(<HomePage />);

    typeUrl("https://example.com/not-github");
    fireEvent.click(screen.getByRole("button", { name: "Analyze repository" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("repoUrl must be a full https://github.com/<owner>/<repo> URL.");
    expect(alert.textContent).toContain("INVALID_URL");
    expect(screen.getByLabelText("Public GitHub repository URL").getAttribute("aria-invalid")).toBe(
      "true",
    );
    expect(push).not.toHaveBeenCalled();
    // The form is usable again.
    expect((screen.getByRole("button", { name: "Analyze repository" }) as HTMLButtonElement).disabled).toBe(
      false,
    );
  });

  it("shows the rate-limit error the server sends", async () => {
    stubFetch(
      json(
        {
          error: {
            code: "RATE_LIMITED",
            title: "Too many analyses started",
            message: "You've started 5 analyses within an hour, the most allowed from one address. Try again later.",
            canRetry: true,
          },
        },
        429,
      ),
    );
    render(<HomePage />);

    typeUrl("https://github.com/acme/acme-notes");
    fireEvent.click(screen.getByRole("button", { name: "Analyze repository" }));

    expect((await screen.findByRole("alert")).textContent).toContain("Too many analyses started");
    expect(push).not.toHaveBeenCalled();
  });

  it("reports an unreachable server as a connection problem", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    render(<HomePage />);

    typeUrl("https://github.com/acme/acme-notes");
    fireEvent.click(screen.getByRole("button", { name: "Analyze repository" }));

    expect((await screen.findByRole("alert")).textContent).toContain("Connection problem");
  });

  it("keeps submit disabled until a URL is entered", () => {
    render(<HomePage />);
    expect((screen.getByRole("button", { name: "Analyze repository" }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });

  it("labels the hero graphic as an illustration, not a result", () => {
    render(<HomePage />);
    const caption = screen.getByText(/real diagram appears after its analysis runs/);
    expect(caption.textContent).toContain("Illustration");
  });
});
