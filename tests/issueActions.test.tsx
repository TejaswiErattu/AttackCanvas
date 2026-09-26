// @vitest-environment jsdom

/**
 * The card's issue actions: the link, its too-long fallback, and a refused clipboard.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import ThreatCard from "@/components/ThreatCard";
import type { ThreatCardData } from "@/shared/viewModel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function threat(overrides: Partial<ThreatCardData> = {}): ThreatCardData {
  return {
    id: "t1", title: "<script>alert(1)</script>", severity: "high", confidence: 70,
    confidenceLabel: "high", priority: "fix_now", priorityLabel: "Fix now",
    stride: [], owasp: [], cwe: [], basis: "evidence_backed", basisLabel: "Confirmed by evidence",
    componentNames: [], affectedNames: [], componentIds: [], dataFlowIds: [],
    confidenceReasons: [], attackScenario: "Scenario", evidence: [],
    mitigation: { summary: "Fix", steps: [], codeLocation: null }, assumptions: [],
    ...overrides,
  };
}

const REPO = { fullName: "acme/shop", ref: "main" };

describe("issue actions", () => {
  it("links to a prefilled new issue and renders the title only as text", () => {
    const { container } = render(<ThreatCard threat={threat()} selected={false} onSelect={() => {}} repo={REPO} />);
    const link = screen.getByRole("link", { name: "Open as GitHub issue" });
    expect(link.getAttribute("href")).toContain("https://github.com/acme/shop/issues/new?title=%3Cscript%3E");
    expect(link.getAttribute("rel")).toContain("noopener");
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByRole("heading", { level: 3 }).textContent).toBe("<script>alert(1)</script>");
  });

  it("drops the link and points at Copy as Markdown when the link would be too long", () => {
    render(<ThreatCard threat={threat({ attackScenario: "→".repeat(3000) })} selected={false} onSelect={() => {}} repo={REPO} />);
    expect(screen.queryByRole("link", { name: "Open as GitHub issue" })).toBeNull();
    expect(screen.getByRole("note").textContent).toContain("Too long for a link");
    expect(screen.getByRole("button", { name: "Copy as Markdown" })).toBeTruthy();
  });

  it("copies the body, and shows it for manual copying when the clipboard is refused", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    render(<ThreatCard threat={threat()} selected={false} onSelect={() => {}} repo={REPO} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy as Markdown" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Copied" })).toBeTruthy());
    expect(writeText.mock.calls[0][0]).toContain("**Severity:** High");

    cleanup();
    vi.stubGlobal("navigator", { clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    render(<ThreatCard threat={threat()} selected={false} onSelect={() => {}} repo={REPO} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy as Markdown" }));
    const box = await screen.findByRole("textbox");
    expect((box as HTMLTextAreaElement).value).toContain("**Severity:** High");
  });

  it("gives two copies of one card different status control ids", () => {
    const props = { threat: threat(), selected: false, onSelect: () => {}, onStatusChange: () => {} };
    const { container } = render(<><ThreatCard {...props} /><ThreatCard {...props} /></>);
    const ids = [...container.querySelectorAll("select")].map((s) => s.id);
    expect(new Set(ids).size).toBe(2);
    for (const id of ids) expect(container.querySelector(`label[for="${id}"]`)).not.toBeNull();
  });
});
