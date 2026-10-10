// @vitest-environment jsdom

/**
 * The Limitations list: one sentence per line, a fold-out for the lines the server sent
 * detail for. Links go only to names that are components of the view.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import Limitations, { findNodeForSubject, gapKindNames } from "@/components/Limitations";
import type { LimitationDetail } from "@/shared/viewModel";

afterEach(cleanup);

const NODES = [
  { id: "api", label: "API server" },
  { id: "db", label: "mongodb datastore" },
];

const TWO = "The diagram shows lint.yml and API server as external systems.";
const PLAIN = "1 dependency was not checked against OSV.";
const GAPS = "2 possible missing controls could not be tied to a single component.";

const DETAILS: LimitationDetail[] = [
  { code: "deployment_modelled_as_external", sentence: TWO, subjects: ["the lint.yml workflow", "the API server"] },
  { code: "plain", sentence: PLAIN, subjects: [] },
  { code: "gap_bound_broadly", sentence: GAPS, subjects: [], gapKinds: ["rate_limit_missing", "authn_missing"] },
];

function renderList(onSelectNode = vi.fn()) {
  render(<Limitations lines={[TWO, PLAIN, GAPS]} details={DETAILS} nodes={NODES} onSelectNode={onSelectNode} />);
  return onSelectNode;
}

describe("Limitations", () => {
  it("keeps one line per sentence, as on the wire", () => {
    const { container } = render(
      <Limitations lines={[TWO, PLAIN, GAPS]} details={DETAILS} nodes={NODES} onSelectNode={vi.fn()} />,
    );
    expect(container.querySelector(":scope > ul")?.children).toHaveLength(3);
    expect(screen.getByText(TWO)).toBeTruthy();
    expect(screen.getByText(PLAIN)).toBeTruthy();
  });

  it("renders both subjects of a limitation with two", () => {
    renderList();
    const fold = screen.getByTestId("limitation-deployment_modelled_as_external");
    expect(within(fold).getByText("the lint.yml workflow")).toBeTruthy();
    expect(within(fold).getByText(/the API server/)).toBeTruthy();
  });

  it("links a subject that is a component and selects it", () => {
    const onSelect = renderList();
    fireEvent.click(screen.getByRole("button", { name: /the API server/ }));
    expect(onSelect).toHaveBeenCalledWith("api");
  });

  it("renders a subject that is not a component as text, not a link", () => {
    renderList();
    const fold = screen.getByTestId("limitation-deployment_modelled_as_external");
    const text = within(fold).getByText("the lint.yml workflow");
    expect(text.tagName).toBe("SPAN");
    expect(within(fold).getAllByRole("button")).toHaveLength(1);
  });

  it("names the gap kinds for gap_bound_broadly", () => {
    renderList();
    const fold = screen.getByTestId("limitation-gap_bound_broadly");
    expect(fold.textContent).toContain("Missing controls involved: rate limiting, authentication");
  });

  it("shows a line with no detail, or no subjects, as plain text with no fold-out", () => {
    renderList();
    expect(screen.queryByTestId("limitation-plain")).toBeNull();
    cleanup();
    render(<Limitations lines={[TWO]} nodes={NODES} onSelectNode={vi.fn()} />);
    expect(screen.getByText(TWO)).toBeTruthy();
    expect(document.querySelector("details")).toBeNull();
  });
});

describe("findNodeForSubject", () => {
  it("matches ignoring case, spacing and a leading 'the'", () => {
    expect(findNodeForSubject("The  MongoDB datastore", NODES)?.id).toBe("db");
    expect(findNodeForSubject("the lint.yml workflow", NODES)).toBeUndefined();
    expect(findNodeForSubject("  ", NODES)).toBeUndefined();
  });
});

describe("gapKindNames", () => {
  it("maps kinds to plain names in order and skips unknown ones", () => {
    expect(gapKindNames(["csrf_missing", "nope", "logging_missing"])).toEqual([
      "CSRF protection",
      "security logging",
    ]);
  });
});
