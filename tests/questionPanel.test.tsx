// @vitest-environment jsdom

/**
 * QuestionPanel: renders the backend's developer questions and submits the shape the
 * answers route already accepts.
 *
 * The contract being protected is POST /api/analyze/[id]/answers:
 *   { questionId, status: "answered" | "skipped" | "unsure", optionIndex? }
 * with one entry per question. The easy mistakes are submitting only the questions the
 * user touched, omitting optionIndex, or inventing a status the Zod schema rejects -- all
 * of which would 400. Each is asserted against here.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import QuestionPanel from "@/components/QuestionPanel";
import type { QuestionData } from "@/shared/viewModel";

afterEach(cleanup);

const QUESTIONS: QuestionData[] = [
  {
    id: "auth-on-notes-api",
    text: "Is the notes API behind authentication in production?",
    whyAsking: "No auth middleware was detected, which changes three threat ratings.",
    options: ["Yes, every route requires a session", "No, some routes are public"],
    allowsUnsure: true,
    defaultAssumption: "We assume the routes are unauthenticated.",
    index: 1,
    total: 2,
  },
  {
    id: "db-network-exposure",
    text: "Is the database reachable from the public internet?",
    whyAsking: "Network exposure decides the likelihood of the data-at-rest threats.",
    options: ["No, private network only", "Yes, it has a public endpoint"],
    allowsUnsure: false,
    defaultAssumption: "We assume the database is private.",
    index: 2,
    total: 2,
  },
];

function renderPanel(overrides: Partial<React.ComponentProps<typeof QuestionPanel>> = {}) {
  const onSubmit = vi.fn();
  render(
    <QuestionPanel
      questions={QUESTIONS}
      submitting={false}
      onSubmit={onSubmit}
      {...overrides}
    />,
  );
  return { onSubmit };
}

describe("QuestionPanel rendering", () => {
  it("renders every question with its text, reason and position", () => {
    renderPanel();

    expect(screen.getByText(QUESTIONS[0].text)).toBeTruthy();
    expect(screen.getByText(QUESTIONS[1].text)).toBeTruthy();
    expect(screen.getByText(QUESTIONS[0].whyAsking)).toBeTruthy();
    expect(screen.getByText("Question 1 of 2")).toBeTruthy();
    expect(screen.getByText("Question 2 of 2")).toBeTruthy();
  });

  it("renders each option as a labelled radio", () => {
    renderPanel();

    QUESTIONS.flatMap((question) => question.options).forEach((option) => {
      const input = screen.getByLabelText(option);
      expect(input.getAttribute("type")).toBe("radio");
    });
  });

  it("offers 'not sure' only where the backend allows it", () => {
    renderPanel();

    // allowsUnsure is true for the first question and false for the second.
    expect(screen.getAllByLabelText(/not sure/i)).toHaveLength(1);
  });

  it("always offers skip, and shows the default assumption that applies", () => {
    renderPanel();

    expect(screen.getAllByLabelText("Skip this question")).toHaveLength(2);
    expect(screen.getByText(/We assume the routes are unauthenticated/)).toBeTruthy();
    expect(screen.getByText(/We assume the database is private/)).toBeTruthy();
  });

  it("defaults every question to skipped", () => {
    renderPanel();

    screen.getAllByLabelText("Skip this question").forEach((input) => {
      expect((input as HTMLInputElement).checked).toBe(true);
    });
  });

  it("renders nothing when there are no questions", () => {
    const { container } = render(
      <QuestionPanel questions={[]} submitting={false} onSubmit={vi.fn()} />,
    );
    expect(container.innerHTML).toBe("");
  });
});

describe("QuestionPanel submission", () => {
  it("submits one entry per question even when none were touched", () => {
    const { onSubmit } = renderPanel();
    fireEvent.click(screen.getByRole("button", { name: /submit answers/i }));

    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit.mock.calls[0][0]).toEqual([
      { questionId: "auth-on-notes-api", status: "skipped" },
      { questionId: "db-network-exposure", status: "skipped" },
    ]);
  });

  it("submits the chosen option as an answered status with its index", () => {
    const { onSubmit } = renderPanel();

    fireEvent.click(screen.getByLabelText("No, some routes are public"));
    fireEvent.click(screen.getByLabelText("Yes, it has a public endpoint"));
    fireEvent.click(screen.getByRole("button", { name: /submit answers/i }));

    expect(onSubmit.mock.calls[0][0]).toEqual([
      { questionId: "auth-on-notes-api", status: "answered", optionIndex: 1 },
      { questionId: "db-network-exposure", status: "answered", optionIndex: 1 },
    ]);
  });

  it("uses index 0 for the first option", () => {
    const { onSubmit } = renderPanel();

    fireEvent.click(screen.getByLabelText("Yes, every route requires a session"));
    fireEvent.click(screen.getByRole("button", { name: /submit answers/i }));

    expect(onSubmit.mock.calls[0][0][0]).toEqual({
      questionId: "auth-on-notes-api",
      status: "answered",
      optionIndex: 0,
    });
  });

  it("submits 'unsure' without an option index", () => {
    const { onSubmit } = renderPanel();

    fireEvent.click(screen.getByLabelText(/not sure/i));
    fireEvent.click(screen.getByRole("button", { name: /submit answers/i }));

    expect(onSubmit.mock.calls[0][0][0]).toEqual({
      questionId: "auth-on-notes-api",
      status: "unsure",
    });
  });

  it("mixes answered and skipped questions in one submission", () => {
    const { onSubmit } = renderPanel();

    fireEvent.click(screen.getByLabelText("No, private network only"));
    fireEvent.click(screen.getByRole("button", { name: /submit answers/i }));

    expect(onSubmit.mock.calls[0][0]).toEqual([
      { questionId: "auth-on-notes-api", status: "skipped" },
      { questionId: "db-network-exposure", status: "answered", optionIndex: 0 },
    ]);
  });

  it("only ever submits statuses the answers route accepts", () => {
    const { onSubmit } = renderPanel();

    fireEvent.click(screen.getByLabelText(/not sure/i));
    fireEvent.click(screen.getByRole("button", { name: /submit answers/i }));

    const allowed = new Set(["answered", "skipped", "unsure"]);
    onSubmit.mock.calls[0][0].forEach((answer: { status: string }) => {
      expect(allowed.has(answer.status)).toBe(true);
    });
  });

  it("disables the button and shows progress while submitting", () => {
    renderPanel({ submitting: true });

    const button = screen.getByRole("button", { name: /submitting/i });
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows a submission error using the backend's own copy", () => {
    renderPanel({
      error: {
        code: "AI_FAILURE",
        title: "Analysis failed",
        message: "This analysis is not waiting for answers.",
        canRetry: true,
      },
    });

    expect(screen.getByRole("alert").textContent).toContain(
      "This analysis is not waiting for answers.",
    );
  });
});
