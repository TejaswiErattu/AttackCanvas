"use client";

/**
 * One threat, exactly as the server scored it.
 *
 * Severity, confidence, confidence label, priority, priority label, basis and basis label
 * are all rendered straight from ThreatCardData. Nothing on this card is derived,
 * re-thresholded or re-ranked in the browser — scoring belongs to src/server/scoring
 * (CLAUDE.md rule 2). The percentage shown is the server's already-rounded 0-100 value.
 *
 * `confidenceReasons` are shown line for line, exactly as the adapter built them: exact
 * point contributions for most threats, qualitative wording for gap-backed ones. The card
 * adds no numbers, totals or wording of its own to them, since only the adapter knows
 * whether they add up to the percentage.
 *
 * Selecting the card is what drives graph highlighting: the parent passes the threat's
 * `highlightIds` to the architecture graph. The header is a real <button>, so selection is
 * keyboard-operable and announces its expanded state.
 *
 * All text here originates from repository content or a model and is untrusted; it is only
 * ever rendered as text (CLAUDE.md rule 3).
 */

import type { ThreatCardData } from "@/shared/viewModel";
import EvidencePanel from "@/components/EvidencePanel";
import { SEVERITY_BADGE_CLASS, SEVERITY_TEXT } from "@/components/SeveritySummary";

const CONFIDENCE_TEXT: Record<string, string> = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
};

const PRIORITY_BADGE_CLASS: Record<string, string> = {
  fix_now: "bg-mint text-ink border-mint",
  fix_soon: "bg-transparent text-mint border-mint/60",
  monitor: "bg-transparent text-muted border-line-strong",
};

const SEVERITY_STRIPE: Record<string, string> = {
  critical: "before:bg-sev-critical",
  high: "before:bg-sev-high",
  medium: "before:bg-sev-medium",
  low: "before:bg-sev-low",
};

type ThreatCardProps = {
  threat: ThreatCardData;
  selected: boolean;
  onSelect: (id: string) => void;
};

function Chip({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className="rounded-full border border-line bg-ink-2/80 px-2 py-0.5 text-[11px] font-medium text-muted"
    >
      {children}
    </span>
  );
}

function DetailHeading({ children }: { children: React.ReactNode }) {
  return (
    <h4 className="text-[11px] font-medium uppercase tracking-[0.14em] text-mint">{children}</h4>
  );
}

export default function ThreatCard({ threat, selected, onSelect }: ThreatCardProps) {
  const headingId = `threat-${threat.id}-title`;
  const detailsId = `threat-${threat.id}-details`;
  const severityClass =
    SEVERITY_BADGE_CLASS[threat.severity] ?? SEVERITY_BADGE_CLASS.low;
  const priorityClass = PRIORITY_BADGE_CLASS[threat.priority] ?? PRIORITY_BADGE_CLASS.monitor;
  const stripe = SEVERITY_STRIPE[threat.severity] ?? SEVERITY_STRIPE.low;

  return (
    <article
      data-testid={`threat-card-${threat.id}`}
      aria-labelledby={headingId}
      className={`relative overflow-hidden rounded-2xl border bg-surface/80 transition-colors before:absolute before:inset-y-0 before:left-0 before:w-1 ${stripe} ${
        selected ? "border-mint/70 bg-surface-2/90" : "border-line hover:border-line-strong"
      }`}
    >
      <button
        type="button"
        onClick={() => onSelect(threat.id)}
        aria-expanded={selected}
        aria-controls={detailsId}
        className="w-full rounded-2xl py-4 pl-6 pr-4 text-left sm:pr-5"
      >
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider ${severityClass}`}
          >
            {SEVERITY_TEXT[threat.severity] ?? threat.severity}
          </span>
          <span
            className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${priorityClass}`}
          >
            {threat.priorityLabel}
          </span>
          <span className="text-xs text-muted">
            {threat.confidence}% &middot;{" "}
            {CONFIDENCE_TEXT[threat.confidenceLabel] ?? threat.confidenceLabel}
          </span>
          <span aria-hidden="true" className="ml-auto text-subtle">
            {selected ? "\u2212" : "+"}
          </span>
        </div>

        <h3 id={headingId} className="mt-2 font-display text-lg font-semibold leading-snug text-fg">
          {threat.title}
        </h3>

        <p className="mt-1 text-xs text-subtle">
          {threat.basisLabel}
          {threat.componentNames?.length
            ? ` \u00b7 ${threat.componentNames.join(", ")}`
            : ""}
        </p>

        <div className="mt-3 flex flex-wrap gap-1.5">
          {(threat.stride ?? []).map((item) => (
            <Chip key={`s-${item.code}`} title={item.label}>
              {item.code} {item.label}
            </Chip>
          ))}
          {(threat.owasp ?? []).map((item) => (
            <Chip key={`o-${item.code}`} title={item.label}>
              {item.code} {item.label}
            </Chip>
          ))}
          {(threat.cwe ?? []).map((cwe) => (
            <Chip key={`c-${cwe}`}>{cwe}</Chip>
          ))}
        </div>
      </button>

      {selected ? (
        <div id={detailsId} className="space-y-6 border-t border-line py-5 pl-6 pr-4 sm:pr-5">
          <div>
            <DetailHeading>Attack scenario</DetailHeading>
            <p className="mt-2 text-sm leading-relaxed text-fg">{threat.attackScenario}</p>
          </div>

          <div>
            <DetailHeading>Evidence</DetailHeading>
            <div className="mt-2">
              <EvidencePanel evidence={threat.evidence ?? []} />
            </div>
          </div>

          {threat.confidenceReasons?.length ? (
            <div>
              <DetailHeading>Why this confidence</DetailHeading>
              <ul
                data-testid={`confidence-reasons-${threat.id}`}
                className="mt-2 space-y-1 rounded-xl border border-line bg-ink-2/70 p-3 font-mono text-xs text-muted"
              >
                {threat.confidenceReasons.map((line, index) => (
                  <li key={index}>{line}</li>
                ))}
              </ul>
            </div>
          ) : null}

          <div>
            <DetailHeading>Mitigation</DetailHeading>
            <p className="mt-2 text-sm text-fg">{threat.mitigation?.summary ?? ""}</p>
            {threat.mitigation?.steps?.length ? (
              <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-muted marker:text-mint">
                {threat.mitigation.steps.map((step, index) => (
                  <li key={index}>{step}</li>
                ))}
              </ol>
            ) : null}
            {threat.mitigation?.codeLocation ? (
              <p className="mt-2 break-all font-mono text-xs text-subtle">
                {threat.mitigation.codeLocation}
              </p>
            ) : null}
          </div>

          {threat.assumptions?.length ? (
            <div className="rounded-xl border border-sev-medium/30 bg-sev-medium/5 p-3">
              <DetailHeading>Assumptions</DetailHeading>
              <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
                {threat.assumptions.map((assumption, index) => (
                  <li key={index}>{assumption}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}
