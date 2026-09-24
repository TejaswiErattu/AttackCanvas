"use client";

/**
 * Filter controls for the threat list.
 *
 * Every option offered here comes from DashboardViewModel.filterOptions, which the server
 * builds from the threats it actually returned — so the bar never offers a facet value
 * that cannot match anything. The two exceptions are priority and basis, whose values are
 * closed enums in the frozen schema (src/shared/schema/enums.ts) rather than data, and are
 * labelled from src/shared/labels.ts.
 *
 * The bar owns no filtering logic: it hands a new ThreatFilters object to the parent via
 * the pure helpers in src/client/filterThreats.ts.
 *
 * Each group is a fieldset with a legend, and every checkbox has a real <label>, so the
 * whole bar is keyboard- and screen-reader-navigable.
 */

import { BASIS_LABELS, PRIORITY_LABELS } from "@/shared/labels";
import type { Basis, Priority } from "@/shared/schema";
import type { FilterOptions } from "@/shared/viewModel";
import {
  hasActiveFilters,
  toggleFilterValue,
  EMPTY_FILTERS,
  type ThreatFilters,
} from "@/client/filterThreats";
import { SEVERITY_TEXT } from "@/components/SeveritySummary";

const PRIORITY_VALUES: readonly Priority[] = ["fix_now", "fix_soon", "monitor"];
const BASIS_VALUES: readonly Basis[] = ["evidence_backed", "assumption_dependent"];

const CONFIDENCE_TEXT: Record<string, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

type FilterBarProps = {
  options: FilterOptions;
  filters: ThreatFilters;
  onChange: (next: ThreatFilters) => void;
};

type Option = { value: string; label: string };

function CheckboxGroup({
  legend,
  name,
  options,
  selected,
  onToggle,
}: {
  legend: string;
  name: string;
  options: readonly Option[];
  selected: readonly string[];
  onToggle: (value: string) => void;
}) {
  if (options.length === 0) return null;
  return (
    <fieldset className="min-w-0">
      <legend className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted">
        {legend}
      </legend>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {options.map((option) => {
          const id = `filter-${name}-${option.value}`;
          return (
            <div key={option.value} className="relative">
              <input
                id={id}
                type="checkbox"
                checked={selected.includes(option.value)}
                onChange={() => onToggle(option.value)}
                className="peer sr-only"
              />
              <label
                htmlFor={id}
                className="block cursor-pointer rounded-full border border-line bg-ink-2/70 px-3 py-1 text-xs text-muted transition-colors hover:border-line-strong peer-checked:border-mint peer-checked:bg-mint-deep peer-checked:text-fg peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-mint"
              >
                {option.label}
              </label>
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}

export default function FilterBar({ options, filters, onChange }: FilterBarProps) {
  const active = hasActiveFilters(filters);

  return (
    <section
      aria-labelledby="filter-bar-heading"
      className="rounded-2xl border border-line bg-surface/70 p-4 sm:p-5"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2
          id="filter-bar-heading"
          className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted"
        >
          Filters
        </h2>
        <button
          type="button"
          onClick={() => onChange({ ...EMPTY_FILTERS })}
          disabled={!active}
          className="rounded-full border border-line-strong px-3 py-1 text-xs font-medium text-fg hover:border-mint hover:text-mint disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-line-strong disabled:hover:text-fg"
        >
          Clear all
        </button>
      </div>

      <div className="mt-3">
        <label htmlFor="filter-search" className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted">
          Search threats
        </label>
        <input
          id="filter-search"
          type="search"
          value={filters.search}
          onChange={(event) => onChange({ ...filters, search: event.target.value })}
          placeholder="Title, component, CWE or OWASP category"
          className="mt-2 w-full rounded-full border border-line-strong bg-ink px-4 py-2 text-sm text-fg placeholder:text-subtle focus-visible:border-mint"
        />
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2 lg:grid-cols-1">
        <CheckboxGroup
          legend="Severity"
          name="severity"
          options={(options?.severities ?? []).map((value) => ({
            value,
            label: SEVERITY_TEXT[value] ?? value,
          }))}
          selected={filters.severities}
          onToggle={(value) =>
            onChange(toggleFilterValue(filters, "severities", value as never))
          }
        />

        <CheckboxGroup
          legend="Confidence"
          name="confidence"
          options={(options?.confidenceLabels ?? []).map((value) => ({
            value,
            label: CONFIDENCE_TEXT[value] ?? value,
          }))}
          selected={filters.confidenceLabels}
          onToggle={(value) =>
            onChange(toggleFilterValue(filters, "confidenceLabels", value as never))
          }
        />

        <CheckboxGroup
          legend="Priority"
          name="priority"
          options={PRIORITY_VALUES.map((value) => ({
            value,
            label: PRIORITY_LABELS[value],
          }))}
          selected={filters.priorities}
          onToggle={(value) =>
            onChange(toggleFilterValue(filters, "priorities", value as never))
          }
        />

        <CheckboxGroup
          legend="Basis"
          name="basis"
          options={BASIS_VALUES.map((value) => ({
            value,
            label: BASIS_LABELS[value],
          }))}
          selected={filters.basis}
          onToggle={(value) =>
            onChange(toggleFilterValue(filters, "basis", value as never))
          }
        />

        <CheckboxGroup
          legend="STRIDE"
          name="stride"
          options={(options?.stride ?? []).map((item) => ({
            value: item.code,
            label: `${item.code} \u2013 ${item.label}`,
          }))}
          selected={filters.stride}
          onToggle={(value) =>
            onChange(toggleFilterValue(filters, "stride", value as never))
          }
        />

        <CheckboxGroup
          legend="OWASP Top 10:2025"
          name="owasp"
          options={(options?.owasp ?? []).map((item) => ({
            value: item.code,
            label: `${item.code} \u2013 ${item.label}`,
          }))}
          selected={filters.owasp}
          onToggle={(value) =>
            onChange(toggleFilterValue(filters, "owasp", value as never))
          }
        />

        <CheckboxGroup
          legend="Component"
          name="component"
          options={(options?.components ?? []).map((item) => ({
            value: item.id,
            label: item.name,
          }))}
          selected={filters.componentIds}
          onToggle={(value) =>
            onChange(toggleFilterValue(filters, "componentIds", value as never))
          }
        />
      </div>
    </section>
  );
}
