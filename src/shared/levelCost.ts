import type { AnalysisLevel } from "@/shared/schema";

/**
 * Shown next to each level in the picker: "about $low to $high for a small repository".
 * Level 2 is measured (six NodeGoat runs, $2.84 to $4.07); the others are estimates from
 * list prices. docs/cost.md shows the working. Lives in src/shared so the client can
 * import it without pulling in server modules; src/server/ai/levels.ts re-exports it.
 */
export const LEVEL_COST_RANGES: Readonly<Record<AnalysisLevel, { low: number; high: number }>> = {
  0: { low: 0.3, high: 0.6 },
  1: { low: 1, high: 1.5 },
  2: { low: 3, high: 4 },
  3: { low: 3.5, high: 5 },
  4: { low: 4, high: 6 },
};

/**
 * Levels switched off on the hosted deployment: the most expensive one, so a shared,
 * self-funded demo cannot be run up by testers. The picker refuses it with this message
 * and POST /api/analyze enforces it, so a direct API call cannot get around the page.
 */
export const LOCKED_LEVELS: readonly AnalysisLevel[] = [4];

export const LOCKED_LEVEL_MESSAGE =
  "Level 4 is switched off for this demo: it costs about $4 to $6 a run, and this is a shared, self-funded deployment. Please pick a level from 0 to 3. Thank you!";

export function isLevelLocked(level: number): boolean {
  return (LOCKED_LEVELS as readonly number[]).includes(level);
}

export function formatCostRange(level: AnalysisLevel): string {
  const { low, high } = LEVEL_COST_RANGES[level];
  const usd = (n: number) => `$${Number.isInteger(n) ? String(n) : n.toFixed(2)}`;
  return `about ${usd(low)} to ${usd(high)} for a small repository`;
}
