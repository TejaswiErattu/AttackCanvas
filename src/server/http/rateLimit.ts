/**
 * A minimal in-memory, fixed-window rate limiter for the analyze endpoint, plus a
 * global concurrency cap (Prompt U Part 2: cost-abuse controls).
 *
 * Matches src/server/analysis/pipeline.ts's own choice: this app is single-process and
 * already keeps its job store in memory, so a second in-memory Map for request counts
 * adds no new deployment constraint. Keyed by caller IP (or "unknown" when no proxy
 * header is present, which degrades to one shared global bucket -- acceptable for a
 * single-instance deployment, not for one behind a untrusted multi-tenant proxy). The
 * Map is swept of expired windows and capped at MAX_TRACKED_KEYS, so a stream of
 * distinct keys cannot grow it without bound.
 *
 * Two separate controls, because they answer different abuse shapes:
 *   - checkRateLimit bounds how often ONE caller may start an analysis (5 per IP per
 *     hour), which is what stops a single abusive client from running up cost alone.
 *   - checkConcurrency bounds how many REAL analyses run at once, GLOBALLY, regardless
 *     of who started them -- the control docs/security-design.md calls out for "denial
 *     of wallet": a gap-rich repository produces more elements worth reasoning about
 *     and therefore more model calls, so even a handful of callers each within their
 *     own per-IP limit could otherwise stack an unbounded number of expensive analyses
 *     in flight simultaneously. The golden-demo path is exempt (src/app/api/analyze
 *     route.ts checks isDemo before calling this): a demo job is seeded from a fixture
 *     and never calls a paid model, so it does not compete for this budget.
 */

export const RATE_LIMIT_MAX = 5;
export const RATE_LIMIT_WINDOW_MS = 60 * 60_000; // 1 hour

/** Most keys tracked at once. Past it, the oldest window is dropped for the new one. */
export const MAX_TRACKED_KEYS = 10_000;

/** How often expired windows are swept out, at most. */
const SWEEP_INTERVAL_MS = 60_000;

type Window = { count: number; windowStart: number };

/**
 * Insertion-ordered, and a key is re-inserted whenever its window restarts, so iteration
 * order is window-start order: the first entry is always the oldest window.
 */
const windows = new Map<string, Window>();
let lastSweep = Number.NEGATIVE_INFINITY;

/** Drops every window that has expired. Deleting while iterating a Map is safe. */
function sweepExpired(now: number): void {
  for (const [key, window] of windows) {
    if (now - window.windowStart >= RATE_LIMIT_WINDOW_MS) windows.delete(key);
  }
  lastSweep = now;
}

/**
 * Records one attempt for `key` and reports whether it is allowed under the fixed
 * window. `now` is injectable so tests do not depend on wall-clock timing.
 */
export function checkRateLimit(key: string, now: number = Date.now()): boolean {
  if (now - lastSweep >= SWEEP_INTERVAL_MS) sweepExpired(now);

  const existing = windows.get(key);
  if (!existing || now - existing.windowStart >= RATE_LIMIT_WINDOW_MS) {
    windows.delete(key); // re-inserted below, at the end: window-start order
    while (windows.size >= MAX_TRACKED_KEYS) {
      const oldest = windows.keys().next();
      if (oldest.done) break;
      windows.delete(oldest.value);
    }
    windows.set(key, { count: 1, windowStart: now });
    return true;
  }
  if (existing.count >= RATE_LIMIT_MAX) return false;
  existing.count += 1;
  return true;
}

/** Test-only: drops every recorded window. */
export function resetRateLimiter(): void {
  windows.clear();
  lastSweep = Number.NEGATIVE_INFINITY;
}

/** Test-only: how many keys currently hold a window. */
export function trackedKeyCount(): number {
  return windows.size;
}

/**
 * The caller's IP from the standard proxy header, or "unknown" when it is absent or its
 * last hop is empty.
 *
 * The RIGHTMOST hop, not the first: every proxy appends the address it received the
 * request from, so the last entry is the one our nearest proxy wrote, while everything
 * to its left arrived from the client and can be anything. Reading the first hop let a
 * client send a fresh `X-Forwarded-For` per request and get a fresh budget each time.
 *
 * Limitation: without a proxy in front, Next.js only fills the header when the request
 * lacks one (`??=`), so a client talking to `next start` directly still controls it.
 * Deploy behind a proxy that appends or overwrites X-Forwarded-For.
 */
export function clientKey(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for");
  const last = forwarded?.split(",").pop()?.trim();
  return last && last.length > 0 ? last : "unknown";
}

// ---------------------------------------------------------------------------
// Concurrency cap
// ---------------------------------------------------------------------------

/** Global ceiling on real (non-demo) analyses running at once. */
export const MAX_CONCURRENT_ANALYSES = 2;

/**
 * Pure comparator, deliberately not the counter itself: counting "how many analyses
 * are active right now" needs the job store in src/server/analysis/pipeline.ts
 * (`countActiveAnalyses`), and this module has no reason to depend on that one or hold
 * its own parallel notion of "active". The route composes the two:
 *
 *   checkConcurrency(countActiveAnalyses())
 *
 * `< max`, not `<= max`: `active` already counts the analyses in flight BEFORE the
 * caller's new one is created, so `active === max` means accepting one more would push
 * the count to `max + 1`.
 */
export function checkConcurrency(
  active: number,
  max: number = MAX_CONCURRENT_ANALYSES,
): boolean {
  return active < max;
}
