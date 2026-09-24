import { beforeEach, describe, expect, it } from "vitest";
import {
  MAX_CONCURRENT_ANALYSES,
  MAX_TRACKED_KEYS,
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW_MS,
  checkConcurrency,
  checkRateLimit,
  clientKey,
  resetRateLimiter,
  trackedKeyCount,
} from "@/server/http/rateLimit";

beforeEach(() => {
  resetRateLimiter();
});

describe("checkRateLimit", () => {
  it("allows up to RATE_LIMIT_MAX attempts in a window, then refuses", () => {
    const now = 1_000_000;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      expect(checkRateLimit("1.2.3.4", now)).toBe(true);
    }
    expect(checkRateLimit("1.2.3.4", now)).toBe(false);
  });

  it("tracks each key independently", () => {
    const now = 1_000_000;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) checkRateLimit("a", now);
    expect(checkRateLimit("a", now)).toBe(false);
    expect(checkRateLimit("b", now)).toBe(true);
  });

  it("resets after the window elapses", () => {
    const now = 1_000_000;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) checkRateLimit("a", now);
    expect(checkRateLimit("a", now)).toBe(false);
    expect(checkRateLimit("a", now + RATE_LIMIT_WINDOW_MS + 1)).toBe(true);
  });

  it("is at the exact count boundary: the RATE_LIMIT_MAXth call succeeds, the next one does not", () => {
    const now = 1_000_000;
    for (let i = 0; i < RATE_LIMIT_MAX - 1; i++) {
      expect(checkRateLimit("boundary", now)).toBe(true);
    }
    expect(checkRateLimit("boundary", now)).toBe(true); // this is the RATE_LIMIT_MAXth
    expect(checkRateLimit("boundary", now)).toBe(false); // one past it
  });

  it("resets at exactly RATE_LIMIT_WINDOW_MS, not a moment before", () => {
    const now = 1_000_000;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) checkRateLimit("edge", now);
    expect(checkRateLimit("edge", now + RATE_LIMIT_WINDOW_MS - 1)).toBe(false); // still inside
    expect(checkRateLimit("edge", now + RATE_LIMIT_WINDOW_MS)).toBe(true); // exactly at it
  });

  it("admits requests 1-5 and rejects the 6th, spread across the hour rather than at one instant", () => {
    // The same-instant version above cannot tell a 1-minute window from a 1-hour one.
    // This walks real offsets inside the hour, so a window that silently shrank back to
    // 60s would let the later attempts through and fail here.
    const now = 1_000_000;
    const minute = 60_000;
    const offsets = [0, 5 * minute, 20 * minute, 45 * minute, 58 * minute];

    offsets.forEach((offset, index) => {
      expect(checkRateLimit("spread", now + offset), `request ${index + 1}`).toBe(true);
    });

    // 6th, still inside the same hour
    expect(checkRateLimit("spread", now + 59 * minute)).toBe(false);
    // and still refused one millisecond before the window closes
    expect(checkRateLimit("spread", now + RATE_LIMIT_WINDOW_MS - 1)).toBe(false);
    // the window is anchored to the FIRST request, so it opens exactly an hour after it
    expect(checkRateLimit("spread", now + RATE_LIMIT_WINDOW_MS)).toBe(true);
  });

  it("gives each IP its own budget: one exhausted key never blocks another", () => {
    const now = 1_000_000;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) checkRateLimit("203.0.113.5", now);

    expect(checkRateLimit("203.0.113.5", now)).toBe(false); // exhausted
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      expect(checkRateLimit("198.51.100.9", now), `other IP request ${i + 1}`).toBe(true);
    }
    expect(checkRateLimit("198.51.100.9", now)).toBe(false); // and has its own ceiling
  });

  it("sweeps expired windows, so keys seen once do not accumulate forever", () => {
    const now = 1_000_000;
    for (let i = 0; i < 50; i++) checkRateLimit(`198.51.100.${i}`, now);
    expect(trackedKeyCount()).toBe(50);

    checkRateLimit("203.0.113.5", now + RATE_LIMIT_WINDOW_MS);
    expect(trackedKeyCount()).toBe(1);
  });

  it("caps the number of tracked keys, dropping the oldest window first", () => {
    const now = 1_000_000;
    for (let i = 0; i < MAX_TRACKED_KEYS + 25; i++) checkRateLimit(`key-${i}`, now + i);
    expect(trackedKeyCount()).toBe(MAX_TRACKED_KEYS);

    // The newest keys keep their windows; the oldest were the ones dropped.
    const newest = `key-${MAX_TRACKED_KEYS + 24}`;
    for (let i = 1; i < RATE_LIMIT_MAX; i++) checkRateLimit(newest, now + MAX_TRACKED_KEYS + 30);
    expect(checkRateLimit(newest, now + MAX_TRACKED_KEYS + 30)).toBe(false);
  });
});

describe("clientKey", () => {
  it("reads the last hop of x-forwarded-for: the one the nearest proxy appended", () => {
    const headers = new Headers({ "x-forwarded-for": "10.0.0.1, 203.0.113.5" });
    expect(clientKey(headers)).toBe("203.0.113.5");
  });

  it("falls back to \"unknown\" when the header is absent", () => {
    expect(clientKey(new Headers())).toBe("unknown");
  });

  it.each([
    ["empty header", ""],
    ["whitespace only", "   "],
    ["trailing comma (empty last hop)", "10.0.0.1, "],
    ["comma only", ","],
    ["whitespace last hop", "10.0.0.1,   "],
  ])(
    "falls back to the documented \"unknown\" bucket for a malformed header: %s",
    (_label, value) => {
      // Documented behaviour (clientKey's own comment): an unusable header degrades to
      // ONE shared bucket rather than to "no limit". Asserting the fallback is the
      // sharing key -- not a per-request unique value -- is the point: a malformed
      // header must not become a way to mint a fresh budget per request.
      const headers = new Headers({ "x-forwarded-for": value });
      expect(clientKey(headers)).toBe("unknown");
    },
  );

  it("ignores an empty first hop: only the last one counts", () => {
    expect(clientKey(new Headers({ "x-forwarded-for": ", 10.0.0.1" }))).toBe("10.0.0.1");
    expect(clientKey(new Headers({ "x-forwarded-for": "  , 10.0.0.1" }))).toBe("10.0.0.1");
  });

  it("cannot be steered by client-supplied hops: a forged prefix never mints a new budget", () => {
    // A client controls everything LEFT of what its proxy appends. Proxies append, so a
    // forged value lands first and the real address last.
    const now = 1_000_000;
    for (let i = 0; i < RATE_LIMIT_MAX; i++) {
      const forged = new Headers({ "x-forwarded-for": `198.51.100.${i}, 203.0.113.5` });
      expect(checkRateLimit(clientKey(forged), now)).toBe(true);
    }
    const again = new Headers({ "x-forwarded-for": "192.0.2.77, 203.0.113.5" });
    expect(checkRateLimit(clientKey(again), now)).toBe(false);
  });

  it("shares one bucket across every malformed-header caller, by construction", () => {
    const now = 1_000_000;
    const malformed = new Headers({ "x-forwarded-for": "  " });
    const absent = new Headers();

    for (let i = 0; i < RATE_LIMIT_MAX; i++) checkRateLimit(clientKey(malformed), now);

    // Same bucket, so the absent-header caller is already exhausted too. This is the
    // documented limitation in docs/security-design.md ("Residual limits"), pinned here
    // so it stays a known trade rather than becoming a surprise.
    expect(checkRateLimit(clientKey(absent), now)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Prompt U, Part 2: the exact policy values, locked in explicitly so a future edit
// that quietly reverts "per hour" back to "per minute" (or loosens the concurrency
// cap) fails a test, not just a doc.
// ---------------------------------------------------------------------------

describe("policy constants", () => {
  it("is 5 attempts per IP per hour", () => {
    expect(RATE_LIMIT_MAX).toBe(5);
    expect(RATE_LIMIT_WINDOW_MS).toBe(60 * 60 * 1000);
  });

  it("caps global concurrency at 2 real analyses", () => {
    expect(MAX_CONCURRENT_ANALYSES).toBe(2);
  });
});

describe("checkConcurrency", () => {
  it("allows any count strictly below the max", () => {
    expect(checkConcurrency(0)).toBe(true);
    expect(checkConcurrency(MAX_CONCURRENT_ANALYSES - 1)).toBe(true);
  });

  it("refuses at and above the max", () => {
    expect(checkConcurrency(MAX_CONCURRENT_ANALYSES)).toBe(false);
    expect(checkConcurrency(MAX_CONCURRENT_ANALYSES + 1)).toBe(false);
  });

  it("accepts an explicit max override, for callers that need a different budget", () => {
    expect(checkConcurrency(1, 1)).toBe(false);
    expect(checkConcurrency(0, 1)).toBe(true);
  });
});
