// @vitest-environment jsdom

/**
 * src/client/useFullscreen.ts against fake elements and a fake fullscreenElement: the
 * standard API, the webkit-prefixed one, a refused request, the overlay fallback, and
 * every way out (the button, Escape in the overlay, the browser leaving by itself).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, renderHook } from "@testing-library/react";
import {
  activeFullscreenElement,
  enterNativeFullscreen,
  exitNativeFullscreen,
  fullscreenSupported,
  NATIVE_REQUEST_TIMEOUT_MS,
  useFullscreen,
  type FullscreenElement,
} from "@/client/useFullscreen";

let current: Element | null = null;
const doc = document as unknown as Record<string, unknown>;

function install() {
  Object.defineProperty(document, "fullscreenElement", { configurable: true, get: () => current });
  doc.exitFullscreen = vi.fn(async () => {
    current = null;
  });
}

afterEach(() => {
  cleanup();
  current = null;
  for (const key of ["fullscreenElement", "webkitFullscreenElement", "exitFullscreen", "webkitExitFullscreen"]) {
    delete doc[key];
  }
  document.documentElement.style.overflow = "";
});

function hookFor(el: HTMLElement) {
  return renderHook(() => useFullscreen({ current: el }));
}

describe("the helpers", () => {
  it("know a standard, a prefixed and a missing API", () => {
    expect(fullscreenSupported({ requestFullscreen: async () => {} })).toBe(true);
    expect(fullscreenSupported({ webkitRequestFullscreen: () => {} })).toBe(true);
    expect(fullscreenSupported({})).toBe(false);
    expect(fullscreenSupported(null)).toBe(false);
  });

  it("reads the active element from either name", () => {
    const el = document.createElement("div");
    expect(activeFullscreenElement({ fullscreenElement: el })).toBe(el);
    expect(activeFullscreenElement({ webkitFullscreenElement: el })).toBe(el);
    expect(activeFullscreenElement({})).toBeNull();
  });

  it("enters natively through the standard API, then the prefixed one, else reports false", async () => {
    const standard = vi.fn(async () => {});
    const prefixed = vi.fn();
    expect(await enterNativeFullscreen({ requestFullscreen: standard, webkitRequestFullscreen: prefixed })).toBe(true);
    expect(standard).toHaveBeenCalledTimes(1);
    expect(prefixed).not.toHaveBeenCalled();
    expect(await enterNativeFullscreen({ webkitRequestFullscreen: prefixed })).toBe(true);
    expect(prefixed).toHaveBeenCalledTimes(1);
    expect(await enterNativeFullscreen({})).toBe(false);
    expect(await enterNativeFullscreen(null)).toBe(false);
  });

  it("reports false, and never rejects, when the browser refuses", async () => {
    const refused: FullscreenElement = { requestFullscreen: () => Promise.reject(new TypeError("denied")) };
    expect(await enterNativeFullscreen(refused)).toBe(false);
  });

  it("exits through the standard or prefixed API and never rejects", async () => {
    const standard = vi.fn(async () => {});
    const prefixed = vi.fn();
    await exitNativeFullscreen({ exitFullscreen: standard, webkitExitFullscreen: prefixed });
    expect(standard).toHaveBeenCalledTimes(1);
    expect(prefixed).not.toHaveBeenCalled();
    await exitNativeFullscreen({ webkitExitFullscreen: prefixed });
    expect(prefixed).toHaveBeenCalledTimes(1);
    await expect(exitNativeFullscreen({ exitFullscreen: () => Promise.reject(new Error("x")) })).resolves.toBeUndefined();
    await expect(exitNativeFullscreen({})).resolves.toBeUndefined();
  });
});

describe("useFullscreen with the Fullscreen API", () => {
  it("goes native on toggle and back off on the next", async () => {
    install();
    const el = document.createElement("div");
    el.requestFullscreen = vi.fn(async () => {
      current = el;
    });
    const { result } = hookFor(el);
    expect(result.current.mode).toBe("off");
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("native");
    expect(el.requestFullscreen).toHaveBeenCalledTimes(1);
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("off");
    expect(doc.exitFullscreen).toHaveBeenCalledTimes(1);
  });

  it("uses the webkit-prefixed API when that is all there is", async () => {
    install();
    const el = document.createElement("div");
    (el as unknown as FullscreenElement).webkitRequestFullscreen = vi.fn();
    const { result } = hookFor(el);
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("native");
  });

  it("follows the browser leaving full screen on its own (Escape)", async () => {
    install();
    const el = document.createElement("div");
    el.requestFullscreen = vi.fn(async () => {
      current = el;
    });
    const { result } = hookFor(el);
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("native");
    current = null;
    act(() => {
      document.dispatchEvent(new Event("fullscreenchange"));
    });
    expect(result.current.mode).toBe("off");
  });

  it("stays native while another element's change event fires and this one is still full screen", async () => {
    install();
    const el = document.createElement("div");
    el.requestFullscreen = vi.fn(async () => {
      current = el;
    });
    const { result } = hookFor(el);
    await act(async () => result.current.toggle());
    act(() => {
      document.dispatchEvent(new Event("fullscreenchange"));
    });
    expect(result.current.mode).toBe("native");
  });
});

describe("useFullscreen without it", () => {
  it("falls back to the overlay when there is no API", async () => {
    const { result } = hookFor(document.createElement("div"));
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("overlay");
  });

  it("falls back to the overlay when the request is refused", async () => {
    const el = document.createElement("div");
    el.requestFullscreen = () => Promise.reject(new TypeError("denied"));
    const { result } = hookFor(el);
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("overlay");
  });

  it("leaves the overlay on the next toggle, and on Escape", async () => {
    const { result } = hookFor(document.createElement("div"));
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("overlay");
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("off");

    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("overlay");
    act(() => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    });
    expect(result.current.mode).toBe("off");
  });

  it("ignores other keys, and stops the page scrolling behind the overlay only while it is open", async () => {
    const { result } = hookFor(document.createElement("div"));
    await act(async () => result.current.toggle());
    expect(document.documentElement.style.overflow).toBe("hidden");
    act(() => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "a" }));
    });
    expect(result.current.mode).toBe("overlay");
    act(() => result.current.toggle());
    expect(document.documentElement.style.overflow).toBe("");
  });

  it("stops listening for Escape once it is off", async () => {
    const add = vi.spyOn(document, "removeEventListener");
    const { result } = hookFor(document.createElement("div"));
    await act(async () => result.current.toggle());
    act(() => result.current.toggle());
    expect(add).toHaveBeenCalledWith("keydown", expect.any(Function));
  });
});

describe("useFullscreen when the browser never answers", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("uses the overlay after the timeout instead of leaving the button dead", async () => {
    install();
    const el = document.createElement("div");
    el.requestFullscreen = () => new Promise<void>(() => {});
    const { result } = hookFor(el);
    act(() => result.current.toggle());
    expect(result.current.mode).toBe("off");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(NATIVE_REQUEST_TIMEOUT_MS + 10);
    });
    expect(result.current.mode).toBe("overlay");
  });

  it("undoes a native grant that arrives after the overlay is already showing", async () => {
    install();
    const el = document.createElement("div");
    let grant: () => void = () => {};
    el.requestFullscreen = () =>
      new Promise<void>((resolve) => {
        grant = () => {
          current = el;
          resolve();
        };
      });
    const { result } = hookFor(el);
    act(() => result.current.toggle());
    await act(async () => {
      await vi.advanceTimersByTimeAsync(NATIVE_REQUEST_TIMEOUT_MS + 10);
    });
    expect(result.current.mode).toBe("overlay");
    await act(async () => {
      grant();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(doc.exitFullscreen).toHaveBeenCalledTimes(1);
    expect(result.current.mode).toBe("overlay");
  });

  it("takes a prompt answer without waiting for the timeout", async () => {
    install();
    const el = document.createElement("div");
    el.requestFullscreen = vi.fn(async () => {
      current = el;
    });
    const { result } = hookFor(el);
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("native");
  });
});

describe("useFullscreen repeated clicks and stale answers", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  /** An element whose request settles only when the test says so. */
  function slowElement() {
    const el = document.createElement("div");
    const calls: { grant: () => void; refuse: () => void }[] = [];
    el.requestFullscreen = () =>
      new Promise<void>((resolve, reject) => {
        calls.push({
          grant: () => {
            current = el;
            resolve();
          },
          refuse: () => reject(new TypeError("denied")),
        });
      });
    return { el, calls };
  }
  const wait = (ms: number) =>
    act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });

  it("a second click in the same tick undoes the first instead of entering again", async () => {
    // No API: the first click's fallback is the overlay, the second must leave it.
    const { result } = hookFor(document.createElement("div"));
    await act(async () => {
      result.current.toggle();
      result.current.toggle();
    });
    await wait(10);
    expect(result.current.mode).toBe("off");
  });

  it("a click while the browser has not answered cancels the attempt", async () => {
    install();
    const { el, calls } = slowElement();
    const { result } = hookFor(el);
    act(() => result.current.toggle());
    await wait(400);
    act(() => result.current.toggle());
    await wait(NATIVE_REQUEST_TIMEOUT_MS + 100);
    expect(result.current.mode).toBe("off");
    expect(calls).toHaveLength(1); // no second request was made
  });

  it("undoes a native grant that arrives for a cancelled attempt", async () => {
    install();
    const { el, calls } = slowElement();
    const { result } = hookFor(el);
    act(() => result.current.toggle());
    act(() => result.current.toggle());
    await act(async () => {
      calls[0].grant();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(doc.exitFullscreen).toHaveBeenCalledTimes(1);
    expect(result.current.mode).toBe("off");
  });

  it("does not let an old attempt's late grant undo a newer attempt's full screen", async () => {
    install();
    const { el, calls } = slowElement();
    const { result } = hookFor(el);
    act(() => result.current.toggle()); // attempt 1
    await wait(NATIVE_REQUEST_TIMEOUT_MS + 10);
    expect(result.current.mode).toBe("overlay");
    act(() => result.current.toggle()); // leave the overlay
    act(() => result.current.toggle()); // attempt 2
    expect(calls).toHaveLength(2);
    await act(async () => {
      calls[0].grant(); // attempt 1 answers late
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(doc.exitFullscreen).not.toHaveBeenCalled();
  });

  it("only exits full screen on unmount when this diagram is the one in full screen", async () => {
    install();
    const el = document.createElement("div");
    el.requestFullscreen = vi.fn(async () => {
      current = el;
    });
    const { result, unmount } = hookFor(el);
    await act(async () => result.current.toggle());
    expect(result.current.mode).toBe("native");
    unmount();
    expect(doc.exitFullscreen).toHaveBeenCalledTimes(1);

    cleanup();
    install();
    const other = document.createElement("video");
    current = other; // something else is in full screen
    const second = hookFor(document.createElement("div"));
    second.unmount();
    expect(doc.exitFullscreen).not.toHaveBeenCalled();
  });
});

