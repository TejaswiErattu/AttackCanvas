"use client";

/**
 * Full screen for one element: the browser's Fullscreen API where it exists, and a
 * fixed-position overlay where it does not.
 *
 * Safari before 16.4 (and iPhone Safari) only has the webkit-prefixed API or none at all;
 * some embedding contexts refuse the request. Either way the reader still gets a bigger
 * diagram: the caller draws the "overlay" mode as a fixed, full-viewport element. Escape
 * leaves both modes (the browser handles it for native full screen, this hook for the
 * overlay), and the mode is kept in step when the browser leaves full screen on its own.
 *
 * The pure helpers take the element or document as an argument, so they run in tests
 * against plain objects.
 */

import { useCallback, useEffect, useRef, useState, type RefObject } from "react";

export type FullscreenMode = "off" | "native" | "overlay";

/** The prefixed and standard parts of Element this module uses. */
export type FullscreenElement = {
  requestFullscreen?: (options?: { navigationUI?: "hide" | "show" | "auto" }) => Promise<void>;
  webkitRequestFullscreen?: () => void | Promise<void>;
};

/** The prefixed and standard parts of Document this module uses. */
export type FullscreenDocument = {
  fullscreenElement?: Element | null;
  webkitFullscreenElement?: Element | null;
  exitFullscreen?: () => Promise<void>;
  webkitExitFullscreen?: () => void | Promise<void>;
};

/**
 * How long the browser gets to answer a full screen request before the overlay is used. A
 * browser normally answers at once; an embedded one (a webview, a frame without permission)
 * may never settle the request, and the button would seem dead.
 */
export const NATIVE_REQUEST_TIMEOUT_MS = 1200;

export const FULLSCREEN_CHANGE_EVENTS = ["fullscreenchange", "webkitfullscreenchange"] as const;

/** The element currently in native full screen, standard or prefixed, or null. */
export function activeFullscreenElement(doc: FullscreenDocument): Element | null {
  return doc.fullscreenElement ?? doc.webkitFullscreenElement ?? null;
}

/** True when `el` has a Fullscreen API to call, standard or prefixed. */
export function fullscreenSupported(el: FullscreenElement | null | undefined): boolean {
  return !!el && (typeof el.requestFullscreen === "function" || typeof el.webkitRequestFullscreen === "function");
}

/**
 * Asks the browser to put `el` in full screen. Resolves true when it did, false when the
 * API is missing or the request was refused, in which case the caller falls back to the
 * overlay. Never rejects.
 */
export async function enterNativeFullscreen(el: FullscreenElement | null | undefined): Promise<boolean> {
  if (!el) return false;
  try {
    if (typeof el.requestFullscreen === "function") {
      await el.requestFullscreen({ navigationUI: "hide" });
      return true;
    }
    if (typeof el.webkitRequestFullscreen === "function") {
      await el.webkitRequestFullscreen();
      return true;
    }
  } catch {
    // Refused (no user gesture, a frame that forbids it): use the overlay instead.
  }
  return false;
}

/** Leaves native full screen, standard or prefixed. Never rejects. */
export async function exitNativeFullscreen(doc: FullscreenDocument): Promise<void> {
  try {
    if (typeof doc.exitFullscreen === "function") await doc.exitFullscreen();
    else if (typeof doc.webkitExitFullscreen === "function") await doc.webkitExitFullscreen();
  } catch {
    // Already out.
  }
}

/** One request for native full screen, from the click to the browser's answer (or its absence). */
type Attempt = { cancelled: boolean };

export function useFullscreen(ref: RefObject<HTMLElement | null>): {
  mode: FullscreenMode;
  toggle: () => void;
} {
  const [mode, setModeState] = useState<FullscreenMode>("off");
  // The mode as of right now. State only catches up on the next render, so two clicks in
  // one tick would both read the old value; every change goes through setMode to keep this
  // in step.
  const modeRef = useRef<FullscreenMode>("off");
  // The request still waiting for the browser, if any: a click while one waits cancels it.
  const inFlight = useRef<Attempt | null>(null);
  // The newest request ever made. An older request that is answered late must not undo
  // the full screen a newer one is responsible for.
  const newest = useRef<Attempt | null>(null);
  // The element we asked the browser to put in full screen.
  const requested = useRef<Element | null>(null);

  const setMode = useCallback((next: FullscreenMode) => {
    modeRef.current = next;
    setModeState(next);
  }, []);

  const toggle = useCallback(() => {
    if (inFlight.current) {
      // The browser has not answered the last click yet: this click withdraws it.
      inFlight.current.cancelled = true;
      inFlight.current = null;
      return;
    }
    if (modeRef.current === "overlay") {
      setMode("off");
      return;
    }
    if (modeRef.current === "native") {
      setMode("off");
      void exitNativeFullscreen(document as FullscreenDocument);
      return;
    }

    const attempt: Attempt = { cancelled: false };
    inFlight.current = attempt;
    newest.current = attempt;
    requested.current = ref.current;
    const request = enterNativeFullscreen(ref.current as FullscreenElement | null);
    // A request that is answered after we gave up on it: if the browser grants it, undo
    // that, unless a newer request has since taken over.
    const undoIfLate = () =>
      void request.then((ok) => {
        if (ok && newest.current === attempt) void exitNativeFullscreen(document as FullscreenDocument);
      });

    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), NATIVE_REQUEST_TIMEOUT_MS);
    });
    void Promise.race([request, timeout]).then((settled) => {
      clearTimeout(timer);
      if (inFlight.current === attempt) inFlight.current = null;
      if (attempt.cancelled) {
        undoIfLate();
        return;
      }
      if (settled === "timeout") {
        setMode("overlay");
        undoIfLate();
        return;
      }
      setMode(settled ? "native" : "overlay");
    });
  }, [ref, setMode]);

  // The browser can leave native full screen without us (Escape, a gesture, another tab).
  useEffect(() => {
    if (mode !== "native") return;
    const onChange = () => {
      if (activeFullscreenElement(document as FullscreenDocument) !== ref.current) setMode("off");
    };
    for (const name of FULLSCREEN_CHANGE_EVENTS) document.addEventListener(name, onChange);
    return () => {
      for (const name of FULLSCREEN_CHANGE_EVENTS) document.removeEventListener(name, onChange);
    };
  }, [mode, ref, setMode]);

  // The overlay has no browser Escape of its own, and must not let the page scroll behind it.
  useEffect(() => {
    if (mode !== "overlay") return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMode("off");
    };
    const root = document.documentElement;
    const previous = root.style.overflow;
    root.style.overflow = "hidden";
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      root.style.overflow = previous;
    };
  }, [mode, setMode]);

  // Leaving the page (or the diagram unmounting) must not leave this diagram in full screen,
  // and must not touch some other element that is. A request still waiting is withdrawn, so
  // a late grant is undone.
  useEffect(() => {
    const waiting = inFlight;
    const asked = requested;
    return () => {
      if (waiting.current) waiting.current.cancelled = true;
      const doc = document as FullscreenDocument;
      if (asked.current && activeFullscreenElement(doc) === asked.current) void exitNativeFullscreen(doc);
    };
  }, []);

  return { mode, toggle };
}
