// ============================================================================
// GOOGLE SIGN-IN (Google Identity Services)
//
// Uses the current GIS library (accounts.google.com/gsi/client), not the
// deprecated gapi.auth2 / "Google Sign-In for Websites" library.
//
// ***  READ THIS BEFORE TRUSTING THIS FILE  ***
// In Mode A (direct browser calls, Anthropic key in localStorage) this is a
// UI LOCK, NOT A SECURITY BOUNDARY. All of the checks below run in the browser,
// so anyone with DevTools open can bypass them - and they would not even need
// to, because in Mode A the Anthropic key is sitting in localStorage in the
// same browser profile and can simply be read. This gate stops a passer-by from
// using the chatbot on an unlocked laptop. It stops nothing else.
//
// In Mode B (Cloudflare Worker proxy) the SAME ID token is verified server-side
// in proxy/worker.js - signature against Google's JWKS, audience, expiry, and
// allowlist - and that check IS a real boundary, because the Anthropic key
// never leaves the Worker.
// ============================================================================

import {
  GOOGLE_CLIENT_ID, ALLOWED_EMAILS, ALLOW_LOCALHOST_BYPASS, isLocalhost, isConfigured
} from "./auth-config.js?v=20260916a";
import { registerIdTokenGetter } from "./api.js?v=20260916a";

const GIS_SRC = "https://accounts.google.com/gsi/client";

// sessionStorage, deliberately: the session dies when the browser closes rather
// than persisting indefinitely the way localStorage would.
const SESSION_KEY = "chatbot_google_session";

let gisLoaded = false;
let session = null;              // { idToken, email, name, picture, exp }
const listeners = new Set();

export function onAuthChange(cb) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}
function emit() {
  listeners.forEach(cb => { try { cb(getSession()); } catch (e) { console.warn("[chatbot auth]", e); } });
}

// --- JWT decoding -----------------------------------------------------------
// NOTE: this decodes WITHOUT verifying the signature. That is fine for what we
// use it for here - populating the UI and checking the allowlist to decide
// whether to unlock the panel - and it is NOT sufficient for authorization.
// Real verification happens server-side in proxy/worker.js (Mode B).
export function decodeJwt(token) {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = decodeURIComponent(
      atob(pad).split("").map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)).join("")
    );
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function emailAllowed(email) {
  if (!email) return false;
  const e = String(email).trim().toLowerCase();
  return ALLOWED_EMAILS.some(a => String(a).trim().toLowerCase() === e);
}

// --- Session ----------------------------------------------------------------
function persist(s) {
  try {
    if (s) sessionStorage.setItem(SESSION_KEY, JSON.stringify(s));
    else sessionStorage.removeItem(SESSION_KEY);
  } catch {}
}

function loadPersisted() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw);
    if (!s || !s.exp) return null;
    // A real session must carry a token; the localhost dev bypass has none.
    if (!s.devBypass && !s.idToken) return null;
    return s;
  } catch {
    return null;
  }
}
