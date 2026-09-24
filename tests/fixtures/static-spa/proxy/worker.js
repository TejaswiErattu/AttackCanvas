// ============================================================================
// CLOUDFLARE WORKER - Mode B proxy for the study-tracker chatbot
//
// What this does:
//   1. Verifies the caller's Google ID token SERVER-SIDE (signature against
//      Google's published JWKS, issuer, audience, expiry, email_verified).
//   2. Checks the email against an allowlist held in a Worker env var.
//   3. Only then forwards the request body to the Anthropic Messages API,
//      adding the API key from a Worker secret.
//
// This is the mode to use once anyone other than you can reach the deployed
// site. Unlike the browser-side gate, these checks cannot be bypassed from
// DevTools, and the Anthropic key never leaves the server.
//
// Required environment variables (see README.md):
//   ANTHROPIC_API_KEY   (secret)   your Anthropic key
//   GOOGLE_CLIENT_ID    (var)      must match the client ID in auth-config.js
//   ALLOWED_EMAILS      (var)      comma-separated list of permitted emails
//   ALLOWED_ORIGINS     (var)      comma-separated list of permitted origins
// ============================================================================

const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

// Reject oversized bodies outright - this endpoint only ever receives a small
// JSON payload, and refusing early keeps a hostile caller from burning CPU.
const MAX_BODY_BYTES = 128 * 1024; // 128 KB

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "";
    const cors = corsHeaders(origin, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== "POST") {
      return json({ error: "Method not allowed" }, 405, cors);
    }
    if (!isOriginAllowed(origin, env)) {
      return json({ error: "Origin not allowed" }, 403, cors);
    }

    // --- size guard (declared length, then actual) ---
    const declared = Number(request.headers.get("content-length") || 0);
    if (declared && declared > MAX_BODY_BYTES) {
      return json({ error: "Request body too large" }, 413, cors);
    }

    const raw = await request.text();
    if (byteLength(raw) > MAX_BODY_BYTES) {
      return json({ error: "Request body too large" }, 413, cors);
    }

    // --- auth: verify the Google ID token ---
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    if (!token) {
      return json({ error: "Missing Google ID token" }, 401, cors);
    }

    let claims;
    try {
      claims = await verifyGoogleIdToken(token, env.GOOGLE_CLIENT_ID);
    } catch (e) {
      // Never echo the token back, and never log it.
      return json({ error: `Token rejected: ${e.message}` }, 401, cors);
    }

    if (!isEmailAllowed(claims.email, env.ALLOWED_EMAILS)) {
      return json({ error: "This account is not authorized" }, 401, cors);
    }

    // --- shape guard on the forwarded body ---
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return json({ error: "Body must be valid JSON" }, 400, cors);
    }
    if (!body || typeof body !== "object" || !Array.isArray(body.messages)) {
      return json({ error: "Body must be an Anthropic Messages request" }, 400, cors);
    }
    // Don't let a caller pick an arbitrarily huge max_tokens on your bill.
    if (typeof body.max_tokens !== "number" || body.max_tokens > 4096) {
      body.max_tokens = 2048;
    }

    if (!env.ANTHROPIC_API_KEY) {
      return json({ error: "Proxy is missing ANTHROPIC_API_KEY" }, 500, cors);
    }

    // --- forward ---
    let upstream;
    try {
      upstream = await fetch(ANTHROPIC_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": env.ANTHROPIC_API_KEY,
          "anthropic-version": ANTHROPIC_VERSION
        },
        body: JSON.stringify(body)
      });
    } catch (e) {
      return json({ error: "Upstream request failed" }, 502, cors);
    }

    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: { ...cors, "content-type": "application/json" }
    });
  }
};

// --- CORS -------------------------------------------------------------------
function allowedOrigins(env) {
  return String(env.ALLOWED_ORIGINS || "")
    .split(",").map(s => s.trim()).filter(Boolean);
}

function isOriginAllowed(origin, env) {
  const list = allowedOrigins(env);
  if (list.length === 0) return true; // unset = allow all (tighten in production)
  return list.includes(origin);
}

function corsHeaders(origin, env) {
  const list = allowedOrigins(env);
  const allow = list.length === 0 ? "*" : (list.includes(origin) ? origin : list[0]);
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...headers, "content-type": "application/json" }
  });
}

function byteLength(s) { return new TextEncoder().encode(s).length; }

// --- Allowlist --------------------------------------------------------------
function isEmailAllowed(email, allowedCsv) {
  if (!email) return false;
  const list = String(allowedCsv || "")
    .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  if (list.length === 0) return false; // fail closed: unset means nobody
  return list.includes(String(email).trim().toLowerCase());
}

// --- Google ID token verification -------------------------------------------
// Full verification: signature (RS256 against Google's JWKS), issuer,
// audience, expiry, not-before, and email_verified.
let jwksCache = { keys: null, fetchedAt: 0 };
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour

async function getGoogleKeys() {
  const now = Date.now();
  if (jwksCache.keys && now - jwksCache.fetchedAt < JWKS_TTL_MS) {
    return jwksCache.keys;
  }
  const res = await fetch(GOOGLE_JWKS_URL);
  if (!res.ok) throw new Error("could not fetch Google signing keys");
  const data = await res.json();
  jwksCache = { keys: data.keys || [], fetchedAt: now };
  return jwksCache.keys;
}

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

export async function verifyGoogleIdToken(token, expectedAud) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");

  const [headerB64, payloadB64, sigB64] = parts;
  let header, claims;
  try {
    header = b64urlToJson(headerB64);
    claims = b64urlToJson(payloadB64);
  } catch {
    // Don't leak a raw parser error back to the caller.
    throw new Error("malformed token");
  }

  if (header.alg !== "RS256") throw new Error("unexpected signing algorithm");

  // --- signature ---
  const keys = await getGoogleKeys();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error("unknown signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(sigB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  );
  if (!valid) throw new Error("signature verification failed");

  // --- claims ---
  if (!GOOGLE_ISSUERS.includes(claims.iss)) throw new Error("unexpected issuer");

  if (!expectedAud) throw new Error("proxy is missing GOOGLE_CLIENT_ID");
  if (claims.aud !== expectedAud) throw new Error("audience mismatch");

  const now = Math.floor(Date.now() / 1000);
  const SKEW = 60; // seconds of clock tolerance
  if (typeof claims.exp !== "number" || now > claims.exp + SKEW) {
    throw new Error("token expired");
  }
  if (typeof claims.nbf === "number" && now < claims.nbf - SKEW) {
    throw new Error("token not yet valid");
  }
  if (typeof claims.iat === "number" && now < claims.iat - SKEW) {
    throw new Error("token issued in the future");
  }
  if (claims.email_verified === false) throw new Error("email not verified");
  if (!claims.email) throw new Error("token has no email claim");

  return claims;
}

// Exported for tests.
export const __internals = { isEmailAllowed, isOriginAllowed, MAX_BODY_BYTES };
