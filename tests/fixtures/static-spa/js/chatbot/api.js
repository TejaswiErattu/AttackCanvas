// ============================================================================
// ANTHROPIC API CLIENT - Mode A (direct browser) and Mode B (proxy)
//
// The API key is read from localStorage at call time and placed only in a
// request header. It is never logged, never interpolated into a URL, never put
// in an error message, and never persisted anywhere but that one key.
// ============================================================================

const API_URL = "https://api.anthropic.com/v1/messages";
const API_VERSION = "2023-06-01";

export const SETTINGS_KEY = "chatbot_settings_v1";
export const API_KEY_STORAGE_KEY = "chatbot_anthropic_api_key";

// Adding a model later is a one-line change here.
export const MODELS = [
  { id: "claude-sonnet-5",           label: "Sonnet 5 (default, balanced)", inputPerMTok: 2, outputPerMTok: 10 },
  { id: "claude-haiku-4-5-20251001", label: "Haiku 4.5 (cheapest)",         inputPerMTok: 1, outputPerMTok: 5 },
  { id: "claude-opus-5",             label: "Opus 5 (most accurate, pricey)", inputPerMTok: 5, outputPerMTok: 25 }
];

export const DEFAULT_MODEL = "claude-sonnet-5";

export function getModel(id) {
  return MODELS.find(m => m.id === id) || MODELS[0];
}

// --- Settings ---------------------------------------------------------------
const DEFAULT_SETTINGS = {
  mode: "direct",        // "direct" (Mode A) | "proxy" (Mode B)
  model: DEFAULT_MODEL,
  proxyUrl: "",
  maxTokens: 2048
};

export function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    return raw ? { ...DEFAULT_SETTINGS, ...JSON.parse(raw) } : { ...DEFAULT_SETTINGS };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(patch) {
  const next = { ...loadSettings(), ...patch };
  try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(next)); } catch {}
  return next;
}

// The key lives on its own so it is never accidentally serialised alongside
// anything we might export, log, or sync.
export function getApiKey() {
  try { return localStorage.getItem(API_KEY_STORAGE_KEY) || ""; } catch { return ""; }
}

export function setApiKey(key) {
  try {
    if (key) localStorage.setItem(API_KEY_STORAGE_KEY, key.trim());
    else localStorage.removeItem(API_KEY_STORAGE_KEY);
  } catch {}
}

export function hasApiKey() { return !!getApiKey(); }

