const DEFAULT_API_BASE = "http://localhost:8000";
const DEFAULT_API_KEY = "siem-viewer-dev-key";
const DEFAULT_WS_BASE = "ws://localhost:8000/ws/live";
const STORAGE_KEY = "0xchou00-v2-dashboard";

function readStored() {
  if (typeof window === "undefined") {
    return {};
  }
  try {
    return JSON.parse(window.localStorage.getItem(STORAGE_KEY) || "{}");
  } catch {
    return {};
  }
}

export function getApiConfig() {
  const stored = readStored();
  return {
    baseUrl: stored.baseUrl || import.meta.env.VITE_TOOL_API_BASE || DEFAULT_API_BASE,
    apiKey: stored.apiKey || import.meta.env.VITE_TOOL_API_KEY || DEFAULT_API_KEY,
    wsUrl: stored.wsUrl || import.meta.env.VITE_TOOL_WS_BASE || DEFAULT_WS_BASE,
  };
}

export function saveApiConfig(config) {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      baseUrl: config.baseUrl?.trim() || DEFAULT_API_BASE,
      apiKey: config.apiKey?.trim() || DEFAULT_API_KEY,
      wsUrl: config.wsUrl?.trim() || DEFAULT_WS_BASE,
    }),
  );
}

function withQuery(path, query = {}) {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") {
      return;
    }
    params.set(key, String(value));
  });
  const suffix = params.toString();
  return `${path}${suffix ? `?${suffix}` : ""}`;
}

async function request(path, { config, query } = {}) {
  const active = config || getApiConfig();
  const response = await fetch(`${active.baseUrl}${withQuery(path, query)}`, {
    headers: {
      Accept: "application/json",
      "X-API-Key": active.apiKey,
    },
  });
  if (!response.ok) {
    throw new Error(`Request failed (${response.status}) on ${path}`);
  }
  return response.json();
}

export function fetchHealth(config) {
  return request("/health", { config });
}

export function fetchEvents(query, config) {
  return request("/events", { query, config });
}

export function fetchAlerts(query, config) {
  return request("/alerts", { query, config });
}

export function fetchCorrelations(query, config) {
  return request("/correlations", { query, config });
}

export function createLiveSocket(config, onMessage, onError, onOpen, onClose) {
  const active = config || getApiConfig();
  const url = new URL(active.wsUrl);
  if (!url.searchParams.get("api_key")) {
    url.searchParams.set("api_key", active.apiKey);
  }
  const ws = new WebSocket(url.toString());
  ws.onopen = () => onOpen?.();
  ws.onclose = () => onClose?.();
  ws.onerror = () => onError?.("WebSocket error");
  ws.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      onMessage?.(payload);
    } catch {
      onError?.("Malformed WebSocket payload");
    }
  };
  return ws;
}
