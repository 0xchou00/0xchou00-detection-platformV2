const DEFAULT_API_BASE = "http://localhost:8000";
const DEFAULT_API_KEY = "siem-viewer-dev-key";
const DEFAULT_REFRESH_SECONDS = 5;
const REQUEST_TIMEOUT_MS = 8000;
const STORAGE_KEY = "0xchou00-dashboard-config";

function readStoredConfig() {
  if (typeof window === "undefined") {
    return {};
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {};
    }

    const parsed = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null ? parsed : {};
  } catch {
    return {};
  }
}

function normalizeRefreshSeconds(value) {
  return Number(value) > 0 ? Number(value) : DEFAULT_REFRESH_SECONDS;
}

export function getApiConfig() {
  const stored = readStoredConfig();

  return {
    baseUrl: stored.baseUrl || import.meta.env.VITE_TOOL_API_BASE || DEFAULT_API_BASE,
    apiKey: stored.apiKey || import.meta.env.VITE_TOOL_API_KEY || DEFAULT_API_KEY,
    refreshSeconds: normalizeRefreshSeconds(stored.refreshSeconds),
  };
}

export function saveApiConfig(config) {
  if (typeof window === "undefined") {
    return;
  }

  const next = {
    baseUrl: config.baseUrl?.trim() || DEFAULT_API_BASE,
    apiKey: config.apiKey?.trim() || DEFAULT_API_KEY,
    refreshSeconds: normalizeRefreshSeconds(config.refreshSeconds),
  };

  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
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
  return suffix ? `${path}?${suffix}` : path;
}

function describeHttpError(status, path) {
  if (status === 401 || status === 403) {
    return `Access denied for ${path}. Check the viewer API key.`;
  }

  if (status === 404) {
    return `${path} is not exposed by the backend.`;
  }

  if (status >= 500) {
    return `Backend error on ${path}.`;
  }

  return `Request failed for ${path}.`;
}

async function request(path, { config, query, headers, init } = {}) {
  const activeConfig = config || getApiConfig();
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${activeConfig.baseUrl}${withQuery(path, query)}`, {
      headers: {
        Accept: "application/json",
        ...(activeConfig.apiKey ? { "X-API-Key": activeConfig.apiKey } : {}),
        ...(headers || {}),
      },
      signal: controller.signal,
      ...(init || {}),
    });

    if (!response.ok) {
      throw new Error(describeHttpError(response.status, path));
    }

    return response.json();
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error(`Request timeout while calling ${path}.`);
    }

    if (error instanceof TypeError) {
      throw new Error(`API offline or unreachable at ${activeConfig.baseUrl}.`);
    }

    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

export function fetchHealth(config) {
  return request("/health", { config });
}

export function fetchAlerts(query = {}, config) {
  return request("/alerts", { query, config });
}

export function fetchLogs(query = {}, config) {
  return request("/logs", { query, config });
}
