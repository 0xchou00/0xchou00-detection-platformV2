export function formatTimestamp(value) {
  if (!value) {
    return "unknown";
  }

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function severityClass(value) {
  return `severity severity-${String(value || "info").toLowerCase()}`;
}

export function safeJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "unavailable";
  }
}

export function normalizeResponseItems(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (payload && Array.isArray(payload.items)) {
    return payload.items;
  }

  return [];
}

export function summarizeAttackers(logs, alerts) {
  const scores = new Map();

  alerts.forEach((alert) => {
    const ip = alert.source_ip;
    if (!ip) {
      return;
    }
    const current = scores.get(ip) || { ip, alerts: 0, logs: 0, severityScore: 0 };
    current.alerts += 1;
    current.severityScore += severityWeight(alert.severity);
    scores.set(ip, current);
  });

  logs.forEach((log) => {
    const ip = log.source_ip;
    if (!ip) {
      return;
    }
    const current = scores.get(ip) || { ip, alerts: 0, logs: 0, severityScore: 0 };
    current.logs += 1;
    scores.set(ip, current);
  });

  return [...scores.values()]
    .sort((left, right) => {
      return (
        right.severityScore - left.severityScore ||
        right.alerts - left.alerts ||
        right.logs - left.logs
      );
    })
    .slice(0, 8);
}

export function buildTimeline(logs, alerts) {
  const entries = [
    ...logs.map((log) => ({
      id: `log-${log.id}`,
      timestamp: log.created_at || log.timestamp,
      kind: "log",
      title: log.event_type,
      subtitle: log.raw_message,
      sourceIp: log.source_ip,
      severity: log.severity,
      sourceType: log.source_type,
    })),
    ...alerts.map((alert) => ({
      id: `alert-${alert.id}`,
      timestamp: alert.created_at,
      kind: "alert",
      title: alert.title,
      subtitle: alert.description,
      sourceIp: alert.source_ip,
      severity: alert.severity,
      sourceType: alert.source_type,
    })),
  ];

  return entries
    .filter((entry) => entry.timestamp)
    .sort((left, right) => new Date(right.timestamp) - new Date(left.timestamp))
    .slice(0, 20);
}

export function groupIncidents(alerts) {
  const groups = new Map();

  alerts.forEach((alert) => {
    const metadata = alert.metadata || {};
    const key =
      metadata.correlation_fingerprint ||
      `${alert.source_ip || "unknown"}:${metadata.correlation_rule_id || alert.detector}`;

    const current = groups.get(key) || {
      id: key,
      sourceIp: alert.source_ip || "unknown",
      title:
        metadata.correlation_rule_id || alert.alert_kind === "correlation"
          ? alert.title
          : `Incident cluster for ${alert.source_ip || "unknown"}`,
      severity: alert.severity,
      alerts: [],
      detectors: new Set(),
      relatedLogIds: new Set(),
      createdAt: alert.created_at,
    };

    current.alerts.push(alert);
    current.detectors.add(alert.detector);
    (metadata.related_log_ids || []).forEach((id) => current.relatedLogIds.add(id));
    if (new Date(alert.created_at) > new Date(current.createdAt)) {
      current.createdAt = alert.created_at;
    }
    if (severityWeight(alert.severity) > severityWeight(current.severity)) {
      current.severity = alert.severity;
    }

    groups.set(key, current);
  });

  return [...groups.values()]
    .map((group) => ({
      ...group,
      detectors: [...group.detectors],
      relatedLogIds: [...group.relatedLogIds],
    }))
    .sort((left, right) => new Date(right.createdAt) - new Date(left.createdAt))
    .slice(0, 8);
}

function severityWeight(value) {
  switch (String(value || "").toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}
