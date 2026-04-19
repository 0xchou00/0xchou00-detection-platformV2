import { formatTimestamp, severityClass, safeJson } from "../assets/formatters.js";

export function AlertsPanel({ alerts, error }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <p className="kicker">alerts</p>
        <h2>Live alerts</h2>
      </div>
      {alerts.length === 0 ? (
        <p className="empty-state">
          {error ? "Alert stream unavailable while the API is offline." : "No alerts matched the active window."}
        </p>
      ) : (
        <div className="stack">
          {alerts.map((alert) => (
            <article className="record-card" key={alert.id}>
              <div className="record-head">
                <div>
                  <p className="record-meta">{alert.detector}</p>
                  <h3>{alert.title}</h3>
                </div>
                <span className={severityClass(alert.severity)}>{alert.severity}</span>
              </div>
              <p className="record-copy">{alert.description}</p>
              <div className="record-tags">
                <span>IP {alert.source_ip || "unknown"}</span>
                <span>kind {alert.alert_kind}</span>
                <span>events {alert.event_count}</span>
                <span>{formatTimestamp(alert.created_at)}</span>
              </div>
              <details>
                <summary>Evidence</summary>
                <pre>{safeJson(alert.evidence)}</pre>
              </details>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
