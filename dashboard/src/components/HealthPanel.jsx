import { formatTimestamp } from "../assets/formatters.js";

export function HealthPanel({ health, loading, error, lastUpdated }) {
  const online = !error && health;

  return (
    <section className="panel panel-compact">
      <div className="panel-header">
        <p className="kicker">health</p>
        <h2>Backend state</h2>
      </div>
      <div className={`status-banner ${online ? "online" : "offline"}`}>
        {loading ? "Connecting to API..." : online ? "API reachable" : `API offline: ${error}`}
      </div>
      <div className="metric-strip">
        <div>
          <span>Status</span>
          <strong>{health?.status || "offline"}</strong>
        </div>
        <div>
          <span>Logs</span>
          <strong>{health?.logs ?? 0}</strong>
        </div>
        <div>
          <span>Alerts</span>
          <strong>{health?.alerts ?? 0}</strong>
        </div>
      </div>
      <p className="muted-line">Last refresh: {formatTimestamp(lastUpdated)}</p>
    </section>
  );
}
