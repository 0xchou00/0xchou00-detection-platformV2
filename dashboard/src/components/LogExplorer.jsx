import { formatTimestamp, safeJson, severityClass } from "../assets/formatters.js";

export function LogExplorer({ logs, filters, onFilterChange, error }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <p className="kicker">logs</p>
        <h2>Log explorer</h2>
      </div>

      <div className="filter-grid">
        <label>
          <span>IP</span>
          <input
            type="text"
            value={filters.ip}
            onChange={(event) => onFilterChange("ip", event.target.value)}
            placeholder="198.51.100.77"
          />
        </label>
        <label>
          <span>Time window</span>
          <select
            value={filters.sinceMinutes}
            onChange={(event) => onFilterChange("sinceMinutes", event.target.value)}
          >
            <option value="15">15 min</option>
            <option value="60">60 min</option>
            <option value="360">6 hours</option>
            <option value="1440">24 hours</option>
          </select>
        </label>
        <label>
          <span>Type</span>
          <select
            value={filters.sourceType}
            onChange={(event) => onFilterChange("sourceType", event.target.value)}
          >
            <option value="">all</option>
            <option value="ssh">ssh</option>
            <option value="nginx">nginx</option>
            <option value="firewall">firewall</option>
          </select>
        </label>
        <label>
          <span>Search</span>
          <input
            type="text"
            value={filters.search}
            onChange={(event) => onFilterChange("search", event.target.value)}
            placeholder="invalid user, wp-login, DPT=22"
          />
        </label>
      </div>

      {logs.length === 0 ? (
        <p className="empty-state">
          {error ? "Log explorer unavailable while the API is offline." : "No log events matched the current filters."}
        </p>
      ) : (
        <div className="stack">
          {logs.map((log) => (
            <article className="record-card" key={log.id}>
              <div className="record-head">
                <div>
                  <p className="record-meta">{log.source_type}</p>
                  <h3>{log.event_type}</h3>
                </div>
                <span className={severityClass(log.severity)}>{log.severity}</span>
              </div>
              <p className="record-copy">{log.raw_message}</p>
              <div className="record-tags">
                <span>IP {log.source_ip || "unknown"}</span>
                <span>country {log.country || "unknown"}</span>
                <span>risk {log.risk_score ?? "n/a"}</span>
                <span>{formatTimestamp(log.created_at || log.timestamp)}</span>
              </div>
              <details>
                <summary>Normalized event</summary>
                <pre>{safeJson(log.normalized)}</pre>
              </details>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
