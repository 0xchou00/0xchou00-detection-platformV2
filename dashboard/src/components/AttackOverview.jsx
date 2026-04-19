import { formatTimestamp, severityClass } from "../assets/formatters.js";

export function AttackOverview({ attackers, timeline, error }) {
  return (
    <>
      <section className="panel panel-half">
        <div className="panel-header">
          <p className="kicker">attackers</p>
          <h2>Top attacking IPs</h2>
        </div>
        {attackers.length === 0 ? (
          <p className="empty-state">
            {error ? "Top attackers unavailable while the API is offline." : "No active sources in the selected window."}
          </p>
        ) : (
          <div className="attacker-list">
            {attackers.map((item) => (
              <article className="attacker-row" key={item.ip}>
                <div className="attacker-head">
                  <strong>{item.ip}</strong>
                  <span>{item.severityScore} risk points</span>
                </div>
                <div className="attacker-bar">
                  <div
                    className="attacker-bar-fill"
                    style={{ width: `${Math.min(item.severityScore * 10, 100)}%` }}
                  />
                </div>
                <div className="record-tags">
                  <span>alerts {item.alerts}</span>
                  <span>logs {item.logs}</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="panel panel-half">
        <div className="panel-header">
          <p className="kicker">timeline</p>
          <h2>Recent event timeline</h2>
        </div>
        {timeline.length === 0 ? (
          <p className="empty-state">
            {error ? "Timeline unavailable while the API is offline." : "No recent events available."}
          </p>
        ) : (
          <div className="timeline-list">
            {timeline.map((entry) => (
              <article className="timeline-item" key={entry.id}>
                <div className="timeline-dot" />
                <div className="timeline-body">
                  <div className="record-head">
                    <div>
                      <p className="record-meta">{entry.kind}</p>
                      <h3>{entry.title}</h3>
                    </div>
                    <span className={severityClass(entry.severity)}>{entry.severity}</span>
                  </div>
                  <p className="record-copy">{entry.subtitle}</p>
                  <div className="record-tags">
                    <span>IP {entry.sourceIp || "unknown"}</span>
                    <span>{entry.sourceType}</span>
                    <span>{formatTimestamp(entry.timestamp)}</span>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </>
  );
}
