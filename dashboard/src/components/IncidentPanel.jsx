import { formatTimestamp, severityClass } from "../assets/formatters.js";

export function IncidentPanel({ incidents, error }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <p className="kicker">incidents</p>
        <h2>Correlated attack chains</h2>
      </div>
      {incidents.length === 0 ? (
        <p className="empty-state">
          {error
            ? "Incident view unavailable while the API is offline."
            : "No incident chains are active in the current alert window."}
        </p>
      ) : (
        <div className="stack">
          {incidents.map((incident) => (
            <article className="record-card" key={incident.id}>
              <div className="record-head">
                <div>
                  <p className="record-meta">{incident.sourceIp}</p>
                  <h3>{incident.title}</h3>
                </div>
                <span className={severityClass(incident.severity)}>{incident.severity}</span>
              </div>
              <div className="record-tags">
                <span>detectors {incident.detectors.join(" -> ")}</span>
                <span>alerts {incident.alerts.length}</span>
                <span>related logs {incident.relatedLogIds.length}</span>
                <span>{formatTimestamp(incident.createdAt)}</span>
              </div>
              <div className="chain-list">
                {incident.alerts.map((alert) => (
                  <div className="chain-step" key={alert.id}>
                    <span className={severityClass(alert.severity)}>{alert.severity}</span>
                    <div>
                      <strong>{alert.detector}</strong>
                      <p>{alert.title}</p>
                    </div>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
