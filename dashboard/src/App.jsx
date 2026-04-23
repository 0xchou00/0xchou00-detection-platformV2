import { useEffect, useMemo, useState } from "react";
import {
  createLiveSocket,
  fetchAlerts,
  fetchCorrelations,
  fetchEvents,
  fetchHealth,
  getApiConfig,
  saveApiConfig,
} from "./services/api.js";

function badgeClass(severity) {
  return `badge badge-${String(severity || "info").toLowerCase()}`;
}

function withinFilter(item, filter) {
  const text = JSON.stringify(item).toLowerCase();
  if (filter.ip && !String(item.source_ip || "").includes(filter.ip)) {
    return false;
  }
  if (filter.rule && !String(item.rule_id || "").includes(filter.rule)) {
    return false;
  }
  if (filter.severity && String(item.severity || "").toLowerCase() !== filter.severity.toLowerCase()) {
    return false;
  }
  if (filter.search && !text.includes(filter.search.toLowerCase())) {
    return false;
  }
  return true;
}

export default function App() {
  const initial = useMemo(() => getApiConfig(), []);
  const [config, setConfig] = useState(initial);
  const [draft, setDraft] = useState(initial);
  const [health, setHealth] = useState(null);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [wsState, setWsState] = useState("connecting");
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({ ip: "", severity: "", rule: "", search: "" });

  useEffect(() => {
    let active = true;
    let socket = null;

    async function bootstrap() {
      try {
        const [healthPayload, eventsPayload, alertsPayload, corrPayload] = await Promise.all([
          fetchHealth(config),
          fetchEvents({ limit: 300, since_minutes: 120 }, config),
          fetchAlerts({ limit: 300, since_minutes: 120 }, config),
          fetchCorrelations({ limit: 200, since_minutes: 1440 }, config),
        ]);
        if (!active) {
          return;
        }
        setHealth(healthPayload);
        setEvents(eventsPayload.items || []);
        setAlerts(alertsPayload.items || []);
        setCorrelations(corrPayload.items || []);
      } catch (apiError) {
        setError(apiError instanceof Error ? apiError.message : "Initial load failed");
      }
    }

    bootstrap();
    socket = createLiveSocket(
      config,
      (message) => {
        if (message.kind === "event") {
          setEvents((current) => [message.payload, ...current].slice(0, 500));
        }
        if (message.kind === "alert") {
          setAlerts((current) => [message.payload, ...current].slice(0, 500));
          if (message.payload.alert_kind === "correlation" || message.payload.detector === "correlation") {
            setCorrelations((current) => [message.payload, ...current].slice(0, 300));
          }
        }
      },
      (msg) => {
        setWsState("error");
        setError(msg);
      },
      () => setWsState("connected"),
      () => setWsState("closed"),
    );

    return () => {
      active = false;
      socket?.close();
    };
  }, [config]);

  const filteredAlerts = useMemo(() => alerts.filter((item) => withinFilter(item, filters)), [alerts, filters]);
  const filteredEvents = useMemo(() => events.filter((item) => withinFilter(item, filters)), [events, filters]);
  const filteredCorrelations = useMemo(
    () => correlations.filter((item) => withinFilter(item, filters)),
    [correlations, filters],
  );

  const timeline = useMemo(() => {
    const items = [
      ...filteredAlerts.map((item) => ({ kind: "alert", ts: item.created_at, item })),
      ...filteredEvents.map((item) => ({ kind: "event", ts: item.timestamp || item.received_at, item })),
    ];
    return items
      .filter((entry) => entry.ts)
      .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())
      .slice(0, 80);
  }, [filteredAlerts, filteredEvents]);

  function onDraft(key, value) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function applyConfig(event) {
    event.preventDefault();
    saveApiConfig(draft);
    setConfig(getApiConfig());
    setWsState("reconnecting");
  }

  return (
    <div className="layout">
      <header className="hero">
        <div>
          <p className="kicker">0XCHOU00 DETECTION PLATFORM V2</p>
          <h1>Real-Time SOC Operations Console</h1>
        </div>
        <div className={`status ${wsState}`}>WebSocket: {wsState}</div>
      </header>

      <section className="card">
        <h2>Connection</h2>
        <form className="grid3" onSubmit={applyConfig}>
          <label>
            API Base
            <input value={draft.baseUrl} onChange={(e) => onDraft("baseUrl", e.target.value)} />
          </label>
          <label>
            Viewer API Key
            <input value={draft.apiKey} onChange={(e) => onDraft("apiKey", e.target.value)} />
          </label>
          <label>
            WebSocket URL
            <input value={draft.wsUrl} onChange={(e) => onDraft("wsUrl", e.target.value)} />
          </label>
          <button type="submit">Reconnect</button>
        </form>
      </section>

      <section className="grid4">
        <article className="metric card">
          <span>Events</span>
          <strong>{health?.events ?? "-"}</strong>
        </article>
        <article className="metric card">
          <span>Alerts</span>
          <strong>{health?.alerts ?? "-"}</strong>
        </article>
        <article className="metric card">
          <span>Backlog</span>
          <strong>{health?.ingest_stream_backlog ?? "-"}</strong>
        </article>
        <article className="metric card">
          <span>Correlations</span>
          <strong>{filteredCorrelations.length}</strong>
        </article>
      </section>

      <section className="card">
        <h2>Filters</h2>
        <div className="grid4">
          <label>
            Source IP
            <input value={filters.ip} onChange={(e) => setFilters((c) => ({ ...c, ip: e.target.value }))} />
          </label>
          <label>
            Severity
            <select value={filters.severity} onChange={(e) => setFilters((c) => ({ ...c, severity: e.target.value }))}>
              <option value="">All</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
          </label>
          <label>
            Rule
            <input value={filters.rule} onChange={(e) => setFilters((c) => ({ ...c, rule: e.target.value }))} />
          </label>
          <label>
            Free Search
            <input value={filters.search} onChange={(e) => setFilters((c) => ({ ...c, search: e.target.value }))} />
          </label>
        </div>
      </section>

      <section className="split">
        <article className="card">
          <h2>Live Alerts Stream</h2>
          <div className="stream">
            {filteredAlerts.slice(0, 80).map((alert) => (
              <div key={alert.id} className="entry">
                <div className="entry-head">
                  <span className={badgeClass(alert.severity)}>{alert.severity}</span>
                  <small>{new Date(alert.created_at).toLocaleString()}</small>
                </div>
                <strong>{alert.title}</strong>
                <p>{alert.description}</p>
                <code>{alert.detector}</code>
                <code>{alert.rule_id || "no-rule"}</code>
                <code>{alert.source_ip || "no-ip"}</code>
              </div>
            ))}
          </div>
        </article>
        <article className="card">
          <h2>Correlation View</h2>
          <div className="stream">
            {filteredCorrelations.slice(0, 50).map((alert) => (
              <div key={alert.id} className="entry">
                <div className="entry-head">
                  <span className={badgeClass(alert.severity)}>{alert.severity}</span>
                  <small>{new Date(alert.created_at).toLocaleString()}</small>
                </div>
                <strong>{alert.title}</strong>
                <p>{alert.description}</p>
                <pre>{JSON.stringify(alert.metadata || {}, null, 2)}</pre>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="card">
        <h2>Timeline</h2>
        <div className="timeline">
          {timeline.map((item, index) => (
            <div key={`${item.kind}-${index}`} className="timeline-item">
              <div className={`dot ${item.kind}`} />
              <div>
                <strong>{item.kind === "alert" ? item.item.title : item.item.event_type}</strong>
                <p>{item.kind === "alert" ? item.item.description : item.item.raw_message}</p>
                <small>{new Date(item.ts).toLocaleString()}</small>
              </div>
            </div>
          ))}
        </div>
      </section>

      {error ? <section className="error card">{error}</section> : null}
    </div>
  );
}

