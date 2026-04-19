import { useEffect, useMemo, useState } from "react";
import { AppShell } from "../components/AppShell.jsx";
import { ConnectionPanel } from "../components/ConnectionPanel.jsx";
import { HealthPanel } from "../components/HealthPanel.jsx";
import { AlertsPanel } from "../components/AlertsPanel.jsx";
import { LogExplorer } from "../components/LogExplorer.jsx";
import { AttackOverview } from "../components/AttackOverview.jsx";
import { IncidentPanel } from "../components/IncidentPanel.jsx";
import {
  buildTimeline,
  groupIncidents,
  normalizeResponseItems,
  summarizeAttackers,
} from "../assets/formatters.js";
import {
  fetchAlerts,
  fetchHealth,
  fetchLogs,
  getApiConfig,
  saveApiConfig,
} from "../services/api.js";

export function DashboardPage() {
  const initialConfig = useMemo(() => getApiConfig(), []);
  const [config, setConfig] = useState(initialConfig);
  const [draft, setDraft] = useState(initialConfig);
  const [filters, setFilters] = useState({
    ip: "",
    sinceMinutes: "60",
    sourceType: "",
    search: "",
  });
  const [snapshot, setSnapshot] = useState({
    loading: true,
    error: "",
    lastUpdated: "",
    health: null,
    alerts: [],
    logs: [],
  });

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [healthPayload, alertsPayload, logsPayload] = await Promise.all([
          fetchHealth(config),
          fetchAlerts({ limit: 200, since_minutes: filters.sinceMinutes }, config),
          fetchLogs(
            {
              limit: 250,
              since_minutes: filters.sinceMinutes,
              source_type: filters.sourceType || undefined,
            },
            config,
          ),
        ]);

        if (cancelled) {
          return;
        }

        setSnapshot({
          loading: false,
          error: "",
          lastUpdated: new Date().toISOString(),
          health: healthPayload,
          alerts: normalizeResponseItems(alertsPayload),
          logs: normalizeResponseItems(logsPayload),
        });
      } catch (error) {
        if (cancelled) {
          return;
        }

        setSnapshot((current) => ({
          ...current,
          loading: false,
          error: error instanceof Error ? error.message : "Request failed",
          lastUpdated: new Date().toISOString(),
        }));
      }
    }

    load();
    const timer = window.setInterval(load, config.refreshSeconds * 1000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [config, filters.sinceMinutes, filters.sourceType]);

  const filteredLogs = useMemo(() => {
    return snapshot.logs.filter((log) => {
      const matchesIp = !filters.ip || String(log.source_ip || "").includes(filters.ip.trim());
      const searchHaystack = [
        log.raw_message,
        log.event_type,
        log.source_ip,
        log.country,
        JSON.stringify(log.normalized || {}),
      ]
        .join(" ")
        .toLowerCase();
      const matchesSearch =
        !filters.search || searchHaystack.includes(filters.search.trim().toLowerCase());

      return matchesIp && matchesSearch;
    });
  }, [snapshot.logs, filters.ip, filters.search]);

  const filteredAlerts = useMemo(() => {
    return snapshot.alerts.filter((alert) => {
      if (filters.ip && !String(alert.source_ip || "").includes(filters.ip.trim())) {
        return false;
      }

      if (!filters.search) {
        return true;
      }

      const haystack = [
        alert.title,
        alert.description,
        alert.detector,
        alert.source_ip,
        JSON.stringify(alert.metadata || {}),
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(filters.search.trim().toLowerCase());
    });
  }, [snapshot.alerts, filters.ip, filters.search]);

  const attackers = useMemo(
    () => summarizeAttackers(filteredLogs, filteredAlerts),
    [filteredLogs, filteredAlerts],
  );
  const timeline = useMemo(
    () => buildTimeline(filteredLogs, filteredAlerts),
    [filteredLogs, filteredAlerts],
  );
  const incidents = useMemo(() => groupIncidents(filteredAlerts), [filteredAlerts]);

  function handleDraftChange(key, value) {
    setDraft((current) => ({
      ...current,
      [key]: key === "refreshSeconds" ? Number(value) || current.refreshSeconds : value,
    }));
  }

  function handleFilterChange(key, value) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  function handleConfigSubmit(event) {
    event.preventDefault();
    saveApiConfig(draft);
    setConfig(getApiConfig());
  }

  return (
    <AppShell>
      <HealthPanel
        health={snapshot.health}
        loading={snapshot.loading}
        error={snapshot.error}
        lastUpdated={snapshot.lastUpdated}
      />
      <ConnectionPanel draft={draft} onChange={handleDraftChange} onSubmit={handleConfigSubmit} />
      <AttackOverview attackers={attackers} timeline={timeline} error={snapshot.error} />
      <IncidentPanel incidents={incidents} error={snapshot.error} />
      <AlertsPanel alerts={filteredAlerts} error={snapshot.error} />
      <LogExplorer
        logs={filteredLogs}
        filters={filters}
        onFilterChange={handleFilterChange}
        error={snapshot.error}
      />
    </AppShell>
  );
}
