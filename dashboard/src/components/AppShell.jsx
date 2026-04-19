export function AppShell({ children }) {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="kicker">0xchou00</p>
          <h1>Detection dashboard</h1>
        </div>
        <div className="topbar-copy">
          <span>Local SOC view for alerts, logs, and correlated incidents.</span>
        </div>
      </header>
      <main className="dashboard-grid">{children}</main>
    </div>
  );
}
