export function ConnectionPanel({ draft, onChange, onSubmit }) {
  return (
    <section className="panel panel-compact">
      <div className="panel-header">
        <p className="kicker">connection</p>
        <h2>API settings</h2>
      </div>
      <form className="form-grid" onSubmit={onSubmit}>
        <label>
          <span>Base URL</span>
          <input
            type="text"
            value={draft.baseUrl}
            onChange={(event) => onChange("baseUrl", event.target.value)}
          />
        </label>
        <label>
          <span>API key</span>
          <input
            type="text"
            value={draft.apiKey}
            onChange={(event) => onChange("apiKey", event.target.value)}
          />
        </label>
        <label>
          <span>Refresh seconds</span>
          <input
            type="number"
            min="2"
            max="300"
            value={draft.refreshSeconds}
            onChange={(event) => onChange("refreshSeconds", event.target.value)}
          />
        </label>
        <button type="submit" className="button-primary">
          Apply
        </button>
      </form>
    </section>
  );
}
