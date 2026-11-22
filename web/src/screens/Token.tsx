import { useState, type FormEvent } from "react";
import { api, AuthError, clearToken, setToken } from "../api";
import { errorText } from "../components/common";

/**
 * Shown when there is no session token or the server rejected it. The token
 * is printed by "photofinish serve" as part of the UI link; pasting it here
 * is the same as opening that link.
 */
export function TokenScreen({ onToken }: { onToken: () => void }) {
  const [value, setValue] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const token = value.trim().replace(/^.*#token=/, "");
    if (!token) return;
    setBusy(true);
    setErr("");
    setToken(token);
    try {
      await api.info();
      onToken();
    } catch (e2) {
      clearToken();
      setErr(e2 instanceof AuthError ? "The server did not accept this token." : errorText(e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="token-screen" data-testid="token-screen">
      <div className="token-card">
        <div className="token-brand">
          <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true" className="brand-mark">
            <rect x="1" y="1" width="16" height="16" rx="3" />
            <line x1="9" y1="4" x2="9" y2="14" />
          </svg>
          <span>PhotoFinish</span>
        </div>
        <h1>Session token missing: open the link printed by photofinish serve</h1>
        <p className="muted">
          The local server only answers requests that carry its session token, so that other web pages cannot drive it. On start it
          prints a line like
        </p>
        <pre className="code">PhotoFinish UI: http://127.0.0.1:7340/#token=…</pre>
        <p className="muted">Open that link in this browser, or paste the token or the whole link below.</p>
        <form onSubmit={(e) => void submit(e)} className="token-form">
          <label htmlFor="token-input">Token or link</label>
          <div className="row">
            <input
              id="token-input"
              type="password"
              className="input mono"
              autoComplete="off"
              spellCheck={false}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
            <button type="submit" className="btn primary" disabled={busy || !value.trim()}>
              {busy ? "Checking…" : "Continue"}
            </button>
          </div>
          {err && (
            <p className="field-error" role="alert">
              {err}
            </p>
          )}
        </form>
        <p className="muted small">
          The token is kept for this browser tab only (sessionStorage) and is removed from the address bar. Set PHOTOFINISH_TOKEN to use
          a fixed token, for example in a container.
        </p>
      </div>
    </div>
  );
}
