import { useEffect, useRef, useState, type FormEvent } from "react";
import { Radar } from "lucide-react";
import { api } from "../api";
import type { AppContext } from "../App";
import { ErrorNote, errorText, Lozenge, PageHead, Toggle } from "../components/common";
import { formatBytes, formatMs } from "../format";
import type { ProbeReport } from "../types";

/** Inspects a target without race traffic and recommends an engine. */
export function ProbeScreen({ ctx }: { ctx: AppContext }) {
  const demoUrl = ctx.info?.demo.running ? ctx.info.demo.url : "";
  const [url, setUrl] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [result, setResult] = useState<ProbeReport | null>(null);
  const ctl = useRef<AbortController | null>(null);
  useEffect(() => () => ctl.current?.abort(), []);

  const urlProblem = (() => {
    const u = url.trim();
    if (!u) return "";
    try {
      const p = new URL(u);
      return p.protocol === "https:" || p.protocol === "http:" ? "" : "The URL must start with https:// or http://.";
    } catch {
      return "This is not an absolute URL.";
    }
  })();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!url.trim() || urlProblem) return;
    ctl.current?.abort();
    ctl.current = new AbortController();
    setBusy(true);
    setErr("");
    setResult(null);
    try {
      setResult(await api.probe(url.trim(), insecure, ctl.current.signal));
    } catch (e2) {
      if (!(e2 instanceof DOMException && e2.name === "AbortError")) setErr(errorText(e2));
    } finally {
      setBusy(false);
    }
  };

  const fillDemo = () => {
    setUrl(`${demoUrl.replace(/\/$/, "")}/`);
    setInsecure(true);
  };

  return (
    <div className="screen">
      <PageHead title="Probe" detail="TLS, ALPN, HTTP/2 settings and round trips of a target, without race traffic" />
      <div className="screen-body narrow">
        <section className="panel">
          <form className="probe-form" onSubmit={(e) => void submit(e)}>
            <label htmlFor="probe-url" className="field-label">
              URL
            </label>
            <div className="row gap">
              <input
                id="probe-url"
                className={`input mono grow ${urlProblem ? "invalid" : ""}`}
                type="url"
                placeholder="https://staging.example.test/api/health"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                aria-invalid={!!urlProblem}
                aria-describedby={urlProblem ? "probe-url-err" : undefined}
                data-testid="probe-url"
              />
              {demoUrl && (
                <button type="button" className="btn" onClick={fillDemo} data-testid="probe-use-demo">
                  Use the demo shop
                </button>
              )}
              <button type="submit" className="btn primary" disabled={busy || !url.trim() || !!urlProblem} data-testid="probe-submit">
                <Radar size={14} aria-hidden="true" />
                {busy ? "Probing…" : "Probe"}
              </button>
            </div>
            {urlProblem && (
              <p id="probe-url-err" className="field-error">
                {urlProblem}
              </p>
            )}
            <Toggle
              checked={insecure}
              onChange={setInsecure}
              label="Skip TLS certificate verification"
              hint="For lab targets with self-signed certificates."
              testId="probe-insecure"
            />
            <p className="muted small">
              Sends a TLS handshake, an HTTP/2 connection preface and three GET requests to the URL. Probe only systems you are authorized to
              test.
            </p>
          </form>
        </section>
        {err && <ErrorNote onDismiss={() => setErr("")}>{err}</ErrorNote>}
        {result && <ProbeCard r={result} />}
      </div>
    </div>
  );
}

function ProbeCard({ r }: { r: ProbeReport }) {
  const rtts = [...r.rtts].sort((a, b) => a - b);
  const median = rtts.length ? rtts[Math.floor((rtts.length - 1) / 2)] : 0;
  const yesNo = (v: boolean, yes = "yes", no = "no") => <Lozenge tone={v ? "ok" : "neutral"}>{v ? yes : no}</Lozenge>;
  return (
    <section className="panel" aria-labelledby="probe-result" data-testid="probe-result">
      <div className="panel-head">
        <h2 id="probe-result">Result</h2>
        <span className="muted mono ellipsis">{r.url}</span>
      </div>
      <div className="strip">
        <div className="verdict-cell">
          <span className="label-inline">Recommended engine</span>
          <Lozenge tone="accent">
            <span data-testid="probe-recommended">{r.recommended || "unknown"}</span>
          </Lozenge>
          <span className="muted">
            {r.recommended === "h2"
              ? "single-packet release over one HTTP/2 connection"
              : r.recommended === "h1"
                ? "last-byte synchronization over one connection per request"
                : ""}
          </span>
        </div>
      </div>
      <dl className="kv wide-kv">
        <dt>TLS</dt>
        <dd className="mono">{r.tlsVersion || "none (plain HTTP)"}</dd>
        <dt>ALPN</dt>
        <dd className="mono">{r.alpn || "not negotiated"}</dd>
        <dt>HTTP/2</dt>
        <dd>{yesNo(r.http2, "works", "not available")}</dd>
        {r.server && (
          <>
            <dt>Server</dt>
            <dd className="mono">{r.server}</dd>
          </>
        )}
        <dt>HTTP/2 settings</dt>
        <dd className="mono">
          {r.http2 ? (
            <>
              max concurrent streams {r.maxConcurrentStreams || "unlimited"} · initial window {formatBytes(r.initialWindowSize)} · max frame{" "}
              {formatBytes(r.maxFrameSize)}
            </>
          ) : (
            <span className="muted">none</span>
          )}
        </dd>
        <dt>Statuses</dt>
        <dd className="mono">{r.statuses.length ? r.statuses.join(", ") : <span className="muted">no response</span>}</dd>
        <dt>Round trips</dt>
        <dd className="mono">
          {r.rtts.length ? (
            <>
              {r.rtts.map((v) => formatMs(v)).join(", ")}
              <span className="muted"> · median {formatMs(median)}</span>
            </>
          ) : (
            <span className="muted">none measured</span>
          )}
        </dd>
        <dt>Arrival header</dt>
        <dd>
          {yesNo(r.arrivalHeader, "present", "absent")}{" "}
          <span className="muted">{r.arrivalHeader ? "server arrival times will be shown" : "server arrival spread will not be reported"}</span>
        </dd>
      </dl>
      {r.notes.length > 0 && (
        <div className="block">
          <h3 className="block-title">Notes</h3>
          <ul className="plain">
            {r.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
