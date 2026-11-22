import { useCallback, useEffect, useRef, useState } from "react";
import { FileInput, FileText, History, Loader, Moon, Radar, Sun } from "lucide-react";
import { adoptTokenFromLocation, api, AuthError, clearToken, getToken, onUnauthorized } from "./api";
import { ErrorNote, errorText } from "./components/common";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { href, useRoute, type RouteName } from "./router";
import { useTheme } from "./theme";
import type { Info } from "./types";
import { EditorScreen } from "./screens/Editor";
import { ImportScreen } from "./screens/Import";
import { ProbeScreen } from "./screens/Probe";
import { RunScreen } from "./screens/Run";
import { RunsScreen } from "./screens/Runs";
import { ScenariosScreen } from "./screens/Scenarios";
import { TokenScreen } from "./screens/Token";

/** Shared state handed to every screen. */
export interface AppContext {
  info: Info | null;
  refreshInfo: () => Promise<void>;
}

const NAV: { name: RouteName; label: string; icon: typeof FileText; also: RouteName[] }[] = [
  { name: "scenarios", label: "Scenarios", icon: FileText, also: ["scenario"] },
  { name: "runs", label: "Runs", icon: History, also: ["run"] },
  { name: "probe", label: "Probe", icon: Radar, also: [] },
  { name: "import", label: "Import", icon: FileInput, also: [] },
];

/** The app shell: token gate, sidebar and the screen of the current route. */
export default function App() {
  const [authed, setAuthed] = useState<boolean>(() => {
    adoptTokenFromLocation();
    return getToken() !== "";
  });
  const [info, setInfo] = useState<Info | null>(null);
  const [infoErr, setInfoErr] = useState("");
  const route = useRoute();
  const [theme, toggleTheme] = useTheme();

  useEffect(() => {
    onUnauthorized(() => {
      clearToken();
      setAuthed(false);
    });
    return () => onUnauthorized(null);
  }, []);

  const refreshInfo = useCallback(async () => {
    try {
      setInfo(await api.info());
      setInfoErr("");
    } catch (e) {
      if (e instanceof AuthError) setAuthed(false);
      else setInfoErr(errorText(e));
    }
  }, []);

  // The link printed by the server may also be pasted into a tab that is
  // already open; only the fragment changes then, so the page does not load.
  useEffect(() => {
    const onHash = () => {
      if (adoptTokenFromLocation()) {
        setAuthed(true);
        void refreshInfo();
      }
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [refreshInfo]);

  // Keep the sidebar current: demo shop state and the run in progress.
  useEffect(() => {
    if (!authed) return;
    void refreshInfo();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void refreshInfo();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [authed, refreshInfo]);

  useEffect(() => {
    if (authed) void refreshInfo();
  }, [route.name, authed, refreshInfo]);

  // Move focus to the main area on screen changes so that keyboard and
  // screen reader users start at the new content.
  const main = useRef<HTMLElement>(null);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    main.current?.focus({ preventScroll: true });
  }, [route.name]);

  if (!authed) return <TokenScreen onToken={() => setAuthed(true)} />;

  const ctx: AppContext = { info, refreshInfo };
  const key = route.name === "run" ? `run:${route.params.get("id")}` : route.name === "scenario" ? `scenario:${route.raw}` : route.name;

  return (
    <div className="shell">
      <button type="button" className="skip" onClick={() => main.current?.focus()}>
        Skip to content
      </button>
      <aside className="sidebar" aria-label="PhotoFinish">
        <a className="brand" href={href("scenarios")}>
          <svg className="brand-mark" width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
            <rect x="1" y="1" width="16" height="16" rx="3" />
            <line x1="9" y1="4" x2="9" y2="14" />
          </svg>
          <span className="brand-name">PhotoFinish</span>
        </a>
        <nav aria-label="Main">
          <ul className="nav">
            {NAV.map((n) => {
              const current = route.name === n.name || n.also.includes(route.name);
              const Icon = n.icon;
              return (
                <li key={n.name}>
                  <a href={href(n.name)} className={current ? "current" : ""} aria-current={current ? "page" : undefined}>
                    <Icon size={15} aria-hidden="true" />
                    {n.label}
                  </a>
                </li>
              );
            })}
          </ul>
        </nav>
        {info?.running && (
          <a className="running-link" href={href("run", { id: info.running })} data-testid="running-link">
            <Loader size={13} className="spin" aria-hidden="true" />
            Run in progress
          </a>
        )}
        <div className="sidebar-fill" />
        <DemoPanel info={info} refresh={refreshInfo} />
        <div className="sidebar-foot">
          <div className="workspace" title={info?.workspace}>
            <span className="label">Workspace{info?.version ? ` · ${info.version}` : ""}</span>
            <span className="path mono" data-testid="workspace-path">
              <bdi>{info?.workspace ?? "…"}</bdi>
            </span>
          </div>
          <button
            type="button"
            className="icon-btn"
            onClick={toggleTheme}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            data-testid="theme-toggle"
          >
            {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
          </button>
        </div>
      </aside>
      <main id="main" className="main" ref={main} tabIndex={-1}>
        {infoErr && (
          <div className="banner">
            <ErrorNote>{infoErr}</ErrorNote>
          </div>
        )}
        <ErrorBoundary resetKey={key}>
          {route.name === "scenarios" && <ScenariosScreen key={key} ctx={ctx} />}
          {route.name === "scenario" && <EditorScreen key={key} ctx={ctx} path={route.params.get("path") ?? ""} />}
          {route.name === "run" && <RunScreen key={key} ctx={ctx} id={route.params.get("id") ?? ""} />}
          {route.name === "runs" && <RunsScreen key={key} ctx={ctx} initialScenario={route.params.get("scenario") ?? ""} />}
          {route.name === "probe" && <ProbeScreen key={key} ctx={ctx} />}
          {route.name === "import" && <ImportScreen key={key} ctx={ctx} />}
        </ErrorBoundary>
      </main>
    </div>
  );
}

/** Demo shop status with start and stop. */
function DemoPanel({ info, refresh }: { info: Info | null; refresh: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const running = info?.demo.running ?? false;
  const toggle = async () => {
    setBusy(true);
    setErr("");
    try {
      if (running) await api.demoStop();
      else await api.demoStart();
      await refresh();
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="demo" aria-label="Demo shop" data-testid="demo-panel">
      <div className="demo-head">
        <span className={`dot ${running ? "on" : ""}`} aria-hidden="true" />
        <span className="demo-title">Demo shop</span>
        <span className="demo-state" data-testid="demo-state">
          {info ? (running ? "running" : "stopped") : ""}
        </span>
      </div>
      {running && info?.demo.url && <div className="demo-url mono">{info.demo.url}</div>}
      <button type="button" className="btn small" disabled={busy || !info} onClick={() => void toggle()} data-testid="demo-toggle">
        {busy ? (running ? "Stopping…" : "Starting…") : running ? "Stop" : "Start"}
      </button>
      {err && <p className="demo-err">{err}</p>}
    </section>
  );
}
