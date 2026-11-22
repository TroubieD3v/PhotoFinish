import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { ChevronDown, ChevronRight, Download, FileText, Play, Square } from "lucide-react";
import { api, ApiError, downloadReport, parseProgress, runningIdFrom, streamEvents } from "../api";
import type { AppContext } from "../App";
import { CopyButton, ErrorNote, errorText, Lozenge, PageHead } from "../components/common";
import { JsonView } from "../components/JsonView";
import { ArrivalStrip, Timeline } from "../components/Timeline";
import { elapsed, formatDuration, formatMs, formatTime, plural } from "../format";
import {
  compactStatuses,
  defaultTrial,
  metrics,
  oneLine,
  raceCaption,
  reportNotes,
  reproduceWords,
  responseSpread,
  termState,
  trialsOf,
  tryJSON,
  verdictTone,
} from "../report";
import { href, navigate } from "../router";
import type { Report, ReportFormat, RunDetail, StepRecord, Trial, Verdict } from "../types";

/** Term values longer than this get a row of their own. */
const MAX_INLINE_VALUE = 24;

const FORMATS: { format: ReportFormat; label: string }[] = [
  { format: "json", label: "JSON" },
  { format: "sarif", label: "SARIF" },
  { format: "junit", label: "JUnit" },
  { format: "html", label: "HTML" },
];

/** Live state of a run in progress, built from progress events. */
interface Live {
  planned: number;
  done: number;
  trials: Trial[];
  verdict?: Verdict;
  connected: boolean;
}

const sleep = (ms: number) => new Promise((r) => window.setTimeout(r, ms));

/** The longest pause between two progress announcements of a live run. */
const ANNOUNCE_EVERY_MS = 5000;

/** The --copies of a reproduce command, if it has one. */
function reproduceCopies(cmd: string | undefined): number | undefined {
  const m = /(?:^|\s)--copies (\d+)(?:\s|$)/.exec(cmd ?? "");
  return m ? Number(m[1]) : undefined;
}

/** One run: live progress while it goes on, the full report when it is done. */
export function RunScreen({ ctx, id }: { ctx: AppContext; id: string }) {
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const [err, setErr] = useState("");
  const [live, setLive] = useState<Live>({ planned: 0, done: 0, trials: [], connected: false });
  const [selected, setSelected] = useState<number | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [announce, setAnnounce] = useState("");
  const announced = useRef({ violation: false, at: 0 });
  const { refreshInfo } = ctx;

  const load = useCallback(async () => {
    const d = await api.run(id);
    setDetail(d);
    return d;
  }, [id]);

  useEffect(() => {
    if (!id) {
      setLoadErr("No run id in the address.");
      return;
    }
    load().catch((e) => setLoadErr(e instanceof ApiError && e.status === 404 ? "This run does not exist (any more)." : errorText(e)));
  }, [id, load]);

  const isRunning = detail?.run.running ?? false;

  // Follow the event stream while the run goes on.
  useEffect(() => {
    if (!isRunning) return;
    const ctl = new AbortController();
    let finished = false;
    const onProgress = (data: string) => {
      const p = parseProgress(data);
      if (!p) return;
      if (p.trial) {
        // Screen readers queue every polite update: announce the first
        // violation, then progress about every tenth of the run or every
        // few seconds, not every trial.
        const now = Date.now();
        const step = Math.max(1, Math.ceil((p.planned || 1) / 10));
        if (p.trial.verdict === "VIOLATED" && !announced.current.violation) {
          announced.current.violation = true;
          announced.current.at = now;
          setAnnounce(`Trial ${p.trial.number}: VIOLATED`);
        } else if (now - announced.current.at >= ANNOUNCE_EVERY_MS || p.done % step === 0) {
          announced.current.at = now;
          setAnnounce(`${p.done} of ${p.planned || "?"} trials done`);
        }
      }
      setLive((prev) => {
        const next: Live = { ...prev, connected: true, planned: p.planned || prev.planned, done: Math.max(prev.done, p.done) };
        if (p.trial) {
          const t = p.trial;
          next.trials = [...prev.trials.filter((x) => x.number !== t.number), t].sort((a, b) => a.number - b.number);
        }
        if (p.phase === "done" && p.verdict) next.verdict = p.verdict;
        return next;
      });
    };
    const settle = async () => {
      // The server stores the report before it sends "done", so the first
      // fetch normally has it; retry briefly after a lost stream.
      for (let i = 0; i < 20 && !ctl.signal.aborted; i++) {
        try {
          const d = await api.run(id);
          if (!d.run.running && d.report) {
            setDetail(d);
            setAnnounce(`Run finished: ${d.report.verdict}. ${d.report.summary}`);
            void refreshInfo();
            return;
          }
          if (!d.run.running) {
            setDetail(d);
            return;
          }
        } catch (e) {
          setErr(errorText(e));
        }
        await sleep(i < 5 ? 200 : 700);
      }
    };
    const follow = async () => {
      for (let attempt = 0; !ctl.signal.aborted && !finished; attempt++) {
        try {
          await streamEvents(
            api.runEventsUrl(id),
            (ev) => {
              if (ev.event === "progress") onProgress(ev.data);
              else if (ev.event === "done") finished = true;
            },
            ctl.signal,
          );
          finished = true;
        } catch (e) {
          if (ctl.signal.aborted) return;
          setLive((l) => ({ ...l, connected: false }));
          if (attempt >= 2) setErr(`Lost the event stream: ${errorText(e)}. Showing the stored state.`);
          await sleep(1000);
          // The run may have ended while we were away.
          const d = await api.run(id).catch(() => null);
          if (d && !d.run.running) {
            finished = true;
          }
        }
      }
      if (!ctl.signal.aborted) await settle();
    };
    void follow();
    return () => ctl.abort();
  }, [isRunning, id, refreshInfo]);

  const cancel = async () => {
    setCancelling(true);
    try {
      await api.cancelRun(id);
    } catch (e) {
      setErr(errorText(e));
      setCancelling(false);
    }
  };

  if (loadErr) {
    return (
      <div className="screen">
        <PageHead title="Run" />
        <div className="screen-body">
          <ErrorNote>{loadErr}</ErrorNote>
          <a className="btn" href={href("runs")}>
            All runs
          </a>
        </div>
      </div>
    );
  }
  if (!detail) {
    return (
      <div className="screen">
        <PageHead title="Run" />
        <p className="empty pad">Loading…</p>
      </div>
    );
  }

  const { run, report } = detail;
  const name = report?.scenario || run.scenario || run.file || "scenario";
  const file = report?.file || run.file;

  return (
    <div className="screen run-screen">
      <div className="sr-only" aria-live="polite" role="status" data-testid="run-announce">
        {announce}
      </div>
      <PageHead
        title={
          <>
            <a href={href("runs")} className="crumb">
              Runs
            </a>
            <span className="crumb-sep">/</span>
            <span>{name}</span>
            <span className="crumb-sep">/</span>
            <span className="mono muted">{run.id}</span>
          </>
        }
      >
        {isRunning ? (
          <button type="button" className="btn" onClick={() => void cancel()} disabled={cancelling} data-testid="cancel">
            <Square size={13} aria-hidden="true" />
            {cancelling ? "Cancelling…" : "Cancel run"}
          </button>
        ) : (
          <>
            {report && <Downloads id={run.id} onError={setErr} />}
            {file && <RunAgain ctx={ctx} file={file} report={report} onError={setErr} />}
          </>
        )}
      </PageHead>
      <div className="screen-body">
        {err && <ErrorNote onDismiss={() => setErr("")}>{err}</ErrorNote>}
        {isRunning || !report ? (
          <LiveRun
            name={name}
            file={file}
            live={live}
            running={isRunning}
            cancelling={cancelling}
            selected={selected}
            onSelect={setSelected}
            engine={run.engine}
          />
        ) : (
          <FinishedRun report={report} selected={selected} onSelect={setSelected} />
        )}
      </div>
    </div>
  );
}

/** Report downloads. */
function Downloads({ id, onError }: { id: string; onError: (s: string) => void }) {
  const [busy, setBusy] = useState("");
  const get = async (f: ReportFormat) => {
    setBusy(f);
    try {
      await downloadReport(id, f);
    } catch (e) {
      onError(errorText(e));
    } finally {
      setBusy("");
    }
  };
  return (
    <div className="btn-group" role="group" aria-label="Download the report">
      <span className="btn-group-label">
        <Download size={13} aria-hidden="true" />
        Report
      </span>
      {FORMATS.map((f) => (
        <button
          key={f.format}
          type="button"
          className="btn small"
          disabled={busy !== ""}
          onClick={() => void get(f.format)}
          data-testid={`download-${f.format}`}
          aria-label={`Download the ${f.label} report`}
        >
          {f.label}
        </button>
      ))}
    </div>
  );
}

/** Opens the scenario or runs it again as the reproduce command does: same engine, trials and copies. */
function RunAgain({ ctx, file, report, onError }: { ctx: AppContext; file: string; report: Report | null; onError: (s: string) => void }) {
  const [busy, setBusy] = useState(false);
  const again = async () => {
    setBusy(true);
    try {
      const nid = await api.startRun({
        path: file,
        engine: report?.engine,
        trials: report?.stats.planned || undefined,
        copies: reproduceCopies(report?.reproduce),
        insecure: report?.reproduce.includes("--insecure") || undefined,
      });
      await ctx.refreshInfo();
      navigate(href("run", { id: nid }));
    } catch (e) {
      const other = runningIdFrom(e);
      onError(other ? "Another run is in progress; one run at a time." : errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <a className="btn" href={href("scenario", { path: file })}>
        <FileText size={13} aria-hidden="true" />
        Scenario
      </a>
      <button type="button" className="btn primary" onClick={() => void again()} disabled={busy || !!ctx.info?.running} data-testid="run-again">
        <Play size={13} aria-hidden="true" />
        Run again
      </button>
    </>
  );
}

/** The run while it goes on. */
function LiveRun({
  name,
  file,
  live,
  running,
  cancelling,
  selected,
  onSelect,
  engine,
}: {
  name: string;
  file: string;
  live: Live;
  running: boolean;
  cancelling: boolean;
  selected: number | null;
  onSelect: (n: number) => void;
  engine: string;
}) {
  const pct = live.planned > 0 ? Math.round((live.done / live.planned) * 100) : 0;
  const trial = live.trials.find((t) => t.number === selected) ?? live.trials[live.trials.length - 1];
  // The scenario may say "auto"; the races show the engine it resolved to.
  const shownEngine = live.trials.find((t) => t.race)?.race?.engine ?? engine;
  return (
    <section className="panel run-panel" data-testid="run-live">
      <div className="panel-head">
        <h2>{name}</h2>
        {file && <span className="muted mono">{file}</span>}
      </div>
      <div className="strip">
        <div className="verdict-cell">
          <Lozenge tone="accent">{running ? (cancelling ? "CANCELLING" : "RUNNING") : "FINISHING"}</Lozenge>
          <div className="progress-wrap">
            <div className="progress-text">
              {live.planned > 0 ? `Trial ${Math.min(live.done + (running ? 1 : 0), live.planned)} of ${live.planned}` : "Starting…"}
              <span className="muted">
                {live.done > 0 ? ` · ${live.done} done` : ""}
                {!live.connected && running ? " · connecting to the event stream" : ""}
              </span>
            </div>
            <div
              className="progress"
              role="progressbar"
              aria-label="Trials done"
              aria-valuemin={0}
              aria-valuemax={live.planned || 1}
              aria-valuenow={live.done}
              data-testid="progress"
            >
              <div className="progress-bar" style={{ width: `${pct}%` }} />
            </div>
          </div>
        </div>
        {shownEngine && <Metric label="Engine" value={shownEngine} />}
        <Metric label="Violated so far" value={String(live.trials.filter((t) => t.verdict === "VIOLATED").length)} />
      </div>
      <div className="run-grid">
        <TrialsColumn trials={live.trials} shown={trial} onSelect={onSelect} planned={live.planned} />
        <CenterColumn trial={trial} />
        <div className="col side">{trial ? <TrialBlocks trial={trial} /> : <p className="empty pad">Waiting for the first trial…</p>}</div>
      </div>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  const parts = value.split(" · ");
  if (parts.length === 1) {
    return (
      <div className="metric">
        <div className="label">{label}</div>
        <div className="value">{value}</div>
      </div>
    );
  }
  // A narrow cell wraps the value between its parts only, and a line never
  // starts or ends with the separator (see .metric .value.parts).
  return (
    <div className="metric">
      <div className="label">{label}</div>
      <div className="value parts">
        <span>
          {parts.map((part, i) => (
            <Fragment key={i}>
              {i > 0 && " "}
              <span className="nowrap">
                <span className="sep" aria-hidden={i === 0 || undefined}>
                  {i > 0 ? "·" : ""}
                </span>
                {part}
              </span>
            </Fragment>
          ))}
        </span>
      </div>
    </div>
  );
}

/** The finished run, laid out like the HTML report. */
function FinishedRun({ report, selected, onSelect }: { report: Report; selected: number | null; onSelect: (n: number) => void }) {
  const trials = trialsOf(report);
  const shown = trials.find((t) => t.number === selected) ?? defaultTrial(report);
  const ms = metrics(report, shown);
  const notes = reportNotes(report);
  const race = shown?.race;
  const footer: string[] = [];
  if (race?.tls_version) footer.push(race.tls_version);
  if (race?.alpn) footer.push(`ALPN ${race.alpn}`);
  if (race) footer.push(plural(race.connections, "connection"), `warm-up ${plural(race.warmup, "request")}`);
  if (report.tool) footer.push(report.tool);
  if (report.started_at) footer.push(`started ${formatTime(report.started_at)}`);
  const took = elapsed(report.started_at, report.finished_at);
  if (took) footer.push(`took ${took}`);

  return (
    <section className="panel run-panel" data-testid="run-report">
      <div className="panel-head">
        <h2>{report.scenario || "scenario"}</h2>
        <span className="muted ellipsis">
          {report.file}
          {report.file && report.target ? " · " : ""}
          {report.target}
        </span>
      </div>
      <div className="strip">
        <div className="verdict-cell">
          <Lozenge tone={verdictTone(report.verdict)}>
            <span data-testid="verdict">{report.verdict}</span>
          </Lozenge>
          <p className="summary" data-testid="summary">
            {report.summary}
          </p>
        </div>
        {ms.map((m) => (
          <Metric key={m.label} label={m.label} value={m.value} />
        ))}
      </div>
      <div className="run-grid">
        <TrialsColumn trials={trials} shown={shown} onSelect={onSelect} planned={report.stats.planned} />
        <CenterColumn trial={shown} />
        <div className="col side">
          {report.invariant && (
            <div className="block">
              <h3 className="block-title">Invariant</h3>
              <pre className="code" data-testid="invariant">
                {report.explain && <span className="comment">{`// ${oneLine(report.explain)}\n`}</span>}
                {report.invariant.trim()}
              </pre>
            </div>
          )}
          {shown && <TrialBlocks trial={shown} />}
          {notes.length > 0 && (
            <div className="block">
              <h3 className="block-title">Notes</h3>
              <ul className="plain">
                {notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
          )}
          {report.reproduce && (
            <div className="block">
              <div className="block-title-row">
                <h3 className="block-title">Reproduce</h3>
                <CopyButton text={report.reproduce} label="Copy command" />
              </div>
              <pre className="code reproduce" data-testid="reproduce">
                {reproduceWords(report.reproduce).map((w, i) => (
                  <span key={i}>
                    {i > 0 ? " " : ""}
                    {w}
                  </span>
                ))}
              </pre>
            </div>
          )}
        </div>
      </div>
      {footer.length > 0 && (
        <div className="statusbar">
          {footer.map((f) => (
            <span key={f}>{f}</span>
          ))}
        </div>
      )}
    </section>
  );
}

/** The trials table; selecting a row shows that trial. */
function TrialsColumn({
  trials,
  shown,
  onSelect,
  planned,
}: {
  trials: Trial[];
  shown: Trial | undefined;
  onSelect: (n: number) => void;
  planned: number;
}) {
  const body = useRef<HTMLTableSectionElement>(null);
  const move = (e: KeyboardEvent, idx: number) => {
    const delta = e.key === "ArrowDown" ? 1 : e.key === "ArrowUp" ? -1 : 0;
    if (!delta) return;
    e.preventDefault();
    const next = trials[idx + delta];
    if (!next) return;
    onSelect(next.number);
    body.current?.querySelectorAll<HTMLButtonElement>("button.trial-btn")[idx + delta]?.focus();
  };
  return (
    <div className="col trials">
      <h3 className="col-head">
        Trials <span className="muted">{planned > trials.length ? `${trials.length} of ${planned}` : trials.length}</span>
      </h3>
      {trials.length === 0 ? (
        <p className="empty pad">No trial has finished yet.</p>
      ) : (
        <div className="trials-scroll">
          <table className="table compact" data-testid="trials">
            <thead>
              <tr>
                <th>#</th>
                <th>Verdict</th>
                <th>Statuses</th>
                <th className="right">Spread</th>
              </tr>
            </thead>
            <tbody ref={body}>
              {trials.map((t, i) => {
                const sel = t.number === shown?.number;
                return (
                  <tr key={t.number} className={sel ? "selected" : ""} onClick={() => onSelect(t.number)}>
                    <td>
                      <button
                        type="button"
                        className="trial-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelect(t.number);
                        }}
                        onKeyDown={(e) => move(e, i)}
                        aria-pressed={sel}
                        aria-label={`Show trial ${t.number}, ${t.verdict}`}
                      >
                        {t.number}
                      </button>
                    </td>
                    <td>
                      <Lozenge tone={verdictTone(t.verdict)}>{t.verdict}</Lozenge>
                    </td>
                    <td className="mono nowrap">{compactStatuses(t.race)}</td>
                    <td className="mono right nowrap">{t.race ? formatMs(responseSpread(t.race)) : ""}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** The timeline and the server arrival strip of a trial. */
function CenterColumn({ trial }: { trial: Trial | undefined }) {
  if (!trial) {
    return (
      <div className="col center">
        <h3 className="col-head">Timeline</h3>
        <p className="empty pad">No trial to show yet.</p>
      </div>
    );
  }
  const race = trial.race;
  return (
    <div className="col center">
      <h3 className="col-head">{race ? `Trial ${trial.number} · ${raceCaption(race)}` : `Trial ${trial.number}`}</h3>
      {race && race.results.length > 0 ? (
        <>
          <Timeline race={race} violated={trial.verdict === "VIOLATED"} />
          <ArrivalStrip race={race} />
        </>
      ) : (
        <p className="empty pad">This trial has no race.</p>
      )}
    </div>
  );
}

/** Terms, reasons, check response and steps of one trial. */
function TrialBlocks({ trial }: { trial: Trial }) {
  const terms = trial.terms ?? [];
  const reasons = trial.reasons ?? [];
  const steps = [...(trial.setup ?? []).map((s) => ({ kind: "setup", s })), ...(trial.reset ?? []).map((s) => ({ kind: "reset", s }))];
  return (
    <>
      {terms.length > 0 && (
        <div className="block">
          <h3 className="block-title">Evaluated on trial {trial.number}</h3>
          <table className="terms" data-testid="terms">
            <tbody>
              {terms.map((tm, i) => {
                const st = termState(tm);
                const long = [...tm.value].length > MAX_INLINE_VALUE;
                return long ? (
                  <FragmentRows key={i} expr={tm.expr} value={tm.value} state={st} />
                ) : (
                  <tr key={i} data-state={st.label}>
                    <td className="expr mono">{tm.expr}</td>
                    <td className="val mono">{tm.value}</td>
                    <td className="state">
                      <Lozenge tone={st.tone}>{st.label}</Lozenge>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {reasons.length > 0 && (
        <div className="block">
          <h3 className="block-title">Reasons in trial {trial.number}</h3>
          <ul className="plain">
            {reasons.map((r) => (
              <li key={r} className={r.startsWith("note: ") ? "muted" : ""}>
                {r}
              </li>
            ))}
          </ul>
        </div>
      )}
      {trial.check && <CheckBlock check={trial.check} />}
      {steps.length > 0 && (
        <div className="block">
          <h3 className="block-title">Setup and reset</h3>
          <table className="steps" data-testid="steps">
            <tbody>
              {steps.map(({ kind, s }, i) => (
                <tr key={i}>
                  <td className="muted">{s.id || kind}</td>
                  <td className="mono step-req" title={s.url}>
                    {s.method} {pathOf(s.url)}
                  </td>
                  <td>
                    {s.error ? (
                      <Lozenge tone="err" title={s.error}>
                        error
                      </Lozenge>
                    ) : (
                      <Lozenge tone={s.status >= 200 && s.status < 300 ? "ok" : s.status >= 400 ? "bad" : "neutral"}>{s.status}</Lozenge>
                    )}
                  </td>
                  <td className="mono muted right nowrap">{formatDuration(s.duration_ns)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function FragmentRows({ expr, value, state }: { expr: string; value: string; state: { label: string; tone: ReturnType<typeof termState>["tone"] } }) {
  return (
    <>
      <tr data-state={state.label}>
        <td className="expr mono" colSpan={2}>
          {expr}
        </td>
        <td className="state">
          <Lozenge tone={state.tone}>{state.label}</Lozenge>
        </td>
      </tr>
      <tr className="long-value">
        <td className="val long mono" colSpan={3}>
          {value}
        </td>
      </tr>
    </>
  );
}

/** Path and query of a URL, for compact step lines. */
function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

/** The check request with its response body, collapsible. */
function CheckBlock({ check }: { check: StepRecord }) {
  const [open, setOpen] = useState(true);
  const parsed = useMemo(() => tryJSON(check.body ?? ""), [check.body]);
  return (
    <div className="block">
      <button type="button" className="block-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={13} aria-hidden="true" /> : <ChevronRight size={13} aria-hidden="true" />}
        <span className="block-title">Check response</span>
        {check.error ? (
          <Lozenge tone="err">error</Lozenge>
        ) : (
          <Lozenge tone={check.status >= 200 && check.status < 300 ? "ok" : "neutral"}>{check.status || "none"}</Lozenge>
        )}
        <span className="muted check-time">{formatDuration(check.duration_ns)}</span>
      </button>
      <div className="mono check-line" title={check.url}>
        {check.method} {check.url}
      </div>
      {open &&
        (check.error ? (
          <p className="bad-text">{check.error}</p>
        ) : !check.body ? (
          <p className="muted">Empty response body.</p>
        ) : parsed !== undefined ? (
          <div className="code body">
            <JsonView value={parsed} />
          </div>
        ) : (
          <pre className="code body">{check.body}</pre>
        ))}
    </div>
  );
}
