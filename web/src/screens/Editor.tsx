import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { EditorView } from "@codemirror/view";
import { CircleAlert, CircleCheck, Play, Save, Trash2 } from "lucide-react";
import { api, ApiError, runningIdFrom } from "../api";
import type { AppContext } from "../App";
import { Dialog, ErrorNote, errorText, PageHead, Toggle } from "../components/common";
import { createEditor, goTo, replaceDoc, showProblems } from "../editor/codemirror";
import { NEW_SCENARIO } from "../editor/template";
import { pathProblem, peekYaml, suggestPath } from "../editor/yamlPeek";
import { href, navigate, replaceHash, setLeaveGuard } from "../router";
import { ENGINES, type EngineKind, type RunRequest, type ScenarioSummary, type Validation } from "../types";

/** Delay between the last keystroke and validation. */
const VALIDATE_DELAY = 300;

/** An open dialog; "save-as" with run set starts the run once the file is saved. */
type Pending = { kind: "leave"; next: string } | { kind: "save-as"; run?: boolean } | { kind: "delete" } | { kind: "conflict" } | null;

/** The YAML editor of one workspace scenario, or of a new one when path is "". */
export function EditorScreen({ ctx, path: initialPath }: { ctx: AppContext; path: string }) {
  const [path, setPath] = useState(initialPath);
  const [baseline, setBaseline] = useState<string | null>(initialPath ? null : NEW_SCENARIO);
  const [hash, setHash] = useState<string | undefined>(undefined);
  const [doc, setDoc] = useState(initialPath ? "" : NEW_SCENARIO);
  const [loadErr, setLoadErr] = useState("");
  const [err, setErr] = useState<{ text: string; runId?: string } | null>(null);
  const [validation, setValidation] = useState<Validation | null>(null);
  const [validating, setValidating] = useState(false);
  const [summary, setSummary] = useState<ScenarioSummary | null>(null);
  const [pending, setPending] = useState<Pending>(null);
  const [saving, setSaving] = useState(false);
  const [starting, setStarting] = useState(false);
  const [status, setStatus] = useState("");
  const [engine, setEngine] = useState<EngineKind | "">("");
  const [trials, setTrials] = useState("");
  const [copies, setCopies] = useState("");
  const [insecure, setInsecure] = useState(false);

  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const isNew = path === "";
  const dirty = baseline !== null && doc !== baseline;

  // Load the file.
  useEffect(() => {
    if (!initialPath) return;
    let live = true;
    api
      .readFile(initialPath)
      .then((f) => {
        if (!live) return;
        setBaseline(f.content);
        setDoc(f.content);
        setHash(f.hash);
      })
      .catch((e) => live && setLoadErr(errorText(e)));
    return () => {
      live = false;
    };
  }, [initialPath]);

  // Create the editor once the content is there.
  const ready = baseline !== null;
  useEffect(() => {
    if (!ready || !host.current || view.current) return;
    view.current = createEditor({ parent: host.current, doc, label: "Scenario YAML", onChange: setDoc });
    return () => {
      view.current?.destroy();
      view.current = null;
    };
    // The editor owns the document from here on; doc only seeds it.
  }, [ready]);

  // Validate after a pause in typing.
  useEffect(() => {
    if (!ready) return;
    const ctl = new AbortController();
    setValidating(true);
    const timer = window.setTimeout(() => {
      api
        .validate(doc, path || undefined, ctl.signal)
        .then((v) => {
          setValidation(v);
          if (v.scenario) setSummary(v.scenario);
          if (view.current) showProblems(view.current, v.errors);
        })
        .catch((e) => {
          if (!(e instanceof DOMException && e.name === "AbortError")) setErr({ text: errorText(e) });
        })
        .finally(() => !ctl.signal.aborted && setValidating(false));
    }, VALIDATE_DELAY);
    return () => {
      window.clearTimeout(timer);
      ctl.abort();
    };
  }, [doc, ready, path]);

  // Ask before leaving with unsaved changes.
  useEffect(() => {
    if (!dirty) {
      setLeaveGuard(null);
      return;
    }
    setLeaveGuard((next) => {
      setPending({ kind: "leave", next });
      return false;
    });
    const onUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", onUnload);
    return () => {
      setLeaveGuard(null);
      window.removeEventListener("beforeunload", onUnload);
    };
  }, [dirty]);

  const write = useCallback(
    async (target: string, force = false): Promise<boolean> => {
      setSaving(true);
      setErr(null);
      try {
        const res = await api.writeFile(target, doc, force || target !== path ? undefined : hash);
        setHash(res.hash);
        setBaseline(doc);
        setStatus(`Saved ${target}`);
        if (target !== path) {
          setPath(target);
          // Reflect the file in the address without remounting the editor;
          // the router must know, or a refused navigation restores the old
          // address.
          replaceHash(href("scenario", { path: target }));
        }
        return true;
      } catch (e) {
        if (e instanceof ApiError && e.status === 409 && target === path && !force) {
          setPending({ kind: "conflict" });
        } else {
          setErr({ text: errorText(e) });
        }
        return false;
      } finally {
        setSaving(false);
      }
    },
    [doc, hash, path],
  );

  const save = useCallback(async (): Promise<boolean> => {
    if (isNew) {
      setPending({ kind: "save-as" });
      return false;
    }
    if (!dirty) return true;
    return write(path);
  }, [isNew, dirty, path, write]);

  // Ctrl+S / Cmd+S anywhere on this screen.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "s") {
        e.preventDefault();
        void save();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [save]);

  const peek = useMemo(() => peekYaml(doc), [doc]);
  const scenarioInsecure = summary?.insecure ?? peek.insecure;
  const budgetRequests = summary?.budgetRequests ?? peek.budgetRequests;
  const budgetRps = summary?.budgetRps ?? peek.budgetRps;
  const valid = validation?.valid ?? false;
  const problems = validation?.errors ?? [];
  const running = ctx.info?.running ?? "";

  const trialsN = trials.trim() === "" ? 0 : Number(trials);
  const copiesN = copies.trim() === "" ? 0 : Number(copies);
  const trialsBad = trials.trim() !== "" && (!Number.isInteger(trialsN) || trialsN < 1 || trialsN > 10000);
  const copiesBad = copies.trim() !== "" && (!Number.isInteger(copiesN) || copiesN < 1 || copiesN > 1000);

  // A run always names a workspace file: a new scenario is saved first, so
  // that the buffer is not lost and the stored reproduce command names a
  // file that exists.
  const run = async () => {
    if (isNew) {
      setPending({ kind: "save-as", run: true });
      return;
    }
    await startRun(path, dirty);
  };

  const startRun = async (target: string, saveFirst: boolean) => {
    setErr(null);
    setStarting(true);
    try {
      if (saveFirst && !(await write(target))) return;
      const req: RunRequest = { path: target };
      if (engine) req.engine = engine;
      if (trialsN > 0) req.trials = trialsN;
      if (copiesN > 0) req.copies = copiesN;
      if (insecure && !scenarioInsecure) req.insecure = true;
      const id = await api.startRun(req);
      await ctx.refreshInfo();
      navigate(href("run", { id }), true);
    } catch (e) {
      const other = runningIdFrom(e);
      setErr({ text: other ? "Another run is in progress; one run at a time." : errorText(e), runId: other || undefined });
    } finally {
      setStarting(false);
    }
  };

  const title = isNew ? "New scenario" : path;

  if (loadErr) {
    return (
      <div className="screen">
        <PageHead title={<span className="mono">{initialPath}</span>} detail="Scenario file" />
        <div className="screen-body">
          <ErrorNote>{loadErr}</ErrorNote>
          <a className="btn" href={href("scenarios")}>
            Back to scenarios
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="screen editor-screen">
      <PageHead
        title={
          <>
            <a href={href("scenarios")} className="crumb">
              Scenarios
            </a>
            <span className="crumb-sep">/</span>
            <span className={isNew ? "" : "mono"} data-testid="editor-title">
              {title}
            </span>
            {dirty && (
              <span className="dirty" data-testid="dirty">
                unsaved
              </span>
            )}
          </>
        }
      >
        <span className="status-text" role="status" aria-live="polite">
          {saving ? "Saving…" : status && !dirty ? status : ""}
        </span>
        {!isNew && (
          <button type="button" className="icon-btn" onClick={() => setPending({ kind: "delete" })} aria-label="Delete file" title="Delete file">
            <Trash2 size={14} />
          </button>
        )}
        <button
          type="button"
          className="btn"
          onClick={() => void save()}
          disabled={saving || (!dirty && !isNew)}
          title="Save (Ctrl+S)"
          data-testid="save"
        >
          <Save size={14} aria-hidden="true" />
          Save
          <kbd>Ctrl S</kbd>
        </button>
      </PageHead>

      <div className="editor-layout">
        <div className="editor-col">
          <div className="editor-host" ref={host} data-testid="editor">
            {!ready && <p className="empty pad">Loading…</p>}
          </div>
          <section className="problems" aria-labelledby="problems-head" data-testid="problems">
            <div className="problems-head">
              <h2 id="problems-head">Problems</h2>
              <span className="count" data-testid="problem-count">
                {problems.length}
              </span>
              <span className="muted push" aria-live="polite">
                {validating ? "Checking…" : validation ? (valid ? "Valid scenario" : "") : ""}
              </span>
            </div>
            {problems.length === 0 ? (
              <p className="problems-ok">
                {validation && valid ? (
                  <>
                    <CircleCheck size={13} aria-hidden="true" /> Parsed, validated and the invariant compiles.
                  </>
                ) : (
                  <span className="muted">Checking the scenario…</span>
                )}
              </p>
            ) : (
              <ul className="problem-list">
                {problems.map((p, i) => (
                  <li key={`${i}-${p.line}-${p.message}`}>
                    <button
                      type="button"
                      onClick={() => view.current && p.line > 0 && goTo(view.current, p.line, p.column)}
                      disabled={p.line < 1}
                      data-testid="problem"
                      data-line={p.line}
                    >
                      <CircleAlert size={13} className="bad-icon" aria-hidden="true" />
                      <span className="where mono">{p.line > 0 ? `Ln ${p.line}${p.column > 0 ? `, Col ${p.column}` : ""}` : "File"}</span>
                      {p.field && <span className="field mono">{p.field}</span>}
                      <span className="msg">{p.message}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        <aside className="side-col" aria-label="Scenario summary and run options">
          <section className="block">
            <h2 className="block-title">Scenario</h2>
            {summary ? (
              <dl className={`kv ${valid ? "" : "stale"}`} data-testid="summary">
                <dt>Name</dt>
                <dd className="mono">{summary.name}</dd>
                <dt>Target</dt>
                <dd className="mono break">{summary.target}</dd>
                <dt>Scope</dt>
                <dd className="mono break">
                  {summary.allowHosts.join(", ") || "not set"}
                  {budgetRequests > 0 && (
                    <span className="muted">
                      {" "}
                      · {budgetRequests} requests{budgetRps > 0 ? `, ${budgetRps} rps` : ""}
                    </span>
                  )}
                </dd>
                <dt>Engine</dt>
                <dd className="mono">{summary.engine || "auto"}</dd>
                <dt>Copies</dt>
                <dd className="mono">{summary.copies || "—"}</dd>
                <dt>Trials</dt>
                <dd className="mono">{summary.trials || "—"}</dd>
                <dt>TLS</dt>
                <dd>{scenarioInsecure ? "certificate not verified (tls.insecure)" : "certificate verified"}</dd>
              </dl>
            ) : (
              <p className="muted">{validation && !valid ? "Fix the problems to see the parsed scenario." : "Reading the scenario…"}</p>
            )}
            {summary && !valid && <p className="muted small">From the last valid version.</p>}
          </section>
          {summary?.invariant && (
            <section className="block">
              <h2 className="block-title">Invariant</h2>
              <pre className="code">{summary.invariant.trim()}</pre>
            </section>
          )}
          <section className="block">
            <h2 className="block-title">Run</h2>
            <div className="form-grid">
              <label htmlFor="run-engine">Engine</label>
              <select id="run-engine" className="input" value={engine} onChange={(e) => setEngine(e.target.value as EngineKind | "")}>
                <option value="">From scenario{summary?.engine ? ` (${summary.engine})` : ""}</option>
                {ENGINES.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </select>
              <label htmlFor="run-trials">Trials</label>
              <input
                id="run-trials"
                className={`input mono ${trialsBad ? "invalid" : ""}`}
                inputMode="numeric"
                placeholder={summary?.trials ? String(summary.trials) : "10"}
                value={trials}
                onChange={(e) => setTrials(e.target.value)}
                aria-invalid={trialsBad}
                data-testid="run-trials"
              />
              <label htmlFor="run-copies">Copies</label>
              <input
                id="run-copies"
                className={`input mono ${copiesBad ? "invalid" : ""}`}
                inputMode="numeric"
                placeholder={summary?.copies ? String(summary.copies) : "20"}
                value={copies}
                onChange={(e) => setCopies(e.target.value)}
                aria-invalid={copiesBad}
              />
            </div>
            {!scenarioInsecure && (
              <Toggle
                checked={insecure}
                onChange={setInsecure}
                label="Skip TLS certificate verification"
                hint="For lab targets with self-signed certificates."
              />
            )}
            {(trialsBad || copiesBad) && (
              <p className="field-error">
                {trialsBad ? "Trials must be a whole number from 1 to 10000. " : ""}
                {copiesBad ? "Copies must be a whole number from 1 to 1000." : ""}
              </p>
            )}
            <button
              type="button"
              className="btn primary wide"
              disabled={!valid || starting || saving || trialsBad || copiesBad || running !== ""}
              onClick={() => void run()}
              data-testid="run"
            >
              <Play size={14} aria-hidden="true" />
              {starting ? "Starting…" : dirty || isNew ? "Save and run" : "Run"}
            </button>
            {running && (
              <p className="muted small">
                A run is in progress. <a href={href("run", { id: running })}>Open it</a>
              </p>
            )}
            {!valid && validation && <p className="muted small">Fix the problems to run the scenario.</p>}
            <p className="muted small">Requests go only to the hosts in scope. Run scenarios only against systems you may test.</p>
          </section>
          {err && (
            <div className="pad-x">
              <ErrorNote onDismiss={() => setErr(null)}>
                {err.text}
                {err.runId && (
                  <>
                    {" "}
                    <a href={href("run", { id: err.runId })}>Open the running run</a>
                  </>
                )}
              </ErrorNote>
            </div>
          )}
        </aside>
      </div>

      {pending?.kind === "leave" && (
        <Dialog
          title="Discard unsaved changes?"
          onClose={() => setPending(null)}
          actions={
            <>
              <button type="button" className="btn" data-autofocus onClick={() => setPending(null)}>
                Keep editing
              </button>
              <button
                type="button"
                className="btn danger"
                onClick={() => {
                  const next = pending.next;
                  setPending(null);
                  setLeaveGuard(null);
                  navigate(next, true);
                }}
                data-testid="discard"
              >
                Discard changes
              </button>
            </>
          }
        >
          <p>{isNew ? "The new scenario has not been saved." : `Changes to ${path} have not been saved.`}</p>
        </Dialog>
      )}
      {pending?.kind === "save-as" && (
        <SaveAsDialog
          initial={suggestPath(peek.name || summary?.name || "")}
          andRun={pending.run ?? false}
          onCancel={() => setPending(null)}
          onSave={async (p) => {
            const ok = await write(p);
            if (ok) {
              const then = pending.run;
              setPending(null);
              if (then) await startRun(p, false);
            }
            return ok;
          }}
        />
      )}
      {pending?.kind === "conflict" && (
        <Dialog
          title="The file changed on disk"
          onClose={() => setPending(null)}
          actions={
            <>
              <button type="button" className="btn" data-autofocus onClick={() => setPending(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn"
                onClick={async () => {
                  setPending(null);
                  const f = await api.readFile(path);
                  setBaseline(f.content);
                  setHash(f.hash);
                  if (view.current) replaceDoc(view.current, f.content);
                }}
              >
                Load the file from disk
              </button>
              <button
                type="button"
                className="btn danger"
                onClick={() => {
                  setPending(null);
                  void write(path, true);
                }}
              >
                Overwrite
              </button>
            </>
          }
        >
          <p>{path} was changed by another program since it was opened. Overwrite it with this version, or load the version on disk?</p>
        </Dialog>
      )}
      {pending?.kind === "delete" && (
        <Dialog
          title="Delete this scenario file?"
          onClose={() => setPending(null)}
          actions={
            <>
              <button type="button" className="btn" data-autofocus onClick={() => setPending(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn danger"
                onClick={async () => {
                  setPending(null);
                  try {
                    await api.deleteFile(path);
                    setLeaveGuard(null);
                    navigate(href("scenarios"), true);
                  } catch (e) {
                    setErr({ text: errorText(e) });
                  }
                }}
              >
                Delete
              </button>
            </>
          }
        >
          <p>
            <span className="mono">{path}</span> will be removed from the workspace. Its runs stay in the history.
          </p>
        </Dialog>
      )}
    </div>
  );
}

/** Asks for the workspace path of a new file. */
function SaveAsDialog({
  initial,
  andRun,
  onCancel,
  onSave,
}: {
  initial: string;
  /** The scenario runs once it is saved. */
  andRun: boolean;
  onCancel: () => void;
  onSave: (path: string) => Promise<boolean>;
}) {
  const [value, setValue] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [exists, setExists] = useState(false);
  const problem = pathProblem(value);
  const submit = async () => {
    if (problem) return;
    setBusy(true);
    try {
      if (!exists) {
        const list = await api.scenarios().catch(() => null);
        if (list?.scenarios.some((s) => s.path === value.trim())) {
          setExists(true);
          return;
        }
      }
      await onSave(value.trim());
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title="Save scenario"
      onClose={onCancel}
      actions={
        <>
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="btn primary" disabled={!!problem || busy} onClick={() => void submit()} data-testid="save-as-confirm">
            {exists ? (andRun ? "Overwrite and run" : "Overwrite") : andRun ? "Save and run" : "Save"}
          </button>
        </>
      }
    >
      <label htmlFor="save-path" className="field-label">
        File in the workspace
      </label>
      <input
        id="save-path"
        className="input mono wide"
        value={value}
        data-autofocus
        onChange={(e) => {
          setValue(e.target.value);
          setExists(false);
        }}
        onKeyDown={(e) => e.key === "Enter" && void submit()}
        aria-invalid={!!problem}
        data-testid="save-path"
      />
      {problem && <p className="field-error">{problem}</p>}
      {exists && <p className="field-error">A file with this name exists. Save again to overwrite it.</p>}
      {andRun && <p className="muted small">A run needs a file in the workspace: the run history and the reproduce command name it.</p>}
    </Dialog>
  );
}
