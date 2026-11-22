import { useCallback, useEffect, useState } from "react";
import { Check, Copy, FileInput, Plus, RefreshCw } from "lucide-react";
import { api, ApiError } from "../api";
import type { AppContext } from "../App";
import { Empty, ErrorNote, errorText, Lozenge, PageHead } from "../components/common";
import { formatTime, relativeTime } from "../format";
import { verdictTone } from "../report";
import { href } from "../router";
import type { Example, ScenarioList } from "../types";

/** The scenario files of the workspace and the embedded examples. */
export function ScenariosScreen({ ctx }: { ctx: AppContext }) {
  const [list, setList] = useState<ScenarioList | null>(null);
  const [err, setErr] = useState("");
  const [copying, setCopying] = useState<string[]>([]);

  const load = useCallback(async () => {
    try {
      setList(await api.scenarios());
      setErr("");
    } catch (e) {
      setErr(errorText(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const inWorkspace = (ex: Example) => ex.inWorkspace || (list?.scenarios.some((s) => s.path === ex.path) ?? false);

  const copy = async (names: string[]) => {
    setCopying(names);
    setErr("");
    try {
      for (const n of names) {
        try {
          await api.copyExample(n);
        } catch (e) {
          // Already in the workspace: nothing to do.
          if (!(e instanceof ApiError && e.status === 409)) throw e;
        }
      }
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setCopying([]);
      await load();
    }
  };

  const scenarios = list?.scenarios ?? [];
  const examples = list?.examples ?? [];
  const missing = examples.filter((ex) => !inWorkspace(ex)).map((ex) => ex.name);
  const ws = ctx.info?.workspace;

  return (
    <div className="screen">
      <PageHead title="Scenarios" detail={list ? `${scenarios.length} ${scenarios.length === 1 ? "file" : "files"} in the workspace` : ""}>
        <button type="button" className="icon-btn" onClick={() => void load()} aria-label="Reload the list" title="Reload the list">
          <RefreshCw size={14} />
        </button>
        <a className="btn" href={href("import")}>
          <FileInput size={14} aria-hidden="true" />
          Import
        </a>
        <a className="btn primary" href={href("scenario")} data-testid="new-scenario">
          <Plus size={14} aria-hidden="true" />
          New scenario
        </a>
      </PageHead>
      <div className="screen-body">
        {err && <ErrorNote onDismiss={() => setErr("")}>{err}</ErrorNote>}

        <section className="panel" aria-labelledby="ws-head">
          <div className="panel-head">
            <h2 id="ws-head">Workspace</h2>
            {ws && <span className="muted mono ellipsis">{ws}</span>}
          </div>
          {!list ? (
            <p className="empty pad">Loading…</p>
          ) : scenarios.length === 0 ? (
            <Empty title="No scenarios in this workspace yet">
              <p>
                PhotoFinish lists the <code>*.yaml</code> and <code>*.yml</code> files under {ws ? <code>{ws}</code> : "the workspace"}{" "}
                (four levels deep). Copy the examples to try the demo shop, write a scenario from a template, or turn a captured request
                into one.
              </p>
              <div className="row gap">
                {examples.length > 0 && (
                  <button
                    type="button"
                    className="btn primary"
                    disabled={copying.length > 0}
                    onClick={() => void copy(examples.map((e) => e.name))}
                    data-testid="copy-all-examples"
                  >
                    <Copy size={14} aria-hidden="true" />
                    Copy all examples
                  </button>
                )}
                <a className="btn" href={href("scenario")}>
                  New scenario
                </a>
                <a className="btn" href={href("import")}>
                  Import a request
                </a>
              </div>
            </Empty>
          ) : (
            <div className="table-wrap">
              <table className="table" data-testid="scenario-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th className="col-file">File</th>
                    <th>Target</th>
                    <th>Engine</th>
                    <th>Last run</th>
                  </tr>
                </thead>
                <tbody>
                  {scenarios.map((s) => (
                    <tr key={s.path} data-testid={`scenario-row-${s.path}`} className={s.valid ? "" : "invalid"}>
                      <td className="name-cell">
                        <a href={href("scenario", { path: s.path })} className="strong" title={s.path}>
                          {s.name || s.path}
                        </a>
                        {s.valid ? (
                          s.description && <div className="sub muted clamp">{s.description}</div>
                        ) : (
                          <div className="sub invalid-msg">
                            <Lozenge tone="err">invalid</Lozenge> <span>{s.error || "The file does not parse."}</span>
                          </div>
                        )}
                      </td>
                      <td className="mono path-cell col-file" title={s.path}>
                        <bdi>{s.path}</bdi>
                      </td>
                      <td className="mono ellipsis-cell" title={s.target}>
                        {s.target}
                      </td>
                      <td className="mono">{s.engine}</td>
                      <td className="nowrap last-cell">
                        {s.lastRun ? (
                          <a href={href("run", { id: s.lastRun.id })} className="last-run" title={formatTime(s.lastRun.finishedAt)}>
                            {s.lastRun.verdict ? (
                              <Lozenge tone={verdictTone(s.lastRun.verdict)}>{s.lastRun.verdict}</Lozenge>
                            ) : (
                              <Lozenge tone="accent">RUNNING</Lozenge>
                            )}
                            <span className="muted">{relativeTime(s.lastRun.finishedAt)}</span>
                          </a>
                        ) : (
                          <span className="muted">never</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {list.truncated && (
                <p className="muted small pad">The workspace has more scenario files than the list shows (500 at most); open a smaller workspace.</p>
              )}
            </div>
          )}
        </section>

        {examples.length > 0 && (
          <section className="panel" aria-labelledby="ex-head">
            <div className="panel-head">
              <h2 id="ex-head">Examples for the demo shop</h2>
              <span className="muted">Each comes in a racy (-vuln) and a fixed (-fixed) variant of the same endpoint.</span>
              {missing.length > 0 && scenarios.length > 0 && (
                <button
                  type="button"
                  className="btn small push"
                  disabled={copying.length > 0}
                  onClick={() => void copy(missing)}
                  data-testid="copy-missing-examples"
                >
                  Copy all
                </button>
              )}
            </div>
            <div className="table-wrap">
              <table className="table" data-testid="example-table">
                <thead>
                  <tr>
                    <th>Example</th>
                    <th>Description</th>
                    <th className="right">Workspace</th>
                  </tr>
                </thead>
                <tbody>
                  {examples.map((ex) => {
                    const there = inWorkspace(ex);
                    const busy = copying.includes(ex.name);
                    return (
                      <tr key={ex.name}>
                        <td className="mono nowrap">{ex.name}</td>
                        <td className="muted clamp-cell">{ex.description}</td>
                        <td className="right nowrap">
                          {there ? (
                            <a className="btn small ghost" href={href("scenario", { path: ex.path })}>
                              <Check size={13} aria-hidden="true" />
                              Open
                            </a>
                          ) : (
                            <button
                              type="button"
                              className="btn small"
                              disabled={busy}
                              onClick={() => void copy([ex.name])}
                              data-testid={`copy-example-${ex.name}`}
                            >
                              {busy ? "Copying…" : "Copy to workspace"}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
