import { useCallback, useEffect, useRef, useState } from "react";
import { RefreshCw, Trash2 } from "lucide-react";
import { api } from "../api";
import type { AppContext } from "../App";
import { Dialog, Empty, ErrorNote, errorText, Lozenge, PageHead } from "../components/common";
import { elapsed, formatTime, relativeTime } from "../format";
import { verdictTone } from "../report";
import { href } from "../router";
import type { RunRecord, Verdict } from "../types";

const VERDICTS: Verdict[] = ["VIOLATED", "HELD", "INCONCLUSIVE", "ERROR"];

/** How many runs the history shows; the filters apply on the server first. */
const LIMIT = 500;

/** History of runs with filters by scenario and verdict. */
export function RunsScreen({ ctx, initialScenario }: { ctx: AppContext; initialScenario: string }) {
  const [runs, setRuns] = useState<RunRecord[] | null>(null);
  const [names, setNames] = useState<string[]>([]);
  const [err, setErr] = useState("");
  const [scenario, setScenario] = useState(initialScenario);
  const [verdict, setVerdict] = useState<Verdict | "">("");
  const [confirm, setConfirm] = useState<RunRecord | null>(null);
  const running = ctx.info?.running ?? "";

  // A link to #/runs?scenario=X while this screen is open sets the filter.
  useEffect(() => setScenario(initialScenario), [initialScenario]);

  // The server filters before it limits, so old runs of a scenario are
  // found however many newer runs other scenarios have.
  const seq = useRef(0);
  const load = useCallback(async () => {
    const n = ++seq.current;
    try {
      const [list, all] = await Promise.all([api.runs(scenario, LIMIT, verdict || undefined), api.runScenarios()]);
      if (n !== seq.current) return; // a newer filter is loading
      setRuns(list);
      setNames(all);
      setErr("");
    } catch (e) {
      if (n === seq.current) setErr(errorText(e));
    }
  }, [scenario, verdict]);

  useEffect(() => {
    void load();
  }, [load]);

  // Refresh while a run is in progress so that it lands in the list.
  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(() => void load(), 2000);
    return () => window.clearInterval(t);
  }, [running, load]);

  const filtered = scenario !== "" || verdict !== "";
  const shown = runs ?? [];

  const remove = async (r: RunRecord) => {
    setConfirm(null);
    try {
      await api.deleteRun(r.id);
      await load();
    } catch (e) {
      setErr(errorText(e));
    }
  };

  return (
    <div className="screen">
      <PageHead title="Runs" detail={runs && !filtered ? (runs.length === LIMIT ? `latest ${LIMIT} shown` : `${runs.length} stored`) : ""}>
        <button type="button" className="icon-btn" onClick={() => void load()} aria-label="Reload the list" title="Reload the list">
          <RefreshCw size={14} />
        </button>
      </PageHead>
      <div className="screen-body">
        {err && <ErrorNote onDismiss={() => setErr("")}>{err}</ErrorNote>}
        <section className="panel">
          <div className="panel-head filters">
            <label htmlFor="f-scenario">Scenario</label>
            <select id="f-scenario" className="input" value={scenario} onChange={(e) => setScenario(e.target.value)} data-testid="filter-scenario">
              <option value="">All</option>
              {names.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
              {scenario && !names.includes(scenario) && <option value={scenario}>{scenario}</option>}
            </select>
            <label htmlFor="f-verdict">Verdict</label>
            <select id="f-verdict" className="input" value={verdict} onChange={(e) => setVerdict(e.target.value as Verdict | "")} data-testid="filter-verdict">
              <option value="">All</option>
              {VERDICTS.map((v) => (
                <option key={v} value={v}>
                  {v.toLowerCase()}
                </option>
              ))}
            </select>
            {filtered && (
              <button
                type="button"
                className="btn small ghost"
                onClick={() => {
                  setScenario("");
                  setVerdict("");
                }}
              >
                Clear filters
              </button>
            )}
            <span className="muted push nowrap">{runs ? `${shown.length} shown` : ""}</span>
          </div>
          {!runs ? (
            <p className="empty pad">Loading…</p>
          ) : runs.length === 0 && !filtered ? (
            <Empty title="No runs yet">
              <p>Runs started from the editor are stored here with their full report.</p>
              <a className="btn" href={href("scenarios")}>
                Open the scenarios
              </a>
            </Empty>
          ) : shown.length === 0 ? (
            <p className="empty pad">No run matches the filters.</p>
          ) : (
            <div className="table-wrap">
              <table className="table runs-table" data-testid="runs-table">
                <thead>
                  <tr>
                    <th>Verdict</th>
                    <th>Scenario</th>
                    <th>Summary</th>
                    <th>Engine</th>
                    <th className="right">Trials</th>
                    <th className="right col-copies">Copies</th>
                    <th>Started</th>
                    <th className="right">Took</th>
                    <th>
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((r) => (
                    <tr key={r.id} data-testid="run-row" data-scenario={r.scenario}>
                      <td>
                        <a href={href("run", { id: r.id })} className="loz-link">
                          {r.running ? <Lozenge tone="accent">RUNNING</Lozenge> : <Lozenge tone={verdictTone(r.verdict)}>{r.verdict || "?"}</Lozenge>}
                        </a>
                      </td>
                      <td className="name-cell">
                        <a href={href("run", { id: r.id })} className="strong">
                          {r.scenario || "(unnamed)"}
                        </a>
                        {r.file && (
                          <div className="sub muted mono path-cell" title={r.file}>
                            <bdi>{r.file}</bdi>
                          </div>
                        )}
                      </td>
                      <td className="summary-cell" title={r.summary}>
                        {r.summary}
                      </td>
                      <td className="mono">{r.engine}</td>
                      <td className="mono right nowrap">
                        {r.violated > 0 ? (
                          <span title={`${r.violated} of ${r.trials} trials violated`}>
                            <span className="bad-text">{r.violated}</span>/{r.trials}
                          </span>
                        ) : (
                          r.trials || ""
                        )}
                      </td>
                      <td className="mono right col-copies">{r.copies || ""}</td>
                      <td className="nowrap" title={formatTime(r.startedAt)}>
                        {relativeTime(r.startedAt)}
                      </td>
                      <td className="mono right nowrap">{elapsed(r.startedAt, r.finishedAt)}</td>
                      <td className="right">
                        <button
                          type="button"
                          className="icon-btn"
                          disabled={r.running}
                          onClick={() => setConfirm(r)}
                          aria-label={`Delete run ${r.id} of ${r.scenario}`}
                          title={r.running ? "A run in progress cannot be deleted" : "Delete run"}
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
      {confirm && (
        <Dialog
          title="Delete this run?"
          onClose={() => setConfirm(null)}
          actions={
            <>
              <button type="button" className="btn" data-autofocus onClick={() => setConfirm(null)}>
                Cancel
              </button>
              <button type="button" className="btn danger" onClick={() => void remove(confirm)} data-testid="confirm-delete">
                Delete
              </button>
            </>
          }
        >
          <p>
            The run of {confirm.scenario || "this scenario"} from {formatTime(confirm.startedAt)} and its report are removed from the local
            history. This cannot be undone.
          </p>
        </Dialog>
      )}
    </div>
  );
}
