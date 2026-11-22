import { useEffect, useMemo, useRef, useState, type DragEvent } from "react";
import type { EditorView } from "@codemirror/view";
import { FileUp, ListTodo, Save, Wand2 } from "lucide-react";
import { api } from "../api";
import type { AppContext } from "../App";
import { ErrorNote, errorText, PageHead } from "../components/common";
import { createEditor, replaceDoc } from "../editor/codemirror";
import { pathProblem, suggestPath } from "../editor/yamlPeek";
import { href, navigate } from "../router";
import type { ImportResult } from "../types";

type Kind = "auto" | "burp" | "har";

const KINDS: { kind: Kind; label: string }[] = [
  { kind: "auto", label: "Detect" },
  { kind: "burp", label: "Raw request" },
  { kind: "har", label: "HAR" },
];

/** Largest input accepted; the server caps request bodies at 1 MiB. */
const MAX_INPUT = 1000 * 1024;

interface HarEntry {
  index: number;
  label: string;
}

/** Lists the requests of a HAR file, or returns null when text is not one. */
function harEntries(text: string): HarEntry[] | null {
  const t = text.trim().replace(/^﻿/, "");
  if (!t.startsWith("{")) return null;
  try {
    const doc: unknown = JSON.parse(t);
    if (typeof doc !== "object" || doc === null) return null;
    const log = (doc as { log?: unknown }).log;
    if (typeof log !== "object" || log === null) return null;
    const entries = (log as { entries?: unknown }).entries;
    if (!Array.isArray(entries)) return null;
    return entries.map((e: unknown, index) => {
      const req = typeof e === "object" && e !== null ? (e as { request?: { method?: unknown; url?: unknown } }).request : undefined;
      const method = typeof req?.method === "string" ? req.method : "?";
      const url = typeof req?.url === "string" ? req.url : "";
      return { index, label: `${index} · ${method} ${url}` };
    });
  } catch {
    return null;
  }
}

/** Turns a raw HTTP request or a HAR entry into a scenario skeleton. */
export function ImportScreen({ ctx }: { ctx: AppContext }) {
  const [kind, setKind] = useState<Kind>("auto");
  const [text, setText] = useState("");
  const [entry, setEntry] = useState(0);
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  const [path, setPath] = useState("");
  const [saving, setSaving] = useState(false);
  const [exists, setExists] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const outRef = useRef<HTMLElement>(null);
  const kindRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const entries = useMemo(() => (kind === "burp" ? null : harEntries(text)), [text, kind]);
  const isHar = kind === "har" || (kind === "auto" && entries !== null);

  useEffect(() => {
    if (entries && entry >= entries.length) setEntry(0);
  }, [entries, entry]);

  const readFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > MAX_INPUT) {
      setErr(`${f.name} is ${Math.round(f.size / 1024)} KiB; the import takes up to 1000 KiB.`);
      return;
    }
    setErr("");
    setText(await f.text());
    setResult(null);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    void readFile(e.dataTransfer.files[0]);
  };

  const generate = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await api.importRequest(kind, text, isHar ? entry : undefined);
      setResult(r);
      setPath(suggestPath(r.name, "imported"));
      setExists(false);
      // Below 1180 px the result is stacked under the input, out of view:
      // bring it up and move focus there.
      window.requestAnimationFrame(() => {
        const out = outRef.current;
        if (!out) return;
        const box = out.getBoundingClientRect();
        if (box.top > 80 && box.bottom > window.innerHeight) out.scrollIntoView({ block: "start", behavior: "smooth" });
        out.focus({ preventScroll: true });
      });
    } catch (e) {
      setErr(errorText(e));
      setResult(null);
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    if (!result) return;
    const p = path.trim();
    setSaving(true);
    setErr("");
    try {
      if (!exists) {
        const list = await api.scenarios();
        if (list.scenarios.some((s) => s.path === p)) {
          setExists(true);
          return;
        }
      }
      await api.writeFile(p, result.content);
      navigate(href("scenario", { path: p }), true);
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setSaving(false);
    }
  };

  const problem = result ? pathProblem(path) : "";
  const tooBig = text.length > MAX_INPUT;

  return (
    <div className="screen">
      <PageHead title="Import" detail="A raw HTTP request (for example copied from Burp) or a HAR file becomes a scenario skeleton" />
      <div className="screen-body import-layout">
        <section className="panel import-input" aria-labelledby="imp-in">
          <div className="panel-head">
            <h2 id="imp-in">Captured request</h2>
            <div className="segmented push" role="radiogroup" aria-label="Format">
              {KINDS.map((k, i) => (
                <button
                  key={k.kind}
                  ref={(el) => {
                    kindRefs.current[i] = el;
                  }}
                  type="button"
                  role="radio"
                  aria-checked={kind === k.kind}
                  tabIndex={kind === k.kind ? 0 : -1}
                  className={kind === k.kind ? "on" : ""}
                  onClick={() => setKind(k.kind)}
                  onKeyDown={(e) => {
                    // The radio group pattern: arrows move the selection.
                    const d = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
                    if (!d) return;
                    e.preventDefault();
                    const n = (i + d + KINDS.length) % KINDS.length;
                    setKind(KINDS[n].kind);
                    kindRefs.current[n]?.focus();
                  }}
                >
                  {k.label}
                </button>
              ))}
            </div>
          </div>
          <div
            className={`drop ${over ? "over" : ""}`}
            onDragOver={(e) => {
              e.preventDefault();
              setOver(true);
            }}
            onDragLeave={() => setOver(false)}
            onDrop={onDrop}
          >
            <label htmlFor="import-text" className="sr-only">
              Raw request or HAR
            </label>
            <textarea
              id="import-text"
              className="input mono import-text"
              spellCheck={false}
              placeholder={"POST /api/carts/42/coupons HTTP/2\nHost: shop.example.test\nContent-Type: application/json\n\n{\"code\":\"WELCOME10\"}"}
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                setResult(null);
              }}
              data-testid="import-text"
            />
            {over && <div className="drop-hint">Drop the file to read it</div>}
          </div>
          <div className="import-controls">
            <input
              ref={fileInput}
              type="file"
              hidden
              accept=".har,.json,.txt,.http,.req,.xml"
              onChange={(e) => {
                void readFile(e.target.files?.[0]);
                e.target.value = "";
              }}
              data-testid="import-file"
            />
            <button type="button" className="btn" onClick={() => fileInput.current?.click()}>
              <FileUp size={14} aria-hidden="true" />
              Open file
            </button>
            <span className="muted small">or drop one on the text area</span>
            {isHar && entries && entries.length > 0 && (
              <>
                <label htmlFor="har-entry" className="push">
                  Entry
                </label>
                <select
                  id="har-entry"
                  className="input mono har-select"
                  value={entry}
                  onChange={(e) => setEntry(Number(e.target.value))}
                  data-testid="har-entry"
                >
                  {entries.map((en) => (
                    <option key={en.index} value={en.index}>
                      {en.label.length > 90 ? `${en.label.slice(0, 89)}…` : en.label}
                    </option>
                  ))}
                </select>
              </>
            )}
            <button
              type="button"
              className={`btn primary ${isHar && entries && entries.length > 0 ? "" : "push"}`}
              disabled={busy || !text.trim() || tooBig}
              onClick={() => void generate()}
              data-testid="import-generate"
            >
              <Wand2 size={14} aria-hidden="true" />
              {busy ? "Generating…" : "Generate scenario"}
            </button>
          </div>
          {tooBig && <p className="field-error pad-x">The text is larger than the import accepts (1000 KiB).</p>}
          <p className="muted small pad-x">
            The request is kept as captured, credentials included: move them to <code>{"${env:NAME}"}</code> references before sharing the
            file. Nothing is sent to the target.
          </p>
        </section>

        <section ref={outRef} className="panel import-output" aria-labelledby="imp-out" tabIndex={-1} data-testid="import-output">
          <div className="panel-head">
            <h2 id="imp-out">Scenario</h2>
            {result && <span className="muted">Review before running</span>}
          </div>
          {err && (
            <div className="pad">
              <ErrorNote onDismiss={() => setErr("")}>{err}</ErrorNote>
            </div>
          )}
          {!result ? (
            <p className="empty pad">The generated YAML appears here, with the parts left for you to fill in.</p>
          ) : (
            <>
              {result.todo.length > 0 && (
                <div className="todo" data-testid="import-todo">
                  <h3 className="block-title">
                    <ListTodo size={13} aria-hidden="true" /> To do before it runs
                  </h3>
                  <ul>
                    {result.todo.map((t) => (
                      <li key={t}>{t}</li>
                    ))}
                  </ul>
                </div>
              )}
              <YamlPreview content={result.content} />
              <div className="save-row">
                <label htmlFor="import-path">Save as</label>
                <input
                  id="import-path"
                  className={`input mono grow ${problem ? "invalid" : ""}`}
                  value={path}
                  onChange={(e) => {
                    setPath(e.target.value);
                    setExists(false);
                  }}
                  aria-invalid={!!problem}
                  data-testid="import-path"
                />
                <button type="button" className="btn primary" disabled={!!problem || saving} onClick={() => void save()} data-testid="import-save">
                  <Save size={14} aria-hidden="true" />
                  {exists ? "Overwrite" : "Save to workspace"}
                </button>
              </div>
              {problem && <p className="field-error pad-x">{problem}</p>}
              {exists && <p className="field-error pad-x">A file with this name exists. Save again to overwrite it, or choose another name.</p>}
              {ctx.info?.workspace && (
                <p className="muted small pad-x">
                  Saved under <span className="mono">{ctx.info.workspace}</span> and opened in the editor.
                </p>
              )}
            </>
          )}
        </section>
      </div>
    </div>
  );
}

/** Read-only YAML with line numbers and highlighting. */
function YamlPreview({ content }: { content: string }) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  useEffect(() => {
    if (!host.current) return;
    view.current = createEditor({ parent: host.current, doc: content, readOnly: true, label: "Generated scenario YAML" });
    return () => {
      view.current?.destroy();
      view.current = null;
    };
    // Created once; later content goes through replaceDoc below.
  }, []);
  useEffect(() => {
    if (view.current) replaceDoc(view.current, content);
  }, [content]);
  return <div className="yaml-preview" ref={host} data-testid="import-yaml" />;
}
