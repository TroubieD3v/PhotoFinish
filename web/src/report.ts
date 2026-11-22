// View helpers for runner reports. They follow internal/report/html.go so
// that the UI and the HTML report describe a run in the same words.

import { formatDuration, formatMs, plural } from "./format";
import type { Race, RaceResult, Report, Term, Trial, Verdict } from "./types";

/** Color class of a lozenge. */
export type Tone = "bad" | "ok" | "warn" | "err" | "neutral" | "accent";

/** Maps a verdict to its color: VIOLATED bad, HELD ok, INCONCLUSIVE warn, ERROR err. */
export function verdictTone(v: Verdict | ""): Tone {
  switch (v) {
    case "VIOLATED":
      return "bad";
    case "HELD":
      return "ok";
    case "INCONCLUSIVE":
      return "warn";
    case "ERROR":
      return "err";
    default:
      return "neutral";
  }
}

/** Colors a race response; violated colors successes as the ones that broke the rule. */
export function statusTone(res: RaceResult, violated: boolean): Tone {
  if (res.status === 0) return "err";
  if (res.status === 429 || res.early_response) return "warn";
  if (res.status >= 200 && res.status < 300) return violated ? "bad" : "ok";
  return "neutral";
}

/** Legend text per status tone. */
export const TONE_LEGEND: Partial<Record<Tone, string>> = {
  bad: "succeeded, broke the rule",
  ok: "succeeded",
  neutral: "rejected",
  warn: "rate limited or early",
  err: "no response",
};

/** The status shown in a lozenge: the code, or "none". */
export function statusText(status: number): string {
  return status === 0 ? "none" : String(status);
}

/** Names a timeline row: the HTTP/2 stream, else the shortened request label. */
export function shortLabel(res: RaceResult): string {
  if (res.stream && res.stream > 0) return `s${res.stream}`;
  let l = (res.label ?? "").replace(/request /g, "req ");
  if (!l) l = `#${res.index + 1}`;
  return l.length > 13 ? `${l.slice(0, 12)}…` : l;
}

/** Describes a race: "20 streams over 1 connection". */
export function raceCaption(r: Race): string {
  const n = r.results.length;
  switch (r.engine) {
    case "h2":
      return `${plural(n, "stream")} over ${plural(Math.max(r.connections, 1), "connection")}`;
    case "h1":
      return `${plural(n, "request")} over ${plural(Math.max(r.connections, n), "connection")}`;
    default:
      return `${plural(n, "request")} (${r.engine})`;
  }
}

/** max-min first byte over the results with a response, 0 if fewer than two. */
export function responseSpread(r: Race): number {
  const vals = r.results.filter((x) => x.status !== 0 && x.first_byte_ns !== 0).map((x) => x.first_byte_ns);
  if (vals.length < 2) return 0;
  return Math.max(...vals) - Math.min(...vals);
}

/** max-min server arrival, null if fewer than two results carry one. */
export function serverArrivalSpread(r: Race): number | null {
  const vals = r.results.map((x) => x.server_arrival_ns ?? 0).filter((v) => v !== 0);
  if (vals.length < 2) return null;
  return Math.max(...vals) - Math.min(...vals);
}

/** Status counts in table form: "3×200 17×409". */
export function compactStatuses(r: Race | null | undefined): string {
  if (!r || r.results.length === 0) return "";
  const counts = new Map<number, number>();
  for (const res of r.results) counts.set(res.status, (counts.get(res.status) ?? 0) + 1);
  const codes = [...counts.keys()].sort((a, b) => (a === b ? 0 : a === 0 ? 1 : b === 0 ? -1 : a - b));
  return codes.map((c) => `${counts.get(c)}×${c === 0 ? "none" : c}`).join(" ");
}

/** Number of 2xx responses in a race. */
export function successes(r: Race | null | undefined): number {
  return r ? r.results.filter((x) => x.status >= 200 && x.status < 300).length : 0;
}

/** The trials of a report, never null. */
export function trialsOf(rep: Report): Trial[] {
  return rep.trials ?? [];
}

/** The trial shown first: the first VIOLATED, else the first INCONCLUSIVE of an inconclusive run, else the first. */
export function defaultTrial(rep: Report): Trial | undefined {
  const ts = trialsOf(rep);
  return (
    ts.find((t) => t.verdict === "VIOLATED") ??
    (rep.verdict === "INCONCLUSIVE" ? ts.find((t) => t.verdict === "INCONCLUSIVE") : undefined) ??
    ts[0]
  );
}

/** One cell of the header strip. */
export interface Metric {
  label: string;
  value: string;
}

/** The header strip cells of a report, for the trial shown. */
export function metrics(rep: Report, shown: Trial | undefined): Metric[] {
  const m: Metric[] = [];
  const add = (label: string, value: string) => {
    if (value) m.push({ label, value });
  };
  add("Engine", rep.engine);
  add("Copies per trial", rep.copies > 0 ? String(rep.copies) : "");
  const rel = shown?.race?.release;
  if (rel) {
    if (rel.writes > 0) add("Release", `${plural(rel.writes, "write")} · ${rel.bytes} B`);
    else if (rel.bytes > 0) add("Release", `${rel.bytes} B`);
  }
  const st = rep.stats;
  if (st.ran > 0) add("Trials", `${st.ran} of ${st.planned}`);
  if (trialsOf(rep).some((t) => t.race)) {
    add("Response spread, median", formatMs(st.median_response_spread_ns));
    const arr = st.median_server_arrival_spread_ns;
    add("Server arrival spread, median", arr === undefined || arr === null ? "not reported" : formatDuration(arr));
  }
  if (st.requests_spent > 0) add("Requests spent", String(st.requests_spent));
  return m;
}

/** Run notes followed by the distinct race notes. */
export function reportNotes(rep: Report): string[] {
  const out = [...(rep.notes ?? [])];
  const seen = new Set(out);
  for (const t of trialsOf(rep)) {
    for (const n of t.race?.notes ?? []) {
      if (!seen.has(n)) {
        seen.add(n);
        out.push(n);
      }
    }
  }
  return out;
}

/** State of an evaluated term. */
export function termState(t: Term): { label: string; tone: Tone } {
  if (t.pass === null || t.pass === undefined) return { label: "error", tone: "warn" };
  return t.pass ? { label: "pass", tone: "ok" } : { label: "fail", tone: "bad" };
}

/** Decodes a base64 body (Go []byte in JSON) as UTF-8 text. */
export function decodeBody(b64: string | undefined): string {
  if (!b64) return "";
  try {
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return b64;
  }
}

/** Parses JSON text, returning undefined when it is not JSON. */
export function tryJSON(text: string): unknown {
  const t = text.trim();
  if (!t || (t[0] !== "{" && t[0] !== "[")) return undefined;
  try {
    return JSON.parse(t) as unknown;
  } catch {
    return undefined;
  }
}

/** One-line rendering of possibly multi-line YAML text. */
export function oneLine(s: string): string {
  return s.split(/\s+/).filter(Boolean).join(" ");
}

/** Splits the reproduce command into words for display. */
export function reproduceWords(cmd: string): string[] {
  return cmd ? cmd.split(" ") : [];
}
