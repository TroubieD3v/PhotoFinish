import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type RefObject } from "react";
import { axisStep, exactNs, microseconds, signedDuration, tickLabel } from "../format";
import { TONE_LEGEND, shortLabel, statusText, statusTone, type Tone } from "../report";
import type { Race, RaceResult } from "../types";

/** Rows drawn at most; the rest are counted below the chart. */
const MAX_ROWS = 120;

const LABEL_X = 10;
const STATUS_X = 96;
const STATUS_W = 40;
const PLOT_X0 = 152;
const PLOT_PAD = 16;
const AXIS_H = 24;
const ROW_H = 22;
/** Room an axis label needs, so that a plot of width w gets w / TICK_ROOM ticks. */
const TICK_ROOM = 60;
/** Axes get at least this many labels as long as they fit. */
const MIN_TICKS = 4;
/** Width of one character of an 11 px Plex Mono axis label, and the gap between labels. */
const CHAR_PX = 6.8;
const LABEL_GAP = 10;

/** The width of the widest label of an axis with the given labels. */
const labelWidth = (labels: string[]) => Math.max(...labels.map((l) => l.length)) * CHAR_PX + LABEL_GAP;

/** Tracks the width of an element. */
function useWidth<T extends HTMLElement>(min: number): [RefObject<T>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const update = () => setWidth(Math.max(min, Math.floor(el.clientWidth)));
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, [min]);
  return [ref, width];
}

interface Row {
  res: RaceResult;
  y: number;
  cy: number;
  tone: Tone;
  pre?: { x: number; w: number };
  bar?: { x: number; w: number; end: number };
}

interface Layout {
  release: number;
  lineLabel: string;
  releaseX: number;
  ticks: { x: number; label: string }[];
  rows: Row[];
  hidden: number;
  hasPre: boolean;
  tones: Tone[];
  height: number;
  bottom: number;
}

/** Lays out a race the way internal/report does for the HTML report. */
function layout(race: Race, violated: boolean, width: number): Layout {
  let release = 0;
  for (const r of race.results) if (r.released_ns > 0 && (release === 0 || r.released_ns < release)) release = r.released_ns;
  const lineLabel = race.engine === "burst" || release === 0 ? "first send" : "release";
  if (release === 0) {
    for (const r of race.results) if (r.pre_sent_ns > 0 && (release === 0 || r.pre_sent_ns < release)) release = r.pre_sent_ns;
  }
  let lo = 0;
  let hi = 0;
  for (const r of race.results) {
    for (const ns of [r.released_ns, r.first_byte_ns]) {
      if (ns > 0) {
        lo = Math.min(lo, ns - release);
        hi = Math.max(hi, ns - release);
      }
    }
  }
  if (hi <= 0) hi = 1e6;
  const axisMin = Math.min(-0.35 * hi, 1.1 * lo);
  const axisMax = 1.08 * hi;
  const x1 = width - PLOT_PAD;
  const x = (d: number) => Math.round((PLOT_X0 + ((d - axisMin) / (axisMax - axisMin)) * (x1 - PLOT_X0)) * 10) / 10;

  const step = axisStep(axisMin, axisMax, x1 - PLOT_X0, TICK_ROOM, MIN_TICKS, (s) =>
    labelWidth([tickLabel(Math.floor(axisMin / s) * s, s, true), tickLabel(Math.floor(axisMax / s) * s, s, true)]),
  );
  const ticks: Layout["ticks"] = [];
  for (let v = Math.ceil(axisMin / step) * step; v <= axisMax; v += step) {
    const val = Math.abs(v) < step / 1e6 ? 0 : v;
    const label = tickLabel(val, step, true);
    // A label centred closer to the edge than half its width would be cut off.
    if (x(val) + (label.length * CHAR_PX) / 2 > width - 2) continue;
    ticks.push({ x: x(val), label });
  }

  const shown = race.results.slice(0, MAX_ROWS);
  const tones = new Set<Tone>();
  let hasPre = false;
  const rows = shown.map((res, i): Row => {
    const y = AXIS_H + i * ROW_H;
    const tone = statusTone(res, violated);
    tones.add(tone);
    const row: Row = { res, y, cy: y + ROW_H / 2, tone };
    if (res.pre_sent_ns > 0 && res.released_ns > res.pre_sent_ns) {
      const a = x(Math.max(res.pre_sent_ns - release, axisMin));
      const b = x(res.released_ns - release);
      if (b > a) {
        row.pre = { x: a, w: b - a };
        hasPre = true;
      }
    }
    if (res.first_byte_ns > 0) {
      const start = res.released_ns || res.pre_sent_ns;
      const end = x(res.first_byte_ns - release);
      let a = x(start - release);
      let b = end;
      if (b < a) [a, b] = [b, a];
      row.bar = { x: a, w: Math.max(b - a, 1), end };
    }
    return row;
  });
  const bottom = AXIS_H + rows.length * ROW_H + 4;
  const order: Tone[] = ["bad", "ok", "neutral", "warn", "err"];
  return {
    release,
    lineLabel,
    releaseX: x(0),
    ticks,
    rows,
    hidden: race.results.length - shown.length,
    hasPre,
    tones: order.filter((t) => tones.has(t)),
    height: bottom + 4,
    bottom,
  };
}

/** Lines of the tooltip of one request, with exact nanosecond values. */
function details(res: RaceResult, release: number, firstArrival: number): [string, string][] {
  const rel = (ns: number) => `${signedDuration(ns - release)}  (${exactNs(ns - release)})`;
  const out: [string, string][] = [];
  out.push(["Request", res.label || `request ${res.index + 1}`]);
  if (res.stream) out.push(["Stream", String(res.stream)]);
  out.push(["Connection", `${res.conn}${res.proto ? ` · ${res.proto}` : ""}`]);
  out.push(["Status", res.status === 0 ? "no response" : String(res.status)]);
  if (res.pre_sent_ns > 0) out.push(["Pre-sent", rel(res.pre_sent_ns)]);
  if (res.released_ns > 0) out.push(["Released", rel(res.released_ns)]);
  if (res.first_byte_ns > 0) out.push(["First byte", rel(res.first_byte_ns)]);
  if (res.done_ns > 0) out.push(["Done", rel(res.done_ns)]);
  if (res.server_arrival_ns && firstArrival > 0) {
    out.push(["Server arrival", `+${((res.server_arrival_ns - firstArrival) / 1000).toFixed(1)} µs  (${exactNs(res.server_arrival_ns - firstArrival)})`]);
  }
  if (res.early_response) out.push(["Note", "responded before release"]);
  if (res.error) out.push(["Error", res.error]);
  return out;
}

/**
 * The timeline of one race: a row per request with its label, status
 * lozenge, the hatched pre-send segment, the bar from release to the first
 * response byte and a dashed release line. Rows show exact values on hover
 * and keyboard focus.
 */
export function Timeline({ race, violated }: { race: Race; violated: boolean }) {
  const [wrap, width] = useWidth<HTMLDivElement>(420);
  const hatch = useId().replace(/:/g, "");
  const [active, setActive] = useState<{ i: number; x: number } | null>(null);
  // Roving tab stop: the timeline is one stop, the arrow keys move between
  // the requests.
  const [cursor, setCursor] = useState(0);
  const tip = useRef<HTMLDivElement>(null);
  const [tipH, setTipH] = useState(0);
  const lay = useMemo(() => (width > 0 ? layout(race, violated, width) : null), [race, violated, width]);
  const firstArrival = useMemo(() => {
    const vals = race.results.map((r) => r.server_arrival_ns ?? 0).filter((v) => v > 0);
    return vals.length ? Math.min(...vals) : 0;
  }, [race]);
  useEffect(() => {
    setActive(null);
    setCursor(0);
  }, [race]);
  useLayoutEffect(() => {
    if (tip.current) setTipH(tip.current.offsetHeight);
  }, [active]);

  const show = (i: number, x: number) => {
    if (lay) setActive({ i, x });
  };
  const onKey = (e: KeyboardEvent<SVGGElement>, i: number) => {
    if (!lay) return;
    if (e.key === "Escape") {
      setActive(null);
      return;
    }
    const last = lay.rows.length - 1;
    const n = e.key === "ArrowDown" ? i + 1 : e.key === "ArrowUp" ? i - 1 : e.key === "Home" ? 0 : e.key === "End" ? last : -2;
    if (n === -2) return;
    e.preventDefault();
    const next = Math.min(Math.max(n, 0), last);
    setCursor(next);
    e.currentTarget.parentNode?.querySelectorAll<SVGGElement>("g.tl-row")[next]?.focus();
  };

  // The tooltip sits below the row, or above it when it would run past the
  // bottom of the plot (the plot scrolls sideways, so it clips).
  let tipTop = 0;
  if (lay && active && lay.rows[active.i]) {
    const rowTop = lay.rows[active.i].y;
    const below = rowTop + ROW_H + 2;
    tipTop = below + tipH <= lay.height || rowTop - tipH - 2 < 0 ? below : rowTop - tipH - 2;
  }

  return (
    <div className="timeline">
      <div className="timeline-legend" aria-hidden="true">
        {lay?.tones.map((t) => (
          <span key={t} className={`lg ${t}`}>
            {TONE_LEGEND[t]}
          </span>
        ))}
        {lay?.hasPre && (
          <span className="lg pre">
            <svg viewBox="0 0 9 9" width="9" height="9">
              <rect width="9" height="9" fill={`url(#${hatch})`} />
            </svg>
            pre-sent
          </span>
        )}
        <span className="lg rel">{lay?.lineLabel ?? "release"}</span>
      </div>
      <div className="timeline-plot" ref={wrap} onMouseLeave={() => setActive(null)}>
        {lay && (
          <svg
            width={width}
            height={lay.height}
            viewBox={`0 0 ${width} ${lay.height}`}
            role="group"
            aria-label="Timeline of the race: one row per request, from release to the first response byte; use the arrow keys to move between requests and Escape to hide the details"
            data-testid="timeline"
          >
            <defs>
              <pattern id={hatch} width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                <rect className="hatch" width="1.2" height="4" />
              </pattern>
            </defs>
            {lay.ticks.map((t) => (
              <text key={t.x} className="tick" x={t.x} y={14} textAnchor="middle">
                {t.label}
              </text>
            ))}
            {lay.rows.map((row, i) => (
              <g
                key={row.res.index}
                className={`tl-row ${row.tone} ${active?.i === i ? "active" : ""}`}
                tabIndex={i === Math.min(cursor, lay.rows.length - 1) ? 0 : -1}
                role="img"
                aria-label={details(row.res, lay.release, firstArrival)
                  .map(([k, v]) => `${k} ${v}`)
                  .join(", ")}
                onMouseMove={(e) => {
                  const box = wrap.current?.getBoundingClientRect();
                  if (box) show(i, e.clientX - box.left + (wrap.current?.scrollLeft ?? 0));
                }}
                onFocus={() => {
                  setCursor(i);
                  show(i, row.bar ? row.bar.end : lay.releaseX);
                }}
                onBlur={() => setActive(null)}
                onKeyDown={(e) => onKey(e, i)}
              >
                <rect className="row-hit" x={0} y={row.y} width={width} height={ROW_H} />
                <text className="lbl" x={LABEL_X} y={row.cy + 4}>
                  {shortLabel(row.res)}
                </text>
                <rect className="st" x={STATUS_X} y={row.cy - 8} width={STATUS_W} height={16} rx={2} />
                <text className="st-t" x={STATUS_X + STATUS_W / 2} y={row.cy + 4} textAnchor="middle">
                  {statusText(row.res.status)}
                </text>
                {row.pre && <rect x={row.pre.x} y={row.cy - 3} width={row.pre.w} height={6} fill={`url(#${hatch})`} />}
                {row.bar && (
                  <>
                    <rect className="bar" x={row.bar.x} y={row.cy - 3} width={row.bar.w} height={6} />
                    <line className="end" x1={row.bar.end} y1={row.cy - 7} x2={row.bar.end} y2={row.cy + 7} />
                  </>
                )}
              </g>
            ))}
            <line className="release" x1={lay.releaseX} y1={20} x2={lay.releaseX} y2={lay.bottom} />
          </svg>
        )}
        {lay && active && lay.rows[active.i] && (
          <div
            ref={tip}
            className="tooltip"
            role="tooltip"
            data-testid="timeline-tooltip"
            style={{ left: Math.min(Math.max(8, active.x + 12), Math.max(8, width - 336)), top: tipTop }}
          >
            <dl>
              {details(lay.rows[active.i].res, lay.release, firstArrival).map(([k, v]) => (
                <div key={k}>
                  <dt>{k}</dt>
                  <dd>{v}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </div>
      {lay && lay.hidden > 0 && <p className="muted pad">{lay.hidden} more requests are not drawn.</p>}
    </div>
  );
}

/** The server arrival times of a race as marks on a µs axis, or nothing when fewer than two results carry one. */
export function ArrivalStrip({ race }: { race: Race }) {
  const [wrap, width] = useWidth<HTMLDivElement>(300);
  const marks = race.results.filter((r) => (r.server_arrival_ns ?? 0) > 0);
  if (marks.length < 2) return null;
  const vals = marks.map((r) => r.server_arrival_ns ?? 0);
  const first = Math.min(...vals);
  const spread = Math.max(...vals) - first;
  const axisMax = Math.max(spread * 1.05, 1000);
  const x0 = 16;
  const x1 = Math.max(x0 + 100, width - 40);
  const x = (d: number) => x0 + (d / axisMax) * (x1 - x0);
  const step = axisStep(0, axisMax, x1 - x0, 70, MIN_TICKS, (s) => labelWidth([microseconds(Math.floor(axisMax / s) * s, s)]));
  const ticks: number[] = [];
  for (let v = 0; v <= axisMax + step / 1e6; v += step) ticks.push(v);
  const height = 52;
  return (
    <div className="arrival">
      <div className="arrival-head">
        <h3>Server arrival</h3>
        <span className="muted">
          {marks.length} requests within {microseconds(spread, 1000)}, from the target's arrival header
        </span>
      </div>
      <div ref={wrap} className="arrival-plot">
        {width > 0 && (
          <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Server arrival times: ${marks.length} requests within ${microseconds(spread, 1000)}`}>
            <line className="axis" x1={0} y1={28} x2={width} y2={28} />
            {marks.map((r) => {
              const d = (r.server_arrival_ns ?? 0) - first;
              return (
                <line key={r.index} className="mark" x1={x(d)} y1={4} x2={x(d)} y2={28}>
                  <title>{`${shortLabel(r)}: +${(d / 1000).toFixed(1)} µs (${exactNs(d)})`}</title>
                </line>
              );
            })}
            {ticks.map((v) => (
              <text key={v} className="tick" x={x(v)} y={height - 6} textAnchor="middle">
                {microseconds(v, step)}
              </text>
            ))}
          </svg>
        )}
      </div>
    </div>
  );
}
