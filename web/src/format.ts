// Formatting of durations, times and counts, matching the text and HTML
// reports of the command line.

const MS = 1e6;
const US = 1e3;

/** "0.41 ms" for nanoseconds, as the run command prints spreads. */
export function formatMs(ns: number): string {
  return `${(ns / MS).toFixed(2)} ms`;
}

/** A unit that suits the size: "38 µs", "0.41 ms", "1.20 s". */
export function formatDuration(ns: number): string {
  if (ns < MS) return `${Math.round(ns / US)} µs`;
  if (ns < 1e9) return `${(ns / MS).toFixed(2)} ms`;
  return `${(ns / 1e9).toFixed(2)} s`;
}

/** formatDuration with a sign: "+0.41 ms", "-12 µs". */
export function signedDuration(ns: number): string {
  return ns < 0 ? `-${formatDuration(-ns)}` : `+${formatDuration(ns)}`;
}

/** Exact nanoseconds with digit grouping: "1 234 567 ns". */
export function exactNs(ns: number): string {
  const sign = ns < 0 ? "-" : "";
  return `${sign}${Math.abs(Math.round(ns)).toLocaleString("en-US").replace(/,/g, " ")} ns`;
}

/** "1 write", "2 writes". */
export function plural(n: number, noun: string): string {
  return n === 1 ? `1 ${noun}` : `${n} ${noun}s`;
}

/** 1, 2 or 5 times a power of ten, at least raw. */
export function niceStep(raw: number): number {
  if (raw <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  for (const m of [1, 2, 5, 10]) if (m * p >= raw) return m * p;
  return 10 * p;
}

/** The 1-2-5 step below step: 5 is followed by 2, 2 by 1, 1 by 0.5. */
export function stepBelow(step: number): number {
  const p = Math.pow(10, Math.floor(Math.log10(step) + 1e-9));
  const m = Math.round(step / p);
  return m >= 5 ? 2 * p : m >= 2 ? p : p / 2;
}

/** The number of multiples of step from lo to hi. */
export function tickCount(lo: number, hi: number, step: number): number {
  return Math.floor(hi / step + 1e-9) - Math.ceil(lo / step - 1e-9) + 1;
}

/**
 * A 1-2-5 step for an axis from lo to hi drawn over widthPx: about one label
 * per roomPx, rounded up, then made smaller while the axis would show fewer
 * than minTicks labels and a label (labelPx wide for that step) still fits
 * between two ticks. Without the second pass a range just above a nice
 * value gets two labels only (0 and +5 ms for a range of 9.6 ms).
 */
export function axisStep(lo: number, hi: number, widthPx: number, roomPx: number, minTicks: number, labelPx: (step: number) => number): number {
  const range = hi - lo;
  if (!(range > 0) || !(widthPx > 0)) return 1;
  let step = niceStep(range / Math.max(1, Math.floor(widthPx / roomPx)));
  while (tickCount(lo, hi, step) < minTicks) {
    const next = stepBelow(step);
    if ((next / range) * widthPx < labelPx(next)) break;
    step = next;
  }
  return step;
}

/** An axis label in ms from a step of 100 µs up, in µs below. */
export function tickLabel(v: number, step: number, signed: boolean): string {
  let unit = "ms";
  let div = MS;
  if (step < 100 * US) {
    unit = "µs";
    div = US;
  }
  if (v === 0) return `0 ${unit}`;
  const s = step / div;
  const decimals = s < 1 ? Math.ceil(-Math.log10(s)) : 0;
  const n = (Math.abs(v) / div).toFixed(decimals);
  if (!signed) return `${n} ${unit}`;
  return v < 0 ? `-${n} ${unit}` : `+${n} ${unit}`;
}

/** Microseconds with as many decimals as step needs: "0 µs", "120 µs". */
export function microseconds(ns: number, step: number): string {
  if (ns === 0) return "0 µs";
  const s = step / US;
  const decimals = s < 1 ? Math.ceil(-Math.log10(s)) : 0;
  return `${(ns / US).toFixed(decimals)} µs`;
}

/** "2026-11-22 14:20:12" in local time, "" for an unset time. */
export function formatTime(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** "just now", "5 min ago", "3 h ago", "2 days ago", or the date. */
export function relativeTime(iso: string, now = Date.now()): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  if (d < 14) return d === 1 ? "yesterday" : `${d} days ago`;
  return formatTime(iso).slice(0, 10);
}

/** Wall time between two ISO times: "1.20 s", "" when unknown. */
export function elapsed(from: string, to: string): string {
  if (!from || !to) return "";
  const ms = new Date(to).getTime() - new Date(from).getTime();
  if (!Number.isFinite(ms) || ms < 0) return "";
  if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s`;
  return `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`;
}

/** Bytes for people: "220 B", "4.0 KiB". */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}
