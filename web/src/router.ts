import { useEffect, useState } from "react";

/** The screens of the app. */
export type RouteName = "scenarios" | "scenario" | "run" | "runs" | "probe" | "import";

/** A parsed location hash: "#/run?id=abc" is {name: "run", params: id=abc}. */
export interface Route {
  name: RouteName;
  params: URLSearchParams;
  /** The hash it was parsed from, without "#". */
  raw: string;
}

const NAMES: readonly RouteName[] = ["scenarios", "scenario", "run", "runs", "probe", "import"];

/** Parses a location hash. Unknown hashes lead to the scenarios screen. */
export function parseRoute(hash: string): Route {
  const raw = hash.replace(/^#/, "");
  const path = raw.replace(/^\//, "");
  const qi = path.indexOf("?");
  const name = (qi < 0 ? path : path.slice(0, qi)) as RouteName;
  const params = new URLSearchParams(qi < 0 ? "" : path.slice(qi + 1));
  return NAMES.includes(name) ? { name, params, raw } : { name: "scenarios", params: new URLSearchParams(), raw };
}

/** Builds a hash link: href("run", {id}) is "#/run?id=...". */
export function href(name: RouteName, params: Record<string, string | undefined> = {}): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) sp.set(k, v);
  const s = sp.toString();
  return `#/${name}${s ? `?${s}` : ""}`;
}

/**
 * A leave guard returns true when the current screen may be left for the
 * given hash. When it returns false it has taken over (for example by asking
 * about unsaved changes) and calls navigate(next, true) itself if the user
 * agrees.
 */
export type LeaveGuard = (next: string) => boolean;

let guard: LeaveGuard | null = null;
let forced = false;
/** The hash of the screen shown. */
let current = "";
/** The position of the shown entry in the session history, see stamp. */
let position = 0;
/** A history move made to undo a refused navigation; its hashchange is ignored. */
let undoing = false;

/** The key under which history entries carry their position. */
const POS = "photofinishPos";

/** The position stored in a history state, or null for an entry the app has not stamped. */
function positionOf(state: unknown): number | null {
  if (typeof state !== "object" || state === null) return null;
  const v = (state as Record<string, unknown>)[POS];
  return typeof v === "number" ? v : null;
}

/** Stores the position in the current history entry, keeping its address. */
function stamp(pos: number): void {
  const state: unknown = window.history.state;
  const base = typeof state === "object" && state !== null ? (state as Record<string, unknown>) : {};
  window.history.replaceState({ ...base, [POS]: pos }, "");
}

/** Installs the leave guard of the current screen; pass null to remove it. */
export function setLeaveGuard(g: LeaveGuard | null): void {
  guard = g;
}

/** Navigates to hash; force skips the leave guard. */
export function navigate(hash: string, force = false): void {
  if (hash === window.location.hash) return;
  forced = force;
  window.location.hash = hash;
}

/**
 * Changes the address of the current screen without a navigation, for
 * example once a new scenario has a file. The router keeps it as the hash
 * to return to when a leave guard refuses.
 */
export function replaceHash(hash: string): void {
  current = hash;
  window.history.replaceState(window.history.state, "", hash);
}

/** Tracks the location hash, consulting the leave guard before changing screens. */
export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => {
    current = window.location.hash;
    return parseRoute(current);
  });
  useEffect(() => {
    position = positionOf(window.history.state) ?? 0;
    stamp(position);
    const onChange = () => {
      const next = window.location.hash;
      const pos = positionOf(window.history.state);
      if (undoing) {
        // Back where the refused navigation started.
        undoing = false;
        if (next === current) return;
      }
      const force = forced;
      forced = false;
      if (!force && guard && next !== current && !guard(next)) {
        // Stay. A link or a typed address added a new entry (no position
        // yet): go back to the entry it was added after, so that no
        // duplicate entry is left for the Back button. Back and Forward
        // moved to an entry with a position: move by the same distance the
        // other way.
        const delta = pos === null ? -1 : position - pos;
        if (delta !== 0) {
          undoing = true;
          window.history.go(delta);
        } else {
          window.history.replaceState(window.history.state, "", current || "#/scenarios");
        }
        return;
      }
      position = pos ?? position + 1;
      stamp(position);
      current = next;
      setRoute(parseRoute(next));
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}
