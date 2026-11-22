// Client of the local API of "photofinish serve".
//
// Every /api request carries the session token as a bearer token. The token
// comes from the link the server prints (#token=...), is kept in
// sessionStorage and never appears in a URL the app requests. Responses are
// decoded into the types of types.ts with the field names of the Go JSON.

import type {
  DemoState,
  Example,
  Health,
  ImportResult,
  Info,
  LastRun,
  Problem,
  ProbeReport,
  Progress,
  Report,
  ReportFormat,
  RunDetail,
  RunRecord,
  RunRequest,
  ScenarioContent,
  ScenarioFile,
  ScenarioList,
  ScenarioSummary,
  Validation,
  Verdict,
} from "./types";

const TOKEN_KEY = "photofinish-token";

/** Error of an API call: the HTTP status and the server's message. */
export class ApiError extends Error {
  readonly status: number;
  /** The decoded JSON error body, if any (409 replies carry ids). */
  readonly body: Record<string, unknown>;

  constructor(status: number, message: string, body: Record<string, unknown> = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

/** Raised when the session token is missing or rejected. */
export class AuthError extends ApiError {
  constructor(message = "Session token missing or rejected") {
    super(401, message);
    this.name = "AuthError";
  }
}

let unauthorizedHandler: (() => void) | null = null;

/** Registers the function called when the server answers 401. */
export function onUnauthorized(fn: (() => void) | null): void {
  unauthorizedHandler = fn;
}

/**
 * Moves a token from the URL fragment (#token=...) into sessionStorage and
 * removes it from the address bar and the history entry. Returns whether a
 * token was found.
 */
export function adoptTokenFromLocation(): boolean {
  const hash = window.location.hash.replace(/^#/, "");
  const params = new URLSearchParams(hash.startsWith("/") ? hash.slice(hash.indexOf("?") + 1 || hash.length) : hash);
  const token = params.get("token");
  if (!token) return false;
  setToken(token);
  window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search + "#/scenarios");
  return true;
}

/** Returns the stored session token, "" when there is none. */
export function getToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

/** Stores the session token for this browser tab. */
export function setToken(token: string): void {
  try {
    sessionStorage.setItem(TOKEN_KEY, token.trim());
  } catch {
    /* storage unavailable: the token cannot be kept */
  }
}

/** Forgets the session token. */
export function clearToken(): void {
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* nothing stored */
  }
}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const token = getToken();
  if (!token) throw new AuthError("Session token missing");
  return { Authorization: `Bearer ${token}`, ...extra };
}

async function errorFrom(res: Response): Promise<ApiError> {
  let message = res.statusText || `HTTP ${res.status}`;
  let body: Record<string, unknown> = {};
  try {
    const text = await res.text();
    if (text) {
      try {
        const parsed: unknown = JSON.parse(text);
        if (isObject(parsed)) {
          body = parsed;
          if (typeof parsed.error === "string" && parsed.error) message = parsed.error;
        }
      } catch {
        message = text.trim().slice(0, 300) || message;
      }
    }
  } catch {
    /* body unreadable */
  }
  if (res.status === 401) {
    unauthorizedHandler?.();
    return new AuthError(message);
  }
  return new ApiError(res.status, message, body);
}

async function send(method: string, url: string, body?: unknown, signal?: AbortSignal): Promise<Response> {
  const headers = authHeaders(body === undefined ? undefined : { "Content-Type": "application/json" });
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
      credentials: "omit",
      cache: "no-store",
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    throw new ApiError(0, "The PhotoFinish server is not reachable. Is photofinish serve still running?");
  }
  if (!res.ok) throw await errorFrom(res);
  return res;
}

async function json(method: string, url: string, body?: unknown, signal?: AbortSignal): Promise<unknown> {
  const res = await send(method, url, body, signal);
  if (res.status === 204) return {};
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(res.status, "The server sent a response that is not JSON");
  }
}

// ---- decoding --------------------------------------------------------------
//
// The server's JSON is decoded field by field with the exact names the Go
// handlers write (internal/server); a missing or mistyped field reads as its
// zero value instead of leaking undefined into the screens.

type Obj = Record<string, unknown>;

function isObject(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(o: unknown, name: string): string {
  const v = isObject(o) ? o[name] : undefined;
  return typeof v === "string" ? v : "";
}

function num(o: unknown, name: string): number {
  const v = isObject(o) ? o[name] : undefined;
  return typeof v === "number" && Number.isFinite(v) ? v : 0;
}

function bool(o: unknown, name: string): boolean {
  return isObject(o) && o[name] === true;
}

function arr(o: unknown, name: string): unknown[] {
  const v = isObject(o) ? o[name] : undefined;
  return Array.isArray(v) ? v : [];
}

function strs(o: unknown, name: string): string[] {
  return arr(o, name).filter((x): x is string => typeof x === "string");
}

function nums(o: unknown, name: string): number[] {
  return arr(o, name).filter((x): x is number => typeof x === "number" && Number.isFinite(x));
}

/** A Go zero time ("0001-01-01T00:00:00Z") or an empty string means unset. */
function isUnsetTime(t: string): boolean {
  return t === "" || t.startsWith("0001-01-01");
}

function time(o: unknown, name: string): string {
  const t = str(o, name);
  return isUnsetTime(t) ? "" : t;
}

function verdict(v: string): Verdict | "" {
  return v === "VIOLATED" || v === "HELD" || v === "INCONCLUSIVE" || v === "ERROR" ? v : "";
}

function toDemo(o: unknown): DemoState {
  return { running: bool(o, "running"), url: str(o, "url") };
}

function toInfo(o: unknown): Info {
  return {
    version: str(o, "version"),
    workspace: str(o, "workspace"),
    demo: toDemo(isObject(o) ? o.demo : undefined),
    dataDir: str(o, "dataDir"),
    running: str(o, "runningRun"),
  };
}

function toLastRun(o: unknown): LastRun | undefined {
  if (!isObject(o) || !str(o, "id")) return undefined;
  return { id: str(o, "id"), verdict: verdict(str(o, "verdict")), finishedAt: time(o, "finishedAt") };
}

function toScenarioFile(o: unknown): ScenarioFile {
  return {
    path: str(o, "path"),
    name: str(o, "name"),
    description: str(o, "description"),
    target: str(o, "target"),
    engine: str(o, "engine"),
    valid: bool(o, "valid"),
    error: str(o, "error"),
    lastRun: toLastRun(isObject(o) ? o.lastRun : undefined),
  };
}

function toExample(o: unknown): Example {
  return {
    name: str(o, "name"),
    description: str(o, "description"),
    target: str(o, "target"),
    engine: str(o, "engine"),
    path: str(o, "path"),
    inWorkspace: bool(o, "inWorkspace"),
  };
}

function toScenarioList(o: unknown): ScenarioList {
  return {
    scenarios: arr(o, "scenarios").map(toScenarioFile).filter((s) => s.path !== ""),
    examples: arr(o, "examples").map(toExample).filter((e) => e.name !== ""),
    truncated: bool(o, "truncated"),
  };
}

function toProblem(o: unknown): Problem {
  return { line: num(o, "line"), column: num(o, "column"), field: str(o, "field"), message: str(o, "message") };
}

function toSummary(o: unknown): ScenarioSummary | undefined {
  if (!isObject(o)) return undefined;
  const scope = o.scope;
  return {
    name: str(o, "name"),
    description: str(o, "description"),
    target: str(o, "target"),
    engine: str(o, "engine"),
    copies: num(o, "copies"),
    trials: num(o, "trials"),
    invariant: str(o, "invariant"),
    explain: str(o, "explain"),
    allowHosts: strs(scope, "allowHosts"),
    budgetRequests: num(scope, "requests"),
    budgetRps: num(scope, "rps"),
    insecure: bool(o, "insecure"),
  };
}

function toValidation(o: unknown): Validation {
  return {
    valid: bool(o, "valid"),
    errors: arr(o, "errors").map(toProblem),
    scenario: toSummary(isObject(o) ? o.scenario : undefined),
  };
}

function toImport(o: unknown): ImportResult {
  return {
    content: str(o, "content"),
    todo: strs(o, "todo"),
    kind: str(o, "kind") === "har" ? "har" : "burp",
    name: str(o, "name"),
  };
}

function toProbe(o: unknown): ProbeReport {
  return {
    url: str(o, "url"),
    alpn: str(o, "alpn"),
    tlsVersion: str(o, "tlsVersion"),
    http2: bool(o, "http2"),
    server: str(o, "server"),
    maxConcurrentStreams: num(o, "maxConcurrentStreams"),
    initialWindowSize: num(o, "initialWindowSize"),
    maxFrameSize: num(o, "maxFrameSize"),
    rtts: nums(o, "rttsNs"),
    statuses: nums(o, "statuses"),
    arrivalHeader: bool(o, "arrivalHeader"),
    recommended: str(o, "recommended"),
    notes: strs(o, "notes"),
  };
}

function toRunRecord(o: unknown): RunRecord {
  return {
    id: str(o, "id"),
    scenario: str(o, "scenario"),
    file: str(o, "file"),
    engine: str(o, "engine"),
    verdict: verdict(str(o, "verdict")),
    summary: str(o, "summary"),
    trials: num(o, "trials"),
    violated: num(o, "violated"),
    copies: num(o, "copies"),
    startedAt: time(o, "startedAt"),
    finishedAt: time(o, "finishedAt"),
    running: str(o, "status") === "running",
    planned: num(o, "planned"),
    done: num(o, "done"),
  };
}

/** The stored report is runner.Report as the report package writes it. */
function toReport(o: unknown): Report | null {
  return isObject(o) && typeof o.schema === "string" ? (o as unknown as Report) : null;
}

function toRunDetail(o: unknown): RunDetail {
  return {
    run: toRunRecord(isObject(o) ? o.run : undefined),
    report: toReport(isObject(o) ? o.report : undefined),
  };
}

function toRunList(o: unknown): RunRecord[] {
  return (Array.isArray(o) ? o : []).map(toRunRecord).filter((r) => r.id !== "");
}

// ---- event streams -------------------------------------------------------

/** One server-sent event. */
export interface StreamEvent {
  event: string;
  data: string;
}

/**
 * Reads a text/event-stream response with fetch (the token goes in a
 * header, which EventSource cannot send) and calls onEvent for each event.
 * Resolves when the stream ends; rejects on network errors unless aborted.
 */
export async function streamEvents(url: string, onEvent: (e: StreamEvent) => void, signal: AbortSignal): Promise<void> {
  const res = await fetch(url, {
    headers: authHeaders({ Accept: "text/event-stream" }),
    signal,
    credentials: "omit",
    cache: "no-store",
  });
  if (!res.ok) throw await errorFrom(res);
  if (!res.body) throw new ApiError(res.status, "The browser cannot stream the run events");
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  let event = "";
  let data: string[] = [];
  const dispatch = () => {
    if (data.length > 0 || event) onEvent({ event: event || "message", data: data.join("\n") });
    event = "";
    data = [];
  };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += value;
    let nl: number;
    while ((nl = buf.search(/\r\n|\r|\n/)) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + (buf.startsWith("\r\n", nl) ? 2 : 1));
      if (line === "") {
        dispatch();
        continue;
      }
      if (line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const name = colon < 0 ? line : line.slice(0, colon);
      let val = colon < 0 ? "" : line.slice(colon + 1);
      if (val.startsWith(" ")) val = val.slice(1);
      if (name === "event") event = val;
      else if (name === "data") data.push(val);
    }
  }
  dispatch();
}

/** Parses the data of a "progress" event (runner.Progress). */
export function parseProgress(data: string): Progress | null {
  let o: unknown;
  try {
    o = JSON.parse(data);
  } catch {
    return null;
  }
  if (!isObject(o)) return null;
  const phase = str(o, "phase");
  if (phase !== "start" && phase !== "trial" && phase !== "done") return null;
  return {
    phase,
    planned: num(o, "planned"),
    done: num(o, "done"),
    trial: isObject(o.trial) ? (o.trial as unknown as Progress["trial"]) : undefined,
    verdict: verdict(str(o, "verdict")) || undefined,
  };
}

// ---- downloads -----------------------------------------------------------

function filenameFrom(disposition: string | null, fallback: string): string {
  if (!disposition) return fallback;
  const star = /filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i.exec(disposition);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim().replace(/^"|"$/g, ""));
    } catch {
      /* fall through */
    }
  }
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(disposition);
  return plain ? plain[1].trim() : fallback;
}

/** Downloads a report of a run and saves it through the browser. */
export async function downloadReport(id: string, format: ReportFormat): Promise<string> {
  const res = await send("GET", `/api/runs/${encodeURIComponent(id)}/report.${format}`);
  const ext = format === "junit" ? "junit.xml" : format;
  const name = filenameFrom(res.headers.get("Content-Disposition"), `photofinish-${id}.${ext}`);
  const blob = await res.blob();
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(href), 10_000);
  return name;
}

// ---- routes --------------------------------------------------------------

const q = (params: Record<string, string | number | undefined>) => {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") sp.set(k, String(v));
  const s = sp.toString();
  return s ? `?${s}` : "";
};

/** Fetches /api/health; it needs no token. */
export async function health(): Promise<Health> {
  const res = await fetch("/api/health", { credentials: "omit", cache: "no-store" });
  if (!res.ok) throw await errorFrom(res);
  const o: unknown = await res.json();
  return { status: str(o, "status"), version: str(o, "version") };
}

export const api = {
  info: async () => toInfo(await json("GET", "/api/info")),
  scenarios: async () => toScenarioList(await json("GET", "/api/scenarios")),
  readFile: async (path: string): Promise<ScenarioContent> => {
    const o = await json("GET", `/api/scenarios/file${q({ path })}`);
    return { path: str(o, "path") || path, content: str(o, "content"), hash: str(o, "hash") };
  },
  /** Creates or overwrites a file; with baseHash the server refuses (409) when the file changed since. */
  writeFile: async (path: string, content: string, baseHash?: string): Promise<{ hash: string }> => {
    const o = await json("PUT", `/api/scenarios/file${q({ path })}`, baseHash ? { content, baseHash } : { content });
    return { hash: str(o, "hash") };
  },
  deleteFile: async (path: string) => {
    await json("DELETE", `/api/scenarios/file${q({ path })}`);
  },
  validate: async (content: string, path?: string, signal?: AbortSignal) =>
    toValidation(await json("POST", "/api/scenarios/validate", path ? { content, path } : { content }, signal)),
  copyExample: async (name: string): Promise<string> => {
    const o = await json("POST", `/api/examples/${encodeURIComponent(name)}/copy`);
    return str(o, "path");
  },
  importRequest: async (kind: "burp" | "har" | "auto", content: string, harEntry?: number): Promise<ImportResult> => {
    const body: Record<string, unknown> = { kind, content };
    if (harEntry !== undefined) body.harEntry = harEntry;
    return toImport(await json("POST", "/api/import", body));
  },
  probe: async (url: string, insecure: boolean, signal?: AbortSignal) =>
    toProbe(await json("POST", "/api/probe", { url, insecure }, signal)),
  startRun: async (req: RunRequest): Promise<string> => {
    const o = await json("POST", "/api/runs", req);
    return str(o, "id");
  },
  runs: async (scenario?: string, limit?: number, verdict?: Verdict) =>
    toRunList(await json("GET", `/api/runs${q({ scenario, verdict, limit })}`)),
  /** The distinct scenario names of the run history, sorted. */
  runScenarios: async (): Promise<string[]> => {
    const o = await json("GET", "/api/runs/scenarios");
    return (Array.isArray(o) ? o : []).filter((v): v is string => typeof v === "string" && v !== "");
  },
  run: async (id: string) => toRunDetail(await json("GET", `/api/runs/${encodeURIComponent(id)}`)),
  deleteRun: async (id: string) => {
    await json("DELETE", `/api/runs/${encodeURIComponent(id)}`);
  },
  cancelRun: async (id: string) => {
    await json("POST", `/api/runs/${encodeURIComponent(id)}/cancel`);
  },
  runEventsUrl: (id: string) => `/api/runs/${encodeURIComponent(id)}/events`,
  demoStart: async () => toDemo(await json("POST", "/api/demo/start")),
  demoStop: async () => toDemo(await json("POST", "/api/demo/stop")),
};

/** The id of the run in progress named by a 409 reply to POST /api/runs, if any. */
export function runningIdFrom(err: unknown): string {
  if (!(err instanceof ApiError) || err.status !== 409) return "";
  return str(err.body, "id");
}
