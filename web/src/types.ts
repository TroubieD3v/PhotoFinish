// Types of the local API of "photofinish serve". Report types mirror the JSON
// of runner.Report (internal/runner, internal/engine, internal/check) field by
// field; the other types are the shapes of the server routes
// (internal/server) as api.ts decodes them.

/** Outcome of a trial or of a run. */
export type Verdict = "VIOLATED" | "HELD" | "INCONCLUSIVE" | "ERROR";

/** Engine names accepted by the runner. */
export type EngineKind = "h2" | "h1" | "burst" | "auto";

export const ENGINES: readonly EngineKind[] = ["auto", "h2", "h1", "burst"];

/** HTTP headers as encoded by Go's http.Header. */
export type Headers = Record<string, string[]>;

/** engine.Result: one request of a race. Timestamps are Unix nanoseconds. */
export interface RaceResult {
  index: number;
  label?: string;
  stream?: number;
  conn: number;
  proto: string;
  status: number;
  header?: Headers;
  /** Base64 of the response body bytes (Go []byte). */
  body?: string;
  truncated?: boolean;
  error?: string;
  pre_sent_ns: number;
  released_ns: number;
  first_byte_ns: number;
  done_ns: number;
  server_arrival_ns?: number;
  early_response?: boolean;
}

/** engine.Release: how the withheld parts were written. */
export interface Release {
  writes: number;
  bytes: number;
  spread_ns: number;
}

/** engine.Race: the record of one race. */
export interface Race {
  engine: EngineKind;
  target: string;
  alpn?: string;
  tls_version?: string;
  connections: number;
  warmup: number;
  release: Release;
  results: RaceResult[];
  notes?: string[];
  started_ns: number;
  finished_ns: number;
}

/** runner.StepRecord: a setup, check or reset request. */
export interface StepRecord {
  id?: string;
  method: string;
  url: string;
  status: number;
  header?: Headers;
  body?: string;
  error?: string;
  duration_ns: number;
}

/** check.Term: one conjunct of the invariant with its value. */
export interface Term {
  expr: string;
  value: string;
  pass: boolean | null;
}

/** runner.Trial: one setup-race-check-reset cycle. */
export interface Trial {
  number: number;
  verdict: Verdict;
  reasons?: string[];
  setup: StepRecord[] | null;
  race?: Race | null;
  check?: StepRecord | null;
  terms: Term[] | null;
  reset?: StepRecord[] | null;
}

/** runner.Stats: counts and medians of a run. */
export interface Stats {
  planned: number;
  ran: number;
  violated: number;
  held: number;
  inconclusive: number;
  errored?: number;
  skipped?: number;
  median_response_spread_ns: number;
  median_server_arrival_spread_ns?: number | null;
  requests_spent: number;
}

/** runner.Report: the result of one scenario run, masked. */
export interface Report {
  schema: string;
  tool: string;
  scenario: string;
  file: string;
  target: string;
  engine: EngineKind;
  copies: number;
  invariant: string;
  explain?: string;
  verdict: Verdict;
  summary: string;
  notes?: string[];
  trials: Trial[] | null;
  stats: Stats;
  started_at: string;
  finished_at: string;
  reproduce: string;
}

/** runner.Progress, sent as "progress" events while a run goes on. */
export interface Progress {
  phase: "start" | "trial" | "done";
  planned: number;
  done: number;
  trial?: Trial;
  verdict?: Verdict;
}

/** GET /api/health. */
export interface Health {
  status: string;
  version: string;
}

/** Demo shop state. */
export interface DemoState {
  running: boolean;
  url: string;
}

/** GET /api/info. */
export interface Info {
  version: string;
  workspace: string;
  demo: DemoState;
  dataDir: string;
  /** Id of the run in progress, "" when none. */
  running: string;
}

/** Last run of a workspace scenario. */
export interface LastRun {
  id: string;
  verdict: Verdict | "";
  finishedAt: string;
}

/** A scenario file of the workspace. */
export interface ScenarioFile {
  path: string;
  name: string;
  description: string;
  target: string;
  engine: string;
  valid: boolean;
  error: string;
  lastRun?: LastRun;
}

/** An example embedded in the binary. */
export interface Example {
  name: string;
  description: string;
  target: string;
  engine: string;
  /** Workspace path the example is copied to: examples/<name>.yaml. */
  path: string;
  /** Whether that path exists in the workspace already. */
  inWorkspace: boolean;
}

/** GET /api/scenarios. */
export interface ScenarioList {
  scenarios: ScenarioFile[];
  examples: Example[];
  /** The workspace has more scenario files than the listing returns. */
  truncated: boolean;
}

/** GET /api/scenarios/file. */
export interface ScenarioContent {
  path: string;
  content: string;
  /** Hash of the content on disk, sent back as baseHash on save. */
  hash: string;
}

/** One validation problem; line and column are 1-based, 0 when unknown. */
export interface Problem {
  line: number;
  column: number;
  field: string;
  message: string;
}

/** Parsed summary of a scenario; present whenever the YAML parsed, even if it is invalid. */
export interface ScenarioSummary {
  name: string;
  description: string;
  target: string;
  engine: string;
  copies: number;
  trials: number;
  invariant: string;
  explain: string;
  /** scope.allow_hosts. */
  allowHosts: string[];
  /** scope.budget: requests per run and the rate outside the race. */
  budgetRequests: number;
  budgetRps: number;
  /** tls.insecure of the scenario. */
  insecure: boolean;
}

/** POST /api/scenarios/validate. */
export interface Validation {
  valid: boolean;
  errors: Problem[];
  scenario?: ScenarioSummary;
}

/** POST /api/import. */
export interface ImportResult {
  /** The generated scenario YAML. */
  content: string;
  /** What the skeleton still needs before it runs. */
  todo: string[];
  /** The detected input. */
  kind: "burp" | "har";
  /** The scenario name, a suggestion for the file name. */
  name: string;
}

/** POST /api/probe: engine.ProbeReport. RTTs are nanoseconds. */
export interface ProbeReport {
  url: string;
  alpn: string;
  tlsVersion: string;
  http2: boolean;
  server: string;
  maxConcurrentStreams: number;
  initialWindowSize: number;
  maxFrameSize: number;
  rtts: number[];
  statuses: number[];
  arrivalHeader: boolean;
  recommended: string;
  notes: string[];
}

/** POST /api/runs body. */
export interface RunRequest {
  path?: string;
  content?: string;
  engine?: EngineKind;
  trials?: number;
  copies?: number;
  insecure?: boolean;
}

/** A stored run (store.Run without the report). */
export interface RunRecord {
  id: string;
  scenario: string;
  file: string;
  engine: string;
  /** "" while the run is in progress. */
  verdict: Verdict | "";
  summary: string;
  trials: number;
  violated: number;
  copies: number;
  startedAt: string;
  /** "" while the run is in progress. */
  finishedAt: string;
  /** True while the run is in progress (status "running"). */
  running: boolean;
  /** Trials planned and done while the run is in progress; 0 once finished. */
  planned: number;
  done: number;
}

/** GET /api/runs/{id}. */
export interface RunDetail {
  run: RunRecord;
  report: Report | null;
}

/** Report download formats. */
export type ReportFormat = "json" | "sarif" | "junit" | "html";
