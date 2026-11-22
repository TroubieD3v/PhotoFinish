# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Milestone M4: the web UI and `photofinish serve`.
- `photofinish serve [--addr 127.0.0.1:7340] [--workspace DIR] [--data DIR] [--demo] [--demo-addr 127.0.0.1:8443]
  [--demo-window 0s] [--expose] [--open]`: a local API and the embedded web UI for the scenario files of a
  workspace. It binds to loopback only (a non-loopback
  `--addr` needs `--expose`, else exit 64, and prints a warning) and prints the link
  `PhotoFinish UI: http://127.0.0.1:7340/#token=<token>` once. Every `/api/` request except `GET /api/health` needs
  the session token (32 random bytes, or `PHOTOFINISH_TOKEN` of at least 32 characters) as a Bearer header,
  compared in constant time; there are no cookies. Requests with a foreign `Host` (DNS rebinding) and writes with
  a foreign `Origin` are refused; every response carries a strict Content Security Policy, `nosniff` and
  `no-referrer`, API responses `no-store`. File access stays inside the workspace (`*.yaml`/`*.yml` only, no `..`,
  no absolute paths, no symlinks out, names spelled exactly as on disk so that letter case and Windows 8.3 short
  names do not reach dot directories, 256 KiB per file), request bodies are capped at 1 MiB, one race runs at a
  time and can be cancelled, and the runner still enforces the scope of every scenario. `--open` hands the link to
  the browser through a private redirect page, so the token is not on a command line.
- API routes for the UI: workspace scenarios (list, read, create or overwrite with an optional `baseHash` against
  lost updates, delete), validation with line and column (YAML, scenario rules and the CEL invariant), copying an
  embedded example, import of a raw request or HAR entry, probe, runs (start, list filtered by scenario and verdict
  before the limit, the scenario names of the history, get, delete, cancel), live
  progress as server-sent events read with `fetch` (past events are replayed to late subscribers), report
  downloads as JSON, SARIF, JUnit and HTML, and starting and stopping the in-process demo shop (`--demo` starts it
  at boot).
- The web UI (`web/`, React 18, TypeScript, Vite, IBM Plex fonts bundled, CodeMirror 6 for YAML; embedded with
  `go:embed`): Scenarios (workspace files with their last verdict, the demo examples with "Copy to workspace"),
  Editor (live validation with markers at the error line, a problems list, the parsed summary, run options, Save
  with Ctrl/Cmd+S, an unsaved-changes guard, a commented template for new scenarios), Run (live progress and
  trials, then the verdict strip, trials table, the timeline of the selected trial with release line, pre-send
  segment, exact values on hover or focus and the server arrival strip, the invariant with its evaluated terms, the
  check response, setup and reset steps, the reproduce command and downloads), Runs (history with filters by
  scenario and verdict), Probe and Import. Graphite dark theme with a light variant and a toggle, keyboard
  navigation, visible focus, `aria-live` progress. Without the session token it shows how to open the link printed
  by `photofinish serve`.
- `internal/store`: the run history in SQLite (`<data>/photofinish.db`, WAL, schema versioned with
  `PRAGMA user_version`) with the masked report of every run, ERROR included; `--data ""` or `--data :memory:`
  keeps it in memory.
- `runner.Options.OnProgress`: a structured callback with the resolved plan before the first trial, every masked
  trial, and the overall verdict at the end. The text progress lines of `photofinish run` are unchanged.
- `examples` is a Go package that embeds the example scenarios (`examples.FS`, `examples.Names()`).
- `make ui` (`npm --prefix web ci` and `npm --prefix web run build`); `make build` works with or without it.
- Playwright tests in `web/e2e` against the built binary with the in-process demo shop: copy the coupon examples,
  find a YAML error at its line in the editor, run `coupon-vuln` (VIOLATED, timeline and failing terms) and
  `coupon-fixed` (HELD) with 3 trials, download SARIF, the run history, probe the demo (recommends `h2`), import a
  raw request, and the screen without a token.
- CI: a `web` job (typecheck, the UI build, the binary with the UI, the Playwright tests); a smoke test of
  `photofinish serve` without the UI in the `go` job (token, Host and Origin checks, the "UI not built" page); the
  `docker` job also runs the README's `serve` command in a container and checks the embedded UI and the API.
- Milestone M3: reports, Docker, the GitHub Action and the release pipeline.
- `internal/report`: every report as JSON, SARIF 2.1.0, JUnit XML and a self-contained HTML page. SARIF has the
  rules `PF001` InvariantViolatedUnderConcurrency (error, a proven race) and `PF002` RaceTestInconclusive (warning),
  one result per VIOLATED or INCONCLUSIVE scenario at the line of `check.invariant`, a stable `photofinish/v1`
  fingerprint, and ERROR scenarios as tool execution notifications. JUnit has one test suite per scenario and one
  test case per trial (VIOLATED is a failure, INCONCLUSIVE is skipped, a scenario ERROR is an error). The HTML page
  loads nothing from the network and shows the verdict, the trials, the timeline of a race with the server arrival
  times, the evaluated invariant, the check response and the reproduce command, in a graphite palette with a light
  variant.
- `photofinish run`: `--format text|json|sarif|junit|html`, `--output FILE`, and `--fail-on violated|inconclusive|never`
  (default `violated`, the exit codes of M2; `never` exits 0 unless a scenario is ERROR). `--out DIR` also writes
  `report.html`, `results.sarif` and `junit.xml` for all scenarios of the run. A run that writes SARIF, JUnit or
  `--out` refuses two scenarios with the same name before any request (exit 64), as it refuses an `--output` that
  is one of the `--out` reports. A JSON report that cannot be written and a scenario that Ctrl+C left unrun are
  ERROR in every document of the run, as in the exit code.
- `Dockerfile`: a static binary on `gcr.io/distroless/static-debian12:nonroot`, cross-compiled for the target
  platform; entrypoint `photofinish`, working directory `/work`.
- `action.yml`: a composite GitHub Action (`uses: TroubieD3v/PhotoFinish@<ref>`, or `uses: ./` from a checkout) with
  the inputs `scenarios` (globstar patterns), `engine`, `trials`, `copies`, `insecure`, `fail-on`, `sarif`, `junit`,
  `html` and `version`, a job summary table, and the outputs `verdict`, `exit-code` and `report-dir` (a new
  directory for every use in a job). `verdict` is ERROR whenever the run exits 3, and a scenario without a report
  gets an ERROR row in the summary. Installed with `go install`, the binary reports the resolved module version.
- CI: `photofinish version` in the `go` job; an `examples` job that runs every example against the demo shop
  (`-fixed` must exit 0, `-vuln` must exit 1) and checks the SARIF against the official schema, the JUnit XML and
  the HTML report; an `action` job that runs the action from the checkout and expects it to pass on `-fixed`, fail
  with VIOLATED on `coupon-vuln` and only report with `fail-on: never`; a `docker` job that builds the image and runs
  a scenario in a container against the demo shop in another one. The demo findings stay artifacts and never reach
  code scanning.
- Release workflow for `vX.Y.Z` and `vX.Y.Z-*` tags: tests, binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and
  windows/amd64 with README.md, README.ru.md and LICENSE, `checksums.txt`, a smoke test of the Linux binary against
  the demo shop, release notes from this file, and the multi-arch image `ghcr.io/troubied3v/photofinish` tagged
  `X.Y.Z`, `X.Y` and `latest`. A release moves the major tag (`v0`) to itself when it is the newest of that major.
- Milestones M1-M2: the engines, scenarios, invariants and verdicts.
- `internal/engine`: the `h2` engine (HTTP/2 single-packet attack on its own framer: every request is pre-sent
  without its last body byte or its empty final DATA frame, then the final frames of all streams leave in one
  write; more than 1200 bytes of final frames are split into several writes and the race notes it), the `h1`
  engine (last-byte sync over one connection per request), the `burst` baseline and `auto` (h2 via ALPN, else
  h1). Optional warm-up requests on the same connections, a refusal when the copies exceed the server's
  `MAX_CONCURRENT_STREAMS`, and per-request timestamps in Unix ns: pre-send, release, first response byte, done,
  and the server arrival time from `X-Arrival-Ns` when the target sends it. Response headers are capped at 1 MiB
  per response in `h1`, `h2` and `probe`, and an `h2` stream accepts one trailer block that must end it, so a
  hostile server cannot exhaust memory.
- `photofinish probe <url>`: TLS version, ALPN, HTTP/2 SETTINGS, the round trip of three GET requests, whether
  the arrival header is present, the response statuses (with a warning when every response is an error),
  and the recommended engine.
- Scenario files (YAML, `version: 1`): target, `tls.insecure`, a required `scope.allow_hosts`, a request budget,
  identities, variables with `{{name}}` and `${env:NAME}` (`{{"{{"}}` writes a literal `{{`), setup and reset
  steps with `expect_status` and `extract`, raw requests as copied from Burp or DevTools, single and
  multi-endpoint races, `race.expect_429` for targets whose own defence answers 429, the check request and
  trials. Errors name the field and the line.
- Invariants in CEL over the race, check and setup responses and the variables. Every term of a top-level `&&` is
  evaluated on its own and reported with its concrete values, e.g. `3 <= 1`.
- Trials and verdicts: VIOLATED, HELD ("not reproduced in N trials", never "safe"), INCONCLUSIVE (failed or early
  responses, any 429 unless `race.expect_429` is set, unexpected setup status, evaluation errors; an imperfect
  race is INCONCLUSIVE even when the invariant is false) and ERROR. Every request is checked against the scope
  and counted against the budget; setup, check and reset steps are rate limited. Secrets (credential headers,
  identity headers, `${env:...}` values also in JSON-escaped and percent-encoded form, sensitive query
  parameters, JSON keys such as `password` or `token`, also in truncated bodies) are masked in every report.
- `photofinish run <scenario.yaml>...` with `--engine`, `--trials`, `--copies`, `--insecure`, `--out DIR` (one JSON
  report per scenario), `--format text|json` (one JSON report, or a JSON array for several files) and `--quiet`;
  the exit code is 0 HELD, 1 VIOLATED, 2 INCONCLUSIVE, 3 ERROR, the most severe over all scenarios.
- `photofinish import <file>`: a scenario skeleton from a raw HTTP request or a HAR entry (`--har-entry`,
  `--output`, which never overwrites a file), with a list of what is still to be filled in. HTTP/2 requests
  copied with pseudo headers (`:authority`, `:scheme`) are understood, and `{{` or `${env:` in a captured request
  is kept literal.
- `examples/`: the four demo scenarios against both variants (`coupon`, `transfer`, `twofa`, `giftcard`, each
  `-vuln` and `-fixed`), and an integration test that runs all of them with the `h2` engine against an
  in-process shop: every `-vuln` example must be VIOLATED and every `-fixed` one HELD.
- Usage errors of every command (unknown command, bad flags or arguments, `demo` included) exit with 64
  (`EX_USAGE`); 2 is the INCONCLUSIVE verdict of `run`. `photofinish help` lists `run`, `probe`, `import`, `demo`
  and `version`; `serve` (the web UI) arrives in M4.
- Milestone M0: repository, CI and the demo target.
- `photofinish demo`: a shop served over HTTPS with HTTP/2 and a fresh self-signed certificate (its SHA-256
  fingerprint is printed at start). It listens on loopback only unless `--expose` is given.
- Four race condition scenarios, each in two variants with independent in-memory SQLite state: `/vuln`
  (check-then-act, intentionally racy) and `/fixed` (a conditional statement or a transaction): coupon applied
  twice, transfer overdraft, 2FA attempt limit, gift card redeemed twice.
- `--window` widens the race in `/vuln` handlers with an artificial pause between check and write (up to 2s).
- Every response carries `X-Arrival-Ns`, the server time at which handling started, read from a high-resolution
  counter (QueryPerformanceCounter on Windows, 100 ns ticks; the monotonic clock elsewhere), fine enough to order
  the requests of one burst (copies handled in parallel can still share a tick); API responses also carry
  `X-PhotoFinish-Variant`.
- `POST /<variant>/api/reset` restores the seed state of one variant.
- Non-canonical paths (dot segments, repeated slashes) get a JSON 404 instead of a redirect, and request paths
  are logged percent-encoded so a client cannot forge log lines.
- `photofinish version` and `photofinish help`.
- CI: gofmt, `go vet`, `go test -race`, build, and a smoke test that runs the demo and checks HTTP/2 and the
  fixed coupon endpoint.

### Changed

- `photofinish help` lists `serve`; it no longer says that the web UI arrives in M4.
- `Dockerfile`: a `node:22-alpine` stage builds the web UI on the build platform before the Go build, so the image
  contains it; the image also exposes 7340. The entrypoint is still `photofinish` and the default command `help`.
- Release workflow: the web UI is built before the tests and the binaries, so every release archive and the image
  contain it, and the smoke test checks that the Linux binary serves it.

### Fixed

- Durations of setup, check and reset steps are measured with the high-resolution clock. On Windows they were
  taken from Go's monotonic clock, which advances in steps of up to half a millisecond, so fast local steps were
  reported as 0.
