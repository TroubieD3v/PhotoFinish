# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-22

The first release. It is still early: the command-line flags, the API of `photofinish serve` and the scenario
format may change before 1.0.

### Added

- Race engines: `h2` (the HTTP/2 single-packet attack on its own framer: every request is pre-sent without its
  last body byte or its empty final DATA frame, then the final frames of all streams leave in one write; more than
  1200 bytes of final frames are split into several writes and the report notes it), `h1` (last-byte sync over one
  connection per request), the `burst` baseline and `auto` (`h2` via ALPN, else `h1`). Optional warm-up requests,
  a refusal when the copies exceed the server's `MAX_CONCURRENT_STREAMS`, and per-request timestamps: pre-send,
  release, first response byte, and the server arrival time from `X-Arrival-Ns` when the target sends it.
- Scenario files (YAML, `version: 1`): target, `tls.insecure`, a required `scope.allow_hosts`, a request budget,
  identities, `{{name}}` variables and `${env:NAME}` secrets, setup and reset steps with `expect_status` and
  `extract`, raw requests as copied from Burp or DevTools, single and multi-endpoint races, `race.expect_429`, the
  check request and trials. Errors name the field and the line.
- Invariants in CEL over the race, check and setup responses and the variables. Every term of a top-level `&&` is
  evaluated on its own and reported with its values, e.g. `3 <= 1`.
- The runner: trials and the verdicts VIOLATED, HELD ("not reproduced in N trials", never "safe"), INCONCLUSIVE
  (failed or early responses, rate limiting, unexpected setup status, evaluation errors) and ERROR. Every request
  is checked against the scope and counted against the budget; setup, check and reset steps are rate limited;
  redirects are not followed. Secrets are masked in every report.
- `photofinish run <scenario.yaml>...` with `--engine`, `--trials`, `--copies`, `--insecure`,
  `--format text|json|sarif|junit|html`, `--output FILE`, `--out DIR`, `--fail-on violated|inconclusive|never` and
  `--quiet`. Exit codes: 0 HELD, 1 VIOLATED, 2 INCONCLUSIVE, 3 ERROR, the most severe over all scenarios; usage
  errors of every command exit 64.
- `photofinish probe <url>`: TLS version, ALPN, HTTP/2 SETTINGS, the round trip of three GET requests, the arrival
  header, the response statuses and the recommended engine. No race traffic.
- `photofinish import <file>`: a scenario skeleton from a raw HTTP request or a HAR entry (`--har-entry`,
  `--output`, which never overwrites a file), with a list of what is still to be filled in.
- `photofinish demo`: an intentionally vulnerable shop over HTTPS with HTTP/2 on loopback (`--addr`, `--window`,
  `--expose`, `--quiet`). Four scenarios (coupon, transfer, 2FA attempts, gift card), each as `/vuln`
  (check-then-act) and `/fixed` (atomic), with independent in-memory SQLite state. Every response carries
  `X-Arrival-Ns`, taken from a high-resolution clock when the whole request, body included, has arrived.
- `examples/`: the four demo scenarios against both variants, also embedded in the binary.
- Reports: JSON (the full evidence), SARIF 2.1.0 (rules `PF001` InvariantViolatedUnderConcurrency and `PF002`
  RaceTestInconclusive, located at `check.invariant`, with a stable `photofinish/v1` fingerprint), JUnit XML (a
  test suite per scenario, a test case per trial) and a self-contained HTML page with the trials, the timeline of
  a race, the server arrival times, the evaluated invariant, the check response and the reproduce command.
- `photofinish serve`: the web UI and a local API for the scenario files of a workspace (`--addr`, `--workspace`,
  `--data`, `--demo`, `--demo-addr`, `--demo-window`, `--expose`, `--open`). Screens: Scenarios, Editor (live
  validation at the error line), Run (live trials, verdict, timeline, evaluated invariant, downloads), Runs (the
  history in SQLite), Probe and Import; graphite dark and light themes, keyboard navigation. It binds to loopback
  only, every API request needs the session token printed on start, foreign `Host` and `Origin` values are
  refused, file access stays inside the workspace, and the runner enforces the scope of every scenario. See
  SECURITY.md for the threat model.
- Docker image `ghcr.io/troubied3v/photofinish` for linux/amd64 and linux/arm64: distroless, non-root, with the
  web UI.
- A composite GitHub Action (`uses: TroubieD3v/PhotoFinish@v0`) that installs PhotoFinish with `go install`, runs
  the scenarios, writes SARIF, JUnit and HTML reports and a job summary table, and fails the step under `fail-on`.
- Release archives for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64 with the web UI
  embedded, and `checksums.txt`.
- BENCHMARKS.md: the arrival spread and hit rate of `h2`, `h1` and `burst` on the demo shop, on loopback and under
  added network jitter (the Benchmark workflow).
