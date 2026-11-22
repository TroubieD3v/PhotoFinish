# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
