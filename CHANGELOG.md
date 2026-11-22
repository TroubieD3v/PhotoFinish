# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Milestone M0: repository, CI and the demo target.
- `photofinish demo`: a shop served over HTTPS with HTTP/2 and a fresh self-signed certificate (its SHA-256
  fingerprint is printed at start). It listens on loopback only unless `--expose` is given.
- Four race condition scenarios, each in two variants with independent in-memory SQLite state: `/vuln`
  (check-then-act, intentionally racy) and `/fixed` (a conditional statement or a transaction): coupon applied
  twice, transfer overdraft, 2FA attempt limit, gift card redeemed twice.
- `--window` widens the race in `/vuln` handlers with an artificial pause between check and write (up to 2s).
- Every response carries `X-Arrival-Ns`, the server time at which handling started, read from a high-resolution
  counter (QueryPerformanceCounter on Windows, the monotonic clock elsewhere) so that requests of one burst get
  distinct values; API responses also carry `X-PhotoFinish-Variant`.
- `POST /<variant>/api/reset` restores the seed state of one variant.
- Non-canonical paths (dot segments, repeated slashes) get a JSON 404 instead of a redirect, and request paths
  are logged percent-encoded so a client cannot forge log lines.
- `photofinish version` and `photofinish help`.
- CI: gofmt, `go vet`, `go test -race`, build, and a smoke test that runs the demo and checks HTTP/2 and the
  fixed coupon endpoint.
