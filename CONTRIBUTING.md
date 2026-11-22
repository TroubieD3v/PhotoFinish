# Contributing

```bash
make build                       # bin/photofinish
make test                        # go vet ./... && go test -race ./...
gofmt -l .                       # must print nothing
go run ./cmd/photofinish demo    # the demo shop on https://127.0.0.1:8443
```

Without `make`: `go build -o bin/photofinish ./cmd/photofinish`, `go vet ./...`, `go test -race ./...`.
The binary needs no CGO, but the race detector of `go test -race` does: it needs CGO and a C compiler (gcc on
Windows).
Dependencies are `golang.org/x/net` (HTTP/2 framing), `cel.dev/cel-go` (invariants), `gopkg.in/yaml.v3` (scenarios)
and `modernc.org/sqlite` (the demo shop and the run history of `serve`; pure Go, no CGO). Code, comments and docs
are in English; `README.ru.md` and `docs/DESIGN.ru.md` are the Russian documents.

## The web UI

The UI lives in `web/` (React 18, TypeScript, Vite) and needs Node.js 22. `npm --prefix web run build` writes it to
`internal/ui/dist/app`, which `go build` embeds; that directory is not committed. `internal/ui/dist/README.md` is,
so the Go build and `go test` work without a UI build, and `serve` then answers with a page that says so.

```bash
make ui                                  # npm --prefix web ci && npm --prefix web run build
make build                               # bin/photofinish with the UI embedded
npm --prefix web run typecheck           # tsc --noEmit, as in CI
npm --prefix web run dev                 # Vite on http://127.0.0.1:5173 (bound there), /api proxied to 127.0.0.1:7340
```

For `dev`, start `./bin/photofinish serve` in another terminal and open `http://127.0.0.1:5173/#token=<token>` with
the token it printed (set `PHOTOFINISH_TOKEN` to keep the same one across restarts, and `PHOTOFINISH_API` to proxy
to another address).

The Playwright tests in `web/e2e` run the prebuilt `bin/photofinish` (`serve --addr 127.0.0.1:7341 --demo
--demo-window 2ms --data :memory:` with a temporary workspace and a fixed test token; the 2 ms window makes the
coupon-vuln race reproduce in every trial), so build the UI and the binary first:

```bash
make ui && make build
(cd web && npx playwright install chromium)   # once
npm --prefix web run test:e2e
```

They use the ports 7341 and 8443 (the demo shop). The runtime dependencies of the UI are React, `lucide-react`, the
IBM Plex fonts (`@fontsource/ibm-plex-sans`, `@fontsource/ibm-plex-mono`, bundled, no CDN) and CodeMirror 6; the
styles are hand-written CSS in the palette of the HTML report. Do not add a CSS framework or a component library,
and keep the visual rules: graphite, 1px lines, 3-4px radii, 13px base, sentence case, no gradients, glow or
emoji. Commit `web/package-lock.json` with every dependency change.

## Adding a demo scenario

A scenario lives in `internal/demo/`. Request parsing and responses are shared; only the store operation differs
between the variants:

- the `/vuln` operation (`vuln.go`) checks in one statement and writes in another, with the `Window` pause between
  them;
- the `/fixed` operation (`fixed.go`) does the same thing atomically: one conditional statement whose affected rows
  are checked, or a transaction.

Every `/vuln` scenario needs a `/fixed` twin, plus a concurrent test in `internal/demo/shop_test.go` that proves
both:

1. concurrent requests against `/vuln` break the scenario's invariant (with a widened `Window`, so the test is not
   flaky);
2. the same requests against `/fixed` never break it.

The seed and `POST /<variant>/api/reset` must restore the state the scenario needs. Document the scenario in the
tables of `README.md` and `README.ru.md`, and add a line to `CHANGELOG.md`.

SQLite errors must never reach a client: answer `500 {"error":"internal error"}` and log the detail.

## Releasing

1. Move the entries under `## [Unreleased]` in `CHANGELOG.md` into a new section `## [X.Y.Z] - YYYY-MM-DD` below
   it, and keep an empty `## [Unreleased]` on top. The release notes are this section, from its heading to the next
   `## ` heading; without it the release fails.
2. Merge that to `main`, tag the commit on `main` `vX.Y.Z` (or `vX.Y.Z-rc.1` for a prerelease) and push the tag.
   Only tags of that form start `.github/workflows/release.yml`.
3. The workflow builds the web UI, runs the tests, builds the five archives `photofinish_vX.Y.Z_<os>_<arch>` (with
   the UI embedded; `.zip` for Windows, `.tar.gz` for the rest) and `checksums.txt`, smoke-tests the Linux binary
   against the demo and its `serve` for the embedded UI, and publishes the release. A tag with a suffix is marked
   as a prerelease.
4. It moves the major tag (`v0`) that `uses: TroubieD3v/PhotoFinish@v0` follows to the new release. Prereleases
   and patches of an older minor version leave it alone. Do not push the major tag by hand.
5. A second job pushes the image `ghcr.io/troubied3v/photofinish` (linux/amd64 and linux/arm64) with the tag
   `X.Y.Z`, and for a release without a suffix also `X.Y` and `latest`, then checks that the pushed image runs.
