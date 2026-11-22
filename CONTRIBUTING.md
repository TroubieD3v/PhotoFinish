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
and `modernc.org/sqlite` (the demo shop; pure Go, no CGO). Code, comments and docs are in English;
`README.ru.md` and `docs/DESIGN.ru.md` are the Russian documents.

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

1. Add a section `## [X.Y.Z]` to `CHANGELOG.md` (the release notes come from it; without it the release fails).
2. Tag the commit `vX.Y.Z` (or `vX.Y.Z-rc.1` for a prerelease) and push the tag. Only tags of that form start
   `.github/workflows/release.yml`.
3. The workflow tests, builds the five archives and `checksums.txt`, smoke-tests the Linux binary against the demo,
   publishes the release and the image `ghcr.io/troubied3v/photofinish`, and moves the major tag (`v0`) that
   `uses: TroubieD3v/PhotoFinish@v0` follows to the new release. Prereleases and patches of an older minor version
   leave the major tag alone. Do not push the major tag by hand.
