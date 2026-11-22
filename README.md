# PhotoFinish

**English** · [Русский](README.ru.md)

PhotoFinish proves race conditions in web APIs: synchronized requests via the HTTP/2 single-packet attack, a
business rule you declare, and the evidence.

Pre-alpha: M1-M2 — engines, scenarios and verdicts work; reports, UI and release arrive in M3-M5.

> **Note**: test only systems you own or are explicitly authorized to test. The demo shop in this repository is
> intentionally vulnerable and listens on loopback only. See [SECURITY.md](SECURITY.md).

## What exists now

| Command | Does |
|---|---|
| `photofinish run <scenario.yaml>...` | runs scenarios: setup, a synchronized race, a check request and an invariant, repeated for every trial; prints a verdict and writes JSON evidence |
| `photofinish probe <url>` | inspects a target (TLS, ALPN, HTTP/2 settings, round trips, arrival header) and recommends an engine |
| `photofinish import <file>` | turns a raw HTTP request (Burp, DevTools) or a HAR entry into a scenario skeleton |
| `photofinish demo` | starts a shop over HTTPS with HTTP/2 whose four scenarios exist in a racy and a fixed variant |

The engines:

| Engine | How the requests are sent |
|---|---|
| `h2` | HTTP/2 single-packet attack: one connection; every request is sent except its last byte (or the empty final DATA frame), then the final frames of all streams leave in one write, one TLS record (about 100 streams fit in one write; larger races are split into several writes of at most 1200 bytes and the report notes it) |
| `h1` | HTTP/1.1 last-byte sync: one connection per request, everything but the last byte, then the last bytes in a tight loop |
| `burst` | plain concurrent requests without synchronization, the baseline the other two are compared to |
| `auto` | `h2` if the server negotiates it via ALPN, else `h1` |

## Quick start

Requires Go 1.27+. The binary needs no CGO and no other services.

```bash
git clone https://github.com/TroubieD3v/PhotoFinish.git
cd PhotoFinish
make build            # or: go build -o bin/photofinish ./cmd/photofinish
```

`make test` runs `go vet` and the tests with the race detector, which needs CGO and a C compiler.

## Run a race

Start the demo shop in one terminal:

```bash
./bin/photofinish demo
```

In another, run the coupon scenario against the racy variant. [examples/coupon-vuln.yaml](examples/coupon-vuln.yaml)
resets the shop, creates a cart, applies the single-use coupon `WELCOME10` twenty times in one packet and then
checks that the cart has at most one discount:

```bash
./bin/photofinish run examples/coupon-vuln.yaml --out reports
```

```text
run examples/coupon-vuln.yaml
trial 1/10: HELD (1 of 20 succeeded) spread 1.05ms
trial 2/10: VIOLATED (3 of 20 succeeded) spread 0.77ms
trial 3/10: HELD (1 of 20 succeeded) spread 1.03ms
trial 4/10: VIOLATED (4 of 20 succeeded) spread 0.83ms
trial 5/10: VIOLATED (2 of 20 succeeded) spread 0.78ms
trial 6/10: VIOLATED (4 of 20 succeeded) spread 0.98ms
trial 7/10: VIOLATED (5 of 20 succeeded) spread 0.87ms
trial 8/10: HELD (1 of 20 succeeded) spread 1.11ms
trial 9/10: VIOLATED (4 of 20 succeeded) spread 0.81ms
trial 10/10: VIOLATED (4 of 20 succeeded) spread 0.71ms
coupon-vuln: VIOLATED
  7 of 10 trials broke the rule (h2, median response spread 0.85 ms)
  rule       A single-use coupon must apply at most once per cart.
  invariant  size(check.json.discounts) <= 1 && size(race.filter(r, r.status == 200)) <= 1
  target     https://127.0.0.1:8443/vuln/api (engine h2, 20 copies)
  trials     10 run: 7 violated, 3 held
  timing     median response spread 0.85 ms, server arrival spread 0.35 ms
  failing terms in trial 2:
    FAIL  size(check.json.discounts) <= 1    (3 <= 1)
    FAIL  size(race.filter(r, r.status == 200)) <= 1    (3 <= 1)
  reproduce  photofinish run examples/coupon-vuln.yaml --engine h2 --trials 10 --copies 20
  report     reports/coupon-vuln.json
```

The exit code is 1 (VIOLATED). `reports/coupon-vuln.json` holds the evidence of every trial: the setup and check
responses, every race response with its timestamps (pre-send, release, first byte, and the server arrival time
from `X-Arrival-Ns`), the value of every term of the invariant, and the command that reproduces the run. Secrets
are masked.

Run the same race against the atomic variant and the verdict is HELD (exit code 0):

```bash
./bin/photofinish run examples/coupon-fixed.yaml
```

HELD means "not reproduced in N trials" with the measured spread, never "safe". `examples/` has both variants of
all four demo scenarios; `./bin/photofinish run examples/*.yaml` runs them all.

| Flag | Meaning |
|---|---|
| `--engine auto\|h2\|h1\|burst` | override `race.engine` |
| `--trials N`, `--copies N` | override `trials` and `race.copies` |
| `--insecure` | skip TLS certificate verification (like `tls.insecure`) |
| `--out DIR` | write `DIR/<scenario-name>.json`, the full report |
| `--format text\|json` | `json` prints the report to stdout instead of the text summary: one JSON object for one file, a JSON array of reports (in file order) for several; progress goes to stderr |
| `--quiet` | no progress lines, only the summary |

### Exit codes

| Code | `run` | other commands |
|---|---|---|
| 0 | every scenario HELD | success |
| 1 | at least one scenario VIOLATED | runtime failure (`probe`, `import`, `demo`) |
| 2 | INCONCLUSIVE: at least half of the trials of a scenario could not be judged | - |
| 3 | ERROR: invalid scenario, scope violation or setup failure before the first race | - |
| 64 | usage error (unknown command, bad flag or argument) | usage error |

With several scenarios `run` returns the most severe code: 3 before 1 before 2 before 0.

A trial whose invariant evaluated to false over a clean race is VIOLATED. It is INCONCLUSIVE when the invariant
could not be evaluated, a setup step answered an unexpected status, or the race was imperfect, whatever the
invariant says: a race request failed or got no response, a response arrived before the release (the endpoint may
be static, or the request was not held), or the race was rate limited. Failing terms of such a trial are listed as
notes. Any 429 in the race counts as rate limiting, unless the scenario sets `race.expect_429: true` to declare 429s
the application's own answer (a 2FA lockout, say); even then a 429 with `Retry-After` or a `RateLimit` header, or a
race in which every response is 429, is rate limiting. A scenario is VIOLATED if any trial was.

## Scenario format

A short reference; [examples/](examples/) has complete files.

```yaml
version: 1
name: coupon-applied-twice                # [a-z0-9-]+, names the report file
target: https://shop.example.test/api     # request paths are appended to its path
tls: { insecure: false }                  # true skips certificate verification
scope:
  allow_hosts: [shop.example.test]        # required; every request is checked before it is sent
  budget: { requests: 600, rps: 50 }      # total cap for the run; rate of setup/check/reset steps
identities:
  alice: { headers: { Authorization: "Bearer ${env:ALICE_TOKEN}" } }
vars: { code: WELCOME10 }
setup:                                    # before every trial
  - id: cart
    as: alice
    request: POST /carts
    expect_status: [201]
    extract: { cart_id: "$.id" }          # "$.json.path", "header:Name" or "status"
race:
  engine: auto                            # h2 | h1 | burst | auto
  copies: 20                              # 1..1000
  request:
    as: alice
    raw: |
      POST /carts/{{cart_id}}/coupons HTTP/2
      Content-Type: application/json

      {"code":"{{code}}"}
check:
  as: alice
  request: GET /carts/{{cart_id}}
  invariant: >
    size(check.json.discounts) <= 1 &&
    size(race.filter(r, r.status == 200)) <= 1
  explain: A single-use coupon must apply at most once per cart.
reset: []                                 # optional steps after every trial
trials: 10
```

| Key | Meaning |
|---|---|
| `target` | base URL; `/carts` under `https://host/api` becomes `https://host/api/carts` |
| `scope.allow_hosts` | hosts compared to `host:port` case-insensitively; a bare host allows any port; anything else is refused before a connection is opened |
| `scope.budget` | `requests` caps every request of the run, warm-up included (default 1000); when it runs out, the remaining trials are skipped. `rps` limits setup, check and reset steps, not the race (default 20) |
| `identities` | named header sets chosen per step with `as`; their values are masked in reports |
| `vars`, `{{name}}` | template variables; `extract` adds values from setup responses; an unknown name is an error. `{{"text"}}` writes text literally: `{{"{{"}}` is a literal `{{`, `{{"${env:"}}` a literal `${env:` (`import` escapes captured requests this way) |
| `${env:NAME}` | read from the environment, masked in reports; a missing variable is an error |
| `request` / `raw` | `METHOD /path`, or a full raw request: request line, headers, a blank line, the body. A `Host` header is ignored, the target decides; `json:` sets a JSON body |
| `race.request` / `race.requests` | one request sent `copies` times, or a list of requests (multi-endpoint race) with their own `copies` |
| `race.warmup`, `race.gate` | warm-up requests on the same connections before the race (default 0); pause between pre-send and release (default 100ms) |
| `race.expect_429` | `true` declares 429s without `Retry-After` or `RateLimit` headers to be the application's answer, not rate limiting (default false: any 429 makes the trial INCONCLUSIVE) |
| `check.invariant` | a [CEL](https://cel.dev) expression that must be true after the race |
| `evidence.arrival_header` | response header with the server's arrival time in Unix ns (default `X-Arrival-Ns`, `-` disables) |

The invariant sees `race` (the race responses in order), `check` (the check response), `setup` (the setup
responses by step id) and `vars`. A response has `status`, `headers` (lowercase names), `body`, `json` (parsed
body or null), and in `race` also `index` and `error`. The standard macros `filter`, `exists`, `all`, `map` and
`size` are available. Every term of a top-level `&&` is evaluated on its own, so the report shows which part
failed and with which values, for example `3 <= 1`.

## Probe and import

```bash
./bin/photofinish probe https://127.0.0.1:8443/vuln/api/me --insecure
./bin/photofinish import request.txt --output scenario.yaml    # raw request from Burp or DevTools
./bin/photofinish import capture.har --har-entry 3             # one HAR entry, YAML to stdout
```

`probe` sends three GET requests and no race traffic. `import` writes a skeleton that deliberately fails
validation until you write the check and the invariant; review the scope and budget, and move credentials to
`${env:NAME}`.

## The demo shop

`photofinish demo` starts a small shop over HTTPS with HTTP/2. Each scenario exists twice, with independent
in-memory SQLite state: `/vuln` checks in one statement and writes in another (a real check-then-act race), and
`/fixed` does the same thing atomically.

| Scenario | Endpoint | `/vuln` (racy) | `/fixed` (atomic) | Invariant |
|---|---|---|---|---|
| Coupon | `POST /api/carts/{id}/coupons` | count the code on the cart, then insert the discount | insert guarded by `UNIQUE(cart_id, code)` | at most one discount per code and cart |
| Transfer | `POST /api/transfers` | read the balance, then debit and credit | `UPDATE ... WHERE balance >= ?` in a transaction, affected rows checked | the sender's balance never goes below 0 |
| 2FA attempts | `POST /api/2fa/verify` | read the attempt counter, compare, then increment | `UPDATE ... WHERE attempts < 3`, affected rows checked | at most 3 codes compared |
| Gift card | `POST /api/giftcards/{code}/redeem` | read `redeemed`, credit the balance, then mark it | `UPDATE ... WHERE redeemed = 0` in a transaction, affected rows checked | a card's value is credited once |

Both variants share request parsing and responses; only the store operation differs. Every response carries
`X-Arrival-Ns`, the server's clock (Unix nanoseconds) at the moment it started handling the request, so the spread of
arrival times of a race can be measured on the server side. It is read from a high-resolution counter
(QueryPerformanceCounter on Windows, the monotonic clock elsewhere): the plain wall clock on Windows advances in
steps of tens of microseconds and would give a whole burst the same value. API responses also carry `X-PhotoFinish-Variant`.

Other routes, per variant: `GET /api/me`, `POST /api/carts`, `GET /api/carts/{id}`, `GET /api/2fa/status`, and
`POST /api/reset` (no token), which restores the seed state of that variant. `GET /` lists everything; `GET /healthz`
answers `{"status":"ok"}`.

Demo users: `alice` (token `demo-alice`) and `bob` (token `demo-bob`), 100.00 each (money is integer cents), coupon
`WELCOME10` (10 percent), gift cards `GIFT-ALICE-50` and `GIFT-BOB-50` (50.00 each), 2FA code `482913` with a limit of
3 attempts. The examples write the demo tokens literally; real scenarios read secrets with `${env:NAME}`.

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `127.0.0.1:8443` | listen address; non-loopback addresses are refused without `--expose` |
| `--window` | `0s` | artificial pause between the check and the write in `/vuln` handlers, up to `2s` |
| `--expose` | off | allow a non-loopback address (isolated lab networks only) |
| `--quiet` | off | do not log requests |

Without `--window` the race is real but narrow, which is the case the `h2` engine is built for. The integration
tests run the examples with a 2ms window so that the result does not depend on a slow CI machine.

## Roadmap

The design, in Russian: [docs/DESIGN.ru.md](docs/DESIGN.ru.md).

| Milestone | Delivers | Done when |
|---|---|---|
| **M0** | **repository, CI, the demo shop in two variants** | **`photofinish demo` starts, tests are green** |
| M1 (partly done) | engines `h2` (single-packet), `h1` (last-byte sync), `burst`; the `probe` command | `h2` reliably catches the coupon race on `/vuln` (done); a benchmark measures the arrival spread of `h2` against `h1` and `burst` (not written yet; on loopback the hit rates of the three engines are similar) |
| **M2** | **scenarios, CEL invariants, trials, verdicts, JSON evidence** | **`photofinish run examples/*.yaml` gives the right verdicts on `/vuln` and `/fixed`** |
| M3 | SARIF, JUnit, HTML, Docker, GitHub Action | the Action fails a build against `/vuln` in a test repository |
| M4 | web UI (Scenarios, Editor, Run, Reports) and `photofinish serve` | a scenario is built and run from the UI; the timeline shows the trials |
| M5 | EN/RU documentation, screenshots, GIF, release v0.1.0, article | the release is published, a race lab is in WebSec-Lab |

Planned UI, the Run screen (a mockup, not implemented yet):

![Planned UI: the Run screen with trials, a per-stream timeline and the evaluated invariant](docs/mockup-run.png)

## Responsible use

PhotoFinish is for systems you own or are authorized to test. Race testing sends bursts of synchronized requests
and can change real state: balances, orders, coupons, account lockouts. Every scenario must list the hosts it may
contact, and a request budget caps the run. The demo shop is intentionally vulnerable: it binds to `127.0.0.1` by
default, refuses other addresses unless you pass `--expose`, keeps its state in memory and uses throwaway tokens
and a throwaway certificate.

[SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [CHANGELOG.md](CHANGELOG.md)

## License

[MIT](LICENSE)
