package report

import (
	"net/http"
	"strconv"
	"time"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
)

// The fixture: four reports with fixed times and versions, one per verdict.

var (
	fixtureStart = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	pass, fail   = ptr(true), ptr(false)
)

func ptr[T any](v T) *T { return &v }

// us is a number of microseconds in nanoseconds.
func us(n int64) int64 { return n * int64(time.Microsecond) }

// race builds a race released at offset (from fixtureStart) with one result
// per status. firstByte and arrival are microseconds after the release
// (arrival nil: the target does not report arrival times). A status of 0
// means no response.
func race(kind engine.Kind, offset time.Duration, statuses []int, firstByte, arrival []int64) *engine.Race {
	release := fixtureStart.Add(offset).UnixNano()
	r := &engine.Race{
		Kind:        kind,
		Target:      "https://127.0.0.1:8443",
		ALPN:        "h2",
		TLSVersion:  "TLS 1.3",
		Connections: 1,
		Warmup:      1,
		Release:     engine.Release{Writes: 1, Bytes: 40 * len(statuses)},
		StartedNs:   release - int64(120*time.Millisecond),
		FinishedNs:  release + int64(5*time.Millisecond),
	}
	if kind == engine.H1 {
		r.ALPN, r.Connections = "http/1.1", len(statuses)
		r.Release = engine.Release{Writes: len(statuses), Bytes: len(statuses), SpreadNs: us(12)}
	}
	for i, st := range statuses {
		res := engine.Result{
			Index:      i,
			Label:      "copy " + strconv.Itoa(i+1),
			Proto:      "HTTP/2.0",
			Status:     st,
			PreSentNs:  release - int64(100*time.Millisecond),
			ReleasedNs: release,
		}
		if kind == engine.H2 {
			res.Stream = uint32(2*i + 1)
		} else {
			res.Proto, res.Conn = "HTTP/1.1", i
			res.ReleasedNs = release + us(int64(2*i))
		}
		if st != 0 {
			res.FirstByteNs = release + us(firstByte[i])
			res.DoneNs = res.FirstByteNs + us(30)
			res.Header = http.Header{"Content-Type": {"application/json"}}
		} else {
			res.Err = "stream reset by peer"
		}
		if arrival != nil && st != 0 {
			res.ServerArrivalNs = release + us(arrival[i])
		}
		r.Results = append(r.Results, res)
	}
	return r
}

// step builds a step record.
func step(id, method, url string, status int, body string, d time.Duration) runner.StepRecord {
	return runner.StepRecord{ID: id, Method: method, URL: url, Status: status, Body: body, DurationNs: int64(d)}
}

func fixture() []*runner.Report {
	const couponInvariant = "size(check.json.discounts) <= 1 &&\nsize(race.filter(r, r.status == 200)) <= 1\n"
	couponSetup := []runner.StepRecord{
		step("reset", "POST", "https://127.0.0.1:8443/vuln/api/reset", 200, `{"ok":true}`, 3*time.Millisecond),
		step("cart", "POST", "https://127.0.0.1:8443/vuln/api/carts", 201, `{"id":"c_81f2"}`, 2*time.Millisecond),
	}
	cartBody := `{"id":"c_81f2","total":7.29,"discounts":[{"code":"WELCOME10","amount":0.81},` +
		`{"code":"WELCOME10","amount":0.81},{"code":"WELCOME10","amount":0.81}],` +
		`"note":"<script>alert(1)</script> & \"quoted\""}`
	medianArrival := us(36)

	violated := &runner.Report{
		Schema:    runner.Schema,
		Tool:      "photofinish 0.3.0-test",
		Scenario:  "coupon-vuln",
		File:      "testdata/scenarios/coupon-vuln.yaml",
		Target:    "https://127.0.0.1:8443/vuln/api",
		Engine:    engine.H2,
		Copies:    6,
		Invariant: couponInvariant,
		Explain:   "A single-use coupon must apply at most once per cart.\n",
		Verdict:   runner.Violated,
		Summary:   "1 of 3 trials broke the rule (h2, median response spread 0.32 ms)",
		Trials: []runner.Trial{
			{
				Number:  1,
				Verdict: runner.Violated,
				Reasons: []string{
					"size(check.json.discounts) <= 1 was 3 <= 1",
					"size(race.filter(r, r.status == 200)) <= 1 was 3 <= 1",
					"note: 1 of 6 race responses were 429 without rate-limit headers; treated as application responses",
				},
				Setup: couponSetup,
				Race: race(engine.H2, 200*time.Millisecond, []int{200, 409, 200, 429, 200, 409},
					[]int64{410, 520, 380, 610, 450, 700}, []int64{20, 22, 25, 31, 36, 58}),
				Check: ptr(step("", "GET", "https://127.0.0.1:8443/vuln/api/carts/c_81f2", 200, cartBody, 2*time.Millisecond)),
				Terms: []check.Term{
					{Expr: "size(check.json.discounts) <= 1", Value: "3 <= 1", Pass: fail},
					{Expr: "size(race.filter(r, r.status == 200)) <= 1", Value: "3 <= 1", Pass: fail},
				},
			},
			{
				Number:  2,
				Verdict: runner.Held,
				Setup:   couponSetup,
				Race: race(engine.H2, 600*time.Millisecond, []int{409, 200, 409, 409, 409, 409},
					[]int64{400, 330, 520, 470, 650, 610}, []int64{18, 20, 29, 33, 35, 40}),
				Check: ptr(step("", "GET", "https://127.0.0.1:8443/vuln/api/carts/c_81f3", 200,
					`{"id":"c_81f3","discounts":[{"code":"WELCOME10","amount":0.81}]}`, 2*time.Millisecond)),
				Terms: []check.Term{
					{Expr: "size(check.json.discounts) <= 1", Value: "1 <= 1", Pass: pass},
					{Expr: "size(race.filter(r, r.status == 200)) <= 1", Value: "1 <= 1", Pass: pass},
				},
			},
			{
				Number:  3,
				Verdict: runner.Inconclusive,
				Reasons: []string{
					"1 of 6 race requests got no response (stream reset by peer)",
					"note: failed over this imperfect race: size(check.json.discounts) <= 1 was 2 <= 1",
				},
				Setup: couponSetup,
				Race: race(engine.H2, time.Second, []int{200, 0, 200, 409, 409, 409},
					[]int64{300, 0, 420, 510, 560, 590}, []int64{15, 0, 19, 27, 30, 52}),
				Check: ptr(step("", "GET", "https://127.0.0.1:8443/vuln/api/carts/c_81f4", 200,
					`{"id":"c_81f4","discounts":[{},{}]}`, 2*time.Millisecond)),
				Terms: []check.Term{
					{Expr: "size(check.json.discounts) <= 1", Value: "2 <= 1", Pass: fail},
					{Expr: "size(race.filter(r, r.status == 200)) <= 1", Value: "2 <= 1", Pass: fail},
				},
			},
		},
		Stats: runner.Stats{
			Planned: 3, Ran: 3, Violated: 1, Held: 1, Inconclusive: 1,
			MedianResponseSpreadNs:      us(320),
			MedianServerArrivalSpreadNs: &medianArrival,
			RequestsSpent:               33,
		},
		StartedAt:  fixtureStart,
		FinishedAt: fixtureStart.Add(1500 * time.Millisecond),
		Reproduce:  "photofinish run testdata/scenarios/coupon-vuln.yaml --engine h2 --trials 3",
	}

	held := &runner.Report{
		Schema:    runner.Schema,
		Tool:      "photofinish 0.3.0-test",
		Scenario:  "coupon-fixed",
		File:      "testdata/scenarios/coupon-fixed.yaml",
		Target:    "http://127.0.0.1:8080/fixed/api",
		Engine:    engine.H1,
		Copies:    4,
		Invariant: "size(check.json.discounts) <= 1",
		Verdict:   runner.Held,
		Summary:   "not reproduced in 2 trials (h1, median response spread 0.21 ms); this is not proof of absence",
		Trials: []runner.Trial{
			{
				Number:  1,
				Verdict: runner.Held,
				Race:    race(engine.H1, 2*time.Second, []int{200, 409, 409, 409}, []int64{120, 260, 300, 330}, nil),
				Check:   ptr(step("", "GET", "http://127.0.0.1:8080/fixed/api/carts/c_9", 200, "plain text body", time.Millisecond)),
				Terms:   []check.Term{{Expr: "size(check.json.discounts) <= 1", Value: "1 <= 1", Pass: pass}},
			},
			{
				Number:  2,
				Verdict: runner.Held,
				Race:    race(engine.H1, 3*time.Second, []int{409, 200, 409, 409}, []int64{180, 140, 350, 360}, nil),
				Check:   ptr(step("", "GET", "http://127.0.0.1:8080/fixed/api/carts/c_10", 200, `{"discounts":[1]}`, time.Millisecond)),
				Terms:   []check.Term{{Expr: "size(check.json.discounts) <= 1", Value: "1 <= 1", Pass: pass}},
			},
		},
		Stats: runner.Stats{
			Planned: 2, Ran: 2, Held: 2,
			MedianResponseSpreadNs: us(210),
			RequestsSpent:          10,
		},
		StartedAt:  fixtureStart.Add(2 * time.Second),
		FinishedAt: fixtureStart.Add(3200 * time.Millisecond),
		Reproduce:  "photofinish run testdata/scenarios/coupon-fixed.yaml --engine h1 --trials 2",
	}

	inconclusive := &runner.Report{
		Schema:    runner.Schema,
		Tool:      "photofinish 0.3.0-test",
		Scenario:  "transfer-limited",
		File:      "testdata/scenarios/transfer-limited.yaml",
		Target:    "https://127.0.0.1:8443/vuln/api",
		Engine:    engine.H2,
		Copies:    6,
		Invariant: "check.json.balance_cents >= 0 &&\nsize(race.filter(r, r.status == 200)) <= 1\n",
		Explain:   "A balance must never go below zero; 100.00 covers one 60.00 transfer.",
		Verdict:   runner.Inconclusive,
		Summary:   "2 of 2 trials were inconclusive: rate limited: 4 of 6 race responses were 429",
		Notes:     []string{"1 of 3 planned trials skipped: the request budget ran out"},
		Trials: []runner.Trial{
			{
				Number:  1,
				Verdict: runner.Inconclusive,
				Reasons: []string{"rate limited: 4 of 6 race responses were 429"},
				Race: race(engine.H2, 4*time.Second, []int{200, 429, 429, 429, 429, 409},
					[]int64{350, 90, 95, 110, 120, 480}, nil),
				Check: ptr(step("", "GET", "https://127.0.0.1:8443/vuln/api/me", 200, `{"balance_cents":4000}`, time.Millisecond)),
				Terms: []check.Term{
					{Expr: "check.json.balance_cents >= 0", Value: "4000 >= 0", Pass: pass},
					{Expr: "size(race.filter(r, r.status == 200)) <= 1", Value: "1 <= 1", Pass: pass},
				},
			},
			{
				Number:  2,
				Verdict: runner.Inconclusive,
				Reasons: []string{
					"rate limited: 4 of 6 race responses were 429",
					"invariant could not be evaluated: no such key: balance_cents",
				},
				Race: race(engine.H2, 5*time.Second, []int{429, 429, 200, 429, 429, 409},
					[]int64{80, 85, 300, 100, 105, 420}, nil),
				Check: ptr(step("", "GET", "https://127.0.0.1:8443/vuln/api/me", 503, "", time.Millisecond)),
				Terms: []check.Term{
					{Expr: "check.json.balance_cents >= 0", Value: "error: no such key: balance_cents"},
					{Expr: "size(race.filter(r, r.status == 200)) <= 1", Value: "1 <= 1", Pass: pass},
				},
			},
		},
		Stats: runner.Stats{
			Planned: 3, Ran: 2, Inconclusive: 2, Skipped: 1,
			MedianResponseSpreadNs: us(375),
			RequestsSpent:          14,
		},
		StartedAt:  fixtureStart.Add(4 * time.Second),
		FinishedAt: fixtureStart.Add(5100 * time.Millisecond),
		Reproduce:  "photofinish run testdata/scenarios/transfer-limited.yaml --engine h2 --trials 3",
	}

	errored := &runner.Report{
		Schema:  runner.Schema,
		Tool:    "photofinish 0.3.0-test",
		File:    "testdata/scenarios/broken.yaml",
		Engine:  engine.Auto,
		Verdict: runner.Errored,
		Summary: "invalid scenario: testdata/scenarios/broken.yaml:7: race.copies: must be between 1 and 1000, got 0\n" +
			"testdata/scenarios/broken.yaml:12: check.invariant: required <for every scenario> & \"quoted\"",
		Trials:     []runner.Trial{},
		StartedAt:  fixtureStart.Add(6 * time.Second),
		FinishedAt: fixtureStart.Add(6*time.Second + 2*time.Millisecond),
		Reproduce:  "photofinish run testdata/scenarios/broken.yaml --engine auto",
	}
	return []*runner.Report{violated, held, inconclusive, errored}
}
