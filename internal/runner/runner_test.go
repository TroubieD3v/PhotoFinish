package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

// Secrets used by the masking tests. None of them may appear in a report.
const (
	envToken    = "env-token-7f3a9c"
	sessionVal  = "session-value-51d2e8"
	cookieVal   = "cookie-value-a8b7c6"
	passwordVal = "hunter2-password"
	apiKeyVal   = "apikey-0d9e8f7a"
)

// shop is a tiny HTTP target for the setup, check and reset steps. The race
// itself goes through the fake engine, which sets how many coupons applied.
type shop struct {
	srv     *httptest.Server
	applied atomic.Int64 // discounts the check reports
	resets  atomic.Int64
	carts   atomic.Int64
	checks  atomic.Int64
	total   atomic.Int64 // every request
	// cartStatus overrides the status of POST /carts when non-zero.
	cartStatus atomic.Int64
	// checkBody overrides the body of GET /carts/c1 when set.
	checkBody atomic.Value
}

func newShop(t *testing.T) *shop {
	t.Helper()
	s := &shop{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/reset", func(w http.ResponseWriter, r *http.Request) {
		s.resets.Add(1)
		s.applied.Store(0)
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("POST /api/carts", func(w http.ResponseWriter, r *http.Request) {
		s.carts.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: cookieVal, HttpOnly: true})
		w.Header().Set("Content-Type", "application/json")
		code := int(s.cartStatus.Load())
		if code == 0 {
			code = http.StatusCreated
		}
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"id":"c1","session":%q,"owner":{"api_key":%q}}`, sessionVal, apiKeyVal)
	})
	mux.HandleFunc("GET /api/carts/c1", func(w http.ResponseWriter, r *http.Request) {
		s.checks.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Auth-Token", r.Header.Get("Authorization"))
		if b, ok := s.checkBody.Load().(string); ok {
			w.Write([]byte(b))
			return
		}
		discounts := make([]string, s.applied.Load())
		for i := range discounts {
			discounts[i] = "WELCOME10"
		}
		// The echo field repeats the caller's Authorization header under a
		// key that is not sensitive: only the value-based masking hides it.
		json.NewEncoder(w).Encode(map[string]any{
			"discounts": discounts,
			"echo":      r.Header.Get("Authorization"),
			"password":  passwordVal,
		})
	})
	s.srv = httptest.NewServer(countAll(&s.total, mux))
	t.Cleanup(s.srv.Close)
	return s
}

func countAll(n *atomic.Int64, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h.ServeHTTP(w, r)
	})
}

func (s *shop) host() string {
	u, _ := url.Parse(s.srv.URL)
	return u.Host
}

// testScenario is a coupon scenario against sh with trials trials.
func testScenario(sh *shop, trials int) *scenario.Scenario {
	return &scenario.Scenario{
		Version: 1,
		Name:    "coupon-test",
		Path:    "testdata/coupon test.yaml",
		Target:  sh.srv.URL + "/api",
		Scope: scenario.Scope{
			AllowHosts: []string{sh.host()},
			Budget:     scenario.Budget{Requests: 1000, RPS: 1e6},
		},
		Identities: map[string]scenario.Identity{
			"alice": {Headers: map[string]string{"Authorization": "Bearer ${env:PF_RUNNER_TEST_TOKEN}"}},
		},
		Vars: scenario.Vars{"code": "WELCOME10"},
		Setup: []scenario.Step{
			{Request: "POST /reset"},
			{ID: "cart", As: "alice", Request: "POST /carts", ExpectStatus: []int{201}, Extract: map[string]string{"cart_id": "$.id"}},
		},
		Race: scenario.Race{
			Engine: engine.H2,
			Copies: 5,
			Request: &scenario.RaceRequest{Step: scenario.Step{
				As:  "alice",
				Raw: "POST /carts/{{cart_id}}/coupons HTTP/2\nContent-Type: application/json\n\n{\"code\":\"{{code}}\"}\n",
			}},
		},
		Check: &scenario.Check{
			Step:      scenario.Step{As: "alice", Request: "GET /carts/{{cart_id}}"},
			Invariant: "size(check.json.discounts) <= 1 && size(race.filter(r, r.status == 200)) <= 1",
			Explain:   "A single-use coupon must apply at most once per cart.",
		},
		Reset:  []scenario.Step{{Request: "POST /reset"}},
		Trials: trials,
	}
}

// trialPlan describes what the fake engine returns in one trial.
type trialPlan struct {
	ok      int    // responses with status 200 (the coupon applied this often)
	status  int    // status of the other responses, default 409
	err     string // Err on the last response (Status 0)
	early   bool   // mark the first response EarlyResponse
	runErr  error  // engine.Run error
	body    string // body of every response
	headers http.Header
}

// fakeEngine stands in for engine.Run. It enforces the guard like the real
// engines (Allow before dialing, Spend(copies+warmup) before sending).
type fakeEngine struct {
	t    *testing.T
	shop *shop
	plan func(call int) trialPlan

	mu    sync.Mutex
	calls int
	reqs  [][]engine.Request
	opts  []engine.Options
}

func installEngine(t *testing.T, sh *shop, plan func(call int) trialPlan) *fakeEngine {
	t.Helper()
	f := &fakeEngine{t: t, shop: sh, plan: plan}
	prev := runEngine
	runEngine = f.run
	t.Cleanup(func() { runEngine = prev })
	return f
}

func (f *fakeEngine) run(ctx context.Context, reqs []engine.Request, opts engine.Options) (*engine.Race, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.reqs = append(f.reqs, reqs)
	f.opts = append(f.opts, opts)
	f.mu.Unlock()

	if opts.Guard == nil {
		return nil, errors.New("no guard")
	}
	if err := opts.Guard.Allow(reqs[0].URL.Host); err != nil {
		return nil, err
	}
	if err := opts.Guard.Spend(len(reqs) + opts.Warmup); err != nil {
		return nil, err
	}
	p := f.plan(call)
	if p.runErr != nil {
		return nil, p.runErr
	}
	if f.shop != nil {
		f.shop.applied.Store(int64(p.ok))
	}
	kind := opts.Kind
	if kind == engine.Auto {
		kind = engine.H2
	}
	race := &engine.Race{Kind: kind, Target: "http://" + reqs[0].URL.Host, Connections: 1, StartedNs: 1}
	const base = int64(1_000_000_000)
	for i, req := range reqs {
		st := p.status
		if st == 0 {
			st = http.StatusConflict
		}
		if i < p.ok {
			st = http.StatusOK
		}
		res := engine.Result{
			Index: i, Label: req.Label, Proto: "HTTP/2.0", Status: st,
			Header:          p.headers,
			Body:            []byte(p.body),
			ReleasedNs:      base,
			FirstByteNs:     base + 100_000 + int64(i)*10_000,
			ServerArrivalNs: base + 50_000 + int64(i)*1_000,
		}
		if p.err != "" && i == len(reqs)-1 {
			res.Status, res.Err, res.FirstByteNs = 0, p.err, 0
		}
		if p.early && i == 0 {
			res.EarlyResponse = true
			res.FirstByteNs = base - 1
		}
		race.Results = append(race.Results, res)
	}
	race.FinishedNs = base + 1_000_000
	return race, nil
}

func (f *fakeEngine) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func always(p trialPlan) func(int) trialPlan { return func(int) trialPlan { return p } }

func mustRun(t *testing.T, s *scenario.Scenario, opts Options) *Report {
	t.Helper()
	rep, err := Run(context.Background(), s, opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return rep
}

func verdicts(rep *Report) string {
	var b strings.Builder
	for _, t := range rep.Trials {
		b.WriteString(string(t.Verdict)[:1])
	}
	return b.String()
}

func TestExitCode(t *testing.T) {
	for v, want := range map[Verdict]int{Held: 0, Violated: 1, Inconclusive: 2, Errored: 3, "": 3} {
		if got := ExitCode(v); got != want {
			t.Errorf("ExitCode(%q) = %d, want %d", v, got, want)
		}
	}
}

func TestHeld(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	f := installEngine(t, sh, always(trialPlan{ok: 1}))
	var out bytes.Buffer
	rep := mustRun(t, testScenario(sh, 4), Options{Stdout: &out, Version: "1.2.3"})

	if rep.Verdict != Held || ExitCode(rep.Verdict) != 0 {
		t.Fatalf("verdict %s, summary %q", rep.Verdict, rep.Summary)
	}
	if verdicts(rep) != "HHHH" {
		t.Errorf("trial verdicts %s", verdicts(rep))
	}
	for _, want := range []string{"not reproduced in 4 trials", "h2", "median response spread 0.04 ms", "not proof of absence"} {
		if !strings.Contains(rep.Summary, want) {
			t.Errorf("summary %q lacks %q", rep.Summary, want)
		}
	}
	if rep.Schema != Schema || rep.Tool != "photofinish 1.2.3" || rep.Scenario != "coupon-test" || rep.Copies != 5 || rep.Engine != engine.H2 {
		t.Errorf("header fields: %+v", rep)
	}
	if rep.Reproduce != "photofinish run 'testdata/coupon test.yaml' --engine h2 --trials 4 --copies 5" {
		t.Errorf("reproduce %q", rep.Reproduce)
	}
	st := rep.Stats
	if st.Planned != 4 || st.Ran != 4 || st.Held != 4 || st.Violated != 0 || st.Inconclusive != 0 || st.Skipped != 0 {
		t.Errorf("stats %+v", st)
	}
	// 2 setup + 5 race + 1 check + 1 reset per trial.
	if st.RequestsSpent != 4*9 {
		t.Errorf("requests spent %d, want %d", st.RequestsSpent, 4*9)
	}
	if got := int(sh.total.Load()); got != 4*4 {
		t.Errorf("shop saw %d step requests, want %d", got, 4*4)
	}
	if st.MedianResponseSpreadNs != 40_000 {
		t.Errorf("median response spread %d", st.MedianResponseSpreadNs)
	}
	if st.MedianServerArrivalSpreadNs == nil || *st.MedianServerArrivalSpreadNs != 4_000 {
		t.Errorf("median server arrival spread %v", st.MedianServerArrivalSpreadNs)
	}
	if f.callCount() != 4 {
		t.Errorf("engine called %d times", f.callCount())
	}
	reqs, opts := f.reqs[0], f.opts[0]
	if len(reqs) != 5 || reqs[0].Label != "copy 1" || reqs[4].Label != "copy 5" {
		t.Errorf("race requests %+v", reqs)
	}
	if got := reqs[2].URL.String(); got != sh.srv.URL+"/api/carts/c1/coupons" {
		t.Errorf("race URL %s", got)
	}
	if string(reqs[0].Body) != `{"code":"WELCOME10"}` || reqs[0].Header.Get("Authorization") != "Bearer "+envToken {
		t.Errorf("race request body %q header %v", reqs[0].Body, reqs[0].Header)
	}
	if opts.Kind != engine.H2 || opts.Gate != scenario.DefaultGate || opts.ArrivalHeader != scenario.DefaultArrivalHeader || opts.TLS == nil || opts.TLS.InsecureSkipVerify {
		t.Errorf("engine options %+v", opts)
	}
	tr := rep.Trials[0]
	if len(tr.Setup) != 2 || tr.Setup[1].ID != "cart" || tr.Setup[1].Status != 201 || tr.Check == nil || tr.Check.Status != 200 || len(tr.Reset) != 1 {
		t.Errorf("trial records %+v", tr)
	}
	if len(tr.Terms) != 2 || tr.Terms[0].Value != "1 <= 1" || tr.Terms[1].Value != "1 <= 1" {
		t.Errorf("terms %+v", tr.Terms)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || lines[2] != "trial 3/4: HELD (1 of 5 succeeded) spread 0.04ms" {
		t.Errorf("progress lines %q", lines)
	}
}

func TestViolatedRunsAllTrials(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, func(call int) trialPlan {
		if call == 2 || call == 4 {
			return trialPlan{ok: 3}
		}
		return trialPlan{ok: 1}
	})
	var out bytes.Buffer
	rep := mustRun(t, testScenario(sh, 5), Options{Stdout: &out})
	if rep.Verdict != Violated || ExitCode(rep.Verdict) != 1 {
		t.Fatalf("verdict %s, summary %q", rep.Verdict, rep.Summary)
	}
	if verdicts(rep) != "HVHVH" {
		t.Errorf("trial verdicts %s", verdicts(rep))
	}
	if !strings.HasPrefix(rep.Summary, "2 of 5 trials broke the rule (h2, median response spread") {
		t.Errorf("summary %q", rep.Summary)
	}
	v := rep.Trials[1]
	want := []string{
		"size(check.json.discounts) <= 1 was 3 <= 1",
		"size(race.filter(r, r.status == 200)) <= 1 was 3 <= 1",
	}
	if fmt.Sprint(v.Reasons) != fmt.Sprint(want) {
		t.Errorf("reasons %q, want %q", v.Reasons, want)
	}
	if v.Race == nil || v.Check == nil || len(v.Reset) != 1 {
		t.Error("a violated trial must keep its race, check and reset records")
	}
	if !strings.Contains(out.String(), "trial 2/5: VIOLATED (3 of 5 succeeded) spread 0.04ms\n") {
		t.Errorf("progress %q", out.String())
	}
}

func TestImperfectRaceIsInconclusive(t *testing.T) {
	// A broken invariant over a race in which a request got no response or
	// came back before the release does not show the race: INCONCLUSIVE,
	// with the failing terms kept as notes.
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 3, err: "stream reset", early: true}))
	rep := mustRun(t, testScenario(sh, 2), Options{})
	if rep.Verdict != Inconclusive || verdicts(rep) != "II" {
		t.Fatalf("verdict %s trials %s", rep.Verdict, verdicts(rep))
	}
	rs := rep.Trials[0].Reasons
	if len(rs) < 3 || rs[0] != "1 of 5 race requests got no response (stream reset)" ||
		!strings.HasPrefix(rs[1], "responses arrived before release") {
		t.Fatalf("reasons %q", rs)
	}
	if !strings.Contains(strings.Join(rs, "\n"), "note: failed over this imperfect race: size(check.json.discounts) <= 1 was 3 <= 1") {
		t.Errorf("reasons %q lack the failing term note", rs)
	}
}

func TestNoResponseIsNotAViolation(t *testing.T) {
	// The only reason the invariant fails is a request without a response.
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 0, err: "stream reset"}))
	s := testScenario(sh, 3)
	s.Check.Invariant = "race.all(r, r.status == 409)"
	rep := mustRun(t, s, Options{})
	if rep.Verdict != Inconclusive || verdicts(rep) != "III" || ExitCode(rep.Verdict) != 2 {
		t.Fatalf("verdict %s trials %s summary %q", rep.Verdict, verdicts(rep), rep.Summary)
	}
}

func TestInconclusiveRules(t *testing.T) {
	tests := []struct {
		name   string
		plan   trialPlan
		mutate func(*scenario.Scenario, *shop)
		reason string
	}{
		{name: "race error", plan: trialPlan{ok: 1, err: "timeout"}, reason: "1 of 5 race requests got no response (timeout)"},
		{name: "early response", plan: trialPlan{ok: 1, early: true},
			reason: "responses arrived before release: the endpoint may be static or the request was not held"},
		{name: "rate limited with Retry-After", plan: trialPlan{ok: 1, status: 429, headers: http.Header{"Retry-After": {"1"}}},
			reason: "rate limited: 4 of 5 race responses were 429"},
		{name: "rate limited with RateLimit header", plan: trialPlan{ok: 1, status: 429, headers: http.Header{"X-Ratelimit-Remaining": {"0"}}},
			reason: "rate limited: 4 of 5 race responses were 429"},
		{name: "every response 429", plan: trialPlan{ok: 0, status: 429}, reason: "rate limited: 5 of 5 race responses were 429"},
		{name: "plain 429", plan: trialPlan{ok: 1, status: 429}, reason: "rate limited: 4 of 5 race responses were 429"},
		{name: "every response 429 with expect_429", plan: trialPlan{ok: 0, status: 429},
			mutate: func(s *scenario.Scenario, _ *shop) { s.Race.Expect429 = true },
			reason: "rate limited: 5 of 5 race responses were 429"},
		{name: "Retry-After with expect_429", plan: trialPlan{ok: 1, status: 429, headers: http.Header{"Retry-After": {"1"}}},
			mutate: func(s *scenario.Scenario, _ *shop) { s.Race.Expect429 = true },
			reason: "rate limited: 4 of 5 race responses were 429"},
		{name: "setup expect_status", plan: trialPlan{ok: 1},
			mutate: func(_ *scenario.Scenario, sh *shop) { sh.cartStatus.Store(500) },
			reason: "setup step cart returned status 500, expected [201]"},
		{name: "invariant evaluation error", plan: trialPlan{ok: 1},
			mutate: func(_ *scenario.Scenario, sh *shop) { sh.checkBody.Store(`{"items":[]}`) },
			reason: "invariant could not be evaluated: no such key: discounts"},
		{name: "check expect_status", plan: trialPlan{ok: 1},
			mutate: func(s *scenario.Scenario, _ *shop) { s.Check.ExpectStatus = []int{204} },
			reason: "check request returned status 200, expected [204]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
			sh := newShop(t)
			f := installEngine(t, sh, always(tt.plan))
			s := testScenario(sh, 3)
			if tt.mutate != nil {
				tt.mutate(s, sh)
			}
			rep := mustRun(t, s, Options{})
			if rep.Verdict != Inconclusive || ExitCode(rep.Verdict) != 2 {
				t.Fatalf("verdict %s, summary %q", rep.Verdict, rep.Summary)
			}
			if verdicts(rep) != "III" {
				t.Errorf("trial verdicts %s", verdicts(rep))
			}
			if !strings.HasPrefix(rep.Trials[0].Reasons[0], tt.reason) {
				t.Errorf("reason %q, want prefix %q", rep.Trials[0].Reasons[0], tt.reason)
			}
			if !strings.HasPrefix(rep.Summary, "3 of 3 trials were inconclusive: "+tt.reason) {
				t.Errorf("summary %q", rep.Summary)
			}
			if strings.HasPrefix(tt.name, "setup") && f.callCount() != 0 {
				t.Errorf("race sent %d times after a failed setup", f.callCount())
			}
			if got := len(rep.Trials[0].Reset); got != 1 {
				t.Errorf("reset ran %d times, want 1 even for an inconclusive trial", got)
			}
		})
	}
}

func TestApplication429IsNotRateLimiting(t *testing.T) {
	// A lockout that answers 429 to the surplus guesses is the defence
	// under test, not a rate limiter in front of it, when the scenario
	// says so with race.expect_429.
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 1, status: 429}))
	s := testScenario(sh, 2)
	s.Race.Expect429 = true
	rep := mustRun(t, s, Options{})
	if rep.Verdict != Held || verdicts(rep) != "HH" {
		t.Fatalf("verdict %s trials %s summary %q", rep.Verdict, verdicts(rep), rep.Summary)
	}
	want := "note: 4 of 5 race responses were 429 without rate-limit headers; treated as application responses"
	if r := rep.Trials[0].Reasons; len(r) != 1 || r[0] != want {
		t.Errorf("reasons %q", r)
	}
}

func TestMostly429IsNotHeld(t *testing.T) {
	// Only one request of twenty reached the code under test: that is a
	// single request, not a race, and must not pass as HELD.
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 1, status: 429}))
	s := testScenario(sh, 5)
	s.Race.Copies = 20
	rep := mustRun(t, s, Options{})
	if rep.Verdict != Inconclusive || verdicts(rep) != "IIIII" {
		t.Fatalf("verdict %s trials %s summary %q", rep.Verdict, verdicts(rep), rep.Summary)
	}
	if !strings.HasPrefix(rep.Summary, "5 of 5 trials were inconclusive: rate limited: 19 of 20 race responses were 429") {
		t.Errorf("summary %q", rep.Summary)
	}
}

func TestInconclusiveThreshold(t *testing.T) {
	tests := []struct {
		name     string
		bad      map[int]bool
		verdict  Verdict
		summary  string
		verdicts string
	}{
		{name: "half", bad: map[int]bool{1: true, 3: true}, verdict: Inconclusive, verdicts: "IHIH",
			summary: "2 of 4 trials were inconclusive"},
		{name: "less than half", bad: map[int]bool{2: true}, verdict: Held, verdicts: "HIHH",
			summary: "not reproduced in 3 trials (1 more inconclusive)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
			sh := newShop(t)
			installEngine(t, sh, func(call int) trialPlan {
				return trialPlan{ok: 1, early: tt.bad[call]}
			})
			rep := mustRun(t, testScenario(sh, 4), Options{})
			if rep.Verdict != tt.verdict || verdicts(rep) != tt.verdicts || !strings.HasPrefix(rep.Summary, tt.summary) {
				t.Errorf("verdict %s trials %s summary %q", rep.Verdict, verdicts(rep), rep.Summary)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*scenario.Scenario, *shop)
		opts    Options
		plan    trialPlan
		summary string
		engine  bool // whether the engine may be called
	}{
		{name: "invalid scenario", mutate: func(s *scenario.Scenario, _ *shop) { s.Name = "Bad Name" },
			summary: "invalid scenario: "},
		{name: "invalid invariant", mutate: func(s *scenario.Scenario, _ *shop) { s.Check.Invariant = "size(race) <=" },
			summary: "check.invariant: "},
		{name: "non-bool invariant", mutate: func(s *scenario.Scenario, _ *shop) { s.Check.Invariant = "size(race)" },
			summary: "check.invariant: invariant must be a bool"},
		{name: "target out of scope", mutate: func(s *scenario.Scenario, _ *shop) { s.Scope.AllowHosts = []string{"example.com"} },
			summary: "invalid scenario: "},
		{name: "unknown engine", opts: Options{Engine: "h3"}, summary: `unknown engine "h3"`},
		{name: "too many copies", opts: Options{Copies: scenario.MaxCopies + 1}, summary: "a race must have between 1 and 1000 requests"},
		{name: "budget below one trial", mutate: func(s *scenario.Scenario, _ *shop) { s.Scope.Budget.Requests = 8 },
			summary: "scope.budget.requests is 8 but one trial needs 9 requests"},
		{name: "setup before the first race", mutate: func(s *scenario.Scenario, sh *shop) { sh.srv.Close() },
			summary: "setup step \"POST /reset\" failed before the first race"},
		{name: "first race fails", plan: trialPlan{runErr: errors.New("server did not negotiate h2")},
			summary: "first race failed: server did not negotiate h2", engine: true},
		{name: "missing env", mutate: func(s *scenario.Scenario, _ *shop) {
			s.Vars["token"] = "${env:PF_RUNNER_TEST_UNSET}"
		}, summary: "PF_RUNNER_TEST_UNSET"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
			sh := newShop(t)
			f := installEngine(t, sh, always(tt.plan))
			s := testScenario(sh, 3)
			if tt.mutate != nil {
				tt.mutate(s, sh)
			}
			rep := mustRun(t, s, tt.opts)
			if rep.Verdict != Errored || ExitCode(rep.Verdict) != 3 {
				t.Fatalf("verdict %s, summary %q", rep.Verdict, rep.Summary)
			}
			if !strings.Contains(rep.Summary, tt.summary) {
				t.Errorf("summary %q lacks %q", rep.Summary, tt.summary)
			}
			if !tt.engine && f.callCount() != 0 {
				t.Errorf("engine called %d times", f.callCount())
			}
			// A trial aborted by the fatal error is kept as evidence and
			// marked ERROR, never left without a verdict.
			if n := len(rep.Trials); n > 0 {
				last := rep.Trials[n-1]
				if last.Verdict != Errored || len(last.Reasons) == 0 || !strings.Contains(last.Reasons[0], tt.summary) {
					t.Errorf("aborted trial verdict %q reasons %q", last.Verdict, last.Reasons)
				}
				if rep.Stats.Errored != 1 || rep.Stats.Ran != n {
					t.Errorf("stats %+v", rep.Stats)
				}
			}
			if _, err := json.Marshal(rep); err != nil {
				t.Errorf("marshal: %v", err)
			}
		})
	}
}

func TestLaterRaceFailureIsInconclusive(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, func(call int) trialPlan {
		if call == 2 {
			return trialPlan{runErr: errors.New("connection reset")}
		}
		return trialPlan{ok: 1}
	})
	rep := mustRun(t, testScenario(sh, 3), Options{})
	if rep.Verdict != Held || verdicts(rep) != "HIH" {
		t.Fatalf("verdict %s trials %s", rep.Verdict, verdicts(rep))
	}
	if r := rep.Trials[1].Reasons; len(r) != 1 || r[0] != "race failed: connection reset" {
		t.Errorf("reasons %q", r)
	}
	if rep.Trials[1].Check != nil {
		t.Error("check must not run after a failed race")
	}
}

func TestOutOfScopeStepSendsNothing(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	f := installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 3)
	s.Reset = []scenario.Step{{Request: "POST http://203.0.113.7/reset"}}
	rep := mustRun(t, s, Options{})
	if rep.Verdict != Errored || !strings.Contains(rep.Summary, "203.0.113.7") {
		t.Fatalf("verdict %s summary %q", rep.Verdict, rep.Summary)
	}
	if n := sh.total.Load(); n != 0 || f.callCount() != 0 {
		t.Errorf("sent %d step requests and %d races for an out-of-scope scenario", n, f.callCount())
	}
}

func TestGuardDeniesEngine(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	var sent atomic.Int64
	prev := runEngine
	runEngine = func(ctx context.Context, reqs []engine.Request, opts engine.Options) (*engine.Race, error) {
		// An engine that dials a host the runner never saw (a warm-up
		// request elsewhere) must be stopped by the guard.
		if err := opts.Guard.Allow("evil.example:443"); err != nil {
			return nil, err
		}
		sent.Add(1)
		return &engine.Race{}, nil
	}
	t.Cleanup(func() { runEngine = prev })
	rep := mustRun(t, testScenario(sh, 3), Options{})
	if rep.Verdict != Errored || !strings.Contains(rep.Summary, `"evil.example:443" is not in scope`) {
		t.Fatalf("verdict %s summary %q", rep.Verdict, rep.Summary)
	}
	if sent.Load() != 0 || len(rep.Trials) != 1 {
		t.Errorf("sent %d, trials %d", sent.Load(), len(rep.Trials))
	}
}

func TestBudgetExhaustion(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	f := installEngine(t, sh, func(call int) trialPlan {
		if call == 2 {
			return trialPlan{ok: 2}
		}
		return trialPlan{ok: 1}
	})
	s := testScenario(sh, 10)
	s.Scope.Budget.Requests = 30 // 9 per trial: three trials fit
	rep := mustRun(t, s, Options{})
	if rep.Verdict != Violated || verdicts(rep) != "HVH" {
		t.Fatalf("verdict %s trials %s", rep.Verdict, verdicts(rep))
	}
	st := rep.Stats
	if st.Ran != 3 || st.Skipped != 7 || st.Planned != 10 || st.RequestsSpent != 27 {
		t.Errorf("stats %+v", st)
	}
	if f.callCount() != 3 {
		t.Errorf("engine called %d times", f.callCount())
	}
	if len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "request budget exhausted: 7 of 10 trials skipped") {
		t.Errorf("notes %q", rep.Notes)
	}
	if !strings.Contains(rep.Summary, "1 of 3 trials broke the rule") || !strings.HasSuffix(rep.Summary, "; 7 of 10 planned trials skipped") {
		t.Errorf("summary %q", rep.Summary)
	}
}

func TestBudgetCountsWarmup(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 4)
	s.Race.Warmup = 2
	s.Scope.Budget.Requests = 23 // 11 per trial on h2: two trials fit
	rep := mustRun(t, s, Options{})
	if rep.Stats.Ran != 2 || rep.Stats.RequestsSpent != 22 {
		t.Errorf("stats %+v", rep.Stats)
	}
}

func TestOptionsOverride(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	f := installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 10)
	s.Race.Engine = ""
	rep := mustRun(t, s, Options{Engine: engine.Burst, Trials: 2, Copies: 7, Insecure: true})
	if rep.Stats.Ran != 2 || rep.Copies != 7 || rep.Engine != engine.Burst {
		t.Errorf("ran %d copies %d engine %s", rep.Stats.Ran, rep.Copies, rep.Engine)
	}
	if len(f.reqs[0]) != 7 || f.opts[0].Kind != engine.Burst || !f.opts[0].TLS.InsecureSkipVerify {
		t.Errorf("engine got %d requests, options %+v", len(f.reqs[0]), f.opts[0])
	}
	if rep.Reproduce != "photofinish run 'testdata/coupon test.yaml' --engine burst --trials 2 --copies 7 --insecure" {
		t.Errorf("reproduce %q", rep.Reproduce)
	}
}

func TestAutoReportsResolvedEngine(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 1)
	s.Race.Engine = engine.Auto
	rep := mustRun(t, s, Options{})
	if rep.Engine != engine.H2 || !strings.Contains(rep.Reproduce, "--engine h2") {
		t.Errorf("engine %s reproduce %q", rep.Engine, rep.Reproduce)
	}
}

func TestMultiEndpointRace(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	f := installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 1)
	s.Race.Copies = 0
	s.Race.Request = nil
	s.Race.Requests = []scenario.RaceRequest{
		{Step: scenario.Step{As: "alice", Request: "POST /carts/{{cart_id}}/coupons"}, Copies: 2},
		{Step: scenario.Step{As: "alice", Request: "POST /carts/{{cart_id}}/checkout"}},
	}
	rep := mustRun(t, s, Options{})
	reqs := f.reqs[0]
	if rep.Copies != 3 || len(reqs) != 3 || reqs[1].Label != "request 1 copy 2" || reqs[2].Label != "request 2 copy 1" ||
		!strings.HasSuffix(reqs[2].URL.Path, "/checkout") {
		t.Errorf("copies %d requests %+v", rep.Copies, reqs)
	}
	if strings.Contains(rep.Reproduce, "--copies") {
		t.Errorf("reproduce %q must not flatten a multi-endpoint race into --copies", rep.Reproduce)
	}
}

func TestCancelledContext(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	installEngine(t, sh, func(call int) trialPlan {
		if call == 2 {
			cancel()
		}
		return trialPlan{ok: 1}
	})
	rep, err := Run(ctx, testScenario(sh, 5), Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if rep == nil || rep.Stats.Ran > 2 || rep.Stats.Skipped < 3 || len(rep.Notes) == 0 {
		t.Fatalf("partial report %+v", rep)
	}
}

func TestMasking(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	plan := trialPlan{
		ok: 3,
		body: fmt.Sprintf(`{"applied":true,"token":%q,"nested":[{"Password":%q}],"note":"auth was Bearer %s"}`,
			"race-token-c0ffee", passwordVal, envToken),
		headers: http.Header{
			"Set-Cookie":    {"sid=" + cookieVal + "; Path=/"},
			"X-Session-Id":  {sessionVal},
			"Authorization": {"Bearer " + envToken},
			"Content-Type":  {"application/json"},
		},
	}
	installEngine(t, sh, always(plan))
	s := testScenario(sh, 2)
	s.Vars["api"] = "${env:PF_RUNNER_TEST_TOKEN}"
	s.Check.Invariant = `size(check.json.discounts) <= 1 && check.json.echo != "Bearer " + vars.api && setup.cart.json.session != ""`
	rep := mustRun(t, s, Options{})
	if rep.Verdict != Violated {
		t.Fatalf("verdict %s summary %q", rep.Verdict, rep.Summary)
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{envToken, sessionVal, cookieVal, passwordVal, apiKeyVal, "race-token-c0ffee"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("report contains secret %q", secret)
		}
	}
	if !bytes.Contains(data, []byte(masked)) {
		t.Error("report has no masked values")
	}
	// What is not secret stays readable.
	tr := rep.Trials[0]
	res := tr.Race.Results[0]
	if res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Set-Cookie") != masked {
		t.Errorf("race header %v", res.Header)
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body, &body); err != nil || body["applied"] != true || body["token"] != masked {
		t.Errorf("race body %s (%v)", res.Body, err)
	}
	if tr.Check.Header.Get("X-Auth-Token") != masked {
		t.Errorf("check header %v", tr.Check.Header)
	}
	if !strings.Contains(tr.Setup[1].Body, `"id":"c1"`) {
		t.Errorf("setup body %q", tr.Setup[1].Body)
	}
	if tr.Terms[0].Value != "3 <= 1" {
		t.Errorf("term %+v", tr.Terms[0])
	}
}

func TestMaskingURLAndErrors(t *testing.T) {
	m := newMasker()
	m.addSecret("s3cr3t")
	sc := m.scrubber()
	if got := sc.url("https://h/p/s3cr3t?a=1&access_token=xyz&b=2#frag"); got != "https://h/p/[masked]?a=1&access_token=[masked]&b=2#frag" {
		t.Errorf("url %q", got)
	}
	if got := sc.str(`Post "https://h/?k=s3cr3t": EOF`); strings.Contains(got, "s3cr3t") {
		t.Errorf("error text %q", got)
	}
	if got := string(sc.body([]byte("plain s3cr3t text"))); got != "plain [masked] text" {
		t.Errorf("text body %q", got)
	}
	if got := string(sc.body([]byte(`{"n":12345678901234567890,"apiKey":1}`))); got != `{"apiKey":"[masked]","n":12345678901234567890}` {
		t.Errorf("json body %q", got)
	}
}
