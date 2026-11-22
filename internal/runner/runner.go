// Package runner runs a scenario: trials of setup, race, check and reset,
// a verdict per trial and for the run, under the scenario's scope and
// request budget, and a Report with every secret masked.
//
// A trial is VIOLATED when the invariant evaluated to false, HELD when it
// evaluated to true over a clean race, and INCONCLUSIVE when the trial
// cannot say either (a request got no response, responses came back before
// the release, the server rate limited the race, a setup step returned an
// unexpected status, the invariant could not be evaluated). Any of these
// makes the trial INCONCLUSIVE even when the invariant evaluated to false:
// a rule broken over a race that did not fully happen does not show the
// race. Every 429 in the race counts as rate limiting unless the scenario
// sets race.expect_429, which declares 429s without Retry-After or RateLimit
// headers to be the application's answer (a lockout); even then a race in
// which every response is 429 is rate limited. The run is VIOLATED if any
// trial was; otherwise INCONCLUSIVE if at least half of the trials were;
// otherwise HELD. ERROR is reserved for failures that prevent
// a fair run: an invalid scenario, a request out of scope, or a setup or
// race failure before the first race was sent.
package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

// Schema identifies the report format.
const Schema = "photofinish.report/v1"

// runEngine sends a race. Tests replace it to inject results.
var runEngine = engine.Run

// Verdict is the outcome of a trial or of a run.
type Verdict string

// Verdicts.
const (
	// Violated means the invariant was broken in at least one trial.
	Violated Verdict = "VIOLATED"
	// Held means the invariant held in the trials that could be judged.
	// It is not proof that the race does not exist.
	Held Verdict = "HELD"
	// Inconclusive means too many trials could not be judged.
	Inconclusive Verdict = "INCONCLUSIVE"
	// Errored means the run could not be made fairly at all.
	Errored Verdict = "ERROR"
)

// ExitCode returns the process exit code for a verdict: VIOLATED 1,
// HELD 0, INCONCLUSIVE 2, ERROR (and anything unknown) 3.
func ExitCode(v Verdict) int {
	switch v {
	case Held:
		return 0
	case Violated:
		return 1
	case Inconclusive:
		return 2
	default:
		return 3
	}
}

// Options override scenario settings for one run.
type Options struct {
	// Engine overrides race.engine; "" keeps the scenario's.
	Engine engine.Kind
	// Trials overrides trials; 0 keeps the scenario's.
	Trials int
	// Copies overrides the copy count of every race entry; 0 keeps the
	// scenario's.
	Copies int
	// Insecure skips TLS certificate verification even if the scenario
	// does not ask for it.
	Insecure bool
	// Stdout receives one progress line per trial; nil disables them.
	Stdout io.Writer
	// Version is the tool version written to the report; "" means "dev".
	Version string
}

// Trial is one setup-race-check-reset cycle.
type Trial struct {
	Number  int     `json:"number"`
	Verdict Verdict `json:"verdict"`
	// Reasons say why the trial is INCONCLUSIVE or ERROR, or list the
	// failing terms of a VIOLATED trial. Lines starting with "note: " add
	// context without changing the verdict (application 429s, terms that
	// failed in an inconclusive trial).
	Reasons []string     `json:"reasons,omitempty"`
	Setup   []StepRecord `json:"setup"`
	Race    *engine.Race `json:"race,omitempty"`
	Check   *StepRecord  `json:"check,omitempty"`
	Terms   []check.Term `json:"terms"`
	Reset   []StepRecord `json:"reset,omitempty"`
}

// Stats summarizes the trials of a run.
type Stats struct {
	// Planned is the number of trials the run was asked for.
	Planned int `json:"planned"`
	// Ran is the number of trials that ran; the verdict is computed over them.
	Ran          int `json:"ran"`
	Violated     int `json:"violated"`
	Held         int `json:"held"`
	Inconclusive int `json:"inconclusive"`
	// Errored counts trials aborted by the error that ended the run.
	Errored int `json:"errored,omitempty"`
	// Skipped trials did not run because the budget ran out or the run
	// was interrupted.
	Skipped int `json:"skipped,omitempty"`
	// MedianResponseSpreadNs is the median over races of the spread of
	// first response bytes (engine.Race.ResponseSpread).
	MedianResponseSpreadNs int64 `json:"median_response_spread_ns"`
	// MedianServerArrivalSpreadNs is the median over races of the spread of
	// server arrival times, nil when the target does not report them.
	MedianServerArrivalSpreadNs *int64 `json:"median_server_arrival_spread_ns,omitempty"`
	// RequestsSpent counts every request sent, warm-up included.
	RequestsSpent int `json:"requests_spent"`
}

// Report is the result of running one scenario.
type Report struct {
	// Schema is always the Schema constant.
	Schema string `json:"schema"`
	// Tool is "photofinish <version>".
	Tool string `json:"tool"`
	// Scenario is the scenario name, File the file it came from.
	Scenario string `json:"scenario"`
	File     string `json:"file"`
	Target   string `json:"target"`
	// Engine is the engine actually used (auto resolved after the first race).
	Engine engine.Kind `json:"engine"`
	// Copies is the number of requests in each race.
	Copies    int     `json:"copies"`
	Invariant string  `json:"invariant"`
	Explain   string  `json:"explain,omitempty"`
	Verdict   Verdict `json:"verdict"`
	// Summary is one honest sentence about the outcome, or the error for
	// an ERROR verdict.
	Summary string `json:"summary"`
	// Notes record run-level events such as skipped trials.
	Notes      []string  `json:"notes,omitempty"`
	Trials     []Trial   `json:"trials"`
	Stats      Stats     `json:"stats"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	// Reproduce is the command line that repeats the run.
	Reproduce string `json:"reproduce"`
}

// fatalError aborts the run with an ERROR verdict.
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

// fatalf returns a fatalError.
func fatalf(format string, args ...any) error {
	return &fatalError{fmt.Errorf(format, args...)}
}

// run holds the state of one Run call.
type run struct {
	s       *scenario.Scenario
	opts    Options
	prog    *check.Program
	guard   *guard
	mask    *masker
	client  *http.Client
	tls     *tls.Config
	kind    engine.Kind // requested engine
	used    engine.Kind // engine of the first race, "" before it
	trials  int
	entries []scenario.RaceRequest
	copies  int           // requests per race
	vars    scenario.Vars // initial variables, ${env:...} expanded
	raced   bool
}

// Run runs every trial of s and returns the report. Failures of the
// scenario itself come back as a Report with Verdict ERROR and a nil error;
// the error is non-nil only when s is nil or ctx ends the run early (the
// partial report is still returned).
func Run(ctx context.Context, s *scenario.Scenario, opts Options) (*Report, error) {
	if s == nil {
		return nil, errors.New("runner: nil scenario")
	}
	start := time.Now()
	rep := &Report{
		Schema:    Schema,
		Tool:      "photofinish " + valueOr(opts.Version, "dev"),
		Scenario:  s.Name,
		File:      s.Path,
		Target:    s.Target,
		StartedAt: start,
		Trials:    []Trial{},
	}
	if s.Check != nil {
		rep.Invariant, rep.Explain = s.Check.Invariant, s.Check.Explain
	}
	r, err := prepare(s, opts)
	if err != nil {
		rep.Engine = valueOr(opts.Engine, s.Race.EngineKind())
		rep.Verdict, rep.Summary = Errored, err.Error()
		rep.FinishedAt = time.Now()
		rep.Reproduce = reproduce(s, opts, rep.Engine, 0, 0)
		return rep, nil
	}
	defer r.client.CloseIdleConnections()
	rep.Engine, rep.Copies, rep.Stats.Planned = r.kind, r.copies, r.trials

	runErr := r.loop(ctx, rep)

	if r.used != "" {
		rep.Engine = r.used
	}
	rep.Stats.RequestsSpent = r.guard.Spent()
	rep.Stats.Skipped = r.trials - len(rep.Trials)
	r.finish(rep, runErr)
	rep.Reproduce = reproduce(s, opts, rep.Engine, r.trials, r.copies)
	rep.FinishedAt = time.Now()
	r.scrub(rep)
	if runErr != nil && !isFatal(runErr) && ctx.Err() != nil {
		return rep, ctx.Err()
	}
	return rep, nil
}

// isFatal reports whether err aborts the run with ERROR.
func isFatal(err error) bool {
	var f *fatalError
	return errors.As(err, &f)
}

// prepare validates s, applies opts and compiles the invariant.
func prepare(s *scenario.Scenario, opts Options) (*run, error) {
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("invalid scenario: %w", err)
	}
	if s.Check == nil || strings.TrimSpace(s.Check.Invariant) == "" {
		return nil, errors.New("invalid scenario: check.invariant is required")
	}
	prog, err := check.Compile(s.Check.Invariant)
	if err != nil {
		if s.InvariantLine > 0 {
			return nil, fmt.Errorf("check.invariant (line %d): %w", s.InvariantLine, err)
		}
		return nil, fmt.Errorf("check.invariant: %w", err)
	}
	if len(s.Scope.AllowHosts) == 0 {
		return nil, errors.New("invalid scenario: scope.allow_hosts is required")
	}
	r := &run{s: s, opts: opts, prog: prog, mask: newMasker()}
	r.kind = valueOr(opts.Engine, s.Race.EngineKind())
	switch r.kind {
	case engine.H2, engine.H1, engine.Burst, engine.Auto:
	default:
		return nil, fmt.Errorf("unknown engine %q (want h2, h1, burst or auto)", r.kind)
	}
	r.trials = s.TrialCount()
	if opts.Trials != 0 {
		r.trials = opts.Trials
	}
	if r.trials < 1 || r.trials > scenario.MaxTrials {
		return nil, fmt.Errorf("trials must be between 1 and %d, got %d", scenario.MaxTrials, r.trials)
	}
	if opts.Copies < 0 {
		return nil, fmt.Errorf("copies must be positive, got %d", opts.Copies)
	}
	r.entries = s.Race.Entries()
	if len(r.entries) == 0 {
		return nil, errors.New("invalid scenario: race.request or race.requests is required")
	}
	for i := range r.entries {
		if opts.Copies > 0 {
			r.entries[i].Copies = opts.Copies
		}
		r.copies += r.entries[i].Copies
	}
	if r.copies < 1 || r.copies > scenario.MaxCopies {
		return nil, fmt.Errorf("a race must have between 1 and %d requests, got %d", scenario.MaxCopies, r.copies)
	}
	r.guard = newGuard(s.Scope, s.Scope.Budget.RequestLimit(), s.Scope.Budget.RateLimit())
	r.tls = &tls.Config{MinVersion: tls.VersionTLS12}
	if s.TLS.Insecure || opts.Insecure {
		r.tls.InsecureSkipVerify = true // requested by the scenario or --insecure
	}
	r.client = newStepClient(r.tls)
	vars, secrets, err := s.InitialVars()
	if err != nil {
		return nil, err
	}
	r.vars = vars
	for _, v := range secrets {
		r.mask.addSecret(v)
	}
	for _, id := range s.Identities {
		for name := range id.Headers {
			r.mask.addHeader(name)
		}
	}
	if need := r.trialCost(); need > r.guard.limit {
		return nil, fmt.Errorf("scope.budget.requests is %d but one trial needs %d requests", r.guard.limit, need)
	}
	return r, nil
}

// trialCost is the number of requests one trial spends at most.
func (r *run) trialCost() int {
	n := len(r.s.Setup) + len(r.s.Reset) + r.copies + r.s.Race.Warmup
	kind := r.kind
	if r.used != "" {
		kind = r.used
	}
	if (kind == engine.H1 || kind == engine.Auto) && r.s.Race.Warmup > 0 {
		// h1 sends the warm-up on each of its connections.
		n += r.s.Race.Warmup * (r.copies - 1)
	}
	if r.s.Check.HasRequest() {
		n++
	}
	return n
}

// loop runs the trials, appending them to rep. It stops early on a fatal
// error, an exhausted budget or a cancelled context.
func (r *run) loop(ctx context.Context, rep *Report) error {
	for n := 1; n <= r.trials; n++ {
		if err := ctx.Err(); err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("interrupted: %d of %d trials skipped", r.trials-n+1, r.trials))
			return err
		}
		if need, left := r.trialCost(), r.guard.remaining(); need > left {
			rep.Notes = append(rep.Notes, fmt.Sprintf(
				"request budget exhausted: %d of %d trials skipped (a trial needs %d requests, %d of %d left)",
				r.trials-n+1, r.trials, need, left, r.guard.limit))
			return nil
		}
		t, err := r.trial(ctx, n)
		if err != nil {
			if isFatal(err) {
				// The aborted trial stays in the report as evidence of what
				// was sent, marked ERROR so that no count misses it.
				t.Verdict, t.Reasons = Errored, []string{err.Error()}
				rep.Trials = append(rep.Trials, t)
				return err
			}
			if errors.Is(err, errBudget) {
				rep.Notes = append(rep.Notes, fmt.Sprintf(
					"request budget exhausted during trial %d: it and %d later trials were not counted", n, r.trials-n))
				return nil
			}
			rep.Notes = append(rep.Notes, fmt.Sprintf("interrupted during trial %d: %d of %d trials skipped", n, r.trials-n+1, r.trials))
			return err
		}
		rep.Trials = append(rep.Trials, t)
		r.progress(t)
	}
	return nil
}

// trial runs one trial. A non-nil error means the trial did not complete:
// a fatalError, a budget error or a context error.
func (r *run) trial(ctx context.Context, n int) (Trial, error) {
	t := Trial{Number: n, Setup: []StepRecord{}, Terms: []check.Term{}}
	vars := r.vars.Clone()
	setup := map[string]*scenario.Response{}

	judged := false
	if reason, err := r.runSetup(ctx, &t, vars, setup); err != nil {
		return t, err
	} else if reason != "" {
		t.Verdict, t.Reasons = Inconclusive, []string{reason}
		judged = true
	}

	var race *engine.Race
	if !judged {
		var reason string
		var err error
		race, reason, err = r.runRace(ctx, vars)
		t.Race = race
		if err != nil {
			return t, err
		}
		if reason != "" {
			t.Verdict, t.Reasons = Inconclusive, []string{reason}
			judged = true
		}
	}

	var checkResp *scenario.Response
	if !judged && r.s.Check.HasRequest() {
		rec, resp, err := r.step(ctx, r.s.Check.Step, vars)
		rec.ID = valueOr(rec.ID, "check")
		t.Check = &rec
		switch {
		case err != nil:
			if f := r.stopping(ctx, err); f != nil {
				return t, f
			}
			t.Verdict, t.Reasons = Inconclusive, []string{"check request failed: " + err.Error()}
			judged = true
		case !statusOK(r.s.Check.Step, resp.Status):
			t.Verdict, t.Reasons = Inconclusive, []string{fmt.Sprintf(
				"check request returned status %d, expected %v", resp.Status, r.s.Check.ExpectStatus)}
			judged = true
		default:
			checkResp = resp
		}
	}

	if !judged {
		r.judge(&t, race, checkResp, setup, vars)
	}

	for _, st := range r.s.Reset {
		rec, _, err := r.step(ctx, st, vars)
		t.Reset = append(t.Reset, rec)
		if err != nil {
			if f := r.stopping(ctx, err); f != nil {
				return t, f
			}
		}
	}
	return t, nil
}

// stopping converts a step error into an error that ends the run: a scope
// denial is fatal, an exhausted budget or a cancelled context stops the
// trials. It returns nil for errors that only affect the current trial.
func (r *run) stopping(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, errScope):
		return &fatalError{err}
	case errors.Is(err, errBudget):
		return err
	case ctx.Err() != nil:
		return ctx.Err()
	}
	return nil
}

// runSetup runs the setup steps. It returns the reason that makes the trial
// INCONCLUSIVE, or an error that ends the run.
func (r *run) runSetup(ctx context.Context, t *Trial, vars scenario.Vars, setup map[string]*scenario.Response) (string, error) {
	for _, st := range r.s.Setup {
		rec, resp, err := r.step(ctx, st, vars)
		t.Setup = append(t.Setup, rec)
		if err != nil {
			if f := r.stopping(ctx, err); f != nil {
				return "", f
			}
			if !r.raced {
				return "", fatalf("setup step %s failed before the first race: %v", stepName(st), err)
			}
			return fmt.Sprintf("setup step %s failed: %v", stepName(st), err), nil
		}
		if !statusOK(st, resp.Status) {
			return fmt.Sprintf("setup step %s returned status %d, expected %v", stepName(st), resp.Status, st.ExpectStatus), nil
		}
		if st.ID != "" {
			setup[st.ID] = resp
		}
		names := make([]string, 0, len(st.Extract))
		for name := range st.Extract {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			v, err := scenario.Extract(st.Extract[name], resp)
			if err != nil {
				return fmt.Sprintf("setup step %s: extract %s: %v", stepName(st), name, err), nil
			}
			vars[name] = v
		}
	}
	return "", nil
}

// runRace builds the race requests and sends them. It returns the reason
// that makes the trial INCONCLUSIVE, or an error that ends the run.
func (r *run) runRace(ctx context.Context, vars scenario.Vars) (*engine.Race, string, error) {
	reqs := make([]engine.Request, 0, r.copies)
	for i, e := range r.entries {
		req, err := r.build(e.Step, vars)
		if err == nil {
			err = r.guard.Allow(req.URL.Host)
		}
		if err != nil {
			if errors.Is(err, errScope) || !r.raced {
				return nil, "", fatalf("race request: %v", err)
			}
			return nil, "race request: " + err.Error(), nil
		}
		for c := 1; c <= e.Copies; c++ {
			cp := req
			cp.Header = req.Header.Clone()
			cp.Body = slices.Clone(req.Body)
			cp.Label = fmt.Sprintf("copy %d", c)
			if len(r.entries) > 1 {
				cp.Label = fmt.Sprintf("request %d copy %d", i+1, c)
			}
			reqs = append(reqs, cp)
		}
	}
	race, err := runEngine(ctx, reqs, engine.Options{
		Kind:          r.kind,
		Warmup:        r.s.Race.Warmup,
		Gate:          r.s.Race.GateDuration(),
		TLS:           r.tls.Clone(),
		ArrivalHeader: r.s.Evidence.Header(),
		Guard:         r.guard,
	})
	denied, exhausted := r.guard.failures()
	switch {
	case denied != nil:
		return race, "", &fatalError{denied}
	case exhausted != nil:
		return race, "", exhausted
	case err != nil && ctx.Err() != nil:
		return race, "", ctx.Err()
	case err != nil && !r.raced:
		return race, "", fatalf("first race failed: %v", err)
	case err != nil:
		return race, "race failed: " + err.Error(), nil
	case race == nil:
		return nil, "race failed: the engine returned no results", nil
	}
	if !r.raced {
		r.raced, r.used = true, race.Kind
	}
	for i := range race.Results {
		r.mask.harvestHeader(race.Results[i].Header)
		r.mask.harvestJSON(race.Results[i].Body)
	}
	return race, "", nil
}

// raceProblems lists what makes a race unfit to judge the invariant either
// way, and notes on responses that are worth reporting but do not.
//
// Every 429 counts as rate limiting unless expect429 is set. Then only a
// 429 that says so (Retry-After or a RateLimit header) does, or a race in
// which every response is 429, since nothing reached the code under test;
// the other 429s are the application answering, for example a two-factor
// lockout that is the very defence being tested, and are only noted.
func raceProblems(race *engine.Race, expect429 bool) (problems, notes []string) {
	var failed, early, limited, plain429 int
	firstErr := ""
	for _, res := range race.Results {
		if res.Err != "" || res.Status == 0 {
			failed++
			if firstErr == "" {
				firstErr = valueOr(res.Err, "no response")
			}
		}
		if res.EarlyResponse {
			early++
		}
		if res.Status == http.StatusTooManyRequests {
			if rateLimitHeader(res.Header) {
				limited++
			} else {
				plain429++
			}
		}
	}
	n := len(race.Results)
	if !expect429 || limited+plain429 == n {
		limited, plain429 = limited+plain429, 0
	}
	if failed > 0 {
		problems = append(problems, fmt.Sprintf("%d of %d race requests got no response (%s)", failed, n, firstErr))
	}
	if early > 0 {
		problems = append(problems, fmt.Sprintf("responses arrived before release: the endpoint may be static or the request was not held (%d of %d)", early, n))
	}
	if limited > 0 {
		problems = append(problems, fmt.Sprintf("rate limited: %d of %d race responses were 429", limited, n))
	}
	if plain429 > 0 {
		notes = append(notes, fmt.Sprintf("%d of %d race responses were 429 without rate-limit headers; treated as application responses", plain429, n))
	}
	return problems, notes
}

// rateLimitHeader reports whether h carries a rate-limit signal.
func rateLimitHeader(h http.Header) bool {
	for name := range h {
		c := http.CanonicalHeaderKey(name)
		if c == "Retry-After" || strings.HasPrefix(c, "Ratelimit") || strings.HasPrefix(c, "X-Ratelimit") {
			return true
		}
	}
	return false
}

// judge evaluates the invariant and sets the trial verdict. An imperfect
// race (failed, early or rate limited responses) makes the trial
// INCONCLUSIVE whatever the invariant says: a broken rule over a race that
// did not fully happen does not show the race, and a holding rule proves
// nothing. Failing terms of such a trial are kept as notes.
func (r *run) judge(t *Trial, race *engine.Race, checkResp *scenario.Response, setup map[string]*scenario.Response, vars scenario.Vars) {
	in := check.Input{
		Check: checkResp, Setup: setup, Vars: vars,
		Redact:    r.mask.scrubber().str,
		Sensitive: sensitiveKey.MatchString,
	}
	in.Race = make([]scenario.Response, len(race.Results))
	in.RaceErr = make([]string, len(race.Results))
	for _, res := range race.Results {
		if res.Index < 0 || res.Index >= len(in.Race) {
			continue
		}
		in.Race[res.Index] = scenario.Response{Status: res.Status, Header: res.Header, Body: res.Body}
		in.RaceErr[res.Index] = res.Err
	}
	res := r.prog.Eval(in)
	t.Terms = res.Terms
	problems, notes := raceProblems(race, r.s.Race.Expect429)
	switch {
	case res.Err != "":
		t.Verdict = Inconclusive
		t.Reasons = append([]string{"invariant could not be evaluated: " + res.Err}, problems...)
	case len(problems) > 0:
		t.Verdict, t.Reasons = Inconclusive, problems
		if !res.Holds {
			for _, f := range failingTerms(res.Terms) {
				t.Reasons = append(t.Reasons, "note: failed over this imperfect race: "+f)
			}
		}
	case !res.Holds:
		t.Verdict = Violated
		t.Reasons = failingTerms(res.Terms)
		for _, n := range notes {
			t.Reasons = append(t.Reasons, "note: "+n)
		}
	default:
		t.Verdict = Held
		for _, n := range notes {
			t.Reasons = append(t.Reasons, "note: "+n)
		}
	}
	if t.Terms == nil {
		t.Terms = []check.Term{}
	}
}

// failingTerms renders the terms that did not pass, or all terms when none
// failed on its own (an invariant whose top level is not an && chain).
func failingTerms(terms []check.Term) []string {
	var out []string
	for _, tm := range terms {
		if tm.Pass == nil || !*tm.Pass {
			out = append(out, tm.Expr+" was "+tm.Value)
		}
	}
	if len(out) == 0 {
		for _, tm := range terms {
			out = append(out, tm.Expr+" was "+tm.Value)
		}
	}
	return out
}

// progress prints one line for a finished trial.
func (r *run) progress(t Trial) {
	if r.opts.Stdout == nil {
		return
	}
	line := fmt.Sprintf("trial %d/%d: %s", t.Number, r.trials, t.Verdict)
	if t.Race != nil {
		ok := 0
		for _, res := range t.Race.Results {
			if res.Status >= 200 && res.Status < 300 {
				ok++
			}
		}
		line += fmt.Sprintf(" (%d of %d succeeded) spread %s", ok, len(t.Race.Results), msCompact(t.Race.ResponseSpread()))
	}
	if t.Verdict == Inconclusive && len(t.Reasons) > 0 {
		line += ": " + r.mask.scrubber().str(t.Reasons[0])
	}
	fmt.Fprintln(r.opts.Stdout, line)
}

// finish sets the counts, medians, verdict and summary of rep.
func (r *run) finish(rep *Report, runErr error) {
	st := &rep.Stats
	st.Ran = len(rep.Trials)
	var spreads, arrivals []int64
	for _, t := range rep.Trials {
		switch t.Verdict {
		case Violated:
			st.Violated++
		case Held:
			st.Held++
		case Inconclusive:
			st.Inconclusive++
		case Errored:
			st.Errored++
		}
		if t.Race != nil {
			spreads = append(spreads, t.Race.ResponseSpread().Nanoseconds())
			if d, ok := t.Race.ServerArrivalSpread(); ok {
				arrivals = append(arrivals, d.Nanoseconds())
			}
		}
	}
	st.MedianResponseSpreadNs = median(spreads)
	if len(arrivals) > 0 {
		m := median(arrivals)
		st.MedianServerArrivalSpreadNs = &m
	}

	if isFatal(runErr) {
		// Trials that did run stay in the report as evidence, but a run
		// that broke scope or never got a race off is not judged.
		rep.Verdict, rep.Summary = Errored, runErr.Error()
		return
	}
	evidence := fmt.Sprintf("%s, median response spread %s", rep.Engine, msSpaced(time.Duration(st.MedianResponseSpreadNs)))
	switch {
	case st.Violated > 0:
		rep.Verdict = Violated
		rep.Summary = fmt.Sprintf("%d of %d trials broke the rule (%s)", st.Violated, st.Ran, evidence)
	case st.Ran == 0:
		rep.Verdict = Inconclusive
		rep.Summary = "no trial ran"
	case 2*st.Inconclusive >= st.Ran:
		rep.Verdict = Inconclusive
		rep.Summary = fmt.Sprintf("%d of %d trials were inconclusive: %s", st.Inconclusive, st.Ran, commonReason(rep.Trials))
	default:
		rep.Verdict = Held
		judged := fmt.Sprintf("%d trials", st.Held)
		if st.Inconclusive > 0 {
			judged += fmt.Sprintf(" (%d more inconclusive)", st.Inconclusive)
		}
		rep.Summary = fmt.Sprintf("not reproduced in %s (%s); this is not proof of absence", judged, evidence)
	}
	if st.Skipped > 0 {
		rep.Summary += fmt.Sprintf("; %d of %d planned trials skipped", st.Skipped, st.Planned)
	}
}

// commonReason returns the most frequent first reason of the inconclusive
// trials (the earliest one on ties).
func commonReason(trials []Trial) string {
	count := map[string]int{}
	best, bestN := "", 0
	for _, t := range trials {
		if t.Verdict != Inconclusive || len(t.Reasons) == 0 {
			continue
		}
		reason := t.Reasons[0]
		count[reason]++
		if count[reason] > bestN {
			best, bestN = reason, count[reason]
		}
	}
	return best
}

// scrub masks every secret in rep.
func (r *run) scrub(rep *Report) {
	sc := r.mask.scrubber()
	rep.Summary = sc.str(rep.Summary)
	sc.strs(rep.Notes)
	rep.Target = sc.url(rep.Target)
	steps := func(recs []StepRecord) {
		for i := range recs {
			scrubStep(sc, &recs[i])
		}
	}
	for i := range rep.Trials {
		t := &rep.Trials[i]
		sc.strs(t.Reasons)
		steps(t.Setup)
		steps(t.Reset)
		if t.Check != nil {
			scrubStep(sc, t.Check)
		}
		for j := range t.Terms {
			t.Terms[j].Expr = sc.str(t.Terms[j].Expr)
			t.Terms[j].Value = sc.str(t.Terms[j].Value)
		}
		if t.Race != nil {
			t.Race.Target = sc.url(t.Race.Target)
			sc.strs(t.Race.Notes)
			for j := range t.Race.Results {
				res := &t.Race.Results[j]
				res.Label = sc.str(res.Label)
				res.Header = sc.header(res.Header)
				res.Body = sc.body(res.Body)
				res.Err = sc.str(res.Err)
			}
		}
	}
}

// scrubStep masks one step record.
func scrubStep(sc *scrubber, rec *StepRecord) {
	rec.URL = sc.url(rec.URL)
	rec.Header = sc.header(rec.Header)
	rec.Body = string(sc.body([]byte(rec.Body)))
	rec.Err = sc.str(rec.Err)
}

// reproduce returns the command line that repeats the run.
func reproduce(s *scenario.Scenario, opts Options, kind engine.Kind, trials, copies int) string {
	file := valueOr(s.Path, s.Name+".yaml")
	var b strings.Builder
	b.WriteString("photofinish run " + shellQuote(file) + " --engine " + string(kind))
	if trials > 0 {
		fmt.Fprintf(&b, " --trials %d", trials)
	}
	if opts.Copies > 0 {
		fmt.Fprintf(&b, " --copies %d", opts.Copies)
	} else if copies > 0 && s.Race.Request != nil {
		fmt.Fprintf(&b, " --copies %d", copies)
	}
	if opts.Insecure {
		b.WriteString(" --insecure")
	}
	return b.String()
}

// shellQuote quotes s for a POSIX shell when it contains special characters.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// median returns the median of v, 0 if v is empty.
func median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return s[mid-1] + (s[mid]-s[mid-1])/2
}

// msSpaced formats d in milliseconds for summaries: "0.41 ms".
func msSpaced(d time.Duration) string {
	return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
}

// msCompact formats d in milliseconds for progress lines: "0.41ms".
func msCompact(d time.Duration) string {
	return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
}

// valueOr returns v, or def when v is the zero value.
func valueOr[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
