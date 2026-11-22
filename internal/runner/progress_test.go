package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// recorder collects progress events.
type recorder struct{ events []Progress }

func (r *recorder) add(p Progress) { r.events = append(r.events, p) }

// phases renders the event sequence as "start trial:1 trial:2 done:HELD".
func (r *recorder) phases() string {
	var parts []string
	for _, p := range r.events {
		switch p.Phase {
		case PhaseTrial:
			n := 0
			if p.Trial != nil {
				n = p.Trial.Number
			}
			parts = append(parts, fmt.Sprintf("trial:%d", n))
		case PhaseDone:
			parts = append(parts, "done:"+string(p.Verdict))
		default:
			parts = append(parts, p.Phase)
		}
	}
	return strings.Join(parts, " ")
}

func TestProgressOrder(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, func(call int) trialPlan {
		if call == 2 {
			return trialPlan{ok: 3}
		}
		return trialPlan{ok: 1}
	})
	var rec recorder
	var withHook, without bytes.Buffer
	rep := mustRun(t, testScenario(sh, 3), Options{Stdout: &withHook, OnProgress: rec.add})

	if got, want := rec.phases(), "start trial:1 trial:2 trial:3 done:VIOLATED"; got != want {
		t.Fatalf("events %q, want %q", got, want)
	}
	for i, p := range rec.events {
		if p.Planned != 3 {
			t.Errorf("event %d planned %d", i, p.Planned)
		}
		wantDone := min(i, 3)
		if p.Done != wantDone {
			t.Errorf("event %d (%s) done %d, want %d", i, p.Phase, p.Done, wantDone)
		}
		if p.Phase != PhaseTrial && p.Trial != nil {
			t.Errorf("event %d (%s) carries a trial", i, p.Phase)
		}
		if p.Phase != PhaseDone && p.Verdict != "" {
			t.Errorf("event %d (%s) carries verdict %s", i, p.Phase, p.Verdict)
		}
	}
	if got := rec.events[2].Trial.Verdict; got != Violated {
		t.Errorf("trial 2 verdict %s", got)
	}
	if rec.events[4].Verdict != rep.Verdict {
		t.Errorf("done verdict %s, report %s", rec.events[4].Verdict, rep.Verdict)
	}

	// The text progress lines do not change with a callback installed.
	installEngine(t, sh, func(call int) trialPlan {
		if call == 2 {
			return trialPlan{ok: 3}
		}
		return trialPlan{ok: 1}
	})
	mustRun(t, testScenario(sh, 3), Options{Stdout: &without})
	if withHook.String() != without.String() {
		t.Errorf("progress lines changed:\n%s\nwant:\n%s", withHook.String(), without.String())
	}
}

func TestProgressJSON(t *testing.T) {
	data, err := json.Marshal(Progress{Phase: PhaseStart, Planned: 5})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != `{"phase":"start","planned":5,"done":0}` {
		t.Errorf("start event %s", got)
	}
	data, _ = json.Marshal(Progress{Phase: PhaseDone, Planned: 5, Done: 5, Verdict: Held})
	if got := string(data); got != `{"phase":"done","planned":5,"done":5,"verdict":"HELD"}` {
		t.Errorf("done event %s", got)
	}
}

func TestProgressMasked(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{
		ok:   3,
		body: fmt.Sprintf(`{"applied":true,"token":%q,"note":"auth was Bearer %s"}`, "race-token-c0ffee", envToken),
		headers: http.Header{
			"Set-Cookie":   {"sid=" + cookieVal + "; Path=/"},
			"X-Session-Id": {sessionVal},
			"Content-Type": {"application/json"},
		},
	}))
	var rec recorder
	rep := mustRun(t, testScenario(sh, 2), Options{OnProgress: rec.add})
	if got := rec.phases(); got != "start trial:1 trial:2 done:VIOLATED" {
		t.Fatalf("events %q", got)
	}
	data, err := json.Marshal(rec.events)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{envToken, sessionVal, cookieVal, passwordVal, apiKeyVal, "race-token-c0ffee"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("progress events contain secret %q", secret)
		}
	}
	if !bytes.Contains(data, []byte(masked)) {
		t.Error("progress events have no masked values")
	}
	// Every secret here is known by the end of the trial that shows it, so
	// the event trials are exactly the report trials.
	for i, p := range rec.events[1:3] {
		got, _ := json.Marshal(p.Trial)
		want, _ := json.Marshal(rep.Trials[i])
		if !bytes.Equal(got, want) {
			t.Errorf("trial %d event differs from the report:\n%s\nwant:\n%s", i+1, got, want)
		}
	}
}

func TestProgressTrialIsACopy(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 3, body: `{"applied":true}`, headers: http.Header{"Content-Type": {"application/json"}}}))
	rep := mustRun(t, testScenario(sh, 1), Options{OnProgress: func(p Progress) {
		if p.Trial == nil {
			return
		}
		tr := p.Trial
		tr.Verdict = Held
		tr.Reasons[0] = "changed"
		tr.Setup[0].Header.Set("X-Changed", "1")
		tr.Check.Header.Set("X-Changed", "1")
		*tr.Terms[0].Pass = true
		tr.Race.Results[0].Header.Set("X-Changed", "1")
		tr.Race.Results[0].Body[0] = 'X'
	}})
	tr := rep.Trials[0]
	if tr.Verdict != Violated || tr.Reasons[0] == "changed" {
		t.Errorf("trial changed by the callback: %s %q", tr.Verdict, tr.Reasons)
	}
	if tr.Setup[0].Header.Get("X-Changed") != "" || tr.Check.Header.Get("X-Changed") != "" ||
		tr.Race.Results[0].Header.Get("X-Changed") != "" {
		t.Error("headers changed by the callback")
	}
	if *tr.Terms[0].Pass || tr.Race.Results[0].Body[0] != '{' {
		t.Error("terms or bodies changed by the callback")
	}
}

func TestProgressInvalidScenario(t *testing.T) {
	sh := newShop(t)
	f := installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 3)
	s.Name = "Bad Name"
	var rec recorder
	rep := mustRun(t, s, Options{OnProgress: rec.add})
	if rep.Verdict != Errored || f.callCount() != 0 {
		t.Fatalf("verdict %s, engine calls %d", rep.Verdict, f.callCount())
	}
	if got := rec.phases(); got != "done:ERROR" {
		t.Errorf("events %q", got)
	}
	if p := rec.events[0]; p.Planned != 0 || p.Done != 0 {
		t.Errorf("done event %+v", p)
	}
}

func TestProgressAbortedTrial(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{runErr: errors.New("server did not negotiate h2")}))
	var rec recorder
	rep := mustRun(t, testScenario(sh, 3), Options{OnProgress: rec.add})
	if got := rec.phases(); got != "start trial:1 done:ERROR" {
		t.Fatalf("events %q", got)
	}
	p := rec.events[1]
	if p.Trial.Verdict != Errored || p.Done != 1 || p.Planned != 3 {
		t.Errorf("aborted trial event %+v", p)
	}
	if last := rec.events[2]; last.Done != len(rep.Trials) || last.Verdict != rep.Verdict {
		t.Errorf("done event %+v, report %s with %d trials", last, rep.Verdict, len(rep.Trials))
	}
}

func TestProgressCancelled(t *testing.T) {
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
	var rec recorder
	rep, err := Run(ctx, testScenario(sh, 5), Options{OnProgress: rec.add})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if len(rec.events) < 2 || rec.events[0].Phase != PhaseStart {
		t.Fatalf("events %q", rec.phases())
	}
	last := rec.events[len(rec.events)-1]
	if last.Phase != PhaseDone || last.Done != len(rep.Trials) || last.Verdict != rep.Verdict || last.Planned != 5 {
		t.Errorf("last event %+v, report %s with %d trials", last, rep.Verdict, len(rep.Trials))
	}
	if n := len(rec.events) - 2; n != len(rep.Trials) {
		t.Errorf("%d trial events for %d trials", n, len(rep.Trials))
	}
}
