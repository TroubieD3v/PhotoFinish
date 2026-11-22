package server

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/examples"
	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/store"
)

// demoTrials is the number of trials of the runs against the demo shop.
const demoTrials = 3

// startDemo starts the server's demo shop and returns its host:port.
func (e *env) startDemo() string {
	e.t.Helper()
	r := e.post("/api/demo/start", nil)
	want(e.t, r, http.StatusOK)
	var st demoStatus
	r.json(e.t, &st)
	return strings.TrimPrefix(st.URL, "https://")
}

// copyExampleTo writes an embedded example into the workspace with its
// target pointed at addr.
func (e *env) copyExampleTo(name, addr string) string {
	e.t.Helper()
	data, err := fs.ReadFile(examples.FS, name+".yaml")
	if err != nil {
		e.t.Fatal(err)
	}
	p := "examples/" + name + ".yaml"
	e.write(p, strings.ReplaceAll(string(data), "127.0.0.1:8443", addr))
	return p
}

// progressOf decodes the progress events of a stream and checks that it
// ends with exactly one "done" event.
func progressOf(t *testing.T, events []sseEvent) ([]runner.Progress, doneEvent) {
	t.Helper()
	if len(events) == 0 || events[len(events)-1].name != "done" {
		t.Fatalf("stream does not end with done: %+v", events)
	}
	var out []runner.Progress
	for _, ev := range events[:len(events)-1] {
		if ev.name != "progress" {
			t.Fatalf("unexpected event %q", ev.name)
		}
		var p runner.Progress
		if err := json.Unmarshal([]byte(ev.data), &p); err != nil {
			t.Fatalf("progress %s: %v", ev.data, err)
		}
		out = append(out, p)
	}
	var d doneEvent
	if err := json.Unmarshal([]byte(events[len(events)-1].data), &d); err != nil {
		t.Fatal(err)
	}
	return out, d
}

// phases formats progress events as "start trial:1 trial:2 done:HELD".
func phases(ps []runner.Progress) string {
	var parts []string
	for _, p := range ps {
		switch p.Phase {
		case runner.PhaseTrial:
			parts = append(parts, fmt.Sprintf("trial:%d", p.Done))
		case runner.PhaseDone:
			parts = append(parts, "done:"+string(p.Verdict))
		default:
			parts = append(parts, p.Phase)
		}
	}
	return strings.Join(parts, " ")
}

func TestRunsAgainstDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("races the demo shop")
	}
	e := newEnv(t, demoWindow(2*time.Millisecond))
	addr := e.startDemo()
	vuln := e.copyExampleTo("coupon-vuln", addr)
	fixed := e.copyExampleTo("coupon-fixed", addr)

	vulnID := e.startRun(map[string]any{"path": vuln, "trials": demoTrials})
	live := e.events(vulnID) // subscribed while the run is in progress
	d := e.waitRun(vulnID)
	if d.Run.Verdict != runner.Violated || d.Run.Scenario != "coupon-vuln" || d.Run.File != vuln || d.Run.Trials != demoTrials ||
		d.Run.Violated == 0 || d.Run.Copies != 20 || d.Run.Engine == "" || d.Run.FinishedAt == nil {
		t.Fatalf("vuln run %+v", d.Run)
	}
	var rep runner.Report
	if err := json.Unmarshal(d.Report, &rep); err != nil {
		t.Fatalf("report: %v", err)
	}
	if rep.Verdict != runner.Violated || len(rep.Trials) != demoTrials || rep.File != vuln ||
		!strings.Contains(rep.Reproduce, "photofinish run "+vuln) {
		t.Errorf("report verdict %s, %d trials, file %s, reproduce %q", rep.Verdict, len(rep.Trials), rep.File, rep.Reproduce)
	}
	if strings.Contains(string(d.Report), "demo-alice") {
		t.Error("the stored report contains the identity token")
	}

	ps, done := progressOf(t, live)
	if got, wantPhases := phases(ps), "start trial:1 trial:2 trial:3 done:VIOLATED"; got != wantPhases {
		t.Errorf("live events %q, want %q", got, wantPhases)
	}
	if done.ID != vulnID || done.Verdict != runner.Violated || done.Summary == "" {
		t.Errorf("done %+v", done)
	}
	for _, p := range ps {
		if p.Planned != demoTrials {
			t.Errorf("planned %d", p.Planned)
		}
		if p.Phase == runner.PhaseTrial && (p.Trial == nil || p.Trial.Race == nil || len(p.Trial.Race.Results) != 20) {
			t.Errorf("trial event without race: %+v", p.Trial)
		}
	}
	for _, ev := range live {
		if strings.Contains(ev.data, "demo-alice") {
			t.Error("a progress event contains the identity token")
		}
	}

	// A late subscriber gets the same events from memory, and one after the
	// process forgot the run gets them rebuilt from the stored report.
	late := e.events(vulnID)
	if !slices.Equal(late, live) {
		t.Errorf("late subscriber got other events:\n%v\nwant\n%v", late, live)
	}
	e.srv.runs.forget(vulnID)
	stored, _ := progressOf(t, e.events(vulnID))
	if got := phases(stored); got != "start trial:1 trial:2 trial:3 done:VIOLATED" {
		t.Errorf("replayed events %q", got)
	}

	fixedID := e.startRun(map[string]any{"path": fixed, "trials": demoTrials, "engine": "h2"})
	d = e.waitRun(fixedID)
	if d.Run.Verdict != runner.Held || d.Run.Engine != "h2" || d.Run.Violated != 0 {
		t.Fatalf("fixed run %+v", d.Run)
	}

	// History, newest first, with filters.
	var list []runJSON
	e.get("/api/runs").json(t, &list)
	if len(list) != 2 || list[0].ID != fixedID || list[1].ID != vulnID || list[0].Status != statusFinished {
		t.Errorf("history %+v", list)
	}
	e.get("/api/runs?scenario=coupon-vuln").json(t, &list)
	if len(list) != 1 || list[0].ID != vulnID {
		t.Errorf("filtered history %+v", list)
	}
	e.get("/api/runs?limit=1").json(t, &list)
	if len(list) != 1 || list[0].ID != fixedID {
		t.Errorf("limited history %+v", list)
	}
	for _, bad := range []string{"0", "-1", "abc", "1001"} {
		want(t, e.get("/api/runs?limit="+bad), http.StatusBadRequest)
	}

	// The listing shows the last run of every file.
	var sc scenariosResponse
	e.get("/api/scenarios").json(t, &sc)
	for _, s := range sc.Scenarios {
		wantID, wantVerdict := vulnID, runner.Violated
		if s.Path == fixed {
			wantID, wantVerdict = fixedID, runner.Held
		}
		if s.LastRun == nil || s.LastRun.ID != wantID || s.LastRun.Verdict != wantVerdict || s.LastRun.FinishedAt.IsZero() {
			t.Errorf("%s: last run %+v", s.Path, s.LastRun)
		}
	}

	checkDownloads(t, e, vulnID, vuln)

	// Delete a finished run.
	want(t, e.do(request{method: "DELETE", path: "/api/runs/" + fixedID}), http.StatusNoContent)
	want(t, e.get("/api/runs/"+fixedID), http.StatusNotFound)
	want(t, e.do(request{method: "DELETE", path: "/api/runs/" + fixedID}), http.StatusNotFound)
	if _, err := e.store.Get(fixedID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("store still has the run: %v", err)
	}
}

// checkDownloads fetches every report format of a finished VIOLATED run.
func checkDownloads(t *testing.T, e *env, id, file string) {
	t.Helper()
	cases := []struct {
		name, contentType, ext string
		check                  func([]byte) error
	}{
		{"report.json", "application/json", "json", func(b []byte) error {
			var rep runner.Report
			if err := json.Unmarshal(b, &rep); err != nil {
				return err
			}
			if rep.Verdict != runner.Violated {
				return fmt.Errorf("verdict %s", rep.Verdict)
			}
			return nil
		}},
		{"report.sarif", "application/sarif+json", "sarif", func(b []byte) error {
			var log struct {
				Version string `json:"version"`
				Runs    []struct {
					Results []struct {
						RuleID    string `json:"ruleId"`
						Locations []struct {
							Physical struct {
								Artifact struct {
									URI string `json:"uri"`
								} `json:"artifactLocation"`
								Region struct {
									StartLine int `json:"startLine"`
								} `json:"region"`
							} `json:"physicalLocation"`
						} `json:"locations"`
					} `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(b, &log); err != nil {
				return err
			}
			if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
				return fmt.Errorf("sarif %s", b)
			}
			res := log.Runs[0].Results[0]
			if res.RuleID != "PF001" || len(res.Locations) == 0 {
				return fmt.Errorf("result %+v", res)
			}
			loc := res.Locations[0].Physical
			if loc.Artifact.URI != file || loc.Region.StartLine <= 1 {
				return fmt.Errorf("location %+v, want %s at the invariant line", loc, file)
			}
			return nil
		}},
		{"report.junit", "application/xml", "junit.xml", func(b []byte) error {
			var suites struct {
				XMLName xml.Name
				Tests   int `xml:"tests,attr"`
			}
			if err := xml.Unmarshal(b, &suites); err != nil {
				return err
			}
			if suites.XMLName.Local != "testsuites" || suites.Tests != demoTrials {
				return fmt.Errorf("junit %s with %d tests", suites.XMLName.Local, suites.Tests)
			}
			return nil
		}},
		{"report.html", "text/html", "html", func(b []byte) error {
			if !strings.Contains(strings.ToLower(string(b)), "<html") || !strings.Contains(string(b), "coupon-vuln") {
				return errors.New("not the HTML report")
			}
			return nil
		}},
	}
	for _, c := range cases {
		r := e.get("/api/runs/" + id + "/" + c.name)
		want(t, r, http.StatusOK)
		if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, c.contentType) {
			t.Errorf("%s: Content-Type %q", c.name, ct)
		}
		wantDisp := fmt.Sprintf(`attachment; filename="photofinish-coupon-vuln-%s.%s"`, id, c.ext)
		if got := r.header.Get("Content-Disposition"); got != wantDisp {
			t.Errorf("%s: Content-Disposition %q, want %q", c.name, got, wantDisp)
		}
		if r.header.Get("Content-Security-Policy") != ContentSecurityPolicy {
			t.Errorf("%s: no CSP", c.name)
		}
		if err := c.check(r.body); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if strings.Contains(string(r.body), "demo-alice") {
			t.Errorf("%s contains the identity token", c.name)
		}
	}
	for _, bad := range []string{"report.pdf", "report", "report.json.html", "..%2freport.json", "events.json"} {
		want(t, e.get("/api/runs/"+id+"/"+bad), http.StatusNotFound)
	}
}

// gate is a target whose setup endpoint blocks until released, so that a
// run stays in progress as long as a test needs.
type gate struct {
	ts      *httptest.Server
	entered chan struct{} // receives when a setup request arrived
	release chan struct{} // send to let one setup request through

	mu   sync.Mutex
	hits int
}

func newGate(t *testing.T) *gate {
	t.Helper()
	g := &gate{entered: make(chan struct{}, 16), release: make(chan struct{})}
	g.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/setup" {
			g.mu.Lock()
			g.hits++
			g.mu.Unlock()
			g.entered <- struct{}{}
			select {
			case <-g.release:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(g.ts.Close)
	return g
}

// scenario returns a scenario of trials trials against the gate.
func (g *gate) scenario(name string, trials int) string {
	host := strings.TrimPrefix(g.ts.URL, "http://")
	return fmt.Sprintf(`version: 1
name: %s
target: %s
scope:
  allow_hosts: [%s]
  budget: { requests: 200, rps: 1000 }
setup:
  - id: wait
    request: POST /setup
race:
  engine: h1
  copies: 2
  request: { request: POST /race }
check:
  invariant: size(race) == 2
trials: %d
`, name, g.ts.URL, host, trials)
}

// waitEntered waits until the gate holds a setup request.
func (g *gate) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not reach the gate")
	}
}

func TestOneRunAtATimeAndCancel(t *testing.T) {
	e := newEnv(t)
	g := newGate(t)
	content := g.scenario("gated", 5)
	e.write("gated.yaml", content)
	id := e.startRun(map[string]any{"path": "gated.yaml"})
	g.waitEntered(t)

	// A second run is refused while the first is in progress.
	r := e.post("/api/runs", map[string]any{"content": content})
	want(t, r, http.StatusConflict)
	var busy errorBody
	r.json(t, &busy)
	if busy.ID != id {
		t.Errorf("409 names %q, want %q", busy.ID, id)
	}
	var info infoResponse
	e.get("/api/info").json(t, &info)
	if info.RunningRun != id {
		t.Errorf("info running %q", info.RunningRun)
	}
	r = e.get("/api/runs/" + id)
	want(t, r, http.StatusOK)
	var d runDetail
	r.json(t, &d)
	if d.Run.Status != statusRunning || string(d.Report) != "null" || d.Run.Scenario != "gated" || d.Run.Planned != 5 {
		t.Errorf("running detail %+v %s", d.Run, d.Report)
	}
	var list []runJSON
	e.get("/api/runs").json(t, &list)
	if len(list) != 1 || list[0].ID != id || list[0].Status != statusRunning {
		t.Errorf("history while running %+v", list)
	}
	e.get("/api/runs?scenario=other").json(t, &list)
	if len(list) != 0 {
		t.Errorf("filtered history while running %+v", list)
	}
	want(t, e.do(request{method: "DELETE", path: "/api/runs/" + id}), http.StatusConflict)
	want(t, e.get("/api/runs/"+id+"/report.json"), http.StatusConflict)

	// Let one trial through, then cancel during the second.
	g.release <- struct{}{}
	g.waitEntered(t)
	r = e.post("/api/runs/"+id+"/cancel", nil)
	want(t, r, http.StatusAccepted)
	d = e.waitRun(id)
	if !strings.Contains(d.Run.Summary, "cancelled") || d.Run.Trials != 1 {
		t.Errorf("cancelled run %+v", d.Run)
	}
	var rep runner.Report
	if err := json.Unmarshal(d.Report, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Trials) != 1 || rep.Stats.Skipped != 4 {
		t.Errorf("cancelled report: %d trials, %d skipped", len(rep.Trials), rep.Stats.Skipped)
	}
	ps, _ := progressOf(t, e.events(id))
	if got := phases(ps); !strings.HasPrefix(got, "start trial:1 done:") {
		t.Errorf("events of the cancelled run %q", got)
	}
	want(t, e.post("/api/runs/"+id+"/cancel", nil), http.StatusConflict)
	if info := e.srv.runs.activeID(); info != "" {
		t.Errorf("still active: %s", info)
	}

	// The next run may start.
	next := e.startRun(map[string]any{"content": g.scenario("gated", 1), "path": "gated.yaml"})
	g.waitEntered(t)
	g.release <- struct{}{}
	d = e.waitRun(next)
	if d.Run.Verdict != runner.Held || d.Run.File != "gated.yaml" {
		t.Errorf("next run %+v", d.Run)
	}
}

func TestLiveEventsInOrder(t *testing.T) {
	e := newEnv(t)
	g := newGate(t)
	id := e.startRun(map[string]any{"content": g.scenario("ordered", 3)})
	g.waitEntered(t)

	type result struct {
		events []sseEvent
	}
	streams := make(chan result, 2)
	for range 2 {
		go func() {
			streams <- result{events: e.events(id)}
		}()
	}
	for i := 0; i < 3; i++ {
		if i > 0 {
			g.waitEntered(t)
		}
		time.Sleep(20 * time.Millisecond) // let subscribers see the previous trial first
		g.release <- struct{}{}
	}
	var got [][]sseEvent
	for range 2 {
		select {
		case r := <-streams:
			got = append(got, r.events)
		case <-time.After(time.Minute):
			t.Fatal("streams did not end")
		}
	}
	for _, events := range got {
		ps, done := progressOf(t, events)
		if p := phases(ps); p != "start trial:1 trial:2 trial:3 done:HELD" {
			t.Errorf("events %q", p)
		}
		if done.Verdict != runner.Held {
			t.Errorf("done %+v", done)
		}
	}
	if !slices.Equal(got[0], got[1]) {
		t.Error("two subscribers got different streams")
	}
	// The report is stored by the time "done" arrives.
	r := e.get("/api/runs/" + id)
	var d runDetail
	r.json(t, &d)
	if d.Run.Status != statusFinished || string(d.Report) == "null" {
		t.Errorf("after done: %+v", d.Run)
	}
}

func TestEventsOutliveServerTimeouts(t *testing.T) {
	e := newEnv(t)
	// A server with timeouts far shorter than the run, as serve has.
	ts := httptest.NewUnstartedServer(e.srv.Handler())
	ts.Config.ReadTimeout = 100 * time.Millisecond
	ts.Config.WriteTimeout = 100 * time.Millisecond
	ts.Start()
	defer ts.Close()
	g := newGate(t)
	id := e.startRun(map[string]any{"content": g.scenario("slow", 1)})
	g.waitEntered(t)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/runs/"+id+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	time.Sleep(400 * time.Millisecond)
	g.release <- struct{}{}
	ps, done := progressOf(t, readEvents(t, resp.Body))
	if got := phases(ps); got != "start trial:1 done:HELD" || done.ID != id {
		t.Errorf("events %q, done %+v", got, done)
	}
}

func TestEventsEndWhenClientLeaves(t *testing.T) {
	e := newEnv(t)
	g := newGate(t)
	id := e.startRun(map[string]any{"content": g.scenario("leave", 1)})
	g.waitEntered(t)
	hr, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/api/runs/"+id+"/events", nil)
	hr.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := e.ts.Client().Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() // the handler must notice and return; ts.Close would hang otherwise
	g.release <- struct{}{}
	e.waitRun(id)
}

func TestInvalidScenarioRun(t *testing.T) {
	e := newEnv(t)
	for name, content := range map[string]string{
		"unparsable": "version: 1\nname: [broken\n",
		"invalid":    strings.Replace(minimal, "name: minimal", "name: Bad Name", 1),
	} {
		t.Run(name, func(t *testing.T) {
			id := e.startRun(map[string]any{"content": content})
			d := e.waitRun(id)
			if d.Run.Verdict != runner.Errored || d.Run.Summary == "" || d.Run.Trials != 0 {
				t.Errorf("run %+v", d.Run)
			}
			var rep runner.Report
			if err := json.Unmarshal(d.Report, &rep); err != nil || rep.Verdict != runner.Errored {
				t.Errorf("report %s: %v", d.Report, err)
			}
			ps, done := progressOf(t, e.events(id))
			if got := phases(ps); got != "done:ERROR" {
				t.Errorf("events %q", got)
			}
			if done.Verdict != runner.Errored {
				t.Errorf("done %+v", done)
			}
			want(t, e.get("/api/runs/"+id+"/report.sarif"), http.StatusOK)
			want(t, e.get("/api/runs/"+id+"/report.junit"), http.StatusOK)
			want(t, e.get("/api/runs/"+id+"/report.html"), http.StatusOK)
		})
	}
}

func TestRunRequestValidation(t *testing.T) {
	e := newEnv(t)
	e.write("minimal.yaml", minimal)
	cases := []struct {
		body any
		code int
	}{
		{map[string]any{}, http.StatusBadRequest},
		{map[string]any{"path": "minimal.yaml", "engine": "h3"}, http.StatusBadRequest},
		{map[string]any{"path": "minimal.yaml", "trials": -1}, http.StatusBadRequest},
		{map[string]any{"path": "minimal.yaml", "trials": 10001}, http.StatusBadRequest},
		{map[string]any{"path": "minimal.yaml", "copies": -1}, http.StatusBadRequest},
		{map[string]any{"path": "minimal.yaml", "copies": 1001}, http.StatusBadRequest},
		{map[string]any{"path": "missing.yaml"}, http.StatusNotFound},
		{map[string]any{"path": "../minimal.yaml"}, http.StatusBadRequest},
		{map[string]any{"content": minimal, "path": "C:/x.yaml"}, http.StatusBadRequest},
		{map[string]any{"path": "minimal.yaml", "trials": "3"}, http.StatusBadRequest},
	}
	for _, c := range cases {
		r := e.post("/api/runs", c.body)
		if r.code != c.code {
			t.Errorf("%v: %d %s", c.body, r.code, r.body)
		}
	}
	if runs, _ := e.store.List(0, ""); len(runs) != 0 || e.srv.runs.activeID() != "" {
		t.Errorf("a rejected request started a run: %v", runs)
	}
	for _, id := range []string{"nothex", "0123456789abc", "0123456789AB", "..%2f..%2fx", "0123456789ab%00"} {
		if r := e.get("/api/runs/" + id); r.code != http.StatusNotFound {
			t.Errorf("GET %s: %d", id, r.code)
		}
	}
	want(t, e.get("/api/runs/0123456789ab"), http.StatusNotFound)
	want(t, e.get("/api/runs/0123456789ab/events"), http.StatusNotFound)
	want(t, e.post("/api/runs/0123456789ab/cancel", nil), http.StatusNotFound)
}

// failingStore fails every Save.
type failingStore struct{ *store.Store }

func (failingStore) Save(*store.Run) error { return errors.New("disk full") }

func TestSaveFailureKeepsTheRunInMemory(t *testing.T) {
	st, err := store.Open(store.Memory)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	e := newEnv(t, withStore(failingStore{st}))
	id := e.startRun(map[string]any{"content": "version: 1\n"})
	d := e.waitRun(id)
	if d.Run.Verdict != runner.Errored || string(d.Report) == "null" {
		t.Errorf("run %+v", d.Run)
	}
	want(t, e.get("/api/runs/"+id+"/report.json"), http.StatusOK)
}

func TestCloseCancelsTheRun(t *testing.T) {
	e := newEnv(t)
	g := newGate(t)
	id := e.startRun(map[string]any{"content": g.scenario("closing", 3)})
	g.waitEntered(t)
	done := make(chan error, 1)
	go func() { done <- e.srv.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Close did not cancel the run")
	}
	rec, err := e.store.Get(id)
	if err != nil {
		t.Fatalf("the cancelled run was not saved: %v", err)
	}
	if !strings.Contains(rec.Summary, "cancelled") {
		t.Errorf("summary %q", rec.Summary)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	open := func() *store.Store {
		st, err := store.Open(store.Path(dir))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := open()
	e := newEnv(t, withStore(st))
	id := e.startRun(map[string]any{"content": strings.Replace(minimal, "name: minimal", "name: Bad", 1)})
	first := e.waitRun(id)
	e.srv.Close()
	st.Close()

	// A new server over the same data directory has the run, report included.
	st = open()
	defer st.Close()
	e2 := newEnv(t, withStore(st))
	r := e2.get("/api/runs/" + id)
	want(t, r, http.StatusOK)
	var again runDetail
	r.json(t, &again)
	if again.Run.ID != id || again.Run.Verdict != first.Run.Verdict || again.Run.Summary != first.Run.Summary ||
		!again.Run.StartedAt.Equal(first.Run.StartedAt) {
		t.Errorf("after reopen %+v, before %+v", again.Run, first.Run)
	}
	var a, b any
	if json.Unmarshal(first.Report, &a) != nil || json.Unmarshal(again.Report, &b) != nil || fmt.Sprint(a) != fmt.Sprint(b) {
		t.Error("the report changed through the store")
	}
	ps, _ := progressOf(t, e2.events(id))
	if got := phases(ps); got != "done:ERROR" {
		t.Errorf("replayed events %q", got)
	}
}
