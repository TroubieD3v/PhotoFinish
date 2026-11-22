package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/report"
	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/scenario"
	"github.com/TroubieD3v/photofinish/internal/store"
)

// Run list limits and timings.
const (
	defaultRunList = 100
	maxRunList     = 1000
	// keepFinished is how many finished runs keep their events in memory
	// for late subscribers; older ones are replayed from the stored report.
	keepFinished = 16
	// heartbeat is the interval of SSE comments that keep idle streams open.
	heartbeat = 15 * time.Second
	// probeTimeout bounds POST /api/probe.
	probeTimeout = 30 * time.Second
)

// Run states reported by the API.
const (
	statusRunning  = "running"
	statusFinished = "finished"
)

// runState is a run started by this server process: its progress events and,
// once finished, its stored record.
type runState struct {
	id     string
	cancel context.CancelFunc

	mu       sync.Mutex
	meta     store.Run // Scenario, File, Engine, Copies, StartedAt while running
	planned  int
	done     int
	events   [][]byte // JSON of runner.Progress, in order
	finished bool
	record   *store.Run    // the stored run, with Report, once finished
	changed  chan struct{} // closed and replaced on every change
}

// snapshot returns the events from index i on, whether the run finished
// and a channel that is closed on the next change.
func (st *runState) snapshot(i int) (events [][]byte, finished bool, changed <-chan struct{}) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if i < len(st.events) {
		events = st.events[i:]
	}
	return events, st.finished, st.changed
}

// notifyLocked wakes every subscriber; st.mu must be held.
func (st *runState) notifyLocked() {
	close(st.changed)
	st.changed = make(chan struct{})
}

// add appends a progress event.
func (st *runState) add(p runner.Progress) {
	data, err := json.Marshal(p)
	if err != nil {
		data, _ = json.Marshal(map[string]string{"phase": p.Phase, "error": err.Error()})
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.events = append(st.events, data)
	if p.Trial != nil && p.Trial.Race != nil && p.Trial.Race.Kind != "" && p.Trial.Race.Kind != engine.Auto {
		// The engine "auto" resolved to: the history shows it while the
		// run is in progress, as it does once the run is stored.
		st.meta.Engine = string(p.Trial.Race.Kind)
	}
	if p.Planned > 0 {
		st.planned = p.Planned
	}
	st.done = p.Done
	st.notifyLocked()
}

// runs tracks the active run and recently finished ones.
type runs struct {
	mu     sync.Mutex
	active *runState
	recent []*runState // finished, oldest first
	byID   map[string]*runState
	wg     sync.WaitGroup
}

func newRuns() *runs {
	return &runs{byID: map[string]*runState{}}
}

// activeID returns the id of the running run, or "".
func (rs *runs) activeID() string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.active == nil {
		return ""
	}
	return rs.active.id
}

// get returns the in-memory state of a run, or nil.
func (rs *runs) get(id string) *runState {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.byID[id]
}

// begin registers st as the active run, or returns the id of the run that is
// already active.
func (rs *runs) begin(st *runState) (busy string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.active != nil {
		return rs.active.id
	}
	rs.active = st
	rs.byID[st.id] = st
	rs.wg.Add(1)
	return ""
}

// end moves the active run to the finished ones.
func (rs *runs) end(st *runState) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.active == st {
		rs.active = nil
	}
	rs.recent = append(rs.recent, st)
	for len(rs.recent) > keepFinished {
		delete(rs.byID, rs.recent[0].id)
		rs.recent = rs.recent[1:]
	}
	rs.wg.Done()
}

// forget drops a finished run from memory.
func (rs *runs) forget(id string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	delete(rs.byID, id)
	for i, st := range rs.recent {
		if st.id == id {
			rs.recent = append(rs.recent[:i], rs.recent[i+1:]...)
			break
		}
	}
}

// wait blocks until no run is active.
func (rs *runs) wait() { rs.wg.Wait() }

// runRequest is the body of POST /api/runs.
type runRequest struct {
	// Path is a workspace scenario file. With Content as well, Content is
	// run (the unsaved editor buffer) and Path names it in the report.
	Path     string      `json:"path"`
	Content  *string     `json:"content"`
	Engine   engine.Kind `json:"engine"`
	Trials   int         `json:"trials"`
	Copies   int         `json:"copies"`
	Insecure bool        `json:"insecure"`
}

// runJSON is a run in API responses.
type runJSON struct {
	ID         string         `json:"id"`
	Status     string         `json:"status"`
	Scenario   string         `json:"scenario"`
	File       string         `json:"file"`
	Engine     engine.Kind    `json:"engine"`
	Verdict    runner.Verdict `json:"verdict,omitempty"`
	Summary    string         `json:"summary"`
	Trials     int            `json:"trials"`
	Violated   int            `json:"violated"`
	Copies     int            `json:"copies"`
	StartedAt  time.Time      `json:"startedAt"`
	FinishedAt *time.Time     `json:"finishedAt,omitempty"`
	// Planned and Done count trials while the run is in progress.
	Planned int `json:"planned,omitempty"`
	Done    int `json:"done,omitempty"`
}

// runOf converts a stored run.
func runOf(r *store.Run) runJSON {
	out := runJSON{
		ID: r.ID, Status: statusFinished, Scenario: r.Scenario, File: r.File, Engine: engine.Kind(r.Engine),
		Verdict: r.Verdict, Summary: r.Summary, Trials: r.Trials, Violated: r.Violated, Copies: r.Copies,
		StartedAt: r.StartedAt,
	}
	if !r.FinishedAt.IsZero() {
		fin := r.FinishedAt
		out.FinishedAt = &fin
	}
	return out
}

// view returns the API form of an in-memory run.
func (st *runState) view() runJSON {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.record != nil {
		return runOf(st.record)
	}
	out := runOf(&st.meta)
	out.Status, out.Planned, out.Done, out.FinishedAt = statusRunning, st.planned, st.done, nil
	out.Trials = st.done
	return out
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	var req runRequest
	if !readJSON(w, r, &req) {
		return
	}
	switch req.Engine {
	case "", engine.Auto, engine.H2, engine.H1, engine.Burst:
	default:
		fail(w, http.StatusBadRequest, fmt.Errorf("engine must be auto, h2, h1 or burst, got %q", req.Engine))
		return
	}
	if req.Trials < 0 || req.Trials > scenario.MaxTrials {
		fail(w, http.StatusBadRequest, fmt.Errorf("trials must be between 1 and %d (0 keeps the scenario's value), got %d", scenario.MaxTrials, req.Trials))
		return
	}
	if req.Copies < 0 || req.Copies > scenario.MaxCopies {
		fail(w, http.StatusBadRequest, fmt.Errorf("copies must be between 1 and %d (0 keeps the scenario's value), got %d", scenario.MaxCopies, req.Copies))
		return
	}
	var data []byte
	switch {
	case req.Content != nil:
		if len(*req.Content) > MaxFileBytes {
			fail(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the content is larger than %d KiB", MaxFileBytes>>10))
			return
		}
		if req.Path != "" {
			if _, err := s.checkPath(req.Path); err != nil {
				fail(w, statusOf(err), err)
				return
			}
		}
		data = []byte(*req.Content)
	case req.Path != "":
		d, err := s.readFile(req.Path)
		if err != nil {
			fail(w, statusOf(err), err)
			return
		}
		data = d
	default:
		fail(w, http.StatusBadRequest, errors.New(`the body needs "path" or "content"`))
		return
	}

	ctx, cancel := context.WithCancel(s.ctx)
	st := &runState{id: store.NewID(), cancel: cancel, changed: make(chan struct{})}
	st.meta = store.Run{ID: st.id, File: req.Path, Engine: string(req.Engine), Copies: req.Copies, StartedAt: time.Now()}
	sc, perr := scenario.Parse(data, req.Path)
	if perr == nil {
		st.meta.Scenario = sc.Name
		if st.meta.Engine == "" {
			st.meta.Engine = string(sc.Race.EngineKind())
		}
		if st.meta.Copies == 0 {
			st.meta.Copies = sc.Race.TotalCopies()
		}
	}
	if busy := s.runs.begin(st); busy != "" {
		cancel()
		writeJSON(w, http.StatusConflict, errorBody{Error: "a run is already in progress; wait for it or cancel it", ID: busy})
		return
	}
	opts := runner.Options{
		Engine:   req.Engine,
		Trials:   req.Trials,
		Copies:   req.Copies,
		Insecure: req.Insecure,
		Version:  s.version,
	}
	go s.execute(ctx, st, sc, perr, opts)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": st.id})
}

// execute runs a scenario in the background, saves the masked report and
// finishes the event stream.
func (s *Server) execute(ctx context.Context, st *runState, sc *scenario.Scenario, parseErr error, opts runner.Options) {
	defer s.runs.end(st)
	defer st.cancel()
	started := st.meta.StartedAt
	var sawDone atomic.Bool
	opts.OnProgress = func(p runner.Progress) {
		if p.Phase == runner.PhaseDone {
			sawDone.Store(true)
		}
		st.add(p)
	}

	var rep *runner.Report
	if parseErr != nil {
		rep = s.errorReport(st.meta.File, parseErr, started)
	} else {
		rep = s.runScenario(ctx, sc, opts, started)
	}
	if rep.File == "" {
		rep.File = st.meta.File
	}
	if !sawDone.Load() {
		// The scenario did not parse, so the runner never ran: report
		// "done" only, as the runner does for an invalid scenario.
		st.add(runner.Progress{Phase: runner.PhaseDone, Planned: rep.Stats.Planned, Done: len(rep.Trials), Verdict: rep.Verdict})
	}

	var buf bytes.Buffer
	if err := report.JSON(&buf, []*runner.Report{rep}); err != nil {
		s.logger.Printf("run %s: encode the report: %v", st.id, err)
	}
	rec := &store.Run{
		ID:         st.id,
		Scenario:   rep.Scenario,
		File:       st.meta.File,
		Engine:     string(rep.Engine),
		Verdict:    rep.Verdict,
		Summary:    rep.Summary,
		Trials:     rep.Stats.Ran,
		Violated:   rep.Stats.Violated,
		Copies:     rep.Copies,
		StartedAt:  started,
		FinishedAt: rep.FinishedAt,
		Report:     buf.Bytes(),
	}
	if rec.Trials == 0 {
		rec.Trials = len(rep.Trials)
	}
	if rec.FinishedAt.IsZero() {
		rec.FinishedAt = time.Now()
	}
	if err := s.store.Save(rec); err != nil {
		s.logger.Printf("run %s: save: %v", st.id, err)
	}
	st.mu.Lock()
	st.record = rec
	st.finished = true
	st.notifyLocked()
	st.mu.Unlock()
}

// runScenario runs sc and turns every failure into an ERROR report, as the
// run command does.
func (s *Server) runScenario(ctx context.Context, sc *scenario.Scenario, opts runner.Options, started time.Time) (rep *runner.Report) {
	defer func() {
		if v := recover(); v != nil {
			s.logger.Printf("run %s: panic: %v", sc.Name, v)
			rep = s.errorReport(sc.Path, fmt.Errorf("internal error: %v", v), started)
		}
	}()
	rep, err := runner.Run(ctx, sc, opts)
	if rep == nil {
		if err == nil {
			err = errors.New("the runner returned no report")
		}
		return s.errorReport(sc.Path, err, started)
	}
	if err != nil {
		reason := err.Error()
		if errors.Is(err, context.Canceled) {
			reason = "the run was cancelled"
		}
		if rep.Summary == "" {
			rep.Verdict, rep.Summary = runner.Errored, reason
		} else {
			rep.Summary += fmt.Sprintf(" (stopped early: %s)", reason)
		}
	}
	return rep
}

// errorReport is the report of a scenario that failed before it could run.
func (s *Server) errorReport(file string, err error, started time.Time) *runner.Report {
	return &runner.Report{
		Schema:     runner.Schema,
		Tool:       "photofinish " + s.version,
		File:       file,
		Verdict:    runner.Errored,
		Summary:    err.Error(),
		Trials:     []runner.Trial{},
		StartedAt:  started,
		FinishedAt: time.Now(),
	}
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := defaultRunList
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxRunList {
			fail(w, http.StatusBadRequest, fmt.Errorf("limit must be between 1 and %d, got %q", maxRunList, v))
			return
		}
		limit = n
	}
	name := q.Get("scenario")
	verdict := runner.Verdict(q.Get("verdict"))
	switch verdict {
	case "", runner.Violated, runner.Held, runner.Inconclusive, runner.Errored:
	default:
		fail(w, http.StatusBadRequest, fmt.Errorf("verdict must be VIOLATED, HELD, INCONCLUSIVE or ERROR, got %q", verdict))
		return
	}
	stored, err := s.store.Query(store.Filter{Limit: limit, Scenario: name, Verdict: verdict})
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]runJSON, 0, len(stored)+1)
	activeID := s.runs.activeID()
	if activeID != "" && verdict == "" {
		if st := s.runs.get(activeID); st != nil {
			if v := st.view(); v.Status == statusRunning && (name == "" || v.Scenario == name) {
				out = append(out, v)
			}
		}
	}
	for i := range stored {
		if stored[i].ID == activeID && len(out) > 0 {
			continue
		}
		out = append(out, runOf(&stored[i]))
	}
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, http.StatusOK, out)
}

// runScenarios answers GET /api/runs/scenarios: the distinct scenario names
// of the history and of the run in progress, sorted, for the filter of the
// runs screen.
func (s *Server) runScenarios(w http.ResponseWriter, r *http.Request) {
	names, err := s.store.Scenarios()
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	if st := s.runs.get(s.runs.activeID()); st != nil {
		if v := st.view(); v.Scenario != "" && !slices.Contains(names, v.Scenario) {
			names = append(names, v.Scenario)
			slices.Sort(names)
		}
	}
	writeJSON(w, http.StatusOK, names)
}

// runDetail is the body of GET /api/runs/{id}.
type runDetail struct {
	Run runJSON `json:"run"`
	// Report is the masked report; null while the run is in progress.
	Report json.RawMessage `json:"report"`
}

// lookup returns the record of a finished run (with its report), or the
// in-memory state of a running one. It writes the error response and
// returns false when there is none.
func (s *Server) lookup(w http.ResponseWriter, id string) (*store.Run, *runState, bool) {
	if !store.ValidID(id) {
		fail(w, http.StatusNotFound, fmt.Errorf("no run %q", id))
		return nil, nil, false
	}
	if st := s.runs.get(id); st != nil {
		st.mu.Lock()
		rec := st.record
		st.mu.Unlock()
		return rec, st, true
	}
	rec, err := s.store.Get(id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, fmt.Errorf("no run %q", id))
		return nil, nil, false
	case err != nil:
		fail(w, http.StatusInternalServerError, err)
		return nil, nil, false
	}
	return rec, nil, true
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	rec, st, ok := s.lookup(w, r.PathValue("id"))
	if !ok {
		return
	}
	if rec == nil {
		writeJSON(w, http.StatusOK, runDetail{Run: st.view(), Report: json.RawMessage("null")})
		return
	}
	rep := json.RawMessage(bytes.TrimSpace(rec.Report))
	if len(rep) == 0 || !json.Valid(rep) {
		rep = json.RawMessage("null")
	}
	writeJSON(w, http.StatusOK, runDetail{Run: runOf(rec), Report: rep})
}

func (s *Server) deleteRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, st, ok := s.lookup(w, id)
	if !ok {
		return
	}
	if rec == nil {
		writeJSON(w, http.StatusConflict, errorBody{Error: "the run is still in progress; cancel it first", ID: id})
		return
	}
	err := s.store.Delete(id)
	if err != nil && !(errors.Is(err, store.ErrNotFound) && st != nil) {
		fail(w, statusFor(err), err)
		return
	}
	s.runs.forget(id)
	w.WriteHeader(http.StatusNoContent)
}

// statusFor maps a store error to an HTTP status.
func statusFor(err error) int {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, st, ok := s.lookup(w, id)
	if !ok {
		return
	}
	if rec != nil {
		writeJSON(w, http.StatusConflict, errorBody{Error: "the run has already finished", ID: id})
		return
	}
	st.cancel()
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

// doneEvent is the data of the final "done" event of a run's stream.
type doneEvent struct {
	ID      string         `json:"id"`
	Verdict runner.Verdict `json:"verdict"`
	Summary string         `json:"summary"`
}

// runEvents streams the progress of a run as server-sent events: every
// runner.Progress so far as "event: progress", then new ones as they come,
// and finally "event: done". A run that finished before this process kept
// it in memory is replayed from its stored report.
func (s *Server) runEvents(w http.ResponseWriter, r *http.Request) {
	rec, st, ok := s.lookup(w, r.PathValue("id"))
	if !ok {
		return
	}
	rc := http.NewResponseController(w)
	// A stream lives as long as the run. The read deadline matters too: when
	// the server's ReadTimeout expires, net/http cancels the request
	// context, which would end the stream.
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.SetReadDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	write := func(event string, data []byte) bool {
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if st == nil {
		for _, ev := range replay(rec) {
			if !write("progress", ev) {
				return
			}
		}
		data, _ := json.Marshal(doneEvent{ID: rec.ID, Verdict: rec.Verdict, Summary: rec.Summary})
		write("done", data)
		return
	}

	tick := time.NewTicker(heartbeat)
	defer tick.Stop()
	next := 0
	for {
		events, finished, changed := st.snapshot(next)
		for _, ev := range events {
			if !write("progress", ev) {
				return
			}
		}
		next += len(events)
		if finished {
			st.mu.Lock()
			rec := st.record
			st.mu.Unlock()
			data, _ := json.Marshal(doneEvent{ID: rec.ID, Verdict: rec.Verdict, Summary: rec.Summary})
			write("done", data)
			return
		}
		if len(events) == 0 {
			_ = rc.Flush()
		}
		select {
		case <-changed:
		case <-tick.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil || rc.Flush() != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

// replay rebuilds the progress events of a stored run from its report.
func replay(rec *store.Run) [][]byte {
	var rep runner.Report
	if err := json.Unmarshal(rec.Report, &rep); err != nil {
		rep = runner.Report{Verdict: rec.Verdict}
	}
	planned := rep.Stats.Planned
	if planned == 0 {
		planned = len(rep.Trials)
	}
	var out [][]byte
	add := func(p runner.Progress) {
		if data, err := json.Marshal(p); err == nil {
			out = append(out, data)
		}
	}
	if planned > 0 {
		// A run that failed validation reported "done" only.
		add(runner.Progress{Phase: runner.PhaseStart, Planned: planned})
	}
	for i := range rep.Trials {
		add(runner.Progress{Phase: runner.PhaseTrial, Planned: planned, Done: i + 1, Trial: &rep.Trials[i]})
	}
	add(runner.Progress{Phase: runner.PhaseDone, Planned: planned, Done: len(rep.Trials), Verdict: rec.Verdict})
	return out
}

// reportFormats maps the file names of GET /api/runs/{id}/report.<ext> to
// content types and download extensions.
var reportFormats = map[string]struct{ contentType, ext string }{
	"report.json":  {"application/json; charset=utf-8", "json"},
	"report.sarif": {"application/sarif+json; charset=utf-8", "sarif"},
	"report.junit": {"application/xml; charset=utf-8", "junit.xml"},
	"report.html":  {"text/html; charset=utf-8", "html"},
}

// safeName matches scenario names that may appear in a download file name.
var safeName = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

func (s *Server) runReport(w http.ResponseWriter, r *http.Request) {
	format, ok := reportFormats[r.PathValue("file")]
	if !ok {
		fail(w, http.StatusNotFound, errors.New("unknown report: use report.json, report.sarif, report.junit or report.html"))
		return
	}
	rec, _, found := s.lookup(w, r.PathValue("id"))
	if !found {
		return
	}
	if rec == nil {
		writeJSON(w, http.StatusConflict, errorBody{Error: "the run has not finished yet", ID: r.PathValue("id")})
		return
	}
	var rep runner.Report
	if err := json.Unmarshal(rec.Report, &rep); err != nil {
		fail(w, http.StatusInternalServerError, fmt.Errorf("the stored report cannot be read: %v", err))
		return
	}
	var buf bytes.Buffer
	var err error
	switch format.ext {
	case "json":
		buf.Write(rec.Report)
	case "sarif":
		// Scenario paths are relative to the workspace; SARIF makes the
		// absolute path relative again and reads the file for the invariant
		// line through the workspace root, as every other file access.
		if rep.File != "" && !filepath.IsAbs(rep.File) {
			rep.File = filepath.Join(s.workspace, filepath.FromSlash(rep.File))
		}
		err = report.SARIF(&buf, []*runner.Report{&rep}, report.SARIFOptions{BaseDir: s.workspace, ReadFile: s.readAbs})
	case "junit.xml":
		err = report.JUnit(&buf, []*runner.Report{&rep})
	case "html":
		err = report.HTML(&buf, []*runner.Report{&rep})
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	name := rec.Scenario
	if !safeName.MatchString(name) {
		name = "run"
	}
	h := w.Header()
	h.Set("Content-Type", format.contentType)
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="photofinish-%s-%s.%s"`, name, rec.ID, format.ext))
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// probeRequest is the body of POST /api/probe.
type probeRequest struct {
	URL      string `json:"url"`
	Insecure bool   `json:"insecure"`
}

func (s *Server) probe(w http.ResponseWriter, r *http.Request) {
	var req probeRequest
	if !readJSON(w, r, &req) {
		return
	}
	u, err := parseTargetURL(req.URL)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	opts := engine.Options{Kind: engine.Auto, Guard: engine.AllowAll()}
	if req.Insecure {
		opts.TLS = insecureTLS() // the user asked for it: self-signed lab target
	}
	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()
	rep, err := engine.Probe(ctx, u, opts)
	if err != nil {
		fail(w, http.StatusBadGateway, fmt.Errorf("probe %s: %v", u, err))
		return
	}
	writeJSON(w, http.StatusOK, probeOf(rep))
}

// probeJSON is the answer of POST /api/probe: engine.ProbeReport with the
// camelCase names of the rest of the API and round trips in nanoseconds.
type probeJSON struct {
	URL                  string      `json:"url"`
	ALPN                 string      `json:"alpn"`
	TLSVersion           string      `json:"tlsVersion"`
	HTTP2                bool        `json:"http2"`
	Server               string      `json:"server"`
	MaxConcurrentStreams uint32      `json:"maxConcurrentStreams"`
	InitialWindowSize    uint32      `json:"initialWindowSize"`
	MaxFrameSize         uint32      `json:"maxFrameSize"`
	RTTsNs               []int64     `json:"rttsNs"`
	Statuses             []int       `json:"statuses"`
	ArrivalHeader        bool        `json:"arrivalHeader"`
	Recommended          engine.Kind `json:"recommended"`
	Notes                []string    `json:"notes"`
}

// probeOf converts a probe report; slices are never null.
func probeOf(r *engine.ProbeReport) probeJSON {
	out := probeJSON{
		URL: r.URL, ALPN: r.ALPN, TLSVersion: r.TLSVersion, HTTP2: r.HTTP2, Server: r.Server,
		MaxConcurrentStreams: r.MaxConcurrentStreams, InitialWindowSize: r.InitialWindowSize, MaxFrameSize: r.MaxFrameSize,
		RTTsNs: make([]int64, len(r.RTTs)), Statuses: append([]int{}, r.Statuses...),
		ArrivalHeader: r.ArrivalHeader, Recommended: r.Recommended, Notes: append([]string{}, r.Notes...),
	}
	for i, d := range r.RTTs {
		out.RTTsNs[i] = d.Nanoseconds()
	}
	return out
}
