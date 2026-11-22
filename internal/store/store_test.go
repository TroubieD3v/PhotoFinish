package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
)

// base is the start time of the test runs.
var base = time.Date(2026, 11, 2, 10, 30, 0, 123456789, time.UTC)

// testRun returns run n of scenario name, started n minutes after base.
func testRun(n int, name string, verdict runner.Verdict) *Run {
	start := base.Add(time.Duration(n) * time.Minute)
	return &Run{
		ID:         fmt.Sprintf("%012x", n+1),
		Scenario:   name,
		File:       "examples/" + name + ".yaml",
		Engine:     "h2",
		Verdict:    verdict,
		Summary:    fmt.Sprintf("summary %d", n),
		Trials:     3,
		Violated:   n % 2,
		Copies:     20,
		StartedAt:  start,
		FinishedAt: start.Add(1500 * time.Millisecond),
		Report:     []byte(fmt.Sprintf(`{"scenario":%q,"n":%d}`, name, n)),
	}
}

func openMemory(t *testing.T) *Store {
	t.Helper()
	s, err := Open(Memory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sameRun(t *testing.T, got *Run, want *Run, withReport bool) {
	t.Helper()
	if got.ID != want.ID || got.Scenario != want.Scenario || got.File != want.File || got.Engine != want.Engine ||
		got.Verdict != want.Verdict || got.Summary != want.Summary || got.Trials != want.Trials ||
		got.Violated != want.Violated || got.Copies != want.Copies {
		t.Errorf("run %+v, want %+v", got, want)
	}
	if !got.StartedAt.Equal(want.StartedAt) || !got.FinishedAt.Equal(want.FinishedAt) {
		t.Errorf("times %v %v, want %v %v", got.StartedAt, got.FinishedAt, want.StartedAt, want.FinishedAt)
	}
	if withReport && string(got.Report) != string(want.Report) {
		t.Errorf("report %q, want %q", got.Report, want.Report)
	}
	if !withReport && got.Report != nil {
		t.Errorf("listed run has a report: %q", got.Report)
	}
}

func TestRoundTrip(t *testing.T) {
	s := openMemory(t)
	want := testRun(1, "coupon-vuln", runner.Violated)
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(want.ID)
	if err != nil {
		t.Fatal(err)
	}
	sameRun(t, got, want, true)
	if got.StartedAt.Location() != time.UTC {
		t.Errorf("times not in UTC: %v", got.StartedAt.Location())
	}
}

func TestSaveReplaces(t *testing.T) {
	s := openMemory(t)
	r := testRun(1, "coupon-vuln", runner.Errored)
	r.Report = nil
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(r.ID); err != nil || got.Report != nil {
		t.Fatalf("run without report: %v %q", err, got.Report)
	}
	r.Verdict, r.Summary, r.Report = runner.Held, "updated", []byte(`{}`)
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	sameRun(t, got, r, true)
	if runs, _ := s.List(0, ""); len(runs) != 1 {
		t.Errorf("%d runs after replacing one", len(runs))
	}
}

func TestSaveIDs(t *testing.T) {
	s := openMemory(t)
	r := testRun(1, "coupon-vuln", runner.Held)
	r.ID = ""
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	if !ValidID(r.ID) {
		t.Errorf("generated id %q", r.ID)
	}
	if _, err := s.Get(r.ID); err != nil {
		t.Errorf("get generated id: %v", err)
	}
	for _, id := range []string{"abc", "ABCDEF012345", "0123456789abc", "../../etc/pa", "0123456789ag"} {
		bad := testRun(2, "x", runner.Held)
		bad.ID = id
		if err := s.Save(bad); err == nil {
			t.Errorf("Save accepted id %q", id)
		}
	}
	if err := s.Save(nil); err == nil {
		t.Error("Save accepted nil")
	}
	seen := map[string]bool{}
	for range 100 {
		id := NewID()
		if !ValidID(id) || seen[id] {
			t.Fatalf("NewID %q (seen %v)", id, seen[id])
		}
		seen[id] = true
	}
}

func TestNotFound(t *testing.T) {
	s := openMemory(t)
	for _, id := range []string{"0123456789ab", "", "x' OR '1'='1"} {
		if _, err := s.Get(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) error %v", id, err)
		}
		if err := s.Delete(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete(%q) error %v", id, err)
		}
	}
}

func TestListOrderFilterLimit(t *testing.T) {
	s := openMemory(t)
	// Saved out of order: List sorts by start time, newest first.
	for _, n := range []int{3, 0, 4, 1, 2} {
		name := "coupon-vuln"
		if n%2 == 1 {
			name = "coupon-fixed"
		}
		if err := s.Save(testRun(n, name, runner.Held)); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(runs []Run) string {
		var b []string
		for _, r := range runs {
			b = append(b, r.Summary[len("summary "):])
		}
		return strings.Join(b, ",")
	}
	all, err := s.List(0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(all); got != "4,3,2,1,0" {
		t.Errorf("order %s", got)
	}
	sameRun(t, &all[0], testRun(4, "coupon-vuln", runner.Held), false)
	if runs, _ := s.List(2, ""); ids(runs) != "4,3" {
		t.Errorf("limit 2: %s", ids(runs))
	}
	if runs, _ := s.List(10, "coupon-fixed"); ids(runs) != "3,1" {
		t.Errorf("filtered: %s", ids(runs))
	}
	if runs, err := s.List(10, "missing"); err != nil || runs == nil || len(runs) != 0 {
		t.Errorf("no match: %v %v", runs, err)
	}

	// Equal start times keep the newest insert first.
	a, b := testRun(9, "tie", runner.Held), testRun(9, "tie", runner.Held)
	a.ID, b.ID, a.Summary, b.Summary = "00000000000a", "00000000000b", "summary a", "summary b"
	if err := s.Save(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(b); err != nil {
		t.Fatal(err)
	}
	if runs, _ := s.List(0, "tie"); ids(runs) != "b,a" {
		t.Errorf("tie order: %s", ids(runs))
	}
}

func TestListLimits(t *testing.T) {
	s := openMemory(t)
	for n := range MaxLimit + 5 {
		r := testRun(n, "many", runner.Held)
		r.Report = nil
		if err := s.Save(r); err != nil {
			t.Fatal(err)
		}
	}
	if runs, _ := s.List(-1, ""); len(runs) != DefaultLimit {
		t.Errorf("default limit: %d runs", len(runs))
	}
	if runs, _ := s.List(MaxLimit+100, ""); len(runs) != MaxLimit {
		t.Errorf("max limit: %d runs", len(runs))
	}
}

func TestDelete(t *testing.T) {
	s := openMemory(t)
	r := testRun(1, "coupon-vuln", runner.Held)
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(r.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete: %v", err)
	}
	if err := s.Delete(r.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestZeroTimes(t *testing.T) {
	s := openMemory(t)
	r := testRun(1, "x", runner.Errored)
	r.StartedAt, r.FinishedAt = time.Time{}, time.Time{}
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.StartedAt.IsZero() || !got.FinishedAt.IsZero() {
		t.Errorf("zero times came back as %v %v", got.StartedAt, got.FinishedAt)
	}
}

func TestFileDatabase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data dir", "nested")
	path := Path(dir)
	if path != filepath.Join(dir, FileName) {
		t.Fatalf("Path(%q) = %q", dir, path)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal mode %q (%v)", mode, err)
	}
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != SchemaVersion {
		t.Errorf("user_version %d (%v)", version, err)
	}
	r := testRun(1, "coupon-vuln", runner.Violated)
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// The runs survive a restart, and opening again does not migrate twice.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Get(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	sameRun(t, got, r, true)
	if _, err := os.Stat(path); err != nil {
		t.Errorf("database file: %v", err)
	}
}

func TestMemoryIsNotShared(t *testing.T) {
	if Path("") != Memory || Path(Memory) != Memory {
		t.Fatalf("Path of empty and memory: %q %q", Path(""), Path(Memory))
	}
	for _, path := range []string{"", Memory} {
		a, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Save(testRun(1, "x", runner.Held)); err != nil {
			t.Fatal(err)
		}
		b, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if runs, _ := b.List(0, ""); len(runs) != 0 {
			t.Errorf("Open(%q): a second store sees %d runs", path, len(runs))
		}
		a.Close()
		b.Close()
	}
}

func TestNewerSchemaIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer") {
		if s != nil {
			s.Close()
		}
		t.Errorf("Open of a newer schema: %v", err)
	}
}

func TestMigrationsMatchVersion(t *testing.T) {
	if len(migrations) != SchemaVersion {
		t.Errorf("%d migrations for schema version %d", len(migrations), SchemaVersion)
	}
}

func TestBadPath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "a?b.db")); err == nil {
		t.Error("Open accepted a path with '?'")
	}
}

func TestConcurrentUse(t *testing.T) {
	s := openMemory(t)
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for n := range 20 {
		wg.Go(func() {
			r := testRun(n, "concurrent", runner.Held)
			if err := s.Save(r); err != nil {
				errs <- err
				return
			}
			if _, err := s.Get(r.ID); err != nil {
				errs <- err
			}
			if _, err := s.List(5, "concurrent"); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if runs, _ := s.List(0, "concurrent"); len(runs) != 20 {
		t.Errorf("%d runs saved", len(runs))
	}
}

func TestFromReport(t *testing.T) {
	arrival := int64(4000)
	rep := &runner.Report{
		Schema:     runner.Schema,
		Tool:       "photofinish dev",
		Scenario:   "coupon-vuln",
		File:       "examples/coupon-vuln.yaml",
		Target:     "https://127.0.0.1:8443/vuln/api",
		Engine:     engine.H2,
		Copies:     20,
		Invariant:  "size(check.json.discounts) <= 1",
		Verdict:    runner.Violated,
		Summary:    "2 of 3 trials broke the rule (h2, median response spread 0.41 ms)",
		Trials:     []runner.Trial{{Number: 1, Verdict: runner.Violated}},
		Stats:      runner.Stats{Planned: 3, Ran: 3, Violated: 2, Held: 1, MedianServerArrivalSpreadNs: &arrival},
		StartedAt:  base,
		FinishedAt: base.Add(2 * time.Second),
	}
	r, err := FromReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	want := &Run{
		ID: r.ID, Scenario: "coupon-vuln", File: "examples/coupon-vuln.yaml", Engine: "h2",
		Verdict: runner.Violated, Summary: rep.Summary, Trials: 3, Violated: 2, Copies: 20,
		StartedAt: base, FinishedAt: base.Add(2 * time.Second),
	}
	summary := *r
	summary.Report = nil // compared below
	sameRun(t, &summary, want, false)
	if !ValidID(r.ID) {
		t.Errorf("id %q", r.ID)
	}
	if !strings.Contains(string(r.Report), `"invariant":"size(check.json.discounts) <= 1"`) {
		t.Errorf("report JSON escapes or lacks the invariant: %s", r.Report)
	}
	var back runner.Report
	if err := json.Unmarshal(r.Report, &back); err != nil {
		t.Fatal(err)
	}
	if back.Verdict != rep.Verdict || back.Stats.Ran != 3 || len(back.Trials) != 1 || !back.StartedAt.Equal(base) {
		t.Errorf("decoded report %+v", back)
	}

	s := openMemory(t)
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Report) != string(r.Report) {
		t.Error("stored report differs")
	}
	if _, err := FromReport(nil); err == nil {
		t.Error("FromReport accepted nil")
	}
}

func TestRunJSON(t *testing.T) {
	r := testRun(1, "coupon-vuln", runner.Violated)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "scenario", "file", "engine", "verdict", "summary", "trials", "violated", "copies", "startedAt", "finishedAt"} {
		if _, ok := m[key]; !ok {
			t.Errorf("JSON lacks %q: %s", key, data)
		}
	}
	if _, ok := m["report"]; ok || len(m) != 11 {
		t.Errorf("JSON has extra fields: %s", data)
	}
}

func TestQueryFiltersBeforeTheLimit(t *testing.T) {
	s := openMemory(t)
	// One old run of "rare", then many newer runs of "busy".
	if err := s.Save(testRun(0, "rare", runner.Violated)); err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 30; n++ {
		if err := s.Save(testRun(n, "busy", runner.Held)); err != nil {
			t.Fatal(err)
		}
	}
	if runs, err := s.Query(Filter{Limit: 5, Scenario: "rare"}); err != nil || len(runs) != 1 || runs[0].Scenario != "rare" {
		t.Errorf("scenario filter: %v %v", runs, err)
	}
	if runs, err := s.Query(Filter{Limit: 5, Verdict: runner.Violated}); err != nil || len(runs) != 1 || runs[0].Scenario != "rare" {
		t.Errorf("verdict filter: %v %v", runs, err)
	}
	if runs, err := s.Query(Filter{Limit: 5, Scenario: "busy", Verdict: runner.Violated}); err != nil || len(runs) != 0 {
		t.Errorf("both filters: %v %v", runs, err)
	}
	if runs, _ := s.Query(Filter{Limit: 5}); len(runs) != 5 || runs[0].Summary != "summary 30" {
		t.Errorf("no filter: %v", runs)
	}

	names, err := s.Scenarios()
	if err != nil || strings.Join(names, ",") != "busy,rare" {
		t.Errorf("scenarios %v %v", names, err)
	}
	latest, err := s.LatestByFile()
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 || latest["examples/rare.yaml"].Summary != "summary 0" || latest["examples/busy.yaml"].Summary != "summary 30" {
		t.Errorf("latest by file: %v", latest)
	}
	unsaved := testRun(40, "unsaved", runner.Held)
	unsaved.File = ""
	if err := s.Save(unsaved); err != nil {
		t.Fatal(err)
	}
	if latest, _ := s.LatestByFile(); len(latest) != 2 {
		t.Errorf("a run without a file is listed: %v", latest)
	}
}

func TestConcurrentOpenOfANewDatabase(t *testing.T) {
	// Two processes (or CI jobs) starting on an empty data directory at
	// once: both must open it, and the schema is created once.
	for i := range 10 {
		path := filepath.Join(t.TempDir(), FileName)
		var wg sync.WaitGroup
		stores := make([]*Store, 2)
		errs := make([]error, 2)
		for j := range stores {
			wg.Add(1)
			go func() {
				defer wg.Done()
				stores[j], errs[j] = Open(path)
			}()
		}
		wg.Wait()
		for _, s := range stores {
			if s != nil {
				t.Cleanup(func() { s.Close() })
			}
		}
		for j, err := range errs {
			if err != nil {
				t.Fatalf("iteration %d, store %d: %v", i, j, err)
			}
		}
		for j, s := range stores {
			if err := s.Save(testRun(j, fmt.Sprintf("s%d", j), runner.Held)); err != nil {
				t.Errorf("iteration %d: save: %v", i, err)
			}
		}
		if runs, err := stores[0].List(0, ""); err != nil || len(runs) != 2 {
			t.Errorf("iteration %d: list %v %v", i, runs, err)
		}
	}
}
